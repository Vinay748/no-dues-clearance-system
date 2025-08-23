// auth.js - Production-ready Enhanced Authentication Router
const express = require('express');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { loadJSON } = require('../utils/fileUtils');

const router = express.Router();

// =========================================
// 📊 CONFIGURATION & CONSTANTS
// =========================================

const EMPLOYEE_FILE = './data/users_plain.json';
const IT_USERS = './data/it_users.json';
const HOD_USERS = './data/hod_users.json';

// Session timeout configuration
const SESSION_CONFIG = {
  TIMEOUT_MINUTES: 24 * 60, // 24 hours
  WARNING_THRESHOLD: 0.7,   // Warn at 70% of session lifetime
  REFRESH_THRESHOLD: 0.8,   // Auto-refresh at 80% of session lifetime
  MAX_INACTIVE_MINUTES: 2 * 60 // 2 hours of inactivity before forced logout
};

// Security configuration
const SECURITY_CONFIG = {
  MAX_LOGIN_ATTEMPTS: 5,
  LOCKOUT_DURATION: 15 * 60 * 1000, // 15 minutes
  SESSION_ROTATION_INTERVAL: 60 * 60 * 1000, // 1 hour
  ENABLE_AUDIT_LOG: process.env.NODE_ENV === 'production'
};

// =========================================
// 🛡️ SECURITY MIDDLEWARE
// =========================================

// Rate limiting for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 requests per windowMs
  message: {
    success: false,
    message: 'Too many authentication attempts. Please try again later.',
    retryAfter: 15 * 60,
    type: 'RATE_LIMITED'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    console.warn(`🚨 Rate limit exceeded for IP: ${req.ip} - Endpoint: ${req.path}`);
    res.status(429).json({
      success: false,
      message: 'Too many authentication attempts. Please try again later.',
      retryAfter: Math.ceil(res.getHeader('Retry-After') / 60),
      type: 'RATE_LIMITED',
      timestamp: new Date().toISOString()
    });
  }
});

// Stricter rate limiting for logout endpoints
const logoutLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 20, // Allow more logout attempts
  message: {
    success: false,
    message: 'Too many logout attempts. Please wait before trying again.',
    type: 'LOGOUT_RATE_LIMITED'
  }
});

// Apply security middleware to all auth routes
router.use(helmet({
  contentSecurityPolicy: false, // Disable CSP for API routes
  crossOriginEmbedderPolicy: false
}));

// Apply rate limiting to sensitive routes
router.use('/logout', logoutLimiter);
router.use(['/login', '/verify-otp', '/employee-login', '/hod-login', '/it-login'], authLimiter);

// =========================================
// 📝 AUDIT LOGGING SYSTEM
// =========================================

class AuditLogger {
  static log(action, userId, userRole, details = {}, req = null) {
    if (!SECURITY_CONFIG.ENABLE_AUDIT_LOG) return;

    const auditEntry = {
      timestamp: new Date().toISOString(),
      action,
      userId: userId || 'anonymous',
      userRole: userRole || 'unknown',
      sessionId: req?.session?.id || null,
      ip: req?.ip || req?.connection?.remoteAddress || 'unknown',
      userAgent: req?.get('User-Agent') || 'unknown',
      referer: req?.get('Referer') || null,
      details,
      severity: this.getSeverityLevel(action)
    };

    // In production, this should write to a secure audit log file or database
    console.log(`[AUDIT] ${action} - User: ${userId} (${userRole}) - IP: ${auditEntry.ip}`);

    // Store in session for tracking (if session exists)
    if (req?.session) {
      if (!req.session.auditLog) req.session.auditLog = [];
      req.session.auditLog.push(auditEntry);

      // Keep only last 10 audit entries per session
      if (req.session.auditLog.length > 10) {
        req.session.auditLog = req.session.auditLog.slice(-10);
      }
    }

    return auditEntry;
  }

  static getSeverityLevel(action) {
    const highSeverity = ['LOGIN_FAILED', 'SESSION_HIJACK_ATTEMPT', 'MULTIPLE_FAILURES'];
    const mediumSeverity = ['LOGIN_SUCCESS', 'LOGOUT', 'SESSION_EXPIRED'];
    const lowSeverity = ['SESSION_CHECK', 'PROFILE_UPDATE', 'SESSION_REFRESH'];

    if (highSeverity.includes(action)) return 'HIGH';
    if (mediumSeverity.includes(action)) return 'MEDIUM';
    if (lowSeverity.includes(action)) return 'LOW';
    return 'INFO';
  }
}

// =========================================
// 🔐 SESSION SECURITY MANAGER
// =========================================

class SessionSecurityManager {
  static validateSession(req, res, next) {
    if (!req.session?.user) {
      return res.status(401).json({
        success: false,
        message: 'No active session found',
        needsAuth: true,
        code: 'NO_SESSION'
      });
    }

    const user = req.session.user;
    const now = new Date();
    const loginTime = user.loginTime ? new Date(user.loginTime) : null;

    if (!loginTime) {
      AuditLogger.log('INVALID_SESSION_DATA', user.id, user.role,
        { reason: 'No login timestamp' }, req);
      return res.status(401).json({
        success: false,
        message: 'Invalid session data',
        needsAuth: true,
        code: 'INVALID_SESSION'
      });
    }

    const sessionAge = Math.floor((now - loginTime) / 1000 / 60); // minutes
    const lastActivity = user.lastActivity ? new Date(user.lastActivity) : loginTime;
    const inactiveTime = Math.floor((now - lastActivity) / 1000 / 60); // minutes

    // Check session timeout
    if (sessionAge > SESSION_CONFIG.TIMEOUT_MINUTES) {
      AuditLogger.log('SESSION_EXPIRED', user.id, user.role,
        { sessionAge, maxAge: SESSION_CONFIG.TIMEOUT_MINUTES }, req);

      req.session.destroy((err) => {
        if (err) console.error('Session destruction error:', err);
      });

      return res.status(401).json({
        success: false,
        message: 'Session expired due to timeout',
        needsAuth: true,
        code: 'SESSION_EXPIRED',
        sessionAge,
        maxAge: SESSION_CONFIG.TIMEOUT_MINUTES
      });
    }

    // Check inactivity timeout
    if (inactiveTime > SESSION_CONFIG.MAX_INACTIVE_MINUTES) {
      AuditLogger.log('SESSION_INACTIVE', user.id, user.role,
        { inactiveTime, maxInactive: SESSION_CONFIG.MAX_INACTIVE_MINUTES }, req);

      req.session.destroy((err) => {
        if (err) console.error('Session destruction error:', err);
      });

      return res.status(401).json({
        success: false,
        message: 'Session expired due to inactivity',
        needsAuth: true,
        code: 'SESSION_INACTIVE',
        inactiveTime,
        maxInactive: SESSION_CONFIG.MAX_INACTIVE_MINUTES
      });
    }

    // Update activity timestamp
    user.lastActivity = now.toISOString();
    user.sessionChecks = (user.sessionChecks || 0) + 1;

    // Session rotation for long-running sessions
    if (sessionAge > 0 && sessionAge % 60 === 0) { // Every hour
      req.session.regenerate((err) => {
        if (!err) {
          req.session.user = user;
          AuditLogger.log('SESSION_ROTATED', user.id, user.role,
            { sessionAge }, req);
        }
      });
    }

    next();
  }

  static getSessionHealth(user, now = new Date()) {
    const loginTime = user.loginTime ? new Date(user.loginTime) : null;
    const sessionAge = loginTime ? Math.floor((now - loginTime) / 1000 / 60) : 0;
    const remainingMinutes = Math.max(0, SESSION_CONFIG.TIMEOUT_MINUTES - sessionAge);

    return {
      isHealthy: sessionAge < SESSION_CONFIG.TIMEOUT_MINUTES * SESSION_CONFIG.WARNING_THRESHOLD,
      warningThreshold: sessionAge > SESSION_CONFIG.TIMEOUT_MINUTES * SESSION_CONFIG.WARNING_THRESHOLD,
      needsRefresh: sessionAge > SESSION_CONFIG.TIMEOUT_MINUTES * SESSION_CONFIG.REFRESH_THRESHOLD,
      remainingMinutes,
      sessionAge,
      healthScore: Math.max(0, Math.min(100, ((SESSION_CONFIG.TIMEOUT_MINUTES - sessionAge) / SESSION_CONFIG.TIMEOUT_MINUTES) * 100))
    };
  }
}

// =========================================
// ⚠️  IMPORTANT: LEGACY ROUTES - NOT USED
// =========================================

router.post('/login', async (req, res) => {
  AuditLogger.log('DEPRECATED_ENDPOINT_ACCESS', null, null,
    { endpoint: '/login', ip: req.ip }, req);

  return res.status(410).json({
    success: false,
    message: 'This login endpoint is deprecated. Use the OTP authentication system instead.',
    redirectTo: '/api/auth/employee-login',
    deprecatedSince: '2024-01-01',
    supportEndsOn: '2025-12-31'
  });
});

router.post('/verify-otp', (req, res) => {
  AuditLogger.log('DEPRECATED_ENDPOINT_ACCESS', null, null,
    { endpoint: '/verify-otp', ip: req.ip }, req);

  return res.status(410).json({
    success: false,
    message: 'This OTP endpoint is deprecated. Use /api/auth/verify-otp instead.',
    redirectTo: '/api/auth/verify-otp',
    deprecatedSince: '2024-01-01',
    supportEndsOn: '2025-12-31'
  });
});

// =========================================
// ✅ ENHANCED LOGOUT ROUTES
// =========================================

// POST: Enhanced logout for AJAX requests with comprehensive cleanup
router.post('/logout', async (req, res) => {
  try {
    const user = req.session?.user;
    const sessionId = req.session?.id;
    const userAgent = req.get('User-Agent');
    const ip = req.ip;

    // Log logout attempt
    if (user) {
      console.log(`📤 User logout: ${user.name} (${user.role}) - Session: ${sessionId || 'unknown'} - IP: ${ip}`);
      AuditLogger.log('LOGOUT_INITIATED', user.id, user.role, {
        sessionId,
        userAgent: userAgent?.substring(0, 100), // Truncate for logs
        method: 'POST',
        voluntary: true
      }, req);
    } else {
      console.log(`📤 Logout attempt with no active session - IP: ${ip}`);
      AuditLogger.log('LOGOUT_NO_SESSION', null, null, { ip, userAgent }, req);
    }

    // Perform comprehensive session cleanup
    const destroyPromise = new Promise((resolve) => {
      req.session.destroy((err) => {
        if (err) {
          console.error('❌ Session destruction error:', err);
          AuditLogger.log('LOGOUT_ERROR', user?.id, user?.role, { error: err.message }, req);
        } else {
          AuditLogger.log('LOGOUT_SUCCESS', user?.id, user?.role, { sessionId }, req);
        }
        resolve(err);
      });
    });

    const destroyError = await destroyPromise;

    if (destroyError) {
      return res.status(500).json({
        success: false,
        message: 'Logout failed due to session cleanup error',
        code: 'SESSION_DESTROY_FAILED',
        error: process.env.NODE_ENV === 'development' ? destroyError.message : undefined,
        timestamp: new Date().toISOString()
      });
    }

    // Clear all possible session-related cookies
    const cookiesToClear = [
      'connect.sid',           // Default express-session cookie
      'session-token',         // Custom session token if any
      'auth-token',           // Authentication token
      'remember-me',          // Remember me token
      'csrf-token',           // CSRF token if used
      'refresh-token',        // Refresh token
      'user-pref'             // User preferences
    ];

    cookiesToClear.forEach(cookieName => {
      res.clearCookie(cookieName, {
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
        domain: process.env.NODE_ENV === 'production' ? process.env.COOKIE_DOMAIN : undefined
      });
    });

    // Set comprehensive security headers for logout
    res.set({
      'Cache-Control': 'no-cache, no-store, must-revalidate, private',
      'Pragma': 'no-cache',
      'Expires': '0',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'no-referrer'
    });

    console.log('✅ User logged out successfully - Session destroyed and cookies cleared');

    res.json({
      success: true,
      message: 'Logged out successfully',
      redirect: '/login.html',
      timestamp: new Date().toISOString(),
      sessionCleared: true,
      cookiesCleared: cookiesToClear.length,
      securityHeaders: true,
      auditLogged: true
    });

  } catch (error) {
    console.error('❌ Logout error:', error);
    AuditLogger.log('LOGOUT_SYSTEM_ERROR', req.session?.user?.id, req.session?.user?.role,
      { error: error.message, stack: error.stack }, req);

    res.status(500).json({
      success: false,
      message: 'Logout failed due to server error',
      code: 'LOGOUT_SERVER_ERROR',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
      timestamp: new Date().toISOString()
    });
  }
});

// GET: Enhanced logout for browser navigation with redirect
router.get('/logout', async (req, res) => {
  try {
    const user = req.session?.user;
    const sessionId = req.session?.id;

    // Log logout attempt
    if (user) {
      console.log(`📤 Browser logout: ${user.name} (${user.role}) - Session: ${sessionId}`);
      AuditLogger.log('LOGOUT_BROWSER', user.id, user.role, {
        sessionId,
        method: 'GET',
        userAgent: req.get('User-Agent')?.substring(0, 100)
      }, req);
    }

    const destroyPromise = new Promise((resolve) => {
      req.session.destroy((err) => {
        if (err) {
          console.error('❌ Session destruction error on GET logout:', err);
          AuditLogger.log('LOGOUT_BROWSER_ERROR', user?.id, user?.role, { error: err.message }, req);
        } else {
          AuditLogger.log('LOGOUT_BROWSER_SUCCESS', user?.id, user?.role, { sessionId }, req);
        }
        resolve(err);
      });
    });

    await destroyPromise;

    // Clear cookies even if session destruction fails
    const cookiesToClear = [
      'connect.sid', 'session-token', 'auth-token',
      'remember-me', 'csrf-token', 'refresh-token', 'user-pref'
    ];

    cookiesToClear.forEach(cookieName => {
      res.clearCookie(cookieName, {
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax'
      });
    });

    // Set cache prevention and security headers
    res.set({
      'Cache-Control': 'no-cache, no-store, must-revalidate, private',
      'Pragma': 'no-cache',
      'Expires': '0',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY'
    });

    console.log('✅ Browser logout completed - Redirecting to login');

    // Redirect to login page with logout success indicator
    const redirectUrl = '/login.html?logout=success&t=' + Date.now();
    res.redirect(redirectUrl);

  } catch (error) {
    console.error('❌ GET logout error:', error);
    AuditLogger.log('LOGOUT_BROWSER_SYSTEM_ERROR', req.session?.user?.id, req.session?.user?.role,
      { error: error.message }, req);

    // Still redirect even if there's an error, but indicate the issue
    res.redirect('/login.html?logout=error&t=' + Date.now());
  }
});

// Comprehensive logout handler for all methods (fallback)
router.all('/logout', (req, res) => {
  if (req.method === 'POST' || req.method === 'GET') {
    return; // Already handled above
  }

  // Handle other HTTP methods (PUT, DELETE, PATCH, etc.)
  console.log(`📤 Logout via ${req.method} method - IP: ${req.ip}`);
  AuditLogger.log('LOGOUT_ALTERNATE_METHOD', req.session?.user?.id, req.session?.user?.role,
    { method: req.method, ip: req.ip }, req);

  req.session.destroy((err) => {
    res.clearCookie('connect.sid');
    res.json({
      success: true,
      message: `Logged out via ${req.method} method`,
      method: req.method,
      timestamp: new Date().toISOString()
    });
  });
});

// =========================================
// ✅ ENHANCED SESSION MANAGEMENT
// =========================================

// Enhanced session check API with comprehensive validation
router.get('/check-session', SessionSecurityManager.validateSession, (req, res) => {
  try {
    const user = req.session.user;
    const now = new Date();
    const sessionHealth = SessionSecurityManager.getSessionHealth(user, now);
    const loginTime = user.loginTime ? new Date(user.loginTime) : null;
    const sessionAge = Math.floor((now - (loginTime || now)) / 1000 / 60);

    // Enhanced session information
    const sessionInfo = {
      loginTime: user.loginTime,
      lastActivity: user.lastActivity,
      sessionAge,
      sessionId: req.session.id,
      health: sessionHealth,
      expires: new Date(now.getTime() + (sessionHealth.remainingMinutes * 60 * 1000)).toISOString(),
      checks: user.sessionChecks || 0,
      rotations: user.sessionRotations || 0,
      authMethod: user.role === 'employee' ? 'Email OTP' : 'Direct Login',
      securityLevel: this.calculateSecurityLevel(user, sessionAge),
      flags: {
        nearExpiry: sessionHealth.warningThreshold,
        needsRefresh: sessionHealth.needsRefresh,
        isSecure: req.secure || req.get('x-forwarded-proto') === 'https'
      }
    };

    // Log session check for audit
    AuditLogger.log('SESSION_CHECK', user.id, user.role, {
      sessionAge,
      healthScore: sessionHealth.healthScore,
      remainingMinutes: sessionHealth.remainingMinutes
    }, req);

    return res.json({
      success: true,
      authenticated: true,
      timestamp: now.toISOString(),

      // Core user information
      role: user.role,
      id: user.id,
      employeeId: user.employeeId,
      name: user.name,
      email: user.email,
      department: user.department || '',
      designation: user.designation || '',
      phone: user.phone || '',

      // Enhanced session information
      sessionInfo,

      // Role-specific enhanced data
      ...(user.role === 'hod' && {
        hodId: user.hodId,
        hodSpecificData: true,
        permissions: ['review_forms', 'approve_requests', 'view_reports']
      }),

      ...(user.role === 'employee' && {
        formId: user.formId || null,
        applicationStatus: user.applicationStatus || 'Not Submitted',
        employeeSpecificData: true,
        lastFormUpdate: user.lastFormUpdate || null,
        permissions: ['submit_forms', 'view_status', 'update_profile']
      }),

      ...(user.role === 'it' && {
        itSpecificData: true,
        permissions: ['manage_system', 'view_all_data', 'generate_reports', 'manage_users']
      }),

      // System information
      serverTimestamp: now.toISOString(),
      environment: process.env.NODE_ENV || 'development'
    });

  } catch (error) {
    console.error('❌ Enhanced session check error:', error);
    AuditLogger.log('SESSION_CHECK_ERROR', req.session?.user?.id, req.session?.user?.role,
      { error: error.message }, req);

    return res.status(500).json({
      success: false,
      message: 'Session check failed due to server error',
      code: 'SESSION_CHECK_ERROR',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
      timestamp: new Date().toISOString()
    });
  }
});

// Helper method for security level calculation
function calculateSecurityLevel(user, sessionAge) {
  let score = 100;

  // Reduce score based on session age
  if (sessionAge > 12 * 60) score -= 30; // > 12 hours
  else if (sessionAge > 6 * 60) score -= 15; // > 6 hours
  else if (sessionAge > 2 * 60) score -= 5; // > 2 hours

  // Increase score for recent activity
  const lastActivity = user.lastActivity ? new Date(user.lastActivity) : null;
  if (lastActivity) {
    const timeSinceActivity = (new Date() - lastActivity) / 1000 / 60; // minutes
    if (timeSinceActivity < 5) score += 10; // Very recent activity
    else if (timeSinceActivity < 30) score += 5; // Recent activity
  }

  // Security factors
  if (user.role === 'it') score += 10; // IT users get higher security scoring
  if (user.sessionRotations > 0) score += 5; // Session rotations improve security

  return Math.max(0, Math.min(100, Math.floor(score)));
}

// Enhanced profile update with validation and audit
router.post('/update-profile', SessionSecurityManager.validateSession, async (req, res) => {
  try {
    const { name, email, department, phone, designation } = req.body;
    const user = req.session.user;

    // Enhanced validation with detailed error reporting
    const validationErrors = [];
    const updates = {};

    // Name validation
    if (name !== undefined) {
      if (!name || typeof name !== 'string' || name.trim().length < 2) {
        validationErrors.push({ field: 'name', message: 'Name must be at least 2 characters long' });
      } else if (name.trim().length > 100) {
        validationErrors.push({ field: 'name', message: 'Name must not exceed 100 characters' });
      } else if (!/^[a-zA-Z\s'-]+$/.test(name.trim())) {
        validationErrors.push({ field: 'name', message: 'Name contains invalid characters' });
      } else {
        updates.name = name.trim();
      }
    }

    // Email validation
    if (email !== undefined) {
      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!emailRegex.test(email)) {
        validationErrors.push({ field: 'email', message: 'Please provide a valid email address' });
      } else if (email.length > 255) {
        validationErrors.push({ field: 'email', message: 'Email address is too long' });
      } else {
        updates.email = email.toLowerCase().trim();
      }
    }

    // Phone validation
    if (phone !== undefined && phone.trim()) {
      const phoneRegex = /^[\d\-\+\(\)\s]{10,15}$/;
      const cleanPhone = phone.replace(/\D/g, '');
      if (!phoneRegex.test(phone) || cleanPhone.length < 10) {
        validationErrors.push({ field: 'phone', message: 'Please provide a valid phone number (10-15 digits)' });
      } else {
        updates.phone = phone.trim();
      }
    }

    // Department validation
    if (department !== undefined) {
      if (department.trim().length > 100) {
        validationErrors.push({ field: 'department', message: 'Department name is too long' });
      } else {
        updates.department = department.trim();
      }
    }

    // Designation validation
    if (designation !== undefined) {
      if (designation.trim().length > 100) {
        validationErrors.push({ field: 'designation', message: 'Designation is too long' });
      } else {
        updates.designation = designation.trim();
      }
    }

    if (validationErrors.length > 0) {
      AuditLogger.log('PROFILE_UPDATE_VALIDATION_FAILED', user.id, user.role,
        { validationErrors, attemptedUpdates: Object.keys(req.body) }, req);

      return res.status(400).json({
        success: false,
        message: 'Profile validation failed',
        code: 'VALIDATION_FAILED',
        errors: validationErrors,
        timestamp: new Date().toISOString()
      });
    }

    // Store old values for audit
    const oldValues = {};
    const appliedUpdates = {};

    // Apply updates
    Object.keys(updates).forEach(key => {
      oldValues[key] = user[key];
      user[key] = updates[key];
      appliedUpdates[key] = updates[key];
    });

    // Update metadata
    const now = new Date().toISOString();
    user.lastActivity = now;
    user.profileLastUpdated = now;
    user.profileUpdateCount = (user.profileUpdateCount || 0) + 1;

    // Audit log
    AuditLogger.log('PROFILE_UPDATED', user.id, user.role, {
      updatedFields: Object.keys(appliedUpdates),
      oldValues,
      newValues: appliedUpdates,
      updateCount: user.profileUpdateCount
    }, req);

    console.log(`📝 Profile updated for ${user.role}: ${user.name} - Fields: ${Object.keys(appliedUpdates).join(', ')}`);

    res.json({
      success: true,
      message: 'Profile updated successfully',
      updatedFields: Object.keys(appliedUpdates),
      updateCount: user.profileUpdateCount,
      profile: {
        name: user.name,
        email: user.email,
        department: user.department,
        phone: user.phone,
        designation: user.designation,
        role: user.role,
        lastUpdated: user.profileLastUpdated,
        authMethod: user.role === 'employee' ? 'Email OTP' : 'Direct Login'
      },
      timestamp: now
    });

  } catch (error) {
    console.error('❌ Enhanced profile update error:', error);
    AuditLogger.log('PROFILE_UPDATE_ERROR', req.session?.user?.id, req.session?.user?.role,
      { error: error.message, stack: error.stack }, req);

    res.status(500).json({
      success: false,
      message: 'Profile update failed due to server error',
      code: 'PROFILE_UPDATE_ERROR',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
      timestamp: new Date().toISOString()
    });
  }
});

// Enhanced session refresh with smart refresh logic
router.post('/refresh-session', SessionSecurityManager.validateSession, (req, res) => {
  try {
    const user = req.session.user;
    const now = new Date();
    const sessionHealth = SessionSecurityManager.getSessionHealth(user, now);

    // Touch session to extend expiry
    req.session.touch();

    // Update tracking
    user.lastActivity = now.toISOString();
    user.sessionRefreshed = now.toISOString();
    user.sessionRefreshCount = (user.sessionRefreshCount || 0) + 1;

    // Smart session refresh - rotate session ID if needed
    let sessionRotated = false;
    if (sessionHealth.needsRefresh || req.body.forceRotation) {
      req.session.regenerate((err) => {
        if (!err) {
          req.session.user = user;
          user.sessionRotations = (user.sessionRotations || 0) + 1;
          sessionRotated = true;

          AuditLogger.log('SESSION_ROTATED', user.id, user.role, {
            refreshCount: user.sessionRefreshCount,
            rotationCount: user.sessionRotations,
            forced: !!req.body.forceRotation
          }, req);
        }
      });
    }

    const sessionAge = Math.floor((now - new Date(user.loginTime)) / 1000 / 60);

    AuditLogger.log('SESSION_REFRESHED', user.id, user.role, {
      sessionAge,
      refreshCount: user.sessionRefreshCount,
      rotated: sessionRotated,
      healthScore: sessionHealth.healthScore
    }, req);

    console.log(`🔄 Session refreshed for ${user.role}: ${user.name} - Age: ${sessionAge}min - Health: ${sessionHealth.healthScore}%`);

    res.json({
      success: true,
      message: 'Session refreshed successfully',
      refreshedAt: now.toISOString(),
      sessionRotated,
      refreshCount: user.sessionRefreshCount,
      user: {
        role: user.role,
        name: user.name,
        id: user.id,
        lastActivity: user.lastActivity
      },
      sessionHealth: {
        ...sessionHealth,
        refreshed: true,
        rotated: sessionRotated,
        score: sessionHealth.healthScore
      },
      timestamp: now.toISOString()
    });

  } catch (error) {
    console.error('❌ Enhanced session refresh error:', error);
    AuditLogger.log('SESSION_REFRESH_ERROR', req.session?.user?.id, req.session?.user?.role,
      { error: error.message }, req);

    res.status(500).json({
      success: false,
      message: 'Session refresh failed',
      code: 'SESSION_REFRESH_ERROR',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
      timestamp: new Date().toISOString()
    });
  }
});

// Enhanced user info endpoint with comprehensive data
router.get('/user-info', SessionSecurityManager.validateSession, (req, res) => {
  try {
    const user = req.session.user;
    const now = new Date();
    const sessionHealth = SessionSecurityManager.getSessionHealth(user, now);
    const sessionAge = Math.floor((now - new Date(user.loginTime)) / 1000 / 60);

    AuditLogger.log('USER_INFO_REQUEST', user.id, user.role, {
      sessionAge,
      healthScore: sessionHealth.healthScore
    }, req);

    res.json({
      success: true,
      timestamp: now.toISOString(),
      user: {
        // Core information
        id: user.id,
        employeeId: user.employeeId,
        name: user.name,
        email: user.email,
        phone: user.phone || '',
        role: user.role,
        department: user.department || '',
        designation: user.designation || '',

        // Activity tracking
        loginTime: user.loginTime,
        lastActivity: user.lastActivity,
        profileLastUpdated: user.profileLastUpdated,
        sessionAge,
        authMethod: user.role === 'employee' ? 'Email OTP' : 'Direct Login',

        // Session statistics
        sessionChecks: user.sessionChecks || 0,
        sessionRefreshCount: user.sessionRefreshCount || 0,
        sessionRotations: user.sessionRotations || 0,
        profileUpdateCount: user.profileUpdateCount || 0,

        // Security information
        securityLevel: calculateSecurityLevel(user, sessionAge),
        sessionHealth,

        // Role-specific data
        ...(user.role === 'employee' && {
          formId: user.formId || null,
          applicationStatus: user.applicationStatus || 'Not Submitted',
          lastFormUpdate: user.lastFormUpdate || null
        }),

        ...(user.role === 'hod' && {
          hodId: user.hodId
        })
      },
      systemInfo: {
        serverTime: now.toISOString(),
        environment: process.env.NODE_ENV || 'development',
        sessionTimeout: SESSION_CONFIG.TIMEOUT_MINUTES,
        maxInactive: SESSION_CONFIG.MAX_INACTIVE_MINUTES
      }
    });

  } catch (error) {
    console.error('❌ Enhanced user info error:', error);
    AuditLogger.log('USER_INFO_ERROR', req.session?.user?.id, req.session?.user?.role,
      { error: error.message }, req);

    res.status(500).json({
      success: false,
      message: 'Failed to get user information',
      code: 'USER_INFO_ERROR',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
      timestamp: new Date().toISOString()
    });
  }
});

// Enhanced session validation with detailed health check
router.post('/validate-session', SessionSecurityManager.validateSession, (req, res) => {
  try {
    const user = req.session.user;
    const now = new Date();
    const sessionHealth = SessionSecurityManager.getSessionHealth(user, now);
    const sessionAge = Math.floor((now - new Date(user.loginTime)) / 1000 / 60);

    // Update activity
    user.lastActivity = now.toISOString();
    user.validationCount = (user.validationCount || 0) + 1;

    AuditLogger.log('SESSION_VALIDATED', user.id, user.role, {
      sessionAge,
      healthScore: sessionHealth.healthScore,
      validationCount: user.validationCount
    }, req);

    console.log(`✅ Session validated for ${user.role}: ${user.name} - Age: ${sessionAge}min - Health: ${sessionHealth.healthScore}%`);

    res.json({
      success: true,
      message: 'Session is valid and active',
      validated: true,
      validationCount: user.validationCount,
      sessionInfo: {
        role: user.role,
        name: user.name,
        id: user.id,
        loginTime: user.loginTime,
        lastActivity: user.lastActivity,
        sessionAge,
        authMethod: user.role === 'employee' ? 'Email OTP' : 'Direct Login',
        health: sessionHealth,
        securityLevel: calculateSecurityLevel(user, sessionAge)
      },
      timestamp: now.toISOString()
    });

  } catch (error) {
    console.error('❌ Enhanced session validation error:', error);
    AuditLogger.log('SESSION_VALIDATION_ERROR', req.session?.user?.id, req.session?.user?.role,
      { error: error.message }, req);

    res.status(500).json({
      success: false,
      message: 'Session validation failed due to server error',
      code: 'SESSION_VALIDATION_ERROR',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
      timestamp: new Date().toISOString()
    });
  }
});

// Enhanced session sync with comprehensive data management
router.post('/sync-session', SessionSecurityManager.validateSession, (req, res) => {
  try {
    const { formId, applicationStatus, additionalData } = req.body;
    const user = req.session.user;
    const updates = {};

    // Sync employee-specific data with validation
    if (user.role === 'employee') {
      if (formId !== undefined) {
        if (typeof formId === 'string' && formId.length <= 50) {
          user.formId = formId;
          updates.formId = formId;
        }
      }

      if (applicationStatus !== undefined) {
        const validStatuses = ['Not Submitted', 'Draft', 'Submitted', 'Under Review', 'Approved', 'Rejected'];
        if (validStatuses.includes(applicationStatus)) {
          user.applicationStatus = applicationStatus;
          user.lastFormUpdate = new Date().toISOString();
          updates.applicationStatus = applicationStatus;
          updates.lastFormUpdate = user.lastFormUpdate;
        }
      }

      // Handle additional data sync with security filtering
      if (additionalData && typeof additionalData === 'object') {
        const allowedFields = ['phone', 'department', 'designation', 'preferences'];
        Object.keys(additionalData).forEach(key => {
          if (allowedFields.includes(key) && typeof additionalData[key] === 'string') {
            user[key] = additionalData[key].substring(0, 255); // Limit length
            updates[key] = user[key];
          }
        });
      }
    }

    // Update metadata
    const now = new Date().toISOString();
    user.lastActivity = now;
    user.lastSyncTime = now;
    user.syncCount = (user.syncCount || 0) + 1;

    // Audit logging
    AuditLogger.log('SESSION_SYNCED', user.id, user.role, {
      updatedFields: Object.keys(updates),
      syncCount: user.syncCount,
      dataSize: JSON.stringify(updates).length
    }, req);

    console.log(`🔄 Session synced for ${user.role}: ${user.name} - Fields: ${Object.keys(updates).join(', ')}`);

    res.json({
      success: true,
      message: 'Session synchronized successfully',
      syncedAt: user.lastSyncTime,
      syncCount: user.syncCount,
      updatedFields: Object.keys(updates),
      sessionData: {
        formId: user.formId || null,
        applicationStatus: user.applicationStatus || 'Not Submitted',
        lastActivity: user.lastActivity,
        lastSyncTime: user.lastSyncTime,
        lastFormUpdate: user.lastFormUpdate || null,
        ...updates
      },
      timestamp: now
    });

  } catch (error) {
    console.error('❌ Enhanced session sync error:', error);
    AuditLogger.log('SESSION_SYNC_ERROR', req.session?.user?.id, req.session?.user?.role,
      { error: error.message }, req);

    res.status(500).json({
      success: false,
      message: 'Session sync failed',
      code: 'SESSION_SYNC_ERROR',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
      timestamp: new Date().toISOString()
    });
  }
});

// =========================================
// ✅ ENHANCED DEVELOPMENT & DEBUG ROUTES
// =========================================

// Comprehensive auth info endpoint
router.get('/auth-info', (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(404).json({
      success: false,
      message: 'Development endpoint not available in production'
    });
  }

  const activeSessions = req.sessionStore ?
    Object.keys(req.sessionStore.sessions || {}).length : 'Unknown';

  res.json({
    success: true,
    timestamp: new Date().toISOString(),
    authSystem: {
      name: 'Enterprise Authentication System',
      version: '3.0.0',
      environment: process.env.NODE_ENV || 'development',

      features: {
        multiRoleAuth: true,
        sessionSecurity: true,
        auditLogging: SECURITY_CONFIG.ENABLE_AUDIT_LOG,
        rateLimiting: true,
        sessionRotation: true,
        comprehensiveValidation: true,
        enhancedSecurity: true
      },

      configuration: {
        sessionTimeout: `${SESSION_CONFIG.TIMEOUT_MINUTES} minutes`,
        maxInactive: `${SESSION_CONFIG.MAX_INACTIVE_MINUTES} minutes`,
        warningThreshold: `${SESSION_CONFIG.WARNING_THRESHOLD * 100}%`,
        refreshThreshold: `${SESSION_CONFIG.REFRESH_THRESHOLD * 100}%`,
        maxLoginAttempts: SECURITY_CONFIG.MAX_LOGIN_ATTEMPTS,
        lockoutDuration: `${SECURITY_CONFIG.LOCKOUT_DURATION / 1000 / 60} minutes`
      },

      authMethods: {
        employee: {
          type: 'Email OTP',
          email: 'ruinedjhonny@gmail.com',
          description: 'One-time password sent via email',
          security: 'High'
        },
        hod: {
          type: 'Direct Login',
          encryption: 'bcrypt hashed passwords',
          description: 'Username/password authentication',
          security: 'High'
        },
        it: {
          type: 'Direct Login',
          encryption: 'bcrypt hashed passwords',
          description: 'Username/password authentication',
          security: 'Very High'
        }
      },

      endpoints: {
        authentication: {
          employeeLogin: 'POST /api/auth/employee-login',
          hodLogin: 'POST /api/auth/hod-login',
          itLogin: 'POST /api/auth/it-login',
          otpVerify: 'POST /api/auth/verify-otp',
          otpResend: 'POST /api/auth/resend-otp'
        },
        session: {
          checkSession: 'GET /api/auth/check-session',
          refreshSession: 'POST /api/auth/refresh-session',
          syncSession: 'POST /api/auth/sync-session',
          validateSession: 'POST /api/auth/validate-session'
        },
        profile: {
          getUserInfo: 'GET /api/auth/user-info',
          updateProfile: 'POST /api/auth/update-profile'
        },
        logout: {
          logoutPost: 'POST /api/auth/logout (returns JSON)',
          logoutGet: 'GET /api/auth/logout (redirects to login)',
          logoutAll: 'ALL /api/auth/logout (fallback handler)'
        },
        debug: {
          authInfo: 'GET /api/auth/auth-info (dev only)',
          sessionDebug: 'GET /api/auth/session-debug (dev only)'
        }
      },

      security: {
        rateLimiting: {
          authEndpoints: '10 requests per 15 minutes',
          logoutEndpoints: '20 requests per 5 minutes'
        },
        sessionSecurity: {
          rotation: 'Every hour for long sessions',
          validation: 'Comprehensive with health checks',
          auditLogging: 'All authentication events'
        },
        cookieSecurity: {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict in production',
          managed: ['connect.sid', 'session-token', 'auth-token', 'remember-me', 'csrf-token']
        }
      },

      statistics: {
        activeSessions,
        supportedRoles: ['employee', 'hod', 'it'],
        auditingEnabled: SECURITY_CONFIG.ENABLE_AUDIT_LOG,
        productionReady: true
      }
    }
  });
});

// Enhanced session debug endpoint
router.get('/session-debug', (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(404).json({
      success: false,
      message: 'Debug endpoint not available in production'
    });
  }

  const sessionExists = !!req.session;
  const userExists = !!(req.session && req.session.user);
  const user = req.session?.user;

  res.json({
    success: true,
    timestamp: new Date().toISOString(),
    debug: {
      session: {
        exists: sessionExists,
        id: req.session?.id || null,
        cookie: req.session?.cookie ? {
          maxAge: req.session.cookie.maxAge,
          expires: req.session.cookie.expires,
          httpOnly: req.session.cookie.httpOnly,
          secure: req.session.cookie.secure,
          sameSite: req.session.cookie.sameSite
        } : null
      },
      user: userExists ? {
        role: user.role,
        name: user.name,
        id: user.id,
        loginTime: user.loginTime,
        lastActivity: user.lastActivity,
        sessionAge: user.loginTime ? Math.floor((new Date() - new Date(user.loginTime)) / 1000 / 60) : null,
        statistics: {
          sessionChecks: user.sessionChecks || 0,
          sessionRefreshCount: user.sessionRefreshCount || 0,
          sessionRotations: user.sessionRotations || 0,
          validationCount: user.validationCount || 0,
          syncCount: user.syncCount || 0,
          profileUpdateCount: user.profileUpdateCount || 0
        },
        health: userExists ? SessionSecurityManager.getSessionHealth(user) : null
      } : null,
      request: {
        ip: req.ip,
        ips: req.ips,
        secure: req.secure,
        method: req.method,
        path: req.path,
        protocol: req.protocol,
        headers: {
          userAgent: req.get('User-Agent'),
          referer: req.get('Referer'),
          origin: req.get('Origin'),
          xForwardedFor: req.get('X-Forwarded-For'),
          xForwardedProto: req.get('X-Forwarded-Proto')
        }
      },
      security: {
        rateLimitInfo: req.rateLimit ? {
          limit: req.rateLimit.limit,
          current: req.rateLimit.current,
          remaining: req.rateLimit.remaining,
          resetTime: new Date(Date.now() + req.rateLimit.resetTime)
        } : null,
        auditingEnabled: SECURITY_CONFIG.ENABLE_AUDIT_LOG
      }
    }
  });
});

// Health check endpoint
router.get('/health', (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
    authSystem: {
      version: '3.0.0',
      features: {
        rateLimiting: true,
        sessionSecurity: true,
        auditLogging: SECURITY_CONFIG.ENABLE_AUDIT_LOG,
        multiRole: true
      }
    }
  };

  res.json(health);
});

// =========================================
// ✅ ERROR HANDLING MIDDLEWARE
// =========================================

// Global error handler for auth routes
router.use((error, req, res, next) => {
  console.error('❌ Auth router error:', error);

  // Log error for audit
  AuditLogger.log('SYSTEM_ERROR', req.session?.user?.id, req.session?.user?.role, {
    error: error.message,
    stack: error.stack,
    path: req.path,
    method: req.method
  }, req);

  res.status(500).json({
    success: false,
    message: 'Authentication system error',
    code: 'AUTH_SYSTEM_ERROR',
    error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
    timestamp: new Date().toISOString(),
    requestId: req.session?.id || 'unknown'
  });
});

// Export router
module.exports = router;
