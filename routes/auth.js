const express = require('express');
const bcrypt = require('bcryptjs');
const { loadJSON } = require('../utils/fileUtils');

const router = express.Router();

const EMPLOYEE_FILE = './data/users_plain.json';
const IT_USERS = './data/it_users.json';
const HOD_USERS = './data/hod_users.json';

console.log('[AUTH_ROUTER] Initializing auth router with file paths:', {
  employees: EMPLOYEE_FILE,
  itUsers: IT_USERS,
  hodUsers: HOD_USERS
});

// =========================================
// ⚠️  IMPORTANT: LEGACY ROUTES - NOT USED
// =========================================

router.post('/login', async (req, res) => {
  console.log('[LEGACY_LOGIN] Deprecated login endpoint accessed from IP:', req.ip);
  console.log('[LEGACY_LOGIN] Request headers:', req.headers['user-agent']);

  return res.status(410).json({
    success: false,
    message: 'This login endpoint is deprecated. Use the OTP authentication system instead.',
    redirectTo: '/api/auth/employee-login'
  });
});

router.post('/verify-otp', (req, res) => {
  console.log('[LEGACY_OTP] Deprecated OTP endpoint accessed from IP:', req.ip);

  return res.status(410).json({
    success: false,
    message: 'This OTP endpoint is deprecated. Use /api/auth/verify-otp instead.',
    redirectTo: '/api/auth/verify-otp'
  });
});

// =========================================
// ✅ ENHANCED LOGOUT ROUTES
// =========================================

// POST: Enhanced logout for AJAX requests with comprehensive cleanup
router.post('/logout', (req, res) => {
  console.log('[LOGOUT_POST] Logout request received from IP:', req.ip);
  console.log('[LOGOUT_POST] User agent:', req.headers['user-agent']);

  try {
    const user = req.session?.user;
    const sessionId = req.session?.id;

    // Log logout attempt
    if (user) {
      console.log(`[LOGOUT_POST] 📤 User logout: ${user.name} (${user.role}) - Session: ${sessionId || 'unknown'}`);
      console.log(`[LOGOUT_POST] User details:`, {
        employeeId: user.employeeId,
        email: user.email?.substring(0, 3) + '***',
        loginTime: user.loginTime,
        lastActivity: user.lastActivity
      });
    } else {
      console.log('[LOGOUT_POST] 📤 Logout attempt with no active session');
    }

    // Perform comprehensive session cleanup
    req.session.destroy((err) => {
      if (err) {
        console.error('[LOGOUT_POST] ❌ Session destruction error:', err.message);
        return res.status(500).json({
          success: false,
          message: 'Logout failed due to session cleanup error',
          error: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
      }

      console.log('[LOGOUT_POST] Session destroyed successfully');

      // Clear all possible session-related cookies
      const cookiesToClear = [
        'connect.sid',           // Default express-session cookie
        'session-token',         // Custom session token if any
        'auth-token',           // Authentication token
        'remember-me',          // Remember me token
        'csrf-token'            // CSRF token if used
      ];

      console.log('[LOGOUT_POST] Clearing cookies:', cookiesToClear);

      cookiesToClear.forEach(cookieName => {
        res.clearCookie(cookieName, {
          path: '/',
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax'
        });
      });

      // Set security headers for logout
      res.set({
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      });

      console.log('[LOGOUT_POST] ✅ User logged out successfully - Session destroyed and cookies cleared');

      res.json({
        success: true,
        message: 'Logged out successfully',
        redirect: '/login.html',
        timestamp: new Date().toISOString(),
        sessionCleared: true
      });
    });

  } catch (error) {
    console.error('[LOGOUT_POST] ❌ Logout error:', error.message);
    res.status(500).json({
      success: false,
      message: 'Logout failed due to server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// GET: Enhanced logout for browser navigation with redirect
router.get('/logout', (req, res) => {
  console.log('[LOGOUT_GET] Browser logout request from IP:', req.ip);
  console.log('[LOGOUT_GET] Referer:', req.headers.referer);

  try {
    const user = req.session?.user;

    // Log logout attempt
    if (user) {
      console.log(`[LOGOUT_GET] 📤 Browser logout: ${user.name} (${user.role})`);
    } else {
      console.log('[LOGOUT_GET] Browser logout with no active session');
    }

    req.session.destroy((err) => {
      if (err) {
        console.error('[LOGOUT_GET] ❌ Session destruction error on GET logout:', err.message);
      } else {
        console.log('[LOGOUT_GET] Session destroyed successfully');
      }

      // Clear cookies even if session destruction fails
      const cookiesToClear = [
        'connect.sid', 'session-token', 'auth-token',
        'remember-me', 'csrf-token'
      ];

      console.log('[LOGOUT_GET] Clearing cookies for browser logout');

      cookiesToClear.forEach(cookieName => {
        res.clearCookie(cookieName, {
          path: '/',
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax'
        });
      });

      // Set cache prevention headers
      res.set({
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      });

      console.log('[LOGOUT_GET] ✅ Browser logout completed - Redirecting to login');

      // Redirect to login page (adjust path as needed)
      res.redirect('/login.html');
    });

  } catch (error) {
    console.error('[LOGOUT_GET] ❌ GET logout error:', error.message);
    // Still redirect even if there's an error
    res.redirect('/login.html?error=logout_failed');
  }
});

// ✅ Enhanced logout for all methods (fallback)
router.all('/logout', (req, res) => {
  if (req.method === 'POST') {
    return; // Already handled above
  }
  if (req.method === 'GET') {
    return; // Already handled above
  }

  // Handle other HTTP methods
  console.log(`[LOGOUT_ALL] 📤 Logout via ${req.method} method from IP:`, req.ip);

  req.session.destroy((err) => {
    if (err) {
      console.error('[LOGOUT_ALL] Session destruction error:', err.message);
    }
    res.clearCookie('connect.sid');
    console.log(`[LOGOUT_ALL] Logout completed via ${req.method} method`);
    res.json({
      success: true,
      message: 'Logged out via fallback method',
      method: req.method
    });
  });
});

// =========================================
// ✅ ENHANCED SESSION MANAGEMENT
// =========================================

// ---------- ENHANCED SESSION CHECK API ----------
router.get('/check-session', (req, res) => {
  console.log('[CHECK_SESSION] Session check request from IP:', req.ip);
  console.log('[CHECK_SESSION] Session exists:', !!req.session);
  console.log('[CHECK_SESSION] User exists:', !!(req.session?.user));

  try {
    if (!req.session?.user) {
      console.log('[CHECK_SESSION] No active session found');
      return res.status(401).json({
        success: false,
        message: 'No active session found',
        needsAuth: true,
        sessionExists: false
      });
    }

    const user = req.session.user;
    const now = new Date();
    const loginTime = user.loginTime ? new Date(user.loginTime) : null;
    const sessionAge = loginTime ? Math.floor((now - loginTime) / 1000 / 60) : 0; // minutes

    console.log('[CHECK_SESSION] User found:', {
      name: user.name,
      role: user.role,
      employeeId: user.employeeId,
      sessionAge: sessionAge
    });

    // Enhanced session timeout check (24 hours = 1440 minutes)
    const sessionTimeoutMinutes = 24 * 60;
    if (loginTime && sessionAge > sessionTimeoutMinutes) {
      console.log(`[CHECK_SESSION] ⏰ Session expired for user ${user.name} - Age: ${sessionAge} minutes`);

      req.session.destroy((err) => {
        if (err) console.error('[CHECK_SESSION] Session destruction error:', err.message);
      });

      return res.status(401).json({
        success: false,
        message: 'Session expired due to timeout',
        needsAuth: true,
        sessionExpired: true,
        sessionAge: sessionAge,
        maxAge: sessionTimeoutMinutes
      });
    }

    // Update last activity timestamp
    user.lastActivity = now.toISOString();

    // Calculate session health
    const sessionHealth = {
      isHealthy: sessionAge < sessionTimeoutMinutes * 0.8, // Healthy if less than 80% of max age
      warningThreshold: sessionAge > sessionTimeoutMinutes * 0.7, // Warning at 70%
      remainingMinutes: Math.max(0, sessionTimeoutMinutes - sessionAge)
    };

    console.log('[CHECK_SESSION] Session health:', sessionHealth);
    console.log('[CHECK_SESSION] ✅ Session check successful for user:', user.name);

    return res.json({
      success: true,
      authenticated: true,
      role: user.role,
      id: user.id,
      employeeId: user.employeeId,
      name: user.name,
      email: user.email,
      department: user.department || '',
      designation: user.designation || '',

      // Enhanced session information
      sessionInfo: {
        loginTime: user.loginTime,
        lastActivity: user.lastActivity,
        sessionAge: sessionAge,
        authMethod: user.role === 'employee' ? 'Email OTP' : 'Direct Login',
        sessionId: req.session.id,
        health: sessionHealth,
        expires: new Date(now.getTime() + (sessionHealth.remainingMinutes * 60 * 1000)).toISOString()
      },

      // Role-specific data
      ...(user.role === 'hod' && {
        hodId: user.hodId,
        hodSpecificData: true
      }),

      // Employee-specific session data with form tracking
      ...(user.role === 'employee' && {
        formId: user.formId || null,
        applicationStatus: user.applicationStatus || 'Not Submitted',
        employeeSpecificData: true
      }),

      // IT-specific data
      ...(user.role === 'it' && {
        itSpecificData: true
      })
    });

  } catch (error) {
    console.error('[CHECK_SESSION] ❌ Session check error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Session check failed due to server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ---------- ENHANCED PROFILE UPDATE ----------
router.post('/update-profile', (req, res) => {
  console.log('[UPDATE_PROFILE] Profile update request from IP:', req.ip);
  console.log('[UPDATE_PROFILE] Request body keys:', Object.keys(req.body));

  try {
    if (!req.session?.user) {
      console.log('[UPDATE_PROFILE] Unauthorized access attempt');
      return res.status(401).json({
        success: false,
        message: 'Not authenticated - Cannot update profile',
        needsAuth: true
      });
    }

    const { name, email, department, phone, designation } = req.body;
    const user = req.session.user;

    console.log('[UPDATE_PROFILE] Current user:', {
      name: user.name,
      role: user.role,
      employeeId: user.employeeId
    });

    // Enhanced validation
    const validationErrors = [];

    if (name !== undefined) {
      console.log('[UPDATE_PROFILE] Validating name:', name);
      if (!name || name.trim().length < 2) {
        validationErrors.push('Name must be at least 2 characters long');
      } else if (name.trim().length > 100) {
        validationErrors.push('Name must not exceed 100 characters');
      }
    }

    if (email !== undefined) {
      console.log('[UPDATE_PROFILE] Validating email:', email?.substring(0, 3) + '***');
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        validationErrors.push('Please provide a valid email address');
      }
    }

    if (phone !== undefined && phone.trim()) {
      console.log('[UPDATE_PROFILE] Validating phone:', phone?.substring(0, 3) + '***');
      const phoneRegex = /^[\d\-\+\(\)\s]+$/;
      if (!phoneRegex.test(phone) || phone.trim().length < 10) {
        validationErrors.push('Please provide a valid phone number');
      }
    }

    if (validationErrors.length > 0) {
      console.log('[UPDATE_PROFILE] Validation failed:', validationErrors);
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: validationErrors
      });
    }

    // Update user data
    const oldData = { ...user };
    const updates = {};

    if (name && name.trim()) {
      user.name = name.trim();
      updates.name = user.name;
    }
    if (email && email.trim()) {
      user.email = email.trim();
      updates.email = user.email;
    }
    if (department && department.trim()) {
      user.department = department.trim();
      updates.department = user.department;
    }
    if (phone && phone.trim()) {
      user.phone = phone.trim();
      updates.phone = user.phone;
    }
    if (designation && designation.trim()) {
      user.designation = designation.trim();
      updates.designation = user.designation;
    }

    // Update activity timestamp
    user.lastActivity = new Date().toISOString();
    user.profileLastUpdated = new Date().toISOString();

    console.log(`[UPDATE_PROFILE] 📝 Profile updated for ${user.role}: ${user.name} - Updates:`, Object.keys(updates));

    res.json({
      success: true,
      message: 'Profile updated successfully',
      updatedFields: Object.keys(updates),
      profile: {
        name: user.name,
        email: user.email,
        department: user.department,
        phone: user.phone,
        designation: user.designation,
        role: user.role,
        authMethod: user.role === 'employee' ? 'Email OTP' : 'Direct Login',
        lastUpdated: user.profileLastUpdated
      }
    });

  } catch (error) {
    console.error('[UPDATE_PROFILE] ❌ Profile update error:', error.message);
    res.status(500).json({
      success: false,
      message: 'Profile update failed due to server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ---------- ENHANCED SESSION REFRESH ----------
router.post('/refresh-session', (req, res) => {
  console.log('[REFRESH_SESSION] Session refresh request from IP:', req.ip);

  try {
    if (!req.session?.user) {
      console.log('[REFRESH_SESSION] No session to refresh');
      return res.status(401).json({
        success: false,
        message: 'No session to refresh',
        needsAuth: true
      });
    }

    const user = req.session.user;
    const now = new Date();

    console.log('[REFRESH_SESSION] Refreshing session for user:', {
      name: user.name,
      role: user.role,
      employeeId: user.employeeId
    });

    // Touch session to extend expiry
    req.session.touch();

    // Update activity tracking
    user.lastActivity = now.toISOString();
    user.sessionRefreshed = now.toISOString();

    const sessionAge = user.loginTime ? Math.floor((now - new Date(user.loginTime)) / 1000 / 60) : 0;

    console.log(`[REFRESH_SESSION] 🔄 Session refreshed for ${user.role}: ${user.name} - Age: ${sessionAge} minutes`);

    res.json({
      success: true,
      message: 'Session refreshed successfully',
      refreshedAt: now.toISOString(),
      user: {
        role: user.role,
        name: user.name,
        id: user.id,
        lastActivity: user.lastActivity,
        sessionAge: sessionAge,
        authMethod: user.role === 'employee' ? 'Email OTP' : 'Direct Login'
      },
      sessionHealth: {
        refreshed: true,
        remainingMinutes: Math.max(0, (24 * 60) - sessionAge)
      }
    });

  } catch (error) {
    console.error('[REFRESH_SESSION] ❌ Session refresh error:', error.message);
    res.status(500).json({
      success: false,
      message: 'Session refresh failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ---------- ENHANCED USER INFO ENDPOINT ----------
router.get('/user-info', (req, res) => {
  console.log('[USER_INFO] User info request from IP:', req.ip);

  try {
    if (!req.session?.user) {
      console.log('[USER_INFO] Unauthorized access attempt');
      return res.status(401).json({
        success: false,
        message: 'Not authenticated - Cannot retrieve user info',
        needsAuth: true
      });
    }

    const user = req.session.user;
    const now = new Date();
    const sessionAge = user.loginTime ? Math.floor((now - new Date(user.loginTime)) / 1000 / 60) : 0;

    console.log('[USER_INFO] Providing user info for:', {
      name: user.name,
      role: user.role,
      employeeId: user.employeeId,
      sessionAge: sessionAge
    });

    res.json({
      success: true,
      timestamp: now.toISOString(),
      user: {
        // Basic user information
        id: user.id,
        employeeId: user.employeeId,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role,
        department: user.department,
        designation: user.designation,

        // Session tracking
        loginTime: user.loginTime,
        lastActivity: user.lastActivity,
        profileLastUpdated: user.profileLastUpdated,
        sessionAge: sessionAge,
        authMethod: user.role === 'employee' ? 'Email OTP' : 'Direct Login',

        // Employee-specific data
        ...(user.role === 'employee' && {
          formId: user.formId || null,
          applicationStatus: user.applicationStatus || 'Not Submitted'
        }),

        // HOD-specific data
        ...(user.role === 'hod' && {
          hodId: user.hodId
        })
      }
    });

  } catch (error) {
    console.error('[USER_INFO] ❌ User info error:', error.message);
    res.status(500).json({
      success: false,
      message: 'Failed to get user info',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ---------- ENHANCED SESSION VALIDATION ----------
router.post('/validate-session', (req, res) => {
  console.log('[VALIDATE_SESSION] Session validation request from IP:', req.ip);

  try {
    if (!req.session?.user) {
      console.log('[VALIDATE_SESSION] No session to validate');
      return res.status(401).json({
        success: false,
        message: 'Session expired or invalid',
        needsAuth: true,
        validationFailed: true
      });
    }

    const user = req.session.user;
    const now = new Date();
    const loginTime = user.loginTime ? new Date(user.loginTime) : null;
    const sessionAge = loginTime ? Math.floor((now - loginTime) / 1000 / 60) : 0;

    console.log('[VALIDATE_SESSION] Validating session for user:', {
      name: user.name,
      role: user.role,
      sessionAge: sessionAge
    });

    // Check session timeout (24 hours)
    if (loginTime && sessionAge > (24 * 60)) {
      console.log(`[VALIDATE_SESSION] ⏰ Session validation failed - Expired for user ${user.name}`);

      req.session.destroy((err) => {
        if (err) console.error('[VALIDATE_SESSION] Session destruction error:', err.message);
      });

      return res.status(401).json({
        success: false,
        message: 'Session expired due to inactivity',
        needsAuth: true,
        sessionExpired: true,
        sessionAge: sessionAge
      });
    }

    // Update last activity
    user.lastActivity = now.toISOString();

    console.log(`[VALIDATE_SESSION] ✅ Session validated for ${user.role}: ${user.name} - Age: ${sessionAge} minutes`);

    res.json({
      success: true,
      message: 'Session is valid and active',
      validated: true,
      sessionInfo: {
        role: user.role,
        name: user.name,
        loginTime: user.loginTime,
        lastActivity: user.lastActivity,
        sessionAge: sessionAge,
        authMethod: user.role === 'employee' ? 'Email OTP' : 'Direct Login',
        remainingMinutes: Math.max(0, (24 * 60) - sessionAge)
      }
    });

  } catch (error) {
    console.error('[VALIDATE_SESSION] ❌ Session validation error:', error.message);
    res.status(500).json({
      success: false,
      message: 'Session validation failed due to server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ---------- ENHANCED SESSION SYNC ----------
router.post('/sync-session', (req, res) => {
  console.log('[SYNC_SESSION] Session sync request from IP:', req.ip);
  console.log('[SYNC_SESSION] Request body keys:', Object.keys(req.body));

  try {
    if (!req.session?.user) {
      console.log('[SYNC_SESSION] No session to sync');
      return res.status(401).json({
        success: false,
        message: 'No session to sync',
        needsAuth: true
      });
    }

    const { formId, applicationStatus, additionalData } = req.body;
    const user = req.session.user;
    const updates = {};

    console.log('[SYNC_SESSION] Syncing session for user:', {
      name: user.name,
      role: user.role,
      employeeId: user.employeeId
    });

    // Sync employee-specific data
    if (user.role === 'employee') {
      if (formId !== undefined) {
        console.log('[SYNC_SESSION] Updating formId:', formId);
        user.formId = formId;
        updates.formId = formId;
      }
      if (applicationStatus !== undefined) {
        console.log('[SYNC_SESSION] Updating applicationStatus:', applicationStatus);
        user.applicationStatus = applicationStatus;
        updates.applicationStatus = applicationStatus;
      }

      // Handle additional data sync
      if (additionalData && typeof additionalData === 'object') {
        console.log('[SYNC_SESSION] Processing additional data:', Object.keys(additionalData));
        Object.keys(additionalData).forEach(key => {
          if (key !== 'role' && key !== 'id') { // Protect critical fields
            user[key] = additionalData[key];
            updates[key] = additionalData[key];
          }
        });
      }
    }

    // Update activity timestamp
    user.lastActivity = new Date().toISOString();
    user.lastSyncTime = new Date().toISOString();

    console.log(`[SYNC_SESSION] 🔄 Session synced for ${user.role}: ${user.name} - Updates:`, Object.keys(updates));

    res.json({
      success: true,
      message: 'Session synchronized successfully',
      syncedAt: user.lastSyncTime,
      updatedFields: Object.keys(updates),
      sessionData: {
        formId: user.formId || null,
        applicationStatus: user.applicationStatus || 'Not Submitted',
        lastActivity: user.lastActivity,
        lastSyncTime: user.lastSyncTime,
        ...updates
      }
    });

  } catch (error) {
    console.error('[SYNC_SESSION] ❌ Session sync error:', error.message);
    res.status(500).json({
      success: false,
      message: 'Session sync failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// =========================================
// ✅ ENHANCED DEVELOPMENT & DEBUG ROUTES
// =========================================

// ---------- ENHANCED AUTH INFO ENDPOINT ----------
router.get('/auth-info', (req, res) => {
  console.log('[AUTH_INFO] Auth info request from IP:', req.ip);
  console.log('[AUTH_INFO] Environment:', process.env.NODE_ENV);

  if (process.env.NODE_ENV === 'production') {
    console.log('[AUTH_INFO] Blocking access in production environment');
    return res.status(404).json({
      success: false,
      message: 'Development endpoint not available in production'
    });
  }

  const activeSessionCount = req.sessionStore ?
    Object.keys(req.sessionStore.sessions || {}).length : 'Unknown';

  console.log('[AUTH_INFO] Active sessions:', activeSessionCount);

  res.json({
    success: true,
    timestamp: new Date().toISOString(),
    authSystem: {
      type: 'Mixed Authentication System',
      version: '2.0.0',
      environment: process.env.NODE_ENV || 'development',

      methods: {
        employee: {
          type: 'Email OTP',
          email: 'ruinedjhonny@gmail.com',
          description: 'One-time password sent via email'
        },
        hod: {
          type: 'Direct Login',
          encryption: 'bcrypt hashed passwords',
          description: 'Username/password authentication'
        },
        it: {
          type: 'Direct Login',
          encryption: 'bcrypt hashed passwords',
          description: 'Username/password authentication'
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
        }
      },

      sessionFeatures: {
        timeout: '24 hours (1440 minutes)',
        activityTracking: true,
        formSyncSupport: true,
        multiRoleSupport: true,
        sessionRefresh: true,
        profileUpdate: true,
        enhancedValidation: true,
        secureLogout: true
      },

      statistics: {
        activeSessions: activeSessionCount,
        supportedRoles: ['employee', 'hod', 'it'],
        cookiesManaged: ['connect.sid', 'session-token', 'auth-token', 'remember-me', 'csrf-token']
      },

      note: 'This auth.js provides utility routes only. Main authentication logic is in server.js'
    }
  });
});

// ---------- SESSION DEBUG ENDPOINT ----------
router.get('/session-debug', (req, res) => {
  console.log('[SESSION_DEBUG] Debug request from IP:', req.ip);

  if (process.env.NODE_ENV === 'production') {
    console.log('[SESSION_DEBUG] Blocking debug access in production');
    return res.status(404).json({
      success: false,
      message: 'Debug endpoint not available in production'
    });
  }

  const sessionExists = !!req.session;
  const userExists = !!(req.session && req.session.user);

  console.log('[SESSION_DEBUG] Session status:', {
    sessionExists,
    userExists,
    sessionId: req.session?.id
  });

  res.json({
    success: true,
    debug: {
      sessionExists,
      userExists,
      sessionId: req.session?.id || null,
      cookie: req.session?.cookie ? {
        maxAge: req.session.cookie.maxAge,
        expires: req.session.cookie.expires,
        httpOnly: req.session.cookie.httpOnly,
        secure: req.session.cookie.secure
      } : null,
      user: userExists ? {
        role: req.session.user.role,
        name: req.session.user.name,
        id: req.session.user.id,
        loginTime: req.session.user.loginTime,
        lastActivity: req.session.user.lastActivity
      } : null,
      headers: {
        userAgent: req.get('User-Agent'),
        referer: req.get('Referer'),
        origin: req.get('Origin')
      }
    }
  });
});

// =========================================
// ✅ ERROR HANDLING MIDDLEWARE
// =========================================

// Global error handler for auth routes
router.use((error, req, res, next) => {
  console.error('[AUTH_ERROR] ❌ Auth router error:', error.message);
  console.error('[AUTH_ERROR] Stack trace:', error.stack);
  console.error('[AUTH_ERROR] Request URL:', req.url);
  console.error('[AUTH_ERROR] Request method:', req.method);
  console.error('[AUTH_ERROR] Request IP:', req.ip);

  res.status(500).json({
    success: false,
    message: 'Authentication system error',
    error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
  });
});

console.log('[AUTH_ROUTER] Auth router initialized with enhanced logging');

module.exports = router;
