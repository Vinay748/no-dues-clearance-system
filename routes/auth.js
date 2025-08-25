const express = require('express');
const bcrypt = require('bcrypt');
const { loadJSON } = require('../utils/fileUtils');

const router = express.Router();

const EMPLOYEE_FILE = './data/users_plain.json';
const IT_USERS = './data/it_users.json';
const HOD_USERS = './data/hod_users.json';

// =========================================
// ⚠️  IMPORTANT: LEGACY ROUTES - NOT USED
// =========================================

router.post('/login', async (req, res) => {
  return res.status(410).json({
    success: false,
    message: 'This login endpoint is deprecated. Use the OTP authentication system instead.',
    redirectTo: '/api/auth/employee-login'
  });
});

router.post('/verify-otp', (req, res) => {
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
  try {
    const user = req.session?.user;
    const sessionId = req.session?.id;

    // Log logout attempt
    if (user) {
      console.log(`📤 User logout: ${user.name} (${user.role}) - Session: ${sessionId || 'unknown'}`);
    } else {
      console.log('📤 Logout attempt with no active session');
    }

    // Perform comprehensive session cleanup
    req.session.destroy((err) => {
      if (err) {
        console.error('❌ Session destruction error:', err);
        return res.status(500).json({
          success: false,
          message: 'Logout failed due to session cleanup error',
          error: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
      }

      // Clear all possible session-related cookies
      const cookiesToClear = [
        'connect.sid',           // Default express-session cookie
        'session-token',         // Custom session token if any
        'auth-token',           // Authentication token
        'remember-me',          // Remember me token
        'csrf-token'            // CSRF token if used
      ];

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

      console.log('✅ User logged out successfully - Session destroyed and cookies cleared');

      res.json({
        success: true,
        message: 'Logged out successfully',
        redirect: '/login.html',
        timestamp: new Date().toISOString(),
        sessionCleared: true
      });
    });

  } catch (error) {
    console.error('❌ Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Logout failed due to server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// GET: Enhanced logout for browser navigation with redirect
router.get('/logout', (req, res) => {
  try {
    const user = req.session?.user;

    // Log logout attempt
    if (user) {
      console.log(`📤 Browser logout: ${user.name} (${user.role})`);
    }

    req.session.destroy((err) => {
      if (err) {
        console.error('❌ Session destruction error on GET logout:', err);
      }

      // Clear cookies even if session destruction fails
      const cookiesToClear = [
        'connect.sid', 'session-token', 'auth-token',
        'remember-me', 'csrf-token'
      ];

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

      console.log('✅ Browser logout completed - Redirecting to login');

      // Redirect to login page (adjust path as needed)
      res.redirect('/login.html');
    });

  } catch (error) {
    console.error('❌ GET logout error:', error);
    // Still redirect even if there's an error
    res.redirect('/login.html?error=logout_failed');
  }
});

// Enhanced logout for all methods (fallback)
router.all('/logout', (req, res) => {
  if (req.method === 'POST') {
    return; // Already handled above
  }
  if (req.method === 'GET') {
    return; // Already handled above
  }

  // Handle other HTTP methods
  console.log(`📤 Logout via ${req.method} method`);

  req.session.destroy((err) => {
    res.clearCookie('connect.sid');
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

// Enhanced session check API
router.get('/check-session', (req, res) => {
  try {
    if (!req.session?.user) {
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

    // Enhanced session timeout check (24 hours = 1440 minutes)
    const sessionTimeoutMinutes = 24 * 60;
    if (loginTime && sessionAge > sessionTimeoutMinutes) {
      console.log(`⏰ Session expired for user ${user.name} - Age: ${sessionAge} minutes`);

      req.session.destroy((err) => {
        if (err) console.error('Session destruction error:', err);
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
    console.error('❌ Session check error:', error);
    return res.status(500).json({
      success: false,
      message: 'Session check failed due to server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Enhanced profile update
router.post('/update-profile', (req, res) => {
  try {
    if (!req.session?.user) {
      return res.status(401).json({
        success: false,
        message: 'Not authenticated - Cannot update profile',
        needsAuth: true
      });
    }

    const { name, email, department, phone, designation } = req.body;
    const user = req.session.user;

    // Enhanced validation
    const validationErrors = [];

    if (name !== undefined) {
      if (!name || name.trim().length < 2) {
        validationErrors.push('Name must be at least 2 characters long');
      } else if (name.trim().length > 100) {
        validationErrors.push('Name must not exceed 100 characters');
      }
    }

    if (email !== undefined) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        validationErrors.push('Please provide a valid email address');
      }
    }

    if (phone !== undefined && phone.trim()) {
      const phoneRegex = /^[\d\-\+\(\)\s]+$/;
      if (!phoneRegex.test(phone) || phone.trim().length < 10) {
        validationErrors.push('Please provide a valid phone number');
      }
    }

    if (validationErrors.length > 0) {
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

    console.log(`📝 Profile updated for ${user.role}: ${user.name} - Updates:`, Object.keys(updates));

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
    console.error('❌ Profile update error:', error);
    res.status(500).json({
      success: false,
      message: 'Profile update failed due to server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Enhanced session refresh
router.post('/refresh-session', (req, res) => {
  try {
    if (!req.session?.user) {
      return res.status(401).json({
        success: false,
        message: 'No session to refresh',
        needsAuth: true
      });
    }

    const user = req.session.user;
    const now = new Date();

    // Touch session to extend expiry
    req.session.touch();

    // Update activity tracking
    user.lastActivity = now.toISOString();
    user.sessionRefreshed = now.toISOString();

    const sessionAge = user.loginTime ? Math.floor((now - new Date(user.loginTime)) / 1000 / 60) : 0;

    console.log(`🔄 Session refreshed for ${user.role}: ${user.name} - Age: ${sessionAge} minutes`);

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
    console.error('❌ Session refresh error:', error);
    res.status(500).json({
      success: false,
      message: 'Session refresh failed',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Enhanced user info endpoint
router.get('/user-info', (req, res) => {
  try {
    if (!req.session?.user) {
      return res.status(401).json({
        success: false,
        message: 'Not authenticated - Cannot retrieve user info',
        needsAuth: true
      });
    }

    const user = req.session.user;
    const now = new Date();
    const sessionAge = user.loginTime ? Math.floor((now - new Date(user.loginTime)) / 1000 / 60) : 0;

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
    console.error('❌ User info error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get user info',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Enhanced session validation
router.post('/validate-session', (req, res) => {
  try {
    if (!req.session?.user) {
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

    // Check session timeout (24 hours)
    if (loginTime && sessionAge > (24 * 60)) {
      console.log(`⏰ Session validation failed - Expired for user ${user.name}`);

      req.session.destroy((err) => {
        if (err) console.error('Session destruction error:', err);
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

    console.log(`✅ Session validated for ${user.role}: ${user.name} - Age: ${sessionAge} minutes`);

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
    console.error('❌ Session validation error:', error);
    res.status(500).json({
      success: false,
      message: 'Session validation failed due to server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Enhanced session sync
router.post('/sync-session', (req, res) => {
  try {
    if (!req.session?.user) {
      return res.status(401).json({
        success: false,
        message: 'No session to sync',
        needsAuth: true
      });
    }

    const { formId, applicationStatus, additionalData } = req.body;
    const user = req.session.user;
    const updates = {};

    // Sync employee-specific data
    if (user.role === 'employee') {
      if (formId !== undefined) {
        user.formId = formId;
        updates.formId = formId;
      }
      if (applicationStatus !== undefined) {
        user.applicationStatus = applicationStatus;
        updates.applicationStatus = applicationStatus;
      }

      // Handle additional data sync
      if (additionalData && typeof additionalData === 'object') {
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

    console.log(`🔄 Session synced for ${user.role}: ${user.name} - Updates:`, Object.keys(updates));

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
    console.error('❌ Session sync error:', error);
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

// Enhanced auth info endpoint
router.get('/auth-info', (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(404).json({
      success: false,
      message: 'Development endpoint not available in production'
    });
  }

  const activeSessionCount = req.sessionStore ?
    Object.keys(req.sessionStore.sessions || {}).length : 'Unknown';

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

// Session debug endpoint
router.get('/session-debug', (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(404).json({
      success: false,
      message: 'Debug endpoint not available in production'
    });
  }

  const sessionExists = !!req.session;
  const userExists = !!(req.session && req.session.user);

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
  console.error('❌ Auth router error:', error);

  res.status(500).json({
    success: false,
    message: 'Authentication system error',
    error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
  });
});

module.exports = router;
