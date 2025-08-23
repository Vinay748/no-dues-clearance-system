const express = require('express');
const path = require('path');
const session = require('express-session');
const cors = require('cors');
const fs = require('fs').promises;
const fsSync = require('fs');
const bcrypt = require('bcrypt');
const cron = require('node-cron');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const MongoStore = require('connect-mongo');
const winston = require('winston');
const { promisify } = require('util');

// Load environment variables first
require('dotenv').config();

const OTPManager = require('./otpManager');
const NotificationManager = require('./utils/notificationManager');

// Route imports
const apiEmployee = require('./routes/employee');
const apiItAdmin = require('./routes/itadmin');
const apiPdf = require('./routes/pdf');
const apiHod = require('./routes/hod');
const apiAuth = require('./routes/auth');

const { roleAuth } = require('./middlewares/sessionAuth');
const { loadJSON, saveJSON } = require('./utils/fileUtils');

// =========================================
// PRODUCTION CONFIGURATION
// =========================================

const CONFIG = {
  PORT: process.env.PORT || 3000,
  NODE_ENV: process.env.NODE_ENV || 'development',
  SESSION_SECRET: process.env.SESSION_SECRET || 'fallback-secret-change-in-production',

  // Database configuration
  MONGODB_URI: process.env.MONGODB_URI || null,

  // Security settings
  SECURITY: {
    MAX_LOGIN_ATTEMPTS: 5,
    ACCOUNT_LOCK_TIME: 15 * 60 * 1000, // 15 minutes
    SESSION_TIMEOUT: 24 * 60 * 60 * 1000, // 24 hours
    BCRYPT_ROUNDS: 12
  },

  // Rate limiting
  RATE_LIMIT: {
    WINDOW_MS: 15 * 60 * 1000, // 15 minutes
    MAX_REQUESTS: 100,
    STRICT_PATHS: {
      '/api/auth/': { windowMs: 15 * 60 * 1000, max: 20 },
      '/api/employee/': { windowMs: 15 * 60 * 1000, max: 50 },
      '/api/itadmin/': { windowMs: 15 * 60 * 1000, max: 100 }
    }
  },

  // File system paths
  PATHS: {
    UPLOADS: path.join(__dirname, 'uploads'),
    DATA: path.join(__dirname, 'data'),
    PUBLIC: path.join(__dirname, 'public'),
    CERTIFICATES: path.join(__dirname, 'public', 'certificates'),
    LOGS: path.join(__dirname, 'logs')
  }
};

// =========================================
// PRODUCTION LOGGING SYSTEM
// =========================================

const logger = winston.createLogger({
  level: CONFIG.NODE_ENV === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'no-dues-system' },
  transports: [
    new winston.transports.File({
      filename: path.join(CONFIG.PATHS.LOGS, 'error.log'),
      level: 'error'
    }),
    new winston.transports.File({
      filename: path.join(CONFIG.PATHS.LOGS, 'combined.log')
    })
  ]
});

// Add console transport for development
if (CONFIG.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// =========================================
// PRODUCTION SECURITY MIDDLEWARE
// =========================================

class SecurityManager {
  static createRateLimiters() {
    const rateLimiters = {};

    // General rate limiter
    rateLimiters.general = rateLimit({
      windowMs: CONFIG.RATE_LIMIT.WINDOW_MS,
      max: CONFIG.RATE_LIMIT.MAX_REQUESTS,
      message: { success: false, message: 'Too many requests. Please try again later.' },
      standardHeaders: true,
      legacyHeaders: false,
      handler: (req, res) => {
        logger.warn('Rate limit exceeded', {
          ip: req.ip,
          path: req.path,
          userAgent: req.get('User-Agent')
        });
        res.status(429).json({
          success: false,
          message: 'Too many requests. Please try again later.'
        });
      }
    });

    // Strict rate limiters for specific paths
    Object.entries(CONFIG.RATE_LIMIT.STRICT_PATHS).forEach(([path, config]) => {
      rateLimiters[path] = rateLimit({
        ...config,
        message: { success: false, message: 'Rate limit exceeded for this endpoint.' },
        handler: (req, res) => {
          logger.warn('Strict rate limit exceeded', {
            ip: req.ip,
            path: req.path,
            endpoint: path
          });
          res.status(429).json({
            success: false,
            message: 'Rate limit exceeded for this endpoint.'
          });
        }
      });
    });

    return rateLimiters;
  }

  static validateEnvironment() {
    const required = ['EMAIL_USER', 'EMAIL_PASS'];
    const missing = required.filter(key => !process.env[key]);

    if (missing.length > 0) {
      throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
    }

    if (CONFIG.NODE_ENV === 'production' && CONFIG.SESSION_SECRET === 'fallback-secret-change-in-production') {
      throw new Error('SESSION_SECRET must be set in production');
    }
  }

  static sanitizeInput(input) {
    if (typeof input !== 'string') return input;

    return input
      .replace(/<script[^>]*>.*?<\/script>/gi, '')
      .replace(/<[^>]+>/g, '')
      .trim();
  }
}

// =========================================
// PRODUCTION FILE SYSTEM MANAGER
// =========================================

class FileSystemManager {
  static async ensureDirectories() {
    const directories = [
      CONFIG.PATHS.UPLOADS,
      CONFIG.PATHS.DATA,
      CONFIG.PATHS.PUBLIC,
      CONFIG.PATHS.CERTIFICATES,
      CONFIG.PATHS.LOGS,
      path.join(CONFIG.PATHS.CERTIFICATES, 'temp'),
      path.join(CONFIG.PATHS.CERTIFICATES, 'archive')
    ];

    for (const dir of directories) {
      try {
        await fs.access(dir);
      } catch (error) {
        if (error.code === 'ENOENT') {
          await fs.mkdir(dir, { recursive: true, mode: 0o755 });
          logger.info('Directory created', { directory: dir });
        }
      }
    }
  }

  static async initializeDataFiles() {
    const dataFiles = [
      { path: path.join(CONFIG.PATHS.DATA, 'otp_data.json'), default: '{}' },
      { path: path.join(CONFIG.PATHS.DATA, 'login_sessions.json'), default: '{}' },
      { path: path.join(CONFIG.PATHS.DATA, 'notifications.json'), default: '[]' },
      { path: path.join(CONFIG.PATHS.DATA, 'employee_sessions.json'), default: '[]' },
      { path: path.join(CONFIG.PATHS.DATA, 'form_history.json'), default: '[]' },
      { path: path.join(CONFIG.PATHS.DATA, 'certificates.json'), default: '[]' }
    ];

    for (const file of dataFiles) {
      try {
        await fs.access(file.path);
      } catch (error) {
        if (error.code === 'ENOENT') {
          await fs.writeFile(file.path, file.default, 'utf8');
          logger.info('Data file initialized', { file: file.path });
        }
      }
    }
  }

  static async getDirectoryStats() {
    const stats = {};

    for (const [key, dir] of Object.entries(CONFIG.PATHS)) {
      try {
        const stat = await fs.stat(dir);
        stats[key] = {
          exists: true,
          isDirectory: stat.isDirectory(),
          size: stat.size,
          modified: stat.mtime
        };
      } catch (error) {
        stats[key] = { exists: false, error: error.code };
      }
    }

    return stats;
  }
}

// =========================================
// PRODUCTION USER MANAGEMENT
// =========================================

class UserManager {
  static async loadEmployeeUser() {
    try {
      const data = await loadJSON(path.join(CONFIG.PATHS.DATA, 'users.json'));
      return data;
    } catch (error) {
      logger.error('Failed to load employee user', error);
      return null;
    }
  }

  static async loadHODUsers() {
    try {
      const data = await loadJSON(path.join(CONFIG.PATHS.DATA, 'hod_users.json'));
      return Array.isArray(data) ? data : [];
    } catch (error) {
      logger.error('Failed to load HOD users', error);
      return [];
    }
  }

  static async loadITUsers() {
    try {
      const data = await loadJSON(path.join(CONFIG.PATHS.DATA, 'it_users.json'));
      return Array.isArray(data) ? data : [];
    } catch (error) {
      logger.error('Failed to load IT users', error);
      return [];
    }
  }

  static findEmployee(employeeData, employeeId) {
    if (Array.isArray(employeeData)) {
      return employeeData.find(emp => emp.employeeId === employeeId);
    } else if (employeeData && employeeData.employeeId === employeeId) {
      return employeeData;
    }
    return null;
  }

  static async updateUserLoginStats(userId, userType, success = true) {
    try {
      const filePath = path.join(CONFIG.PATHS.DATA, `${userType}_users.json`);
      const users = await loadJSON(filePath);

      if (Array.isArray(users)) {
        const userIndex = users.findIndex(u =>
          u.employeeId === userId || u.hodId === userId || u.itId === userId
        );

        if (userIndex !== -1) {
          const user = users[userIndex];
          user.lastLogin = new Date().toISOString();
          user.loginAttempts = success ? 0 : (user.loginAttempts || 0) + 1;

          if (!success && user.loginAttempts >= CONFIG.SECURITY.MAX_LOGIN_ATTEMPTS) {
            user.lockedUntil = new Date(Date.now() + CONFIG.SECURITY.ACCOUNT_LOCK_TIME).toISOString();
          }

          users[userIndex] = user;
          await saveJSON(filePath, users);
        }
      }
    } catch (error) {
      logger.error('Failed to update user login stats', error, { userId, userType });
    }
  }
}

// =========================================
// APPLICATION INITIALIZATION
// =========================================

async function initializeApplication() {
  try {
    // Validate environment
    SecurityManager.validateEnvironment();

    // Ensure directories exist
    await FileSystemManager.ensureDirectories();

    // Initialize data files
    await FileSystemManager.initializeDataFiles();

    // Initialize OTP Manager
    const otpManager = new OTPManager();

    logger.info('Application initialized successfully');

    return { otpManager };
  } catch (error) {
    logger.error('Application initialization failed', error);
    throw error;
  }
}

// =========================================
// EXPRESS APPLICATION SETUP
// =========================================

async function createApp() {
  const app = express();
  const { otpManager } = await initializeApplication();
  const rateLimiters = SecurityManager.createRateLimiters();

  // Security middleware
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "blob:"],
        fontSrc: ["'self'"],
        connectSrc: ["'self'", "ws:", "wss:"]
      }
    },
    hsts: CONFIG.NODE_ENV === 'production' ? {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    } : false
  }));

  // Compression middleware
  app.use(compression());

  // Rate limiting
  app.use(rateLimiters.general);

  // Apply strict rate limiters
  Object.entries(rateLimiters).forEach(([path, limiter]) => {
    if (path !== 'general' && path.startsWith('/api/')) {
      app.use(path, limiter);
    }
  });

  // CORS configuration
  app.use(cors({
    origin: function (origin, callback) {
      if (CONFIG.NODE_ENV === 'development') {
        if (!origin) return callback(null, true);

        const allowedOrigins = [
          'http://localhost:3000',
          'http://localhost:3001',
          'http://127.0.0.1:3000'
        ];

        if (origin.includes('localhost') || origin.includes('127.0.0.1') || allowedOrigins.includes(origin)) {
          return callback(null, true);
        }
      } else {
        const allowedProduction = process.env.ALLOWED_ORIGINS ?
          process.env.ALLOWED_ORIGINS.split(',') : [];

        if (allowedProduction.includes(origin)) {
          return callback(null, true);
        }
      }

      callback(new Error('Not allowed by CORS'));
    },
    credentials: true
  }));

  // Body parsing middleware with limits
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // No-cache middleware for API routes
  app.use('/api/', (req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    res.set('Surrogate-Control', 'no-store');
    next();
  });

  // Session configuration with MongoDB store for production
  const sessionConfig = {
    secret: CONFIG.SESSION_SECRET,
    name: 'nodues.session.v2025',
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      secure: CONFIG.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: CONFIG.SECURITY.SESSION_TIMEOUT,
      sameSite: CONFIG.NODE_ENV === 'production' ? 'strict' : 'lax'
    }
  };

  // Use MongoDB store in production if configured
  if (CONFIG.NODE_ENV === 'production' && CONFIG.MONGODB_URI) {
    sessionConfig.store = MongoStore.create({
      mongoUrl: CONFIG.MONGODB_URI,
      touchAfter: 24 * 3600 // Lazy session update
    });
  }

  app.use(session(sessionConfig));

  // Enhanced session cleanup middleware
  app.use(async (req, res, next) => {
    if (req.session?.user) {
      const user = req.session.user;
      const now = new Date();
      const loginTime = user.loginTime ? new Date(user.loginTime) : null;

      const isOldSession = loginTime && (now - loginTime) > CONFIG.SECURITY.SESSION_TIMEOUT;
      const hasOldStructure = !user.sessionVersion || user.sessionVersion !== '2025-08-23';

      if (isOldSession || hasOldStructure) {
        logger.info('Session cleanup performed', {
          userId: user.employeeId || user.id,
          reason: isOldSession ? 'expired' : 'outdated_structure'
        });

        const preservedData = {
          id: user.id,
          employeeId: user.employeeId || user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          department: user.department,
          hodId: user.hodId,
          designation: user.designation
        };

        req.session.regenerate((err) => {
          if (!err) {
            req.session.user = {
              ...preservedData,
              loginTime: now.toISOString(),
              sessionVersion: '2025-08-23',
              cleanupPerformed: true
            };
            req.session.save();
          }
          next();
        });
      } else {
        next();
      }
    } else {
      next();
    }
  });

  // Request logging middleware
  app.use((req, res, next) => {
    logger.info('Request received', {
      method: req.method,
      path: req.path,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.session?.user?.employeeId || req.session?.user?.id
    });

    if (req.method === 'POST' && req.body && typeof req.body === 'object') {
      logger.debug('POST request body keys', { keys: Object.keys(req.body) });
    }

    next();
  });

  // =========================================
  // AUTHENTICATION ENDPOINTS
  // =========================================

  // Employee login with enhanced security
  app.post('/api/auth/employee-login', async (req, res) => {
    try {
      let { employeeId, password } = req.body;

      // Sanitize inputs
      employeeId = SecurityManager.sanitizeInput(employeeId);

      if (!employeeId || !password) {
        return res.status(400).json({
          success: false,
          message: 'Employee ID and password are required'
        });
      }

      const employeeData = await UserManager.loadEmployeeUser();
      const employee = UserManager.findEmployee(employeeData, employeeId);

      if (!employee) {
        await UserManager.updateUserLoginStats(employeeId, 'employee', false);
        return res.status(401).json({
          success: false,
          message: 'Invalid employee ID or password'
        });
      }

      // Check if account is locked
      if (employee.lockedUntil && new Date() < new Date(employee.lockedUntil)) {
        return res.status(423).json({
          success: false,
          message: 'Account temporarily locked. Please try again later.'
        });
      }

      const isValidPassword = await bcrypt.compare(password, employee.password);

      if (!isValidPassword) {
        await UserManager.updateUserLoginStats(employeeId, 'employee', false);
        return res.status(401).json({
          success: false,
          message: 'Invalid employee ID or password'
        });
      }

      if (employee.isActive === false) {
        return res.status(401).json({
          success: false,
          message: 'Account is deactivated. Please contact IT.'
        });
      }

      const clientInfo = {
        ip: req.ip,
        userAgent: req.get('User-Agent')
      };

      const result = await otpManager.createLoginSession(employeeId, employee.email, clientInfo);

      if (result.success) {
        await UserManager.updateUserLoginStats(employeeId, 'employee', true);

        logger.info('Employee login initiated', { employeeId });

        res.json({
          success: true,
          sessionToken: result.sessionToken,
          message: result.message,
          nextStep: 'verify_otp',
          email: employee.email.replace(/(.{2})(.*)(@.*)/, '$1***$3'),
          expiresIn: result.expiresIn
        });
      } else {
        res.status(500).json(result);
      }

    } catch (error) {
      logger.error('Employee login error', error);
      res.status(500).json({
        success: false,
        message: 'Login failed. Please try again.'
      });
    }
  });

  // OTP verification with enhanced session management
  app.post('/api/auth/verify-otp', async (req, res) => {
    try {
      const { sessionToken, otp } = req.body;

      if (!sessionToken || !otp) {
        return res.status(400).json({
          success: false,
          message: 'Session token and OTP are required'
        });
      }

      const clientInfo = {
        ip: req.ip,
        userAgent: req.get('User-Agent')
      };

      const result = await otpManager.verifyOTP(sessionToken, otp, clientInfo);

      if (result.success) {
        const employeeData = await UserManager.loadEmployeeUser();
        const employee = UserManager.findEmployee(employeeData, result.employeeId);

        req.session.regenerate((err) => {
          if (err) {
            logger.error('Session regeneration failed', err);
            return res.status(500).json({ success: false, message: 'Session error' });
          }

          req.session.user = {
            employeeId: result.employeeId,
            id: result.employeeId,
            role: 'employee',
            name: employee?.name || 'Employee',
            email: employee?.email || '',
            department: employee?.department || '',
            loginTime: new Date().toISOString(),
            sessionVersion: '2025-08-23'
          };

          req.session.save((saveErr) => {
            if (saveErr) {
              logger.error('Session save failed', saveErr);
              return res.status(500).json({ success: false, message: 'Session save error' });
            }

            logger.info('Employee login successful', { employeeId: result.employeeId });

            res.json({
              success: true,
              message: result.message,
              employeeId: result.employeeId,
              redirectTo: '/dashboard.html'
            });
          });
        });
      } else {
        res.status(400).json(result);
      }

    } catch (error) {
      logger.error('OTP verification error', error);
      res.status(500).json({
        success: false,
        message: 'Verification failed. Please try again.'
      });
    }
  });

  // Resend OTP with rate limiting
  app.post('/api/auth/resend-otp', async (req, res) => {
    try {
      const { sessionToken } = req.body;

      if (!sessionToken) {
        return res.status(400).json({
          success: false,
          message: 'Session token is required'
        });
      }

      const clientInfo = {
        ip: req.ip,
        userAgent: req.get('User-Agent')
      };

      const result = await otpManager.resendOTP(sessionToken, clientInfo);
      res.json(result);

    } catch (error) {
      logger.error('Resend OTP error', error);
      res.status(500).json({
        success: false,
        message: 'Failed to resend OTP'
      });
    }
  });

  // Enhanced HOD login
  app.post('/api/auth/hod-login', async (req, res) => {
    try {
      let { hodId, password } = req.body;

      hodId = SecurityManager.sanitizeInput(hodId);

      const hodUsers = await UserManager.loadHODUsers();
      const hod = hodUsers.find(h => h.hodId === hodId);

      if (!hod) {
        await UserManager.updateUserLoginStats(hodId, 'hod', false);
        return res.status(401).json({
          success: false,
          message: 'Invalid HOD credentials'
        });
      }

      // Check if account is locked
      if (hod.lockedUntil && new Date() < new Date(hod.lockedUntil)) {
        return res.status(423).json({
          success: false,
          message: 'Account temporarily locked. Please try again later.'
        });
      }

      const isValidPassword = await bcrypt.compare(password, hod.password);

      if (!isValidPassword) {
        await UserManager.updateUserLoginStats(hodId, 'hod', false);
        return res.status(401).json({
          success: false,
          message: 'Invalid HOD credentials'
        });
      }

      req.session.user = {
        hodId: hodId,
        id: hodId,
        role: 'hod',
        name: hod.name,
        email: hod.email,
        employeeId: hod.employeeId,
        department: hod.department || 'Academic Department',
        designation: hod.designation || 'HOD',
        loginTime: new Date().toISOString(),
        sessionVersion: '2025-08-23'
      };

      req.session.save(async (err) => {
        if (err) {
          logger.error('HOD session save error', err);
          return res.status(500).json({
            success: false,
            message: 'Session creation failed'
          });
        }

        await UserManager.updateUserLoginStats(hodId, 'hod', true);

        logger.info('HOD login successful', { hodId, name: hod.name });

        res.json({
          success: true,
          message: 'HOD login successful',
          role: 'hod',
          redirectTo: '/hodreview.html',
          hodDetails: {
            hodId: hod.hodId,
            name: hod.name,
            employeeId: hod.employeeId,
            email: hod.email,
            department: hod.department || 'Academic Department',
            designation: hod.designation || 'HOD'
          }
        });
      });

    } catch (error) {
      logger.error('HOD login error', error);
      res.status(500).json({
        success: false,
        message: 'Login failed'
      });
    }
  });

  // Enhanced IT login
  app.post('/api/auth/it-login', async (req, res) => {
    try {
      let { itId, password } = req.body;

      itId = SecurityManager.sanitizeInput(itId);

      const itUsers = await UserManager.loadITUsers();
      const itUser = itUsers.find(u => u.itId === itId);

      if (!itUser) {
        await UserManager.updateUserLoginStats(itId, 'it', false);
        return res.status(401).json({
          success: false,
          message: 'Invalid IT credentials'
        });
      }

      // Check if account is locked
      if (itUser.lockedUntil && new Date() < new Date(itUser.lockedUntil)) {
        return res.status(423).json({
          success: false,
          message: 'Account temporarily locked. Please try again later.'
        });
      }

      const isValidPassword = await bcrypt.compare(password, itUser.password);

      if (!isValidPassword) {
        await UserManager.updateUserLoginStats(itId, 'it', false);
        return res.status(401).json({
          success: false,
          message: 'Invalid IT credentials'
        });
      }

      req.session.user = {
        itId: itId,
        id: itId,
        role: 'it',
        name: itUser.name,
        email: itUser.email,
        employeeId: itUser.employeeId || itId,
        department: itUser.department || 'IT',
        designation: itUser.designation || 'IT Admin',
        loginTime: new Date().toISOString(),
        sessionVersion: '2025-08-23'
      };

      req.session.save(async (err) => {
        if (err) {
          logger.error('IT session save error', err);
          return res.status(500).json({
            success: false,
            message: 'Session creation failed'
          });
        }

        await UserManager.updateUserLoginStats(itId, 'it', true);

        logger.info('IT login successful', { itId, name: itUser.name });

        res.json({
          success: true,
          message: 'IT login successful',
          role: 'it',
          redirectTo: '/itreview.html'
        });
      });

    } catch (error) {
      logger.error('IT login error', error);
      res.status(500).json({
        success: false,
        message: 'Login failed'
      });
    }
  });

  // Check session status
  app.get('/api/auth/check-session', (req, res) => {
    if (req.session.user) {
      res.json({
        success: true,
        role: req.session.user.role,
        user: {
          id: req.session.user.id,
          employeeId: req.session.user.employeeId,
          name: req.session.user.name,
          email: req.session.user.email,
          role: req.session.user.role,
          department: req.session.user.department,
          loginTime: req.session.user.loginTime
        }
      });
    } else {
      res.status(401).json({
        success: false,
        message: 'No valid session'
      });
    }
  });

  // =========================================
  // AUTOMATED TASKS
  // =========================================

  // Daily form cleanup cron job
  cron.schedule('0 2 * * *', async () => {
    logger.info('Starting daily form cleanup');

    try {
      const PENDING_FORMS = path.join(CONFIG.PATHS.DATA, 'pending_forms.json');
      const FORM_HISTORY = path.join(CONFIG.PATHS.DATA, 'form_history.json');

      let pendingForms = await loadJSON(PENDING_FORMS, []);

      const completedForms = pendingForms.filter(form =>
        form.status === 'IT Completed' &&
        form.itProcessing?.processedAt &&
        new Date() - new Date(form.itProcessing.processedAt) > 7 * 24 * 60 * 60 * 1000
      );

      if (completedForms.length > 0) {
        let history = await loadJSON(FORM_HISTORY, []);

        completedForms.forEach(form => {
          const historyEntry = {
            ...form,
            completedAt: new Date().toISOString(),
            finalStatus: form.status,
            historyType: 'completed_application',
            preservedData: {
              certificates: form.certificates || [],
              hodApproval: form.hodApproval || null,
              itProcessing: form.itProcessing || null,
              assignedForms: form.assignedForms || [],
              formResponses: form.formResponses || {}
            }
          };
          history.push(historyEntry);
        });

        const remainingForms = pendingForms.filter(form =>
          !completedForms.find(cf => cf.formId === form.formId)
        );

        await saveJSON(FORM_HISTORY, history);
        await saveJSON(PENDING_FORMS, remainingForms);

        logger.info('Daily cleanup completed', {
          movedForms: completedForms.length,
          remainingForms: remainingForms.length
        });
      }
    } catch (error) {
      logger.error('Daily cleanup error', error);
    }
  });

  // =========================================
  // API ROUTES
  // =========================================

  // Notification endpoints
  app.get('/api/employee/notifications', roleAuth('employee'), async (req, res) => {
    try {
      const sessionUser = req.session?.user;
      const employeeId = sessionUser.id || sessionUser.employeeId;
      const limit = parseInt(req.query.limit) || 50;

      const notifications = NotificationManager.getInstance()
        .getNotificationHistory(employeeId, limit);

      res.json({
        success: true,
        notifications: notifications
      });
    } catch (error) {
      logger.error('Error fetching notifications', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch notifications'
      });
    }
  });

  // WebSocket connection info
  app.get('/api/notification/websocket-info', (req, res) => {
    const wsPort = process.env.WS_PORT || 8081;
    res.json({
      success: true,
      wsPort: wsPort,
      wsUrl: `${CONFIG.NODE_ENV === 'production' ? 'wss' : 'ws'}://localhost:${wsPort}`,
      isEnabled: true
    });
  });

  // =========================================
  // STATIC FILE SERVING
  // =========================================

  // Secure certificate access
  app.use('/certificates', (req, res, next) => {
    logger.warn('Blocked direct certificate access', {
      path: req.path,
      ip: req.ip
    });
    res.status(403).json({
      success: false,
      message: 'Direct access to certificates is forbidden. Please use the download API.'
    });
  });

  // Static file serving with security headers
  app.use('/uploads', express.static(CONFIG.PATHS.UPLOADS, {
    maxAge: CONFIG.NODE_ENV === 'production' ? '1d' : '0',
    etag: false
  }));

  app.use(express.static(CONFIG.PATHS.PUBLIC, {
    maxAge: CONFIG.NODE_ENV === 'production' ? '1d' : '0',
    etag: false
  }));

  // Specific static routes
  const staticPaths = ['forms', 'css', 'js', 'images'];
  staticPaths.forEach(staticPath => {
    app.use(`/${staticPath}`, express.static(path.join(CONFIG.PATHS.PUBLIC, staticPath), {
      maxAge: CONFIG.NODE_ENV === 'production' ? '1d' : '0',
      etag: false
    }));
  });

  // Mount API routes
  app.use('/api/auth', apiAuth);
  app.use('/api/employee', apiEmployee);
  app.use('/api/itadmin', apiItAdmin);
  app.use('/api/pdf', apiPdf);
  app.use('/api/hod', apiHod);

  // =========================================
  // FRONTEND ROUTES
  // =========================================

  // Root route
  app.get('/', (req, res) => {
    res.sendFile(path.join(CONFIG.PATHS.PUBLIC, 'login.html'));
  });

  // Employee routes
  const employeeRoutes = [
    'dashboard.html',
    'employee.html',
    'confirmation.html',
    'employee-dashboard.html',
    'track.html'
  ];

  employeeRoutes.forEach(route => {
    app.get(`/${route}`, roleAuth('employee'), (req, res) => {
      res.sendFile(path.join(CONFIG.PATHS.PUBLIC, route));
    });
  });

  // IT routes
  const itRoutes = ['itreview.html', 'it-form-review.html'];

  itRoutes.forEach(route => {
    app.get(`/${route}`, roleAuth('it'), (req, res) => {
      res.sendFile(path.join(CONFIG.PATHS.PUBLIC, route));
    });
  });

  // HOD routes
  const hodRoutes = ['hodhome.html', 'hodreview.html', 'hod-form-review.html'];

  hodRoutes.forEach(route => {
    app.get(`/${route}`, roleAuth('hod'), (req, res) => {
      res.sendFile(path.join(CONFIG.PATHS.PUBLIC, route));
    });
  });

  // Form routes with session check
  const formRoutes = [
    'disposalform.html',
    'efile.html',
    'form365transfer.html',
    'form365disposal.html'
  ];

  formRoutes.forEach(route => {
    app.get(`/forms/${route}`, (req, res) => {
      if (!req.session.user) {
        return res.redirect('/');
      }
      res.sendFile(path.join(CONFIG.PATHS.PUBLIC, 'forms', route));
    });
  });

  // =========================================
  // SYSTEM MONITORING ENDPOINTS
  // =========================================

  // Enhanced health check
  app.get('/health', async (req, res) => {
    try {
      const directoryStats = await FileSystemManager.getDirectoryStats();

      const health = {
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        directories: directoryStats,
        certificates: {
          directory: directoryStats.CERTIFICATES?.exists || false,
          count: 0
        },
        otp: {
          otpManagerActive: !!otpManager,
          emailConfigured: !!(process.env.EMAIL_USER && process.env.EMAIL_PASS)
        },
        notifications: {
          notificationManagerActive: !!NotificationManager.getInstance(),
          connectedClients: NotificationManager.getInstance().getConnectedClientsCount(),
          wsPort: process.env.WS_PORT || 8081
        },
        environment: CONFIG.NODE_ENV
      };

      // Count certificates if directory exists
      if (directoryStats.CERTIFICATES?.exists) {
        try {
          const files = await fs.readdir(CONFIG.PATHS.CERTIFICATES);
          health.certificates.count = files.filter(file => file.endsWith('.pdf')).length;
        } catch (error) {
          logger.warn('Could not count certificate files', error);
        }
      }

      res.json(health);
    } catch (error) {
      logger.error('Health check failed', error);
      res.status(500).json({
        status: 'ERROR',
        timestamp: new Date().toISOString(),
        error: error.message
      });
    }
  });

  // System status endpoint
  app.get('/admin/system/status', async (req, res) => {
    try {
      const pendingFormsPath = path.join(CONFIG.PATHS.DATA, 'pending_forms.json');
      const certificatesPath = path.join(CONFIG.PATHS.DATA, 'certificates.json');
      const formHistoryPath = path.join(CONFIG.PATHS.DATA, 'form_history.json');

      const [formsData, certificatesData, historyData] = await Promise.all([
        loadJSON(pendingFormsPath, []),
        loadJSON(certificatesPath, []),
        loadJSON(formHistoryPath, [])
      ]);

      const systemStats = {
        totalApplications: formsData.length,
        applicationsByStatus: {},
        totalCertificates: certificatesData.length,
        activeEmployees: new Set(formsData.map(f => f.employeeId)).size,
        recentActivity: formsData.filter(f => {
          const lastUpdate = new Date(f.lastUpdated || f.submissionDate);
          const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000);
          return lastUpdate > yesterday;
        }).length,
        historyStats: {
          totalHistoricalApplications: historyData.length,
          totalHistoricalCertificates: historyData.reduce((sum, h) =>
            sum + (h.preservedData?.certificates?.length || 0), 0),
          cleanupEnabled: true
        },
        notificationStats: {
          connectedEmployees: NotificationManager.getInstance().getConnectedClientsCount(),
          queuedNotifications: NotificationManager.getInstance().notificationQueue?.length || 0
        }
      };

      formsData.forEach(form => {
        const status = form.status || 'unknown';
        systemStats.applicationsByStatus[status] = (systemStats.applicationsByStatus[status] || 0) + 1;
      });

      res.json({
        success: true,
        system: systemStats,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      logger.error('System status error', error);
      res.status(500).json({
        success: false,
        message: 'Error retrieving system statistics'
      });
    }
  });

  // =========================================
  // ERROR HANDLERS
  // =========================================

  // 404 handler
  app.use((req, res) => {
    logger.warn('Route not found', { method: req.method, path: req.path, ip: req.ip });

    if (req.path.startsWith('/api/')) {
      res.status(404).json({
        success: false,
        message: `API endpoint ${req.path} not found`,
        timestamp: new Date().toISOString()
      });
    } else {
      res.status(404).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>404 Not Found</title>
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style>
            body { 
              font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
              text-align: center; 
              padding: 50px; 
              background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
              color: white; 
              margin: 0;
              min-height: 100vh;
              display: flex;
              align-items: center;
              justify-content: center;
            }
            .container { 
              max-width: 600px; 
              background: rgba(255,255,255,0.1); 
              backdrop-filter: blur(10px); 
              border-radius: 20px; 
              padding: 40px;
              box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
            }
            .error-code { 
              font-size: 72px; 
              color: #fff; 
              font-weight: bold; 
              margin-bottom: 20px; 
            }
            .error-message { 
              font-size: 24px; 
              margin: 20px 0; 
            }
            .back-link { 
              display: inline-block; 
              background: rgba(255,255,255,0.2); 
              color: white; 
              padding: 12px 24px; 
              text-decoration: none; 
              border-radius: 25px; 
              margin-top: 20px;
              border: 2px solid rgba(255,255,255,0.3);
              transition: all 0.3s ease;
            }
            .back-link:hover { 
              background: rgba(255,255,255,0.3); 
              transform: translateY(-2px);
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="error-code">404</div>
            <div class="error-message">Page Not Found</div>
            <p>The requested page <code>${req.path}</code> could not be found.</p>
            <a href="/" class="back-link">Go to Login Page</a>
          </div>
        </body>
        </html>
      `);
    }
  });

  // Global error handler
  app.use((err, req, res, next) => {
    logger.error('Unhandled error', err, {
      path: req.path,
      method: req.method,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    if (req.path.startsWith('/api/')) {
      res.status(500).json({
        success: false,
        message: CONFIG.NODE_ENV === 'production' ? 'Internal server error' : err.message,
        timestamp: new Date().toISOString(),
        ...(CONFIG.NODE_ENV !== 'production' && { stack: err.stack })
      });
    } else {
      res.status(500).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Server Error</title>
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style>
            body { 
              font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
              text-align: center; 
              padding: 50px; 
              background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); 
              color: white; 
              margin: 0;
              min-height: 100vh;
              display: flex;
              align-items: center;
              justify-content: center;
            }
            .container { 
              max-width: 600px; 
              background: rgba(255,255,255,0.1); 
              backdrop-filter: blur(10px); 
              border-radius: 20px; 
              padding: 40px;
              box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
            }
            .error-code { 
              font-size: 72px; 
              color: #fff; 
              font-weight: bold; 
              margin-bottom: 20px; 
            }
            .error-message { 
              font-size: 24px; 
              margin: 20px 0; 
            }
            .back-link { 
              display: inline-block; 
              background: rgba(255,255,255,0.2); 
              color: white; 
              padding: 12px 24px; 
              text-decoration: none; 
              border-radius: 25px; 
              margin-top: 20px;
              border: 2px solid rgba(255,255,255,0.3);
            }
            .back-link:hover { 
              background: rgba(255,255,255,0.3); 
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="error-code">500</div>
            <div class="error-message">Internal Server Error</div>
            <p>Something went wrong on our end. Please try again later.</p>
            <a href="/" class="back-link">Go to Login Page</a>
          </div>
        </body>
        </html>
      `);
    }
  });

  return { app, otpManager };
}

// =========================================
// SERVER STARTUP
// =========================================

async function startServer() {
  try {
    const { app, otpManager } = await createApp();

    const server = app.listen(CONFIG.PORT, () => {
      // Initialize NotificationManager
      try {
        const wsPort = process.env.WS_PORT || 8081;
        NotificationManager.initialize({ wsPort });
        logger.info('NotificationManager initialized', { wsPort });
      } catch (error) {
        logger.error('Failed to initialize NotificationManager', error);
      }

      logger.info('Server started successfully', {
        port: CONFIG.PORT,
        environment: CONFIG.NODE_ENV,
        emailConfigured: !!(process.env.EMAIL_USER && process.env.EMAIL_PASS),
        wsPort: process.env.WS_PORT || 8081
      });

      if (CONFIG.NODE_ENV === 'development') {
        console.log('\n🎉 ================================');
        console.log(`✅ Server running at http://localhost:${CONFIG.PORT}`);
        console.log('📧 Email Configuration:', process.env.EMAIL_USER ? '✅ Configured' : '❌ Missing');
        console.log('🔧 Environment:', CONFIG.NODE_ENV);
        console.log('📡 WebSocket Port:', process.env.WS_PORT || 8081);
        console.log('================================\n');
      }
    });

    // Graceful shutdown handling
    const gracefulShutdown = (signal) => {
      logger.info(`${signal} received. Shutting down gracefully...`);

      server.close(() => {
        logger.info('HTTP server closed');

        // Cleanup notification system
        try {
          NotificationManager.shutdown();
          logger.info('NotificationManager shutdown complete');
        } catch (error) {
          logger.error('NotificationManager shutdown error', error);
        }

        // Cleanup OTP system
        try {
          if (otpManager && typeof otpManager.shutdown === 'function') {
            otpManager.shutdown();
            logger.info('OTPManager shutdown complete');
          }
        } catch (error) {
          logger.error('OTPManager shutdown error', error);
        }

        process.exit(0);
      });
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    process.on('uncaughtException', (error) => {
      logger.error('Uncaught Exception', error);
      process.exit(1);
    });

    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled Rejection', { reason, promise });
      process.exit(1);
    });

  } catch (error) {
    logger.error('Server startup failed', error);
    process.exit(1);
  }
}

// Start the server
startServer();
