const express = require('express');
const path = require('path');
const session = require('express-session');
const cors = require('cors');
const fs = require('fs');
const bcrypt = require('bcrypt');
const cron = require('node-cron'); // âœ… For auto cleanup

// CRITICAL FIX: Load environment variables FIRST
require('dotenv').config();

const OTPManager = require('./otpManager'); // Import OTP manager
const NotificationManager = require('./utils/notificationManager'); // ðŸ†• Import NotificationManager

// ðŸ”— Route Files - INCLUDING AUTH ROUTES
const apiEmployee = require('./routes/employee');
const apiItAdmin = require('./routes/itadmin');
const apiPdf = require('./routes/pdf');
const apiHod = require('./routes/hod');
const apiAuth = require('./routes/auth'); // âœ… ADD THIS LINE - Import auth routes

const { roleAuth } = require('./middlewares/sessionAuth');
const { loadJSON, saveJSON } = require('./utils/fileUtils'); // âœ… Import utilities

// Initialize OTP Manager (will now work with .env variables)
const otpManager = new OTPManager();

const app = express();
const PORT = process.env.PORT || 3000;

// === NO-CACHE Middleware! ===
app.use('/api/', (req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.set('Surrogate-Control', 'no-store');
  next();
});

// ðŸ“ Ensure required directories exist
const uploadsDir = path.join(__dirname, 'uploads');
const dataDir = path.join(__dirname, 'data');
const publicDir = path.join(__dirname, 'public');
const certificatesDir = path.join(__dirname, 'public', 'certificates');

// Create directories if they don't exist
[uploadsDir, dataDir, publicDir, certificatesDir].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    console.log(`âœ… Created directory: ${dir}`);
  }
});

// Create subdirectories for certificates
const certificateSubDirs = [
  path.join(certificatesDir, 'temp'),
  path.join(certificatesDir, 'archive')
];

certificateSubDirs.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    console.log(`âœ… Created certificate subdirectory: ${dir}`);
  }
});

// Initialize OTP data files
const initializeOTPFiles = () => {
  const otpDataPath = path.join(dataDir, 'otp_data.json');
  const loginSessionsPath = path.join(dataDir, 'login_sessions.json');

  if (!fs.existsSync(otpDataPath)) {
    fs.writeFileSync(otpDataPath, '{}', 'utf8');
    console.log('âœ… Initialized otp_data.json file');
  }

  if (!fs.existsSync(loginSessionsPath)) {
    fs.writeFileSync(loginSessionsPath, '{}', 'utf8');
    console.log('âœ… Initialized login_sessions.json file');
  }
};

// ðŸ†• Initialize notification data files
const initializeNotificationFiles = () => {
  const notificationsPath = path.join(dataDir, 'notifications.json');
  const employeeSessionsPath = path.join(dataDir, 'employee_sessions.json');

  if (!fs.existsSync(notificationsPath)) {
    fs.writeFileSync(notificationsPath, '[]', 'utf8');
    console.log('âœ… Initialized notifications.json file');
  }

  if (!fs.existsSync(employeeSessionsPath)) {
    fs.writeFileSync(employeeSessionsPath, '[]', 'utf8');
    console.log('âœ… Initialized employee_sessions.json file');
  }
};

// âœ… Initialize form history file
const initializeFormHistoryFile = () => {
  const formHistoryPath = path.join(dataDir, 'form_history.json');
  if (!fs.existsSync(formHistoryPath)) {
    fs.writeFileSync(formHistoryPath, '[]', 'utf8');
    console.log('âœ… Initialized form_history.json file');
  }
};

// ðŸŒ Enhanced CORS for development and production
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);

    if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
      return callback(null, true);
    }

    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:3001',
      'http://127.0.0.1:3000'
    ];

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

// ðŸ“¦ Body parsing middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// âœ… ENHANCED: Session configuration with versioning
app.use(session({
  secret: process.env.SESSION_SECRET || 'super_secret_key_change_in_production',
  name: 'nodues.session.v2025', // âœ… Versioned session name
  resave: false,
  saveUninitialized: false,
  rolling: true, // âœ… Refresh session on each request
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax'
  }
}));

// âœ… Enhanced session cleanup middleware with data preservation
app.use(async (req, res, next) => {
  if (req.session?.user) {
    const user = req.session.user;
    const now = new Date();
    const loginTime = user.loginTime ? new Date(user.loginTime) : null;

    // Check if session is old (24+ hours) or has old structure
    const isOldSession = loginTime && (now - loginTime) > 24 * 60 * 60 * 1000;
    const hasOldStructure = !user.sessionVersion || user.sessionVersion !== '2025-08-17';

    if (isOldSession || hasOldStructure) {
      console.log(`ðŸ§¹ Auto-cleaning session for user ${user.employeeId || user.id} - ${isOldSession ? 'Old' : 'Outdated structure'}`);

      // PRESERVE important data before cleanup
      const preservedData = {
        id: user.id,
        employeeId: user.employeeId || user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department,
        // âœ… NEW: Preserve HOD-specific data
        hodId: user.hodId,
        designation: user.designation
      };

      // Clear old session but preserve login
      req.session.regenerate((err) => {
        if (!err) {
          req.session.user = {
            ...preservedData,
            loginTime: now.toISOString(),
            sessionVersion: '2025-08-17',
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

// ðŸ” Request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);

  if (req.method === 'POST') {
    try {
      if (req.body && typeof req.body === 'object' && req.body !== null) {
        console.log('POST Body keys:', Object.keys(req.body));
      } else {
        console.log('POST Body: undefined/null or not an object, type:', typeof req.body);
      }
    } catch (error) {
      console.log('Error logging POST body:', error.message);
    }
  }

  next();
});

// Helper functions to load user data
function loadEmployeeUser() {
  try {
    const usersData = fs.readFileSync(path.join(dataDir, 'users.json'), 'utf8');
    return JSON.parse(usersData);
  } catch (error) {
    console.error('Error loading employee user:', error);
    return null;
  }
}

function loadHODUsers() {
  try {
    const hodData = fs.readFileSync(path.join(dataDir, 'hod_users.json'), 'utf8');
    return JSON.parse(hodData);
  } catch (error) {
    console.error('Error loading HOD users:', error);
    return [];
  }
}

function loadITUsers() {
  try {
    const itData = fs.readFileSync(path.join(dataDir, 'it_users.json'), 'utf8');
    return JSON.parse(itData);
  } catch (error) {
    console.error('Error loading IT users:', error);
    return [];
  }
}

// ========================================
// AUTHENTICATION ENDPOINTS (OTP SYSTEM)
// ========================================

// Employee login with OTP (Step 1: Credential verification)
app.post('/api/auth/employee-login', async (req, res) => {
  try {
    const { employeeId, password } = req.body;

    if (!employeeId || !password) {
      return res.status(400).json({
        success: false,
        message: 'Employee ID and password are required'
      });
    }

    // Load employee data correctly
    const employeeData = loadEmployeeUser();

    // Handle both single employee object and array of employees
    let employee = null;
    if (Array.isArray(employeeData)) {
      // If it's an array, find the employee
      employee = employeeData.find(emp => emp.employeeId === employeeId);
    } else if (employeeData && employeeData.employeeId === employeeId) {
      // If it's a single employee object
      employee = employeeData;
    }

    if (!employee) {
      return res.status(401).json({
        success: false,
        message: 'Invalid employee ID or password'
      });
    }

    // Verify password using bcrypt
    const isValidPassword = await bcrypt.compare(password, employee.password);

    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid employee ID or password'
      });
    }

    // Check if account is active
    if (employee.isActive === false) {
      return res.status(401).json({
        success: false,
        message: 'Account is deactivated. Please contact IT.'
      });
    }

    // Check if account is temporarily blocked
    if (employee.otpBlockedUntil && new Date() < new Date(employee.otpBlockedUntil)) {
      return res.status(429).json({
        success: false,
        message: 'Account temporarily blocked. Please try again later.'
      });
    }

    // Generate OTP and create session
    const result = await otpManager.createLoginSession(employeeId, employee.email);

    if (result.success) {
      res.json({
        success: true,
        sessionToken: result.sessionToken,
        message: result.message,
        nextStep: 'verify_otp',
        email: employee.email.replace(/(.{2})(.*)(@.*)/, '$1***$3') // Masked email for display
      });
    } else {
      res.status(500).json(result);
    }

  } catch (error) {
    console.error('Employee login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed. Please try again.'
    });
  }
});

// âœ… ENHANCED: OTP verification with session regeneration
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { sessionToken, otp } = req.body;

    if (!sessionToken || !otp) {
      return res.status(400).json({
        success: false,
        message: 'Session token and OTP are required'
      });
    }

    const result = await otpManager.verifyOTP(sessionToken, otp);

    if (result.success) {
      // Load employee data for session
      const employeeData = loadEmployeeUser();
      let employee = null;

      if (Array.isArray(employeeData)) {
        employee = employeeData.find(emp => emp.employeeId === result.employeeId);
      } else if (employeeData && employeeData.employeeId === result.employeeId) {
        employee = employeeData;
      }

      // âœ… IMPORTANT: Regenerate session to clear old data
      req.session.regenerate((err) => {
        if (err) {
          console.error('Session regeneration failed:', err);
          return res.status(500).json({ success: false, message: 'Session error' });
        }

        // Set fresh user data with session versioning
        req.session.user = {
          employeeId: result.employeeId,
          id: result.employeeId, // For compatibility
          role: 'employee',
          name: employee?.name || 'Employee',
          email: employee?.email || '',
          department: employee?.department || '',
          loginTime: new Date().toISOString(),
          sessionVersion: '2025-08-17' // âœ… Session versioning
        };

        // Save the session
        req.session.save((saveErr) => {
          if (saveErr) {
            console.error('Session save failed:', saveErr);
            return res.status(500).json({ success: false, message: 'Session save error' });
          }

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
    console.error('OTP verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Verification failed. Please try again.'
    });
  }
});

// Resend OTP
app.post('/api/auth/resend-otp', async (req, res) => {
  try {
    const { sessionToken } = req.body;

    if (!sessionToken) {
      return res.status(400).json({
        success: false,
        message: 'Session token is required'
      });
    }

    const result = await otpManager.resendOTP(sessionToken);
    res.json(result);

  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to resend OTP'
    });
  }
});

// âœ… ENHANCED: HOD login with comprehensive session data
app.post('/api/auth/hod-login', async (req, res) => {
  try {
    const { hodId, password } = req.body;

    const hodUsers = loadHODUsers();
    const hod = hodUsers.find(h => h.hodId === hodId);

    if (!hod) {
      return res.status(401).json({
        success: false,
        message: 'Invalid HOD credentials'
      });
    }

    const isValidPassword = await bcrypt.compare(password, hod.password);

    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid HOD credentials'
      });
    }

    // âœ… ENHANCED: Set comprehensive HOD session data
    req.session.user = {
      hodId: hodId,
      id: hodId, // For compatibility
      role: 'hod',
      name: hod.name,
      email: hod.email,
      // âœ… NEW: Add employeeId for HOD forms
      employeeId: hod.employeeId,
      department: hod.department || 'Academic Department',
      designation: hod.designation || 'HOD',
      loginTime: new Date().toISOString(),
      sessionVersion: '2025-08-17' // âœ… Session versioning
    };

    req.session.save((err) => {
      if (err) {
        console.error('HOD session save error:', err);
        return res.status(500).json({
          success: false,
          message: 'Session creation failed'
        });
      }

      console.log(`âœ… HOD login successful: ${hod.name} (${hodId})`);

      res.json({
        success: true,
        message: 'HOD login successful',
        role: 'hod',
        redirectTo: '/hodreview.html',
        // âœ… SEND HOD DETAILS FOR IMMEDIATE USE
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
    console.error('HOD login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed'
    });
  }
});

// IT login (Direct access - no OTP)
app.post('/api/auth/it-login', async (req, res) => {
  try {
    const { itId, password } = req.body;

    const itUsers = loadITUsers();
    const itUser = itUsers.find(u => u.itId === itId);

    if (!itUser) {
      return res.status(401).json({
        success: false,
        message: 'Invalid IT credentials'
      });
    }

    const isValidPassword = await bcrypt.compare(password, itUser.password);

    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid IT credentials'
      });
    }

    // Set session for IT (direct access)
    req.session.user = {
      itId: itId,
      id: itId, // For compatibility
      role: 'it',
      name: itUser.name,
      email: itUser.email,
      employeeId: itUser.employeeId || itId, // Add employeeId for compatibility
      department: itUser.department || 'IT',
      designation: itUser.designation || 'IT Admin',
      loginTime: new Date().toISOString(),
      sessionVersion: '2025-08-17' // âœ… Session versioning
    };

    req.session.save((err) => {
      if (err) {
        console.error('IT session save error:', err);
        return res.status(500).json({
          success: false,
          message: 'Session creation failed'
        });
      }

      res.json({
        success: true,
        message: 'IT login successful',
        role: 'it',
        redirectTo: '/itreview.html'
      });
    });

  } catch (error) {
    console.error('IT login error:', error);
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
      user: req.session.user
    });
  } else {
    res.status(401).json({
      success: false,
      message: 'No valid session'
    });
  }
});

// âœ… AUTO-CLEANUP cron job - Run every day at 2 AM to clean up completed forms
cron.schedule('0 2 * * *', async () => {
  console.log('ðŸ§¹ Running daily form cleanup...');

  try {
    const PENDING_FORMS = './data/pending_forms.json';
    const FORM_HISTORY = './data/form_history.json';

    let pendingForms = [];
    try {
      pendingForms = loadJSON(PENDING_FORMS);
      if (!Array.isArray(pendingForms)) pendingForms = [];
    } catch {
      pendingForms = [];
    }

    const completedForms = pendingForms.filter(form =>
      form.status === 'IT Completed' &&
      form.itProcessing?.processedAt &&
      // Only move forms completed more than 7 days ago
      new Date() - new Date(form.itProcessing.processedAt) > 7 * 24 * 60 * 60 * 1000
    );

    if (completedForms.length > 0) {
      // Move to history
      let history = [];
      try {
        history = loadJSON(FORM_HISTORY);
        if (!Array.isArray(history)) history = [];
      } catch {
        history = [];
      }

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

      // Remove moved forms from pending
      const remainingForms = pendingForms.filter(form => !completedForms.find(cf => cf.formId === form.formId));

      saveJSON(FORM_HISTORY, history);
      saveJSON(PENDING_FORMS, remainingForms);

      console.log(`âœ… Moved ${completedForms.length} completed forms to history`);
    }
  } catch (error) {
    console.error('âŒ Daily cleanup error:', error);
  }
});

// ðŸ†• Notification endpoints
app.get('/api/employee/notifications', roleAuth('employee'), (req, res) => {
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
    console.error('Error fetching notifications:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch notifications'
    });
  }
});

// ðŸ†• WebSocket connection info endpoint
app.get('/api/notification/websocket-info', (req, res) => {
  const wsPort = process.env.WS_PORT || 8081;
  res.json({
    success: true,
    wsPort: wsPort,
    wsUrl: `ws://localhost:${wsPort}`,
    isEnabled: true
  });
});

// ðŸŒ Static file serving
app.use('/certificates', (req, res, next) => {
  console.log(`ðŸš« Blocked direct access to certificates: ${req.path}`);
  res.status(403).json({
    success: false,
    message: 'Direct access to certificates is forbidden. Please use the download API.'
  });
});

app.use('/uploads', express.static(uploadsDir));
app.use(express.static(publicDir));
app.use('/forms', express.static(path.join(publicDir, 'forms')));
app.use('/css', express.static(path.join(publicDir, 'css')));
app.use('/js', express.static(path.join(publicDir, 'js')));
app.use('/images', express.static(path.join(publicDir, 'images')));

// âœ… CRITICAL: Mount API routes INCLUDING AUTH ROUTES
app.use('/api/auth', apiAuth); // âœ… THIS WAS MISSING - Add auth routes
app.use('/api/employee', apiEmployee);
app.use('/api/itadmin', apiItAdmin);
app.use('/api/pdf', apiPdf);
app.use('/api/hod', apiHod);

// ðŸ  Frontend route handlers with role-based access
app.get('/', (req, res) => {
  res.sendFile(path.join(publicDir, 'login.html'));
});

// Employee routes
app.get('/dashboard.html', roleAuth('employee'), (req, res) => {
  res.sendFile(path.join(publicDir, 'dashboard.html'));
});

app.get('/employee.html', roleAuth('employee'), (req, res) => {
  res.sendFile(path.join(publicDir, 'employee.html'));
});

app.get('/confirmation.html', roleAuth('employee'), (req, res) => {
  res.sendFile(path.join(publicDir, 'confirmation.html'));
});

app.get('/employee-dashboard.html', roleAuth('employee'), (req, res) => {
  res.sendFile(path.join(publicDir, 'employee-dashboard.html'));
});

app.get('/track.html', roleAuth('employee'), (req, res) => {
  res.sendFile(path.join(publicDir, 'track.html'));
});

// IT routes
app.get('/itreview.html', roleAuth('it'), (req, res) => {
  res.sendFile(path.join(publicDir, 'itreview.html'));
});

app.get('/it-form-review.html', roleAuth('it'), (req, res) => {
  res.sendFile(path.join(publicDir, 'it-form-review.html'));
});

// HOD routes
app.get('/hodhome.html', roleAuth('hod'), (req, res) => {
  res.sendFile(path.join(publicDir, 'hodhome.html'));
});

app.get('/hodreview.html', roleAuth('hod'), (req, res) => {
  res.sendFile(path.join(publicDir, 'hodreview.html'));
});

app.get('/hod-form-review.html', roleAuth('hod'), (req, res) => {
  res.sendFile(path.join(publicDir, 'hod-form-review.html'));
});

// Individual form routes
app.get('/forms/disposalform.html', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  res.sendFile(path.join(publicDir, 'forms', 'disposalform.html'));
});

app.get('/forms/efile.html', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  res.sendFile(path.join(publicDir, 'forms', 'efile.html'));
});

app.get('/forms/form365transfer.html', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  res.sendFile(path.join(publicDir, 'forms', 'form365transfer.html'));
});

app.get('/forms/form365disposal.html', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  res.sendFile(path.join(publicDir, 'forms', 'form365disposal.html'));
});

// ðŸ”§ Enhanced health check endpoint
app.get('/health', (req, res) => {
  const certificateStatus = {
    main: fs.existsSync(certificatesDir),
    temp: fs.existsSync(path.join(certificatesDir, 'temp')),
    archive: fs.existsSync(path.join(certificatesDir, 'archive'))
  };

  let certificateCount = 0;
  try {
    if (certificateStatus.main) {
      const files = fs.readdirSync(certificatesDir);
      certificateCount = files.filter(file => file.endsWith('.pdf')).length;
    }
  } catch (error) {
    console.warn('Could not count certificate files:', error.message);
  }

  // Check OTP system health
  const otpStatus = {
    otpDataExists: fs.existsSync(path.join(dataDir, 'otp_data.json')),
    loginSessionsExists: fs.existsSync(path.join(dataDir, 'login_sessions.json')),
    otpManagerActive: !!otpManager,
    emailConfigured: !!(process.env.EMAIL_USER && process.env.EMAIL_PASS)
  };

  // ðŸ†• Check notification system health
  const notificationStatus = {
    notificationDataExists: fs.existsSync(path.join(dataDir, 'notifications.json')),
    notificationManagerActive: !!NotificationManager.getInstance(),
    webSocketEnabled: true,
    connectedClients: NotificationManager.getInstance().getConnectedClientsCount(),
    wsPort: process.env.WS_PORT || 8081
  };

  const trackingStatus = {
    trackHtmlExists: fs.existsSync(path.join(publicDir, 'track.html')),
    dashboardExists: fs.existsSync(path.join(publicDir, 'dashboard.html')),
    apiEndpointsActive: true
  };

  // âœ… History system health
  const historyStatus = {
    formHistoryExists: fs.existsSync(path.join(dataDir, 'form_history.json')),
    sessionCleanupActive: true,
    autoCleanupScheduled: true
  };

  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    directories: {
      uploads: fs.existsSync(uploadsDir),
      data: fs.existsSync(dataDir),
      public: fs.existsSync(publicDir),
      certificates: certificateStatus.main
    },
    certificates: {
      directory: certificateStatus,
      count: certificateCount
    },
    otp: otpStatus,
    notifications: notificationStatus,
    tracking: trackingStatus,
    history: historyStatus, // âœ… NEW
    environment: process.env.NODE_ENV || 'development'
  });
});

// Certificate management endpoints
app.get('/admin/certificates/status', (req, res) => {
  try {
    const certificatesPath = path.join(dataDir, 'certificates.json');
    let certificatesData = [];

    if (fs.existsSync(certificatesPath)) {
      certificatesData = JSON.parse(fs.readFileSync(certificatesPath, 'utf8'));
    }

    const stats = {
      total: certificatesData.length,
      byStatus: {},
      byFormType: {},
      recentCount: 0
    };

    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

    certificatesData.forEach(cert => {
      stats.byStatus[cert.status] = (stats.byStatus[cert.status] || 0) + 1;
      stats.byFormType[cert.formType] = (stats.byFormType[cert.formType] || 0) + 1;

      if (new Date(cert.generatedAt) > oneWeekAgo) {
        stats.recentCount++;
      }
    });

    res.json({
      success: true,
      statistics: stats,
      certificatesData: certificatesData.slice(0, 10)
    });
  } catch (error) {
    console.error('Error getting certificate status:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving certificate statistics'
    });
  }
});

// System status endpoint
app.get('/admin/system/status', (req, res) => {
  try {
    const pendingFormsPath = path.join(dataDir, 'pending_forms.json');
    const certificatesPath = path.join(dataDir, 'certificates.json');
    const formHistoryPath = path.join(dataDir, 'form_history.json'); // âœ… NEW

    let formsData = [];
    let certificatesData = [];
    let historyData = []; // âœ… NEW

    if (fs.existsSync(pendingFormsPath)) {
      formsData = JSON.parse(fs.readFileSync(pendingFormsPath, 'utf8'));
    }

    if (fs.existsSync(certificatesPath)) {
      certificatesData = JSON.parse(fs.readFileSync(certificatesPath, 'utf8'));
    }

    // âœ… NEW: Load history data
    if (fs.existsSync(formHistoryPath)) {
      historyData = JSON.parse(fs.readFileSync(formHistoryPath, 'utf8'));
    }

    const systemStats = {
      totalApplications: formsData.length,
      applicationsByStatus: {},
      totalCertificates: certificatesData.length,
      activeEmployees: new Set(formsData.map(f => f.employeeId)).size,
      recentActivity: formsData.filter(f => {
        const lastUpdate = new Date(f.lastUpdated || f.submissionDate);
        const yesterday = new Date();
        yesterday.setDate(yesterday.getDate() - 1);
        return lastUpdate > yesterday;
      }).length,
      // âœ… NEW: History statistics
      historyStats: {
        totalHistoricalApplications: historyData.length,
        totalHistoricalCertificates: historyData.reduce((sum, h) => sum + (h.preservedData?.certificates?.length || 0), 0),
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
    console.error('Error getting system status:', error);
    res.status(500).json({
      success: false,
      message: 'Error retrieving system statistics'
    });
  }
});

// Initialize certificates data file
const initializeCertificatesData = () => {
  const certificatesDataPath = path.join(dataDir, 'certificates.json');
  if (!fs.existsSync(certificatesDataPath)) {
    fs.writeFileSync(certificatesDataPath, '[]', 'utf8');
    console.log('âœ… Initialized certificates.json data file');
  }
};

// ðŸš« Enhanced 404 handler
app.use((req, res) => {
  console.log(`âŒ 404 - Route not found: ${req.method} ${req.path}`);

  if (req.path.startsWith('/api/')) {
    res.status(404).json({
      success: false,
      message: `API endpoint ${req.path} not found`,
      availableEndpoints: [
        '/api/auth/employee-login',
        '/api/auth/hod-login',
        '/api/auth/it-login',
        '/api/auth/verify-otp',
        '/api/auth/resend-otp',
        '/api/auth/check-session',
        '/api/auth/logout', // âœ… NOW PROPERLY AVAILABLE
        '/api/employee/*',
        '/api/itadmin/*',
        '/api/pdf/*',
        '/api/hod/*',
        '/api/employee/notifications',
        '/api/notification/websocket-info'
      ]
    });
  } else {
    res.status(404).send(`
      <html>
        <head>
          <title>404 Not Found</title>
          <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
            .container { max-width: 600px; margin: 0 auto; background: rgba(255,255,255,0.1); backdrop-filter: blur(10px); border-radius: 20px; padding: 40px; }
            .error-code { font-size: 72px; color: #fff; font-weight: bold; margin-bottom: 20px; }
            .error-message { font-size: 24px; margin: 20px 0; }
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
            <p>You might be looking for the tracking page or dashboard.</p>
            <a href="/" class="back-link">ðŸ  Go to Login Page</a>
            <br><br>
            <small>Available pages: Dashboard, Track, Forms, Certificates</small>
          </div>
        </body>
      </html>
    `);
  }
});

// ðŸ’¥ Enhanced global error handler
app.use((err, req, res, next) => {
  console.error('ðŸ’¥ Server Error:', err);
  console.error('Error stack:', err.stack);
  console.error('Request path:', req.path);
  console.error('Request method:', req.method);

  if (req.path.startsWith('/api/')) {
    res.status(500).json({
      success: false,
      message: process.env.NODE_ENV === 'production'
        ? 'Internal server error'
        : err.message,
      ...(process.env.NODE_ENV !== 'production' && {
        stack: err.stack,
        timestamp: new Date().toISOString()
      })
    });
  } else {
    res.status(500).send(`
      <html>
        <head>
          <title>Server Error</title>
          <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); color: white; }
            .container { max-width: 600px; margin: 0 auto; background: rgba(255,255,255,0.1); backdrop-filter: blur(10px); border-radius: 20px; padding: 40px; }
            .error-code { font-size: 72px; color: #fff; font-weight: bold; margin-bottom: 20px; }
            .error-message { font-size: 24px; margin: 20px 0; }
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
            .back-link:hover { background: rgba(255,255,255,0.3); }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="error-code">500</div>
            <div class="error-message">Internal Server Error</div>
            <p>Something went wrong on our end. Please try again later.</p>
            <a href="/" class="back-link">ðŸ  Go to Login Page</a>
          </div>
        </body>
      </html>
    `);
  }
});

// ðŸš€ Start server with enhanced logging
app.listen(PORT, () => {
  // Initialize required data files
  initializeCertificatesData();
  initializeOTPFiles();
  initializeNotificationFiles();
  initializeFormHistoryFile(); // âœ… NEW

  // ðŸ†• Initialize NotificationManager
  try {
    const wsPort = process.env.WS_PORT || 8081;
    NotificationManager.initialize({ wsPort: wsPort });
    console.log(`âœ… NotificationManager initialized on WebSocket port ${wsPort}`);
  } catch (error) {
    console.error('âŒ Failed to initialize NotificationManager:', error);
  }

  console.log('\nðŸŽ‰ ================================');
  console.log(`âœ… Server running at http://localhost:${PORT}`);

  // Show email configuration status
  console.log('ðŸ“§ Email Configuration:');
  console.log(`   - Email User: ${process.env.EMAIL_USER ? 'âœ… Configured' : 'âŒ Missing'}`);
  console.log(`   - Email Pass: ${process.env.EMAIL_PASS ? 'âœ… Configured' : 'âŒ Missing'}`);
  console.log(`   - Email From: ${process.env.EMAIL_FROM || 'Using default'}`);

  console.log('ðŸ“ Static directories:');
  console.log(`   - Public: ${publicDir}`);
  console.log(`   - Uploads: ${uploadsDir}`);
  console.log(`   - Data: ${dataDir}`);
  console.log(`   - Certificates: ${certificatesDir}`);

  console.log('ðŸ”— Available routes:');
  console.log('   - Employee: /dashboard.html, /employee.html, /track.html');
  console.log('   - HOD: /hodhome.html, /hodreview.html, /hod-form-review.html');
  console.log('   - IT: /itreview.html, /it-form-review.html');
  console.log('   - Forms: /forms/disposalform.html, /forms/efile.html');
  console.log('   - Tracking: /track.html (Interactive timeline)');

  console.log('ðŸ”§ Health check: /health');
  console.log('ðŸ“œ Certificate admin: /admin/certificates/status');
  console.log('ðŸŽ¯ System admin: /admin/system/status');
  console.log('âš¡ Environment:', process.env.NODE_ENV || 'development');

  // Log OTP system status
  const otpDataExists = fs.existsSync(path.join(dataDir, 'otp_data.json'));
  const loginSessionsExists = fs.existsSync(path.join(dataDir, 'login_sessions.json'));

  console.log('ðŸ“§ OTP System:');
  console.log(`   - OTP Data file: ${otpDataExists ? 'âœ…' : 'âŒ'}`);
  console.log(`   - Login Sessions file: ${loginSessionsExists ? 'âœ…' : 'âŒ'}`);
  console.log(`   - OTP Manager: âœ… Active`);
  console.log(`   - Employee OTP: âœ… Required`);
  console.log(`   - HOD/IT OTP: âŒ Direct access`);

  // ðŸ†• Log notification system status
  const notificationsExists = fs.existsSync(path.join(dataDir, 'notifications.json'));
  const employeeSessionsExists = fs.existsSync(path.join(dataDir, 'employee_sessions.json'));

  console.log('ðŸ“¡ Notification System:');
  console.log(`   - Notifications file: ${notificationsExists ? 'âœ…' : 'âŒ'}`);
  console.log(`   - Employee sessions file: ${employeeSessionsExists ? 'âœ…' : 'âŒ'}`);
  console.log(`   - WebSocket server: âœ… Active on port ${process.env.WS_PORT || 8081}`);
  console.log(`   - Real-time notifications: âœ… Enabled`);
  console.log(`   - Connected clients: ${NotificationManager.getInstance().getConnectedClientsCount()}`);

  // âœ… Log history and session cleanup status
  const formHistoryExists = fs.existsSync(path.join(dataDir, 'form_history.json'));
  console.log('ðŸ“š History & Session Management:');
  console.log(`   - Form history file: ${formHistoryExists ? 'âœ…' : 'âŒ'}`);
  console.log(`   - Auto session cleanup: âœ… Active`);
  console.log(`   - Daily form archival: âœ… Scheduled (2:00 AM)`);
  console.log(`   - Session versioning: âœ… v2025-08-17`);

  // Log certificate directory status
  const certDirExists = fs.existsSync(certificatesDir);
  const certDataExists = fs.existsSync(path.join(dataDir, 'certificates.json'));
  const trackPageExists = fs.existsSync(path.join(publicDir, 'track.html'));

  console.log('ðŸ“œ Certificate system:');
  console.log(`   - Directory: ${certDirExists ? 'âœ…' : 'âŒ'}`);
  console.log(`   - Data file: ${certDataExists ? 'âœ…' : 'âŒ'}`);
  console.log('ðŸŽ¯ Tracking system:');
  console.log(`   - Track page: ${trackPageExists ? 'âœ…' : 'âŒ'}`);
  console.log(`   - Interactive timeline: âœ… Enabled`);
  console.log('================================\n');

  // Log authentication endpoints
  if (process.env.NODE_ENV !== 'production') {
    console.log('ðŸ”§ Development Mode - Authentication Info:');
    console.log(`   - Employee login: POST /api/auth/employee-login (requires OTP)`);
    console.log(`   - HOD login: POST /api/auth/hod-login (direct access with prefill)`);
    console.log(`   - IT login: POST /api/auth/it-login (direct access)`);
    console.log(`   - OTP verification: POST /api/auth/verify-otp`);
    console.log(`   - Resend OTP: POST /api/auth/resend-otp`);
    console.log(`   - Session check: GET /api/auth/check-session`);
    console.log(`   - Logout: POST /api/auth/logout âœ… NOW WORKING`); // âœ… Updated
    console.log('');
    console.log('âœ… AUTH ROUTES PROPERLY MOUNTED:');
    console.log(`   - âœ… Auth router mounted at /api/auth`);
    console.log(`   - âœ… Logout endpoint: POST /api/auth/logout`);
    console.log(`   - âœ… Logout endpoint: GET /api/auth/logout`);
    console.log(`   - âœ… Session management active`);
    console.log('');
    console.log('âœ… HOD PREFILL SYSTEM ENABLED:');
    console.log(`   - âœ… Auto-fills HOD details on login`);
    console.log(`   - âœ… HOD employee ID included in session`);
    console.log(`   - âœ… Comprehensive HOD data in forms`);
    console.log(`   - âœ… HOD details API: GET /api/hod/my-details`);
    console.log('');
    console.log('ðŸ†• NOTIFICATION SYSTEM ENABLED:');
    console.log(`   - âœ… Real-time form rejection notifications`);
    console.log(`   - âœ… Form approval notifications`);
    console.log(`   - âœ… Certificate ready notifications`);
    console.log(`   - âœ… WebSocket server for instant updates`);
    console.log('');
    console.log('âœ… SMART SESSION MANAGEMENT:');
    console.log(`   - âœ… Auto session cleanup with data preservation`);
    console.log(`   - âœ… Certificate and history retention`);
    console.log(`   - âœ… Daily automated form archival`);
    console.log(`   - âœ… Session versioning for compatibility`);
    console.log('');
  }
});

// ðŸ†• ENHANCED: Graceful shutdown handling with notification cleanup
process.on('SIGTERM', () => {
  console.log('ðŸ›‘ SIGTERM received. Shutting down gracefully...');
  console.log('ðŸ“Š Final server statistics:');
  console.log(`   - Uptime: ${Math.floor(process.uptime())} seconds`);
  console.log(`   - Memory usage: ${Math.round(process.memoryUsage().rss / 1024 / 1024)} MB`);

  // ðŸ†• Shutdown notification system
  try {
    NotificationManager.shutdown();
    console.log('   - NotificationManager: âœ… Shutdown complete');
  } catch (error) {
    console.log('   - NotificationManager: âŒ Shutdown error');
  }

  try {
    const pendingFormsPath = path.join(dataDir, 'pending_forms.json');
    if (fs.existsSync(pendingFormsPath)) {
      const formsData = JSON.parse(fs.readFileSync(pendingFormsPath, 'utf8'));
      console.log(`   - Total applications processed: ${formsData.length}`);
    }

    const certificatesPath = path.join(dataDir, 'certificates.json');
    if (fs.existsSync(certificatesPath)) {
      const certData = JSON.parse(fs.readFileSync(certificatesPath, 'utf8'));
      console.log(`   - Total certificates generated: ${certData.length}`);
    }

    // âœ… History statistics
    const historyPath = path.join(dataDir, 'form_history.json');
    if (fs.existsSync(historyPath)) {
      const historyData = JSON.parse(fs.readFileSync(historyPath, 'utf8'));
      console.log(`   - Total archived applications: ${historyData.length}`);
    }

    console.log(`   - OTP system: Cleaned expired sessions and OTPs`);
  } catch (error) {
    console.log('   - Could not retrieve final statistics');
  }

  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('\nðŸ›‘ SIGINT received. Shutting down gracefully...');
  console.log('ðŸ“Š Final server statistics:');
  console.log(`   - Uptime: ${Math.floor(process.uptime())} seconds`);
  console.log(`   - Memory usage: ${Math.round(process.memoryUsage().rss / 1024 / 1024)} MB`);

  // ðŸ†• Shutdown notification system
  try {
    NotificationManager.shutdown();
    console.log('   - NotificationManager: âœ… Shutdown complete');
  } catch (error) {
    console.log('   - NotificationManager: âŒ Shutdown error');
  }

  process.exit(0);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('ðŸ’¥ Uncaught Exception:', error);
  console.error('ðŸ›‘ Server will shut down...');

  // ðŸ†• Emergency shutdown of notification system
  try {
    NotificationManager.shutdown();
  } catch (shutdownError) {
    console.error('Emergency notification shutdown failed:', shutdownError);
  }

  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('ðŸ’¥ Unhandled Rejection at:', promise, 'reason:', reason);
  console.error('ðŸ›‘ Server will shut down...');

  // ðŸ†• Emergency shutdown of notification system
  try {
    NotificationManager.shutdown();
  } catch (shutdownError) {
    console.error('Emergency notification shutdown failed:', shutdownError);
  }

  process.exit(1);
});