const express = require('express');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const { promisify } = require('util');
const Joi = require('joi');
const { loadJSON, saveJSON } = require('../utils/fileUtils');
const { roleAuth } = require('../middlewares/sessionAuth');
const { getFormDisplayName } = require('../utils/pdfGenerator');

const router = express.Router();

// =========================================
//  SECURITY MIDDLEWARE
// =========================================

// Security headers
router.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "blob:"],
      uploadRestrictions: true
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// Compression for better performance
router.use(compression());

// Rate limiting for different endpoints
const createRateLimit = (windowMs, max, message) => rateLimit({
  windowMs,
  max,
  message: { success: false, message, code: 'RATE_LIMITED' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip} on ${req.path}`, {
      ip: req.ip,
      path: req.path,
      userAgent: req.get('User-Agent')
    });
    res.status(429).json({
      success: false,
      message,
      retryAfter: Math.ceil(res.getHeader('Retry-After')),
      code: 'RATE_LIMITED'
    });
  }
});

// Different rate limits for different operations
const submitLimit = createRateLimit(15 * 60 * 1000, 5, 'Too many form submissions. Please try again later.');
const downloadLimit = createRateLimit(5 * 60 * 1000, 50, 'Too many download requests. Please try again later.');
const generalLimit = createRateLimit(15 * 60 * 1000, 100, 'Too many requests. Please try again later.');

// Apply rate limiting
router.use('/submit-no-dues', submitLimit);
router.use('/final-submit', submitLimit);
router.use('/certificates/*/download', downloadLimit);
router.use(generalLimit);

// =========================================
//  LOGGING & MONITORING
// =========================================

const logger = {
  info: (message, meta = {}) => console.log(`[INFO] ${new Date().toISOString()} - ${message}`, JSON.stringify(meta)),
  warn: (message, meta = {}) => console.warn(`[WARN] ${new Date().toISOString()} - ${message}`, JSON.stringify(meta)),
  error: (message, error, meta = {}) => console.error(`[ERROR] ${new Date().toISOString()} - ${message}`, error?.stack || error, JSON.stringify(meta)),
  audit: (action, userId, meta = {}) => console.log(`[AUDIT] ${new Date().toISOString()} - ${action} - User: ${userId}`, JSON.stringify(meta))
};

// Audit middleware for sensitive operations
const auditMiddleware = (action) => (req, res, next) => {
  const userId = req.session?.user?.id || 'anonymous';
  const ip = req.ip || req.connection?.remoteAddress;

  logger.audit(action, userId, {
    ip,
    userAgent: req.get('User-Agent'),
    path: req.path,
    method: req.method,
    sessionId: req.session?.id
  });

  next();
};

// =========================================
//  DATA VALIDATION
// =========================================

// Validation schemas
const schemas = {
  noDuesSubmission: Joi.object({
    name: Joi.string().trim().min(2).max(100).required(),
    employeeId: Joi.string().trim().min(1).max(50).required(),
    email: Joi.string().email().required(),
    department: Joi.string().trim().min(1).max(100).required(),
    noDuesType: Joi.string().valid('resignation', 'transfer', 'retirement', 'termination').required(),
    reason: Joi.string().trim().max(1000).optional()
  }),

  formData: Joi.object().pattern(
    Joi.string(),
    Joi.alternatives().try(
      Joi.string().max(10000),
      Joi.number(),
      Joi.boolean(),
      Joi.array().items(Joi.string().max(1000)).max(100)
    )
  ).max(50) // Maximum 50 fields
};

// Validation middleware
const validateRequest = (schema) => (req, res, next) => {
  const { error, value } = schema.validate(req.body, { abortEarly: false, stripUnknown: true });

  if (error) {
    logger.warn('Validation failed', {
      errors: error.details.map(d => ({ field: d.path.join('.'), message: d.message })),
      userId: req.session?.user?.id,
      ip: req.ip
    });

    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: error.details.map(d => ({ field: d.path.join('.'), message: d.message })),
      code: 'VALIDATION_ERROR'
    });
  }

  req.body = value; // Use validated data
  next();
};

// =========================================
//  FILE HANDLING
// =========================================

// Enhanced multer configuration with security
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../uploads');

    // Ensure upload directory exists
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true, mode: 0o755 });
    }

    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Sanitize filename
    const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    const uniqueName = `${Date.now()}-${Math.random().toString(36).substring(2)}-${sanitizedName}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB max
    files: 1
  },
  fileFilter: (req, file, cb) => {
    // Only allow PDF files
    if (file.mimetype === 'application/pdf' || path.extname(file.originalname).toLowerCase() === '.pdf') {
      cb(null, true);
    } else {
      logger.warn('Invalid file type attempted', {
        mimetype: file.mimetype,
        originalname: file.originalname,
        userId: req.session?.user?.id,
        ip: req.ip
      });
      cb(new Error('Only PDF files are allowed'), false);
    }
  }
});

// =========================================
//  ERROR HANDLING
// =========================================

// Async error wrapper
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// Enhanced error responses
const createErrorResponse = (message, code = 'INTERNAL_ERROR', statusCode = 500, details = null) => ({
  success: false,
  message,
  code,
  timestamp: new Date().toISOString(),
  ...(process.env.NODE_ENV === 'development' && details && { details })
});

// =========================================
//  DATA ACCESS LAYER
// =========================================

class DataAccessLayer {
  static async safeReadJSON(filePath, defaultValue = []) {
    try {
      const data = loadJSON(filePath);
      return Array.isArray(data) ? data : defaultValue;
    } catch (error) {
      logger.error(`Failed to read JSON file: ${filePath}`, error);
      return defaultValue;
    }
  }

  static async safeWriteJSON(filePath, data) {
    try {
      // Create backup before writing
      if (fs.existsSync(filePath)) {
        const backupPath = `${filePath}.backup.${Date.now()}`;
        fs.copyFileSync(filePath, backupPath);

        // Keep only last 5 backups
        const dir = path.dirname(filePath);
        const basename = path.basename(filePath);
        const backupFiles = fs.readdirSync(dir)
          .filter(f => f.startsWith(`${basename}.backup.`))
          .sort()
          .reverse();

        if (backupFiles.length > 5) {
          backupFiles.slice(5).forEach(f => {
            fs.unlinkSync(path.join(dir, f));
          });
        }
      }

      saveJSON(filePath, data);
      return true;
    } catch (error) {
      logger.error(`Failed to write JSON file: ${filePath}`, error);
      throw new Error('Database write operation failed');
    }
  }

  static validateEmployeeAccess(employeeId, formData) {
    if (formData.employeeId !== employeeId) {
      throw new Error('Access denied: Employee ID mismatch');
    }
  }
}

// =========================================
//  CONSTANTS & CONFIG
// =========================================

const CONFIG = {
  FILES: {
    PENDING_FORMS: './data/pending_forms.json',
    FORM_HISTORY: './data/form_history.json',
    USERS: './data/users.json',
    CERTIFICATES: './data/certificates.json'
  },
  LIMITS: {
    MAX_FORMS_PER_USER: 5,
    MAX_FORM_AGE_DAYS: 365,
    CERTIFICATE_RETENTION_DAYS: 1095 // 3 years
  },
  STATUS: {
    ACTIVE: ['Pending', 'pending', 'Submitted to HOD', 'Submitted to IT', 'approved'],
    COMPLETED: ['IT Completed'],
    REJECTED: ['rejected', 'Rejected']
  }
};

// =========================================
//  HELPER FUNCTIONS
// =========================================

class FormHelpers {
  static async moveCompletedFormToHistory(employeeId, formData) {
    try {
      const history = await DataAccessLayer.safeReadJSON(CONFIG.FILES.FORM_HISTORY);

      const historyEntry = {
        ...formData,
        completedAt: new Date().toISOString(),
        finalStatus: formData.status,
        historyType: 'completed_application',
        archivedBy: 'system',
        preservedData: {
          certificates: formData.certificates || [],
          hodApproval: formData.hodApproval || null,
          itProcessing: formData.itProcessing || null,
          assignedForms: formData.assignedForms || [],
          formResponses: formData.formResponses || {}
        }
      };

      history.push(historyEntry);
      await DataAccessLayer.safeWriteJSON(CONFIG.FILES.FORM_HISTORY, history);

      logger.info(`Form moved to history`, {
        formId: formData.formId,
        employeeId,
        finalStatus: formData.status
      });

      return true;
    } catch (error) {
      logger.error('Failed to move form to history', error, { employeeId, formId: formData.formId });
      return false;
    }
  }

  static getLatestFormForEmployee(allForms, employeeId, allowedStatuses = null) {
    let employeeForms = allForms.filter(f => f && f.employeeId === employeeId);

    if (allowedStatuses) {
      employeeForms = employeeForms.filter(f => allowedStatuses.includes(f.status));
    }

    return employeeForms
      .sort((a, b) => new Date(b.submissionDate || b.lastUpdated) - new Date(a.submissionDate || a.lastUpdated))[0] || null;
  }

  static buildTimelineData(formData) {
    const timeline = [];

    if (formData.submissionDate) {
      timeline.push({
        step: 'submitted',
        title: 'Application Submitted',
        date: formData.submissionDate,
        status: 'completed',
        details: `Application ${formData.formId} submitted for ${formData.noDuesType} clearance`
      });
    }

    if (formData.status !== 'pending') {
      const reviewStatus = formData.status === 'rejected' ? 'rejected' : 'completed';
      timeline.push({
        step: 'it_reviewed',
        title: 'IT Initial Review',
        date: formData.lastUpdated,
        status: reviewStatus,
        details: formData.remark || (reviewStatus === 'rejected' ? 'Application rejected by IT' : 'Application reviewed and approved by IT department')
      });
    }

    if (formData.assignedForms && formData.assignedForms.length > 0) {
      timeline.push({
        step: 'forms_assigned',
        title: 'Forms Assigned',
        date: formData.lastUpdated,
        status: 'completed',
        details: `${formData.assignedForms.length} forms assigned: ${formData.assignedForms.map(f => f.title).join(', ')}`
      });
    }

    if (formData.formResponses && Object.keys(formData.formResponses).length > 0) {
      const completedForms = Object.keys(formData.formResponses);
      timeline.push({
        step: 'forms_completed',
        title: 'Forms Completed',
        date: formData.finalSubmittedAt || formData.lastUpdated,
        status: 'completed',
        details: `Employee completed ${completedForms.length} forms and submitted to HOD`
      });
    }

    if (formData.hodApproval) {
      timeline.push({
        step: 'hod_approved',
        title: 'HOD Approval',
        date: formData.hodApproval.approvedAt,
        status: 'completed',
        details: `Approved by HOD: ${formData.hodApproval.approvedBy}`
      });
    }

    if (formData.itProcessing) {
      const processingStatus = formData.itProcessing.action === 'completed' ? 'completed' : 'rejected';
      timeline.push({
        step: 'it_processing',
        title: 'IT Final Processing',
        date: formData.itProcessing.processedAt,
        status: processingStatus,
        details: formData.itProcessing.remarks || `Forms ${formData.itProcessing.action} by ${formData.itProcessing.processedBy}`
      });
    }

    if (formData.status === 'IT Completed' && formData.certificates) {
      timeline.push({
        step: 'certificates_generated',
        title: 'Certificates Generated',
        date: formData.itProcessing?.processedAt || new Date().toISOString(),
        status: 'completed',
        details: `${formData.certificates.length} digital certificates generated and ready for download`
      });
    }

    return timeline.sort((a, b) => new Date(a.date) - new Date(b.date));
  }

  static getFormsCompletionStatus(formData) {
    if (!formData.assignedForms) return [];

    return formData.assignedForms.map(form => {
      let isCompleted = false;
      let formKey = '';

      const formMappings = {
        'Disposal Form': 'disposalFormData',
        'E-File': 'efileFormData',
        'Form 365 - Transfer': 'form365TransferData',
        'Form 365 - Disposal': 'form365Data'
      };

      formKey = formMappings[form.title];
      if (formKey && formData.formResponses && formData.formResponses[formKey]) {
        isCompleted = true;
      }

      return {
        title: form.title,
        path: form.path,
        status: isCompleted ? 'completed' : 'pending',
        lastUpdated: formData.lastUpdated,
        dataKey: formKey,
        hasData: isCompleted
      };
    });
  }
}

// =========================================
//  API ENDPOINTS
// =========================================

// Enhanced OTP verification with rate limiting
router.post('/verify-otp',
  roleAuth('employee'),
  auditMiddleware('OTP_VERIFY_ATTEMPT'),
  asyncHandler(async (req, res) => {
    const { otp } = req.body;

    if (!otp || typeof otp !== 'string') {
      return res.status(400).json(createErrorResponse('OTP is required', 'MISSING_OTP', 400));
    }

    // In production, implement proper OTP verification logic
    const isValid = otp === '123456'; // Replace with actual verification

    if (isValid) {
      logger.audit('OTP_VERIFY_SUCCESS', req.session.user.id, { ip: req.ip });
    } else {
      logger.audit('OTP_VERIFY_FAILED', req.session.user.id, { ip: req.ip, attemptedOTP: otp });
    }

    res.json({
      success: isValid,
      message: isValid ? 'OTP verified successfully' : 'Invalid OTP',
      timestamp: new Date().toISOString()
    });
  })
);

// Enhanced form submission with comprehensive validation
router.post('/submit-no-dues',
  roleAuth('employee'),
  upload.single('orderLetter'),
  validateRequest(schemas.noDuesSubmission),
  auditMiddleware('FORM_SUBMIT_ATTEMPT'),
  asyncHandler(async (req, res) => {
    const sessionUser = req.session.user;
    const employeeId = sessionUser.id || sessionUser.employeeId;

    if (!req.file) {
      return res.status(400).json(createErrorResponse('Order letter file is required', 'MISSING_FILE', 400));
    }

    // Load and validate existing forms
    const pendingForms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);

    // Check for existing active applications
    const existingForm = FormHelpers.getLatestFormForEmployee(pendingForms, employeeId, CONFIG.STATUS.ACTIVE);

    if (existingForm) {
      return res.status(409).json(createErrorResponse(
        `You already have a ${existingForm.status} application (${existingForm.formId})`,
        'DUPLICATE_APPLICATION',
        409,
        { existingFormId: existingForm.formId, existingStatus: existingForm.status }
      ));
    }

    // Create new form with enhanced data
    const formId = `F${Date.now()}_${Math.random().toString(36).substring(2, 8).toUpperCase()}`;
    const newForm = {
      formId,
      name: req.body.name,
      employeeName: req.body.name,
      employeeId,
      email: req.body.email,
      department: req.body.department,
      noDuesType: req.body.noDuesType,
      reason: req.body.reason || '',
      orderLetter: req.file.filename,
      orderLetterPath: req.file.path,
      status: 'pending',
      submissionDate: new Date().toISOString(),
      submittedBy: employeeId,
      lastUpdated: new Date().toISOString(),
      submissionIP: req.ip,
      userAgent: req.get('User-Agent'),
      assignedForms: [],
      formResponses: {},
      remark: '',
      version: '1.0'
    };

    pendingForms.push(newForm);
    await DataAccessLayer.safeWriteJSON(CONFIG.FILES.PENDING_FORMS, pendingForms);

    // Update session
    req.session.user.formId = formId;
    req.session.user.applicationStatus = 'pending';

    logger.audit('FORM_SUBMIT_SUCCESS', employeeId, {
      formId,
      noDuesType: req.body.noDuesType,
      fileName: req.file.filename
    });

    res.status(201).json({
      success: true,
      message: 'Application submitted successfully',
      formId,
      status: 'pending',
      submissionDate: newForm.submissionDate,
      timestamp: new Date().toISOString()
    });
  })
);

// Enhanced previous application check
router.get('/previous-application',
  roleAuth('employee'),
  asyncHandler(async (req, res) => {
    const sessionUser = req.session.user;
    const employeeId = sessionUser.id || sessionUser.employeeId;

    const pendingForms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    const latestApp = FormHelpers.getLatestFormForEmployee(pendingForms, employeeId);

    if (!latestApp) {
      return res.json({
        success: true,
        hasApplication: false,
        message: 'No previous applications found'
      });
    }

    // Sanitize sensitive data before sending
    const sanitizedApp = {
      formId: latestApp.formId,
      status: latestApp.status,
      submissionDate: latestApp.submissionDate,
      lastUpdated: latestApp.lastUpdated,
      noDuesType: latestApp.noDuesType,
      department: latestApp.department
    };

    res.json({
      success: true,
      hasApplication: true,
      application: sanitizedApp
    });
  })
);

// Enhanced tracking with comprehensive data
router.get('/tracking-details',
  roleAuth('employee'),
  asyncHandler(async (req, res) => {
    const sessionUser = req.session.user;
    const employeeId = sessionUser.id || sessionUser.employeeId;

    const formsData = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    const employeeForm = FormHelpers.getLatestFormForEmployee(formsData, employeeId);

    if (!employeeForm) {
      return res.json({
        success: true,
        hasApplication: false,
        status: 'Not Submitted',
        timeline: [],
        forms: [],
        message: 'No application found for this employee'
      });
    }

    // Update session formId
    if (req.session.user.formId !== employeeForm.formId) {
      req.session.user.formId = employeeForm.formId;
    }

    const timeline = FormHelpers.buildTimelineData(employeeForm);
    const formsStatus = FormHelpers.getFormsCompletionStatus(employeeForm);

    logger.info(`Tracking details accessed`, {
      employeeId,
      formId: employeeForm.formId,
      timelineEvents: timeline.length,
      formsCount: formsStatus.length
    });

    res.json({
      success: true,
      hasApplication: true,
      formId: employeeForm.formId,
      status: employeeForm.status,
      timeline,
      forms: formsStatus,
      hodApproval: employeeForm.hodApproval || null,
      itProcessing: employeeForm.itProcessing || null,
      lastUpdated: employeeForm.lastUpdated,
      submissionDate: employeeForm.submissionDate,
      noDuesType: employeeForm.noDuesType,
      metadata: {
        version: employeeForm.version || '1.0',
        lastAccessed: new Date().toISOString()
      }
    });
  })
);

// Enhanced form data saving with validation
const createSaveHandler = (reqKey, storageKey) => {
  return asyncHandler(async (req, res) => {
    const sessionUser = req.session.user;
    const employeeId = sessionUser.id || sessionUser.employeeId;

    const allForms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    const latestForm = FormHelpers.getLatestFormForEmployee(allForms, employeeId);
    const formIndex = latestForm ? allForms.findIndex(f => f.formId === latestForm.formId) : -1;

    if (formIndex === -1) {
      return res.status(404).json(createErrorResponse(
        'No pending form found for this employee. Please submit initial application first.',
        'NO_PENDING_FORM',
        404
      ));
    }

    // Update session formId
    if (req.session.user.formId !== latestForm.formId) {
      req.session.user.formId = latestForm.formId;
    }

    const inputData = req.body[reqKey] || req.body;

    if (!inputData || typeof inputData !== 'object') {
      return res.status(400).json(createErrorResponse(
        `Invalid data format for ${storageKey}`,
        'INVALID_DATA_FORMAT',
        400
      ));
    }

    // Validate form data size and structure
    const dataString = JSON.stringify(inputData);
    if (dataString.length > 100000) { // 100KB limit
      return res.status(413).json(createErrorResponse(
        'Form data too large',
        'DATA_TOO_LARGE',
        413
      ));
    }

    // Initialize formResponses if not exists
    if (!allForms[formIndex].formResponses) {
      allForms[formIndex].formResponses = {};
    }

    allForms[formIndex].formResponses[storageKey] = inputData;
    allForms[formIndex].lastUpdated = new Date().toISOString();
    allForms[formIndex].version = (parseFloat(allForms[formIndex].version || '1.0') + 0.1).toFixed(1);

    await DataAccessLayer.safeWriteJSON(CONFIG.FILES.PENDING_FORMS, allForms);

    logger.audit('FORM_DATA_SAVED', employeeId, {
      formId: latestForm.formId,
      storageKey,
      dataSize: dataString.length,
      version: allForms[formIndex].version
    });

    res.json({
      success: true,
      message: `${storageKey} saved successfully`,
      formId: latestForm.formId,
      version: allForms[formIndex].version,
      savedAt: allForms[formIndex].lastUpdated,
      dataSize: dataString.length
    });
  });
};

// Enhanced save endpoints with audit logging
router.post('/save-disposal',
  roleAuth('employee'),
  validateRequest(schemas.formData),
  auditMiddleware('DISPOSAL_FORM_SAVE'),
  createSaveHandler('disposalForm', 'disposalFormData')
);

router.post('/save-efile',
  roleAuth('employee'),
  validateRequest(schemas.formData),
  auditMiddleware('EFILE_FORM_SAVE'),
  createSaveHandler('efileForm', 'efileFormData')
);

router.post('/save-form365-transfer',
  roleAuth('employee'),
  validateRequest(schemas.formData),
  auditMiddleware('FORM365_TRANSFER_SAVE'),
  createSaveHandler('form365Transfer', 'form365TransferData')
);

router.post('/save-form365-disposal',
  roleAuth('employee'),
  validateRequest(schemas.formData),
  auditMiddleware('FORM365_DISPOSAL_SAVE'),
  createSaveHandler('form365Disposal', 'form365Data')
);

// Enhanced final submission with comprehensive validation
router.post('/final-submit',
  roleAuth('employee'),
  auditMiddleware('FINAL_SUBMIT_ATTEMPT'),
  asyncHandler(async (req, res) => {
    const sessionUser = req.session.user;
    const employeeId = sessionUser.id || sessionUser.employeeId;
    const { disposalForm, efileForm, form365Transfer, form365Disposal } = req.body;

    // Comprehensive validation
    if (!disposalForm || typeof disposalForm !== 'object') {
      return res.status(400).json(createErrorResponse('Valid disposal form data is required', 'MISSING_DISPOSAL_DATA', 400));
    }

    if (!efileForm || typeof efileForm !== 'object') {
      return res.status(400).json(createErrorResponse('Valid e-file form data is required', 'MISSING_EFILE_DATA', 400));
    }

    if ((!form365Transfer || typeof form365Transfer !== 'object') &&
      (!form365Disposal || typeof form365Disposal !== 'object')) {
      return res.status(400).json(createErrorResponse('Valid Form 365 (Transfer or Disposal) data is required', 'MISSING_FORM365_DATA', 400));
    }

    const pendingForms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    const latestForm = FormHelpers.getLatestFormForEmployee(pendingForms, employeeId);
    const formIndex = latestForm ? pendingForms.findIndex(f => f.formId === latestForm.formId) : -1;

    if (formIndex === -1) {
      return res.status(404).json(createErrorResponse('No pending form found for this employee', 'NO_PENDING_FORM', 404));
    }

    const form = pendingForms[formIndex];

    // Initialize form responses if not exists
    if (!form.formResponses) {
      form.formResponses = {};
    }

    // Save all form data
    form.formResponses.disposalFormData = disposalForm;
    form.formResponses.efileFormData = efileForm;

    if (form365Transfer && typeof form365Transfer === 'object') {
      form.formResponses.form365TransferData = form365Transfer;
    }
    if (form365Disposal && typeof form365Disposal === 'object') {
      form.formResponses.form365Data = form365Disposal;
    }

    // Update form status and metadata
    form.status = 'Submitted to HOD';
    form.finalSubmittedAt = new Date().toISOString();
    form.lastUpdated = new Date().toISOString();
    form.version = (parseFloat(form.version || '1.0') + 0.1).toFixed(1);
    form.submissionIP = req.ip;

    pendingForms[formIndex] = form;

    // Update session
    if (req.session.user.formId !== form.formId) {
      req.session.user.formId = form.formId;
    }

    await DataAccessLayer.safeWriteJSON(CONFIG.FILES.PENDING_FORMS, pendingForms);

    logger.audit('FINAL_SUBMIT_SUCCESS', employeeId, {
      formId: form.formId,
      formsSubmitted: Object.keys(form.formResponses).length,
      version: form.version
    });

    res.json({
      success: true,
      message: 'Forms submitted to HOD for review',
      formId: form.formId,
      status: 'Submitted to HOD',
      submittedAt: form.finalSubmittedAt,
      version: form.version
    });
  })
);

// Enhanced certificate management with history support
router.get('/certificates',
  roleAuth('employee'),
  asyncHandler(async (req, res) => {
    const sessionUser = req.session.user;
    const employeeId = sessionUser.id || sessionUser.employeeId;

    let allCertificates = [];

    // Get active certificates
    const activeCerts = await DataAccessLayer.safeReadJSON(CONFIG.FILES.CERTIFICATES);
    activeCerts.filter(cert => cert.employeeId === employeeId)
      .forEach(cert => {
        allCertificates.push({
          ...cert,
          source: 'active',
          displayName: getFormDisplayName(cert.formType),
          status: 'Active'
        });
      });

    // Get historical certificates
    const historyData = await DataAccessLayer.safeReadJSON(CONFIG.FILES.FORM_HISTORY);
    historyData.filter(h => h.employeeId === employeeId && h.preservedData?.certificates)
      .forEach(historyEntry => {
        if (historyEntry.preservedData.certificates) {
          historyEntry.preservedData.certificates.forEach(cert => {
            allCertificates.push({
              id: `hist_${historyEntry.formId}_${cert.formType}`,
              formId: historyEntry.formId,
              formType: cert.formType,
              filename: cert.filename,
              displayName: getFormDisplayName(cert.formType),
              generatedAt: cert.generatedAt,
              employeeName: historyEntry.employeeName || historyEntry.name,
              noDuesType: historyEntry.noDuesType,
              source: 'history',
              status: 'Completed',
              completedAt: historyEntry.completedAt,
              filepath: cert.filepath
            });
          });
        }
      });

    // Sort by generation date (newest first)
    allCertificates.sort((a, b) => new Date(b.generatedAt || b.completedAt) - new Date(a.generatedAt || a.completedAt));

    logger.info(`Certificate list accessed`, {
      employeeId,
      totalCertificates: allCertificates.length,
      activeCertificates: allCertificates.filter(c => c.source === 'active').length,
      historicalCertificates: allCertificates.filter(c => c.source === 'history').length
    });

    res.json({
      success: true,
      certificates: allCertificates,
      summary: {
        total: allCertificates.length,
        active: allCertificates.filter(c => c.source === 'active').length,
        historical: allCertificates.filter(c => c.source === 'history').length
      }
    });
  })
);

// Enhanced certificate download with security checks
router.get('/certificates/:certId/download',
  roleAuth('employee'),
  auditMiddleware('CERTIFICATE_DOWNLOAD'),
  asyncHandler(async (req, res) => {
    const { certId } = req.params;
    const sessionUser = req.session.user;
    const employeeId = sessionUser.id || sessionUser.employeeId;

    let certificate = null;

    // Check active certificates
    const activeCerts = await DataAccessLayer.safeReadJSON(CONFIG.FILES.CERTIFICATES);
    certificate = activeCerts.find(cert => cert.id === certId && cert.employeeId === employeeId);

    // Check historical certificates if not found
    if (!certificate && certId.startsWith('hist_')) {
      const historyData = await DataAccessLayer.safeReadJSON(CONFIG.FILES.FORM_HISTORY);

      for (const historyEntry of historyData) {
        if (historyEntry.employeeId === employeeId && historyEntry.preservedData?.certificates) {
          for (const cert of historyEntry.preservedData.certificates) {
            const historicalCertId = `hist_${historyEntry.formId}_${cert.formType}`;
            if (historicalCertId === certId) {
              certificate = {
                ...cert,
                id: historicalCertId,
                employeeId: historyEntry.employeeId,
                source: 'history'
              };
              break;
            }
          }
        }
        if (certificate) break;
      }
    }

    if (!certificate) {
      return res.status(404).json(createErrorResponse('Certificate not found', 'CERTIFICATE_NOT_FOUND', 404));
    }

    DataAccessLayer.validateEmployeeAccess(employeeId, certificate);

    const filePath = certificate.filepath;

    if (!fs.existsSync(filePath)) {
      logger.error(`Certificate file not found on disk`, {
        filePath,
        certId,
        employeeId
      });
      return res.status(404).json(createErrorResponse('Certificate file not found on server', 'FILE_NOT_FOUND', 404));
    }

    logger.audit('CERTIFICATE_DOWNLOAD_SUCCESS', employeeId, {
      certId,
      filename: certificate.filename,
      source: certificate.source || 'active',
      fileSize: fs.statSync(filePath).size
    });

    // Set security headers for file download
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${certificate.filename}"`);
    res.setHeader('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    res.setHeader('X-Content-Type-Options', 'nosniff');

    const fileStream = fs.createReadStream(filePath);

    fileStream.on('error', (error) => {
      logger.error('Certificate file streaming error', error, {
        filePath,
        certId,
        employeeId
      });
      if (!res.headersSent) {
        res.status(500).json(createErrorResponse('Error streaming certificate file', 'STREAM_ERROR', 500));
      }
    });

    fileStream.pipe(res);
  })
);

// Enhanced dashboard status with comprehensive data
router.get('/dashboard-status',
  roleAuth('employee'),
  asyncHandler(async (req, res) => {
    const sessionUser = req.session.user;
    const employeeId = sessionUser.id || sessionUser.employeeId;
    const { name, role } = sessionUser;

    const pendingForms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    const form = FormHelpers.getLatestFormForEmployee(pendingForms, employeeId);

    // Update session formId
    if (form && req.session.user.formId !== form.formId) {
      req.session.user.formId = form.formId;
    }

    // Get comprehensive certificate count
    let allCertificates = [];

    const certData = await DataAccessLayer.safeReadJSON(CONFIG.FILES.CERTIFICATES);
    allCertificates = [...allCertificates, ...certData.filter(cert => cert.employeeId === employeeId)];

    const historyData = await DataAccessLayer.safeReadJSON(CONFIG.FILES.FORM_HISTORY);
    const historicalCertificates = historyData
      .filter(h => h.employeeId === employeeId && h.preservedData?.certificates)
      .flatMap(h => h.preservedData.certificates || []);
    allCertificates = [...allCertificates, ...historicalCertificates];

    const certificateCount = allCertificates.length;

    // Handle rejection status
    if (form && form.status && form.status.toLowerCase().includes('rejected')) {
      return res.json({
        success: true,
        employee: {
          name: form?.name || name || 'Unknown',
          employeeId: employeeId || 'Unknown',
          department: form?.department || '-',
          role: role || 'employee'
        },
        status: { latestStatus: 'rejected' },
        formId: null,
        applicationStatus: 'rejected',
        rejectionReason: form.rejectionReason || 'No reason given',
        rejectedAt: form.rejectedAt || null,
        lastUpdated: form?.lastUpdated || null,
        certificatesAvailable: certificateCount,
        canSubmitNew: true,
        sessionCleanup: !!sessionUser.cleanupPerformed,
        metadata: {
          lastAccessed: new Date().toISOString(),
          version: form?.version || '1.0'
        }
      });
    }

    res.json({
      success: true,
      employee: {
        name: form?.name || name || 'Unknown',
        employeeId: employeeId || 'Unknown',
        department: form?.department || '-',
        role: role || 'employee'
      },
      status: {
        latestStatus: form?.status || 'Not Submitted'
      },
      formId: form?.formId || null,
      applicationStatus: form?.status || 'Not Submitted',
      lastUpdated: form?.lastUpdated || null,
      certificatesAvailable: certificateCount,
      sessionCleanup: !!sessionUser.cleanupPerformed,
      metadata: {
        lastAccessed: new Date().toISOString(),
        version: form?.version || '1.0',
        hasActiveForm: !!form
      }
    });
  })
);

// Enhanced assigned forms with security improvements
router.get('/assigned-forms',
  roleAuth('employee'),
  asyncHandler(async (req, res) => {
    const sessionUser = req.session.user;
    const employeeId = sessionUser.id || sessionUser.employeeId;

    const allForms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);

    logger.info(`Assigned forms check for employee ${employeeId}`, {
      totalFormsInSystem: allForms.length,
      employeeForms: allForms.filter(f => f && f.employeeId === employeeId).length
    });

    // Filter only NON-COMPLETED forms for assigned forms display
    const allowedStatuses = ['approved', 'Submitted to HOD', 'pending', 'Pending'];
    const myForms = allForms.filter(f => {
      return f &&
        f.employeeId === employeeId &&
        f.status &&
        allowedStatuses.includes(f.status);
    });

    if (myForms.length === 0) {
      return res.json({
        success: true,
        assignedForms: [],
        assignedFormsCount: 0,
        applicationStatus: "Not Submitted",
        formId: null
      });
    }

    // Get latest non-completed form
    const myForm = myForms.sort((a, b) => {
      const dateA = new Date(a.submissionDate || a.lastUpdated || 0);
      const dateB = new Date(b.submissionDate || b.lastUpdated || 0);
      return dateB - dateA;
    })[0];

    // Update session formId
    if (req.session.user.formId !== myForm.formId) {
      req.session.user.formId = myForm.formId;
    }

    if (myForm.status && myForm.status.toLowerCase().includes('rejected')) {
      return res.json({
        success: true,
        assignedForms: [],
        assignedFormsCount: 0,
        applicationStatus: 'rejected',
        rejectionReason: myForm.rejectionReason || "",
        formId: null,
        canSubmitNew: true
      });
    }

    logger.info(`Selected form for ${employeeId}`, {
      formId: myForm.formId,
      status: myForm.status,
      assignedFormsCount: myForm.assignedForms?.length || 0
    });

    return res.json({
      success: true,
      formId: myForm.formId,
      applicationStatus: myForm.status,
      assignedFormsCount: myForm.assignedForms?.length || 0,
      assignedForms: myForm.assignedForms || [],
      metadata: {
        version: myForm.version || '1.0',
        lastUpdated: myForm.lastUpdated
      }
    });
  })
);

// Enhanced form data retrieval with validation
router.get('/form-data',
  roleAuth('employee'),
  asyncHandler(async (req, res) => {
    const sessionUser = req.session.user;
    const employeeId = sessionUser.id || sessionUser.employeeId;
    const { formName } = req.query;

    if (!formName || typeof formName !== 'string') {
      return res.status(400).json(createErrorResponse('Missing or invalid formName in query', 'MISSING_FORM_NAME', 400));
    }

    const pendingForms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    const formEntry = FormHelpers.getLatestFormForEmployee(pendingForms, employeeId);

    // Update session formId
    if (formEntry && req.session.user.formId !== formEntry.formId) {
      req.session.user.formId = formEntry.formId;
    }

    if (!formEntry) {
      return res.status(404).json(createErrorResponse('No pending form found', 'NO_PENDING_FORM', 404));
    }

    DataAccessLayer.validateEmployeeAccess(employeeId, formEntry);

    const formMap = {
      disposalForm: 'disposalFormData',
      efileForm: 'efileFormData',
      form365Transfer: 'form365TransferData',
      form365Disposal: 'form365Data'
    };

    const formKey = formMap[formName];
    if (!formKey) {
      return res.status(400).json(createErrorResponse(`Invalid formName: ${formName}`, 'INVALID_FORM_NAME', 400));
    }

    const formData = formEntry.formResponses?.[formKey] || null;

    logger.info(`Form data retrieved`, {
      employeeId,
      formName,
      formId: formEntry.formId,
      hasData: !!formData
    });

    res.json({
      success: true,
      formData,
      hasData: !!formData,
      metadata: {
        formId: formEntry.formId,
        lastUpdated: formEntry.lastUpdated,
        version: formEntry.version || '1.0'
      }
    });
  })
);

// Enhanced form status endpoint
router.get('/form-status',
  roleAuth('employee'),
  asyncHandler(async (req, res) => {
    const sessionUser = req.session.user;
    const employeeId = sessionUser.id || sessionUser.employeeId;

    const pendingForms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    const form = FormHelpers.getLatestFormForEmployee(pendingForms, employeeId);

    if (!form) {
      return res.json({
        success: true,
        status: 'pending',
        context: { message: 'No active form found' }
      });
    }

    res.json({
      success: true,
      status: form.status,
      context: {
        formId: form.formId,
        lastUpdated: form.lastUpdated,
        rejectionReason: form.rejectionReason,
        version: form.version || '1.0'
      }
    });
  })
);

// Enhanced tracking endpoint
router.get('/track',
  roleAuth('employee'),
  asyncHandler(async (req, res) => {
    const sessionUser = req.session.user;
    const employeeId = sessionUser.id || sessionUser.employeeId;

    const pendingForms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);

    // Get all forms for employee, sorted by latest first
    const myForms = pendingForms
      .filter(f => f && f.employeeId === employeeId)
      .sort((a, b) => new Date(b.submissionDate || b.lastUpdated) - new Date(a.submissionDate || a.lastUpdated))
      .map(f => ({
        // Sanitize sensitive data
        formId: f.formId,
        status: f.status,
        submissionDate: f.submissionDate,
        lastUpdated: f.lastUpdated,
        noDuesType: f.noDuesType,
        department: f.department,
        version: f.version || '1.0'
      }));

    res.json({
      success: true,
      forms: myForms,
      summary: {
        total: myForms.length,
        active: myForms.filter(f => CONFIG.STATUS.ACTIVE.includes(f.status)).length,
        completed: myForms.filter(f => CONFIG.STATUS.COMPLETED.includes(f.status)).length,
        rejected: myForms.filter(f => CONFIG.STATUS.REJECTED.includes(f.status)).length
      }
    });
  })
);

// Enhanced history with comprehensive data
router.get('/history',
  roleAuth('employee'),
  asyncHandler(async (req, res) => {
    const sessionUser = req.session.user;
    const employeeId = sessionUser.id || sessionUser.employeeId;

    const history = await DataAccessLayer.safeReadJSON(CONFIG.FILES.FORM_HISTORY);

    const myHistory = history
      .filter(f => f && f.employeeId === employeeId)
      .map(form => ({
        ...form,
        historyInfo: {
          type: form.historyType || 'completed_application',
          completedAt: form.completedAt,
          finalStatus: form.finalStatus,
          hadCertificates: !!(form.preservedData?.certificates?.length > 0),
          certificateCount: form.preservedData?.certificates?.length || 0,
          hadHODApproval: !!form.preservedData?.hodApproval,
          hadITProcessing: !!form.preservedData?.itProcessing,
          assignedFormsCount: form.preservedData?.assignedForms?.length || 0
        }
      }))
      .sort((a, b) => new Date(b.completedAt || b.submissionDate || b.lastUpdated) - new Date(a.completedAt || a.submissionDate || a.lastUpdated));

    const summary = {
      totalApplications: myHistory.length,
      totalCertificates: myHistory.reduce((sum, h) => sum + (h.historyInfo.certificateCount || 0), 0),
      completedApplications: myHistory.filter(h => h.finalStatus === 'IT Completed').length,
      rejectedApplications: myHistory.filter(h => h.finalStatus && h.finalStatus.toLowerCase().includes('rejected')).length
    };

    res.json({
      success: true,
      history: myHistory,
      summary
    });
  })
);

// Enhanced confirmation endpoint
router.get('/confirmation',
  roleAuth('employee'),
  asyncHandler(async (req, res) => {
    const sessionUser = req.session.user;
    const employeeId = sessionUser.id || sessionUser.employeeId;

    const pendingForms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    const form = FormHelpers.getLatestFormForEmployee(pendingForms, employeeId);

    // Update session formId
    if (form && req.session.user.formId !== form.formId) {
      req.session.user.formId = form.formId;
    }

    if (!form) {
      return res.status(404).json(createErrorResponse('Form not found', 'FORM_NOT_FOUND', 404));
    }

    DataAccessLayer.validateEmployeeAccess(employeeId, form);

    // Sanitize form data before sending
    const sanitizedForm = {
      formId: form.formId,
      status: form.status,
      submissionDate: form.submissionDate,
      lastUpdated: form.lastUpdated,
      noDuesType: form.noDuesType,
      department: form.department,
      name: form.name,
      version: form.version || '1.0'
    };

    res.json({
      success: true,
      data: sanitizedForm
    });
  })
);

// Enhanced PDF download with security
router.get('/form-pdf/:formId',
  roleAuth('employee'),
  auditMiddleware('PDF_DOWNLOAD'),
  asyncHandler(async (req, res) => {
    const { formId } = req.params;
    const sessionUser = req.session.user;
    const employeeId = sessionUser.id || sessionUser.employeeId;

    // Validate formId format
    if (!/^F\d+_[A-Z0-9]{6}$/.test(formId)) {
      return res.status(400).json(createErrorResponse('Invalid form ID format', 'INVALID_FORM_ID', 400));
    }

    // Verify form ownership
    const pendingForms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    const form = pendingForms.find(f => f.formId === formId && f.employeeId === employeeId);

    if (!form) {
      return res.status(404).json(createErrorResponse('Form not found or access denied', 'FORM_NOT_FOUND', 404));
    }

    const pdfPath = path.join(__dirname, '../public/forms/sample_form.pdf');

    if (!fs.existsSync(pdfPath)) {
      return res.status(404).json(createErrorResponse('PDF file not found', 'PDF_NOT_FOUND', 404));
    }

    logger.audit('PDF_DOWNLOAD_SUCCESS', employeeId, {
      formId,
      pdfPath: path.basename(pdfPath)
    });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="form_${formId}.pdf"`);
    res.setHeader('Cache-Control', 'private, no-cache');

    res.sendFile(pdfPath, (err) => {
      if (err) {
        logger.error('PDF send error', err, { formId, employeeId });
        if (!res.headersSent) {
          res.status(500).json(createErrorResponse('Error sending PDF', 'PDF_SEND_ERROR', 500));
        }
      }
    });
  })
);

// Enhanced employee info with validation
router.get('/employee-info',
  roleAuth('employee'),
  asyncHandler(async (req, res) => {
    const sessionUser = req.session.user;
    const employeeId = sessionUser.id || sessionUser.employeeId;

    const users = await DataAccessLayer.safeReadJSON(CONFIG.FILES.USERS);
    const employee = users.find(u => u && (u.employeeId === employeeId || u.id === employeeId));

    if (!employee) {
      return res.status(404).json(createErrorResponse('Employee not found', 'EMPLOYEE_NOT_FOUND', 404));
    }

    res.json({
      success: true,
      employee: {
        name: employee.name || 'Unknown',
        employeeId: employee.employeeId || employee.id || 'Unknown',
        department: employee.department || 'Unknown',
        email: employee.email || '',
        role: employee.role || 'employee'
      }
    });
  })
);

// =========================================
//  ERROR HANDLING MIDDLEWARE
// =========================================

// Global error handler for this router
router.use((error, req, res, next) => {
  logger.error('Unhandled route error', error, {
    path: req.path,
    method: req.method,
    userId: req.session?.user?.id,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  if (error.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json(createErrorResponse('File too large', 'FILE_TOO_LARGE', 413));
  }

  if (error.code === 'LIMIT_UNEXPECTED_FILE') {
    return res.status(400).json(createErrorResponse('Unexpected file upload', 'UNEXPECTED_FILE', 400));
  }

  if (!res.headersSent) {
    res.status(500).json(createErrorResponse(
      process.env.NODE_ENV === 'production' ? 'Internal server error' : error.message,
      'INTERNAL_ERROR',
      500,
      process.env.NODE_ENV === 'development' ? error.stack : null
    ));
  }
});

// Health check endpoint for this router
router.get('/health', (req, res) => {
  res.json({
    success: true,
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    version: '2.0.0'
  });
});

module.exports = router;
