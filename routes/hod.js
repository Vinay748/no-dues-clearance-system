const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const Joi = require('joi');
const { loadJSON, saveJSON } = require('../utils/fileUtils');
const { roleAuth } = require('../middlewares/sessionAuth');

const router = express.Router();

// =========================================
// PRODUCTION SECURITY MIDDLEWARE
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

// Rate limiting for different operations
const hodRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per IP per windowMs
  message: { success: false, message: 'Too many requests. Please try again later.', code: 'RATE_LIMITED' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for HOD operation`, {
      ip: req.ip,
      path: req.path,
      userId: req.session?.user?.id
    });
    res.status(429).json({
      success: false,
      message: 'Too many requests. Please try again later.',
      code: 'RATE_LIMITED',
      retryAfter: Math.ceil(res.getHeader('Retry-After'))
    });
  }
});

// Stricter rate limiting for file uploads
const uploadRateLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10, // 10 uploads per 5 minutes
  message: { success: false, message: 'Too many upload attempts. Please try again later.', code: 'UPLOAD_RATE_LIMITED' }
});

// Apply rate limiting
router.use(hodRateLimiter);
router.use('/upload-signature', uploadRateLimiter);

// =========================================
// PRODUCTION LOGGING & MONITORING
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
    sessionId: req.session?.id,
    hodId: req.session?.user?.hodId
  });
  
  next();
};

// =========================================
// PRODUCTION DATA VALIDATION
// =========================================

const schemas = {
  formApproval: Joi.object({
    formId: Joi.string().pattern(/^F\d+_[A-Z0-9]{6}$/).required(),
    action: Joi.string().valid('approved', 'approve', 'rejected', 'reject').required(),
    remarks: Joi.string().max(1000).optional().allow('')
  }),
  
  finalApproval: Joi.object({
    formId: Joi.string().pattern(/^F\d+_[A-Z0-9]{6}$/).required(),
    formResponses: Joi.alternatives().try(
      Joi.string().max(100000), // JSON string
      Joi.object().max(50) // Direct object
    ).required(),
    action: Joi.string().valid('approved', 'approve').optional(),
    remarks: Joi.string().max(1000).optional().allow('')
  })
};

// Validation middleware
const validateRequest = (schema) => (req, res, next) => {
  const { error, value } = schema.validate(req.body, { abortEarly: false, stripUnknown: true });
  
  if (error) {
    logger.warn('HOD request validation failed', {
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
  
  req.body = value;
  next();
};

// =========================================
// PRODUCTION FILE HANDLING
// =========================================

// Enhanced multer configuration for signature uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../uploads/signatures');
    
    // Ensure upload directory exists
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true, mode: 0o755 });
    }
    
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Sanitize filename and add HOD identifier
    const hodId = req.session?.user?.hodId || 'unknown';
    const timestamp = Date.now();
    const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    const uniqueName = `hod_${hodId}_${timestamp}_${sanitizedName}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB max
    files: 1
  },
  fileFilter: (req, file, cb) => {
    // Allow only image files for signatures
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif'];
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif'];
    
    const isValidType = allowedTypes.includes(file.mimetype);
    const isValidExtension = allowedExtensions.includes(path.extname(file.originalname).toLowerCase());
    
    if (isValidType && isValidExtension) {
      cb(null, true);
    } else {
      logger.warn('Invalid signature file type attempted', {
        mimetype: file.mimetype,
        originalname: file.originalname,
        userId: req.session?.user?.id,
        ip: req.ip
      });
      cb(new Error('Only image files (JPG, PNG, GIF) are allowed for signatures'), false);
    }
  }
});

// =========================================
// PRODUCTION ERROR HANDLING
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
// PRODUCTION DATA ACCESS LAYER
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

  static validateHODAccess(hodId, formData) {
    // Add any specific HOD access validation logic here
    if (!hodId) {
      throw new Error('HOD ID is required for access validation');
    }
  }
}

// =========================================
// PRODUCTION CONSTANTS & CONFIG
// =========================================

const CONFIG = {
  FILES: {
    PENDING_FORMS: './data/pending_forms.json',
    HOD_SIGNATURES: './data/hod_signatures.json'
  },
  STATUS: {
    SUBMITTED_TO_HOD: 'Submitted to HOD',
    SUBMITTED_TO_IT: 'Submitted to IT',
    REJECTED: 'rejected',
    APPROVED: 'approved'
  },
  SIGNATURE: {
    MAX_SIZE: 5 * 1024 * 1024, // 5MB
    ALLOWED_TYPES: ['image/jpeg', 'image/jpg', 'image/png', 'image/gif'],
    UPLOAD_DIR: 'uploads/signatures'
  }
};

// =========================================
// PRODUCTION HELPER FUNCTIONS
// =========================================

class HODHelpers {
  static getLatestFormForEmployee(allForms, employeeId, allowedStatuses = []) {
    let forms = allForms.filter(f => f && f.employeeId === employeeId);
    if (allowedStatuses.length) {
      forms = forms.filter(f => allowedStatuses.includes(f.status));
    }
    return forms.sort((a, b) => new Date(b.submissionDate || b.lastUpdated) - new Date(a.submissionDate || a.lastUpdated))[0] || null;
  }

  static validateFormForApproval(form, requiredForms) {
    for (const formKey of requiredForms) {
      const formData = form.formResponses?.[formKey];
      if (!formData || Object.keys(formData).length === 0) {
        throw new Error(`Missing or empty ${formKey} data`);
      }
    }
  }

  static createHODActionData(sessionUser, action, remarks, req) {
    return {
      actionBy: sessionUser.name,
      actionEmployeeId: sessionUser.employeeId || sessionUser.id,
      actionEmail: sessionUser.email,
      actionDepartment: sessionUser.department || 'Academic Department',
      actionDesignation: sessionUser.designation || 'HOD',
      actionAt: new Date().toISOString(),
      action,
      remarks: remarks || '',
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      hodDetails: {
        hodId: sessionUser.hodId,
        name: sessionUser.name,
        employeeId: sessionUser.employeeId || sessionUser.id,
        email: sessionUser.email,
        department: sessionUser.department,
        designation: sessionUser.designation || 'HOD'
      }
    };
  }

  static sanitizeFormForResponse(form) {
    // Remove sensitive internal data before sending to client
    const sanitized = { ...form };
    delete sanitized.internalNotes;
    delete sanitized.systemMetadata;
    return sanitized;
  }
}

// =========================================
// PRODUCTION API ENDPOINTS
// =========================================

// Enhanced HOD details endpoint with validation
router.get('/my-details', 
  roleAuth('hod'),
  auditMiddleware('HOD_DETAILS_ACCESS'),
  asyncHandler(async (req, res) => {
    const sessionUser = req.session?.user;

    if (!sessionUser || sessionUser.role !== 'hod') {
      return res.status(401).json(createErrorResponse('HOD authentication required', 'UNAUTHORIZED', 401));
    }

    logger.info(`HOD details provided for prefilling`, {
      hodId: sessionUser.hodId,
      name: sessionUser.name
    });

    res.json({
      success: true,
      hodDetails: {
        hodId: sessionUser.hodId,
        name: sessionUser.name,
        employeeId: sessionUser.employeeId || sessionUser.id,
        email: sessionUser.email,
        department: sessionUser.department || 'Academic Department',
        designation: sessionUser.designation || 'HOD',
        currentDate: new Date().toLocaleDateString('en-IN'),
        currentDateTime: new Date().toISOString()
      },
      timestamp: new Date().toISOString()
    });
  })
);

// Enhanced HOD profile endpoint
router.get('/profile',
  roleAuth('hod'),
  asyncHandler(async (req, res) => {
    const sessionUser = req.session?.user;
    
    if (!sessionUser) {
      return res.status(401).json(createErrorResponse('Session expired', 'SESSION_EXPIRED', 401));
    }

    res.json({
      success: true,
      hodData: {
        name: sessionUser.name,
        employeeId: sessionUser.employeeId || sessionUser.id,
        email: sessionUser.email,
        department: sessionUser.department,
        designation: sessionUser.designation || 'HOD',
        hodId: sessionUser.hodId
      },
      sessionInfo: {
        lastActivity: sessionUser.lastActivity,
        loginTime: sessionUser.loginTime
      }
    });
  })
);

// Enhanced signature retrieval with security checks
router.get('/get-signature',
  roleAuth('hod'),
  asyncHandler(async (req, res) => {
    const { id: hodId, name } = req.session.user;
    
    const signatures = await DataAccessLayer.safeReadJSON(CONFIG.FILES.HOD_SIGNATURES);
    const signature = signatures.find(s => s.hodId === hodId);
    
    if (!signature) {
      return res.status(404).json(createErrorResponse(
        'No signature found. Please upload a signature first.',
        'SIGNATURE_NOT_FOUND',
        404
      ));
    }

    // Verify file still exists
    const filePath = path.join(__dirname, `../${CONFIG.SIGNATURE.UPLOAD_DIR}`, signature.filename);
    if (!fs.existsSync(filePath)) {
      logger.error('Signature file missing from disk', {
        hodId,
        filename: signature.filename,
        expectedPath: filePath
      });
      return res.status(404).json(createErrorResponse(
        'Signature file not found on server. Please re-upload.',
        'SIGNATURE_FILE_MISSING',
        404
      ));
    }

    res.json({
      success: true,
      signature: signature.filename,
      signatureUrl: `/${CONFIG.SIGNATURE.UPLOAD_DIR}/${signature.filename}`,
      hodName: name,
      uploadedAt: signature.uploadedAt
    });
  })
);

// Enhanced form details route with comprehensive validation
router.get('/form-details',
  roleAuth('hod'),
  asyncHandler(async (req, res) => {
    const { formId } = req.query;
    
    if (!formId || typeof formId !== 'string') {
      return res.status(400).json(createErrorResponse('Missing or invalid formId', 'MISSING_FORM_ID', 400));
    }

    const pendingForms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    const form = pendingForms.find(f => f.formId === formId);
    const sessionUser = req.session?.user;

    if (!form) {
      logger.warn(`Form ${formId} not found`, { hodId: sessionUser.hodId });
      return res.status(404).json(createErrorResponse('Form not found', 'FORM_NOT_FOUND', 404));
    }

    logger.info(`Form details accessed`, {
      formId,
      status: form.status,
      hodId: sessionUser.hodId
    });

    const response = {
      success: true,
      form: {
        ...HODHelpers.sanitizeFormForResponse(form),
        hodDetails: {
          hodId: sessionUser.hodId,
          hodName: sessionUser.name,
          employeeId: sessionUser.employeeId || sessionUser.id,
          email: sessionUser.email,
          department: sessionUser.department,
          designation: sessionUser.designation || 'HOD',
          reviewDate: new Date().toISOString()
        }
      },
      formData: form.formResponses || {},
      disposalFormData: form.formResponses?.disposalFormData || form.formResponses?.disposalForm,
      efileFormData: form.formResponses?.efileFormData || form.formResponses?.efileForm,
      form365TransferData: form.formResponses?.form365TransferData || form.formResponses?.form365Transfer,
      form365Data: form.formResponses?.form365Data || form.formResponses?.form365Disposal
    };

    res.json(response);
  })
);

// Enhanced parameterized form details route
router.get('/form-details/:formId',
  roleAuth('hod'),
  asyncHandler(async (req, res) => {
    const { formId } = req.params;
    
    if (!formId || !/^F\d+_[A-Z0-9]{6}$/.test(formId)) {
      return res.status(400).json(createErrorResponse('Invalid form ID format', 'INVALID_FORM_ID', 400));
    }

    const pendingForms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    const form = pendingForms.find(f => f.formId === formId);
    const sessionUser = req.session?.user;

    if (!form) {
      return res.status(404).json(createErrorResponse('Form not found', 'FORM_NOT_FOUND', 404));
    }

    logger.info(`Detailed form access`, {
      formId,
      hodId: sessionUser.hodId,
      employeeId: form.employeeId
    });

    res.json({
      success: true,
      form: {
        ...HODHelpers.sanitizeFormForResponse(form),
        hodDetails: {
          hodId: sessionUser.hodId,
          hodName: sessionUser.name,
          employeeId: sessionUser.employeeId || sessionUser.id,
          email: sessionUser.email,
          department: sessionUser.department || 'Academic Department',
          designation: sessionUser.designation || 'HOD',
          reviewDate: new Date().toISOString()
        }
      },
      forms: form.formResponses || {},
      noDuesType: form.noDuesType || 'Transfer',
      employee: {
        name: form.employeeName || form.name,
        employeeId: form.employeeId,
        department: form.department
      },
      metadata: {
        accessedAt: new Date().toISOString(),
        version: form.version || '1.0'
      }
    });
  })
);

// Enhanced all forms endpoint with filtering and pagination
router.get('/all',
  roleAuth('hod'),
  asyncHandler(async (req, res) => {
    const { page = 1, limit = 50, status, department } = req.query;
    
    let allForms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    
    // Apply filters if provided
    if (status) {
      allForms = allForms.filter(f => f.status === status);
    }
    
    if (department) {
      allForms = allForms.filter(f => f.department === department);
    }
    
    // Sort by submission date (newest first)
    allForms.sort((a, b) => new Date(b.submissionDate || b.lastUpdated) - new Date(a.submissionDate || a.lastUpdated));
    
    // Apply pagination
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + parseInt(limit);
    const paginatedForms = allForms.slice(startIndex, endIndex);
    
    // Sanitize forms before sending
    const sanitizedForms = paginatedForms.map(form => HODHelpers.sanitizeFormForResponse(form));
    
    logger.info(`All forms accessed by HOD`, {
      hodId: req.session.user.hodId,
      totalForms: allForms.length,
      pageRequested: page,
      formsReturned: sanitizedForms.length,
      filters: { status, department }
    });
    
    res.json({
      success: true,
      data: sanitizedForms,
      pagination: {
        total: allForms.length,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(allForms.length / limit),
        hasNextPage: endIndex < allForms.length,
        hasPrevPage: page > 1
      },
      filters: { status, department }
    });
  })
);

// Enhanced pending forms endpoint
router.get('/pending',
  roleAuth('hod'),
  asyncHandler(async (req, res) => {
    const pendingForms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    const forms = pendingForms.filter(f => f.status === CONFIG.STATUS.SUBMITTED_TO_HOD);
    
    // Sort by submission date (oldest first for priority)
    forms.sort((a, b) => new Date(a.submissionDate || a.lastUpdated) - new Date(b.submissionDate || b.lastUpdated));
    
    const sanitizedForms = forms.map(form => HODHelpers.sanitizeFormForResponse(form));
    
    logger.info(`Pending forms accessed`, {
      hodId: req.session.user.hodId,
      pendingCount: forms.length
    });
    
    res.json({
      success: true,
      data: sanitizedForms,
      summary: {
        totalPending: forms.length,
        oldestPending: forms.length > 0 ? forms[0].submissionDate : null,
        newestPending: forms.length > 0 ? forms[forms.length - 1].submissionDate : null
      }
    });
  })
);

// Enhanced final approval with comprehensive validation
router.post('/final-approve',
  roleAuth('hod'),
  validateRequest(schemas.finalApproval),
  auditMiddleware('HOD_FINAL_APPROVAL'),
  asyncHandler(async (req, res) => {
    let { formId, formResponses, action, remarks } = req.body;
    
    // Parse formResponses if it's a string
    if (typeof formResponses === 'string') {
      try {
        formResponses = JSON.parse(formResponses);
      } catch (error) {
        return res.status(400).json(createErrorResponse(
          'Invalid JSON format in formResponses',
          'INVALID_JSON',
          400
        ));
      }
    }

    const forms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    const formIndex = forms.findIndex(f => f.formId === formId);
    
    if (formIndex === -1) {
      return res.status(404).json(createErrorResponse('Form not found', 'FORM_NOT_FOUND', 404));
    }

    const form = forms[formIndex];
    const sessionUser = req.session.user;

    // Validate form is in correct status
    if (form.status !== CONFIG.STATUS.SUBMITTED_TO_HOD) {
      return res.status(400).json(createErrorResponse(
        `Form is not in correct status for approval. Current status: ${form.status}`,
        'INVALID_FORM_STATUS',
        400
      ));
    }

    // Validate required forms are present and complete
    const requiredForms = ['disposalForm', 'efileForm'];
    const form365Key = formResponses.form365Trans ? 'form365Trans' : 'form365Disp';
    requiredForms.push(form365Key);

    try {
      for (const formKey of requiredForms) {
        const formData = formResponses[formKey];
        if (!formData || Object.keys(formData).length === 0) {
          return res.status(400).json(createErrorResponse(
            `Missing or empty ${formKey} data`,
            'MISSING_FORM_DATA',
            400
          ));
        }

        // Check for HOD sections
        const hasHodData = Object.keys(formData).some(key =>
          key.toLowerCase().includes('hod') ||
          key.includes('hodSignature') ||
          key.includes('hodName') ||
          key.includes('hodEmp')
        );

        if (!hasHodData) {
          return res.status(400).json(createErrorResponse(
            `HOD section not completed for ${formKey}`,
            'INCOMPLETE_HOD_SECTION',
            400
          ));
        }
      }
    } catch (validationError) {
      return res.status(400).json(createErrorResponse(
        validationError.message,
        'FORM_VALIDATION_ERROR',
        400
      ));
    }

    // Update form with approval data
    form.formResponses = formResponses;
    form.status = CONFIG.STATUS.SUBMITTED_TO_IT;
    form.lastUpdated = new Date().toISOString();
    form.version = (parseFloat(form.version || '1.0') + 0.1).toFixed(1);

    // Store comprehensive HOD approval data
    form.hodApproval = HODHelpers.createHODActionData(sessionUser, action || 'approved', remarks, req);
    form.hodApproval.completedForms = requiredForms;
    form.hodApproval.autoFilled = true;

    forms[formIndex] = form;
    await DataAccessLayer.safeWriteJSON(CONFIG.FILES.PENDING_FORMS, forms);

    logger.audit('FORM_FINAL_APPROVED', sessionUser.id, {
      formId,
      employeeId: form.employeeId,
      formsCompleted: requiredForms.length,
      version: form.version
    });

    res.json({
      success: true,
      message: 'Form approved and sent to IT',
      formId,
      status: CONFIG.STATUS.SUBMITTED_TO_IT,
      approvedAt: form.hodApproval.actionAt,
      hodData: {
        name: sessionUser.name,
        employeeId: sessionUser.employeeId || sessionUser.id,
        email: sessionUser.email,
        department: sessionUser.department,
        designation: sessionUser.designation || 'HOD'
      }
    });
  })
);

// Enhanced simple approval endpoint
router.post('/approve-form',
  roleAuth('hod'),
  validateRequest(schemas.formApproval),
  auditMiddleware('HOD_FORM_APPROVAL'),
  asyncHandler(async (req, res) => {
    const { formId, action, remarks } = req.body;
    const sessionUser = req.session?.user;

    const forms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    const formIndex = forms.findIndex(f => f.formId === formId);
    
    if (formIndex === -1) {
      return res.status(404).json(createErrorResponse('Form not found', 'FORM_NOT_FOUND', 404));
    }

    const form = forms[formIndex];

    // Validate form is in correct status
    if (form.status !== CONFIG.STATUS.SUBMITTED_TO_HOD) {
      return res.status(400).json(createErrorResponse(
        `Form is not in correct status for approval. Current status: ${form.status}`,
        'INVALID_FORM_STATUS',
        400
      ));
    }

    const hodActionData = HODHelpers.createHODActionData(sessionUser, action, remarks, req);

    if (action === 'approved' || action === 'approve') {
      form.status = CONFIG.STATUS.SUBMITTED_TO_IT;
      form.hodApproval = hodActionData;
      
      logger.audit('FORM_APPROVED', sessionUser.id, {
        formId,
        employeeId: form.employeeId,
        remarks: remarks || 'No remarks'
      });
      
    } else if (action === 'rejected' || action === 'reject') {
      form.status = CONFIG.STATUS.REJECTED;
      form.rejectionReason = remarks || 'No reason provided';
      form.rejectedAt = new Date().toISOString();
      form.rejectedBy = sessionUser.name;
      form.hodRejection = hodActionData;
      form.assignedForms = [];
      form.formResponses = {};
      
      logger.audit('FORM_REJECTED', sessionUser.id, {
        formId,
        employeeId: form.employeeId,
        reason: remarks || 'No reason provided'
      });
    }

    form.lastUpdated = new Date().toISOString();
    form.version = (parseFloat(form.version || '1.0') + 0.1).toFixed(1);

    forms[formIndex] = form;
    await DataAccessLayer.safeWriteJSON(CONFIG.FILES.PENDING_FORMS, forms);

    res.json({
      success: true,
      message: `Form ${action}d successfully`,
      formId,
      status: form.status,
      actionAt: hodActionData.actionAt,
      hodData: {
        name: sessionUser.name,
        employeeId: sessionUser.employeeId || sessionUser.id,
        email: sessionUser.email,
        department: sessionUser.department,
        designation: sessionUser.designation || 'HOD'
      }
    });
  })
);

// Enhanced signature upload with security validations
router.post('/upload-signature',
  upload.single('signature'),
  roleAuth('hod'),
  auditMiddleware('SIGNATURE_UPLOAD'),
  asyncHandler(async (req, res) => {
    const file = req.file;
    const { id: hodId, name } = req.session.user;
    
    if (!file) {
      return res.status(400).json(createErrorResponse('No file uploaded', 'NO_FILE_UPLOADED', 400));
    }

    // Additional file validation
    const maxSize = CONFIG.SIGNATURE.MAX_SIZE;
    if (file.size > maxSize) {
      // Clean up uploaded file
      fs.unlinkSync(file.path);
      return res.status(413).json(createErrorResponse(
        `File too large. Maximum size is ${maxSize / 1024 / 1024}MB`,
        'FILE_TOO_LARGE',
        413
      ));
    }

    const signatures = await DataAccessLayer.safeReadJSON(CONFIG.FILES.HOD_SIGNATURES);
    const now = new Date().toISOString();

    // Remove old signature file if exists
    const existingIndex = signatures.findIndex(sig => sig.hodId === hodId);
    if (existingIndex !== -1) {
      const oldFile = signatures[existingIndex].filename;
      const oldFilePath = path.join(__dirname, `../${CONFIG.SIGNATURE.UPLOAD_DIR}`, oldFile);
      
      if (fs.existsSync(oldFilePath)) {
        try {
          fs.unlinkSync(oldFilePath);
          logger.info('Old signature file removed', { hodId, oldFile });
        } catch (error) {
          logger.warn('Failed to remove old signature file', { hodId, oldFile, error: error.message });
        }
      }
      
      signatures[existingIndex] = {
        ...signatures[existingIndex],
        filename: file.filename,
        uploadedAt: now,
        fileSize: file.size,
        mimeType: file.mimetype
      };
    } else {
      signatures.push({
        hodId,
        name,
        filename: file.filename,
        uploadedAt: now,
        fileSize: file.size,
        mimeType: file.mimetype,
        version: '1.0'
      });
    }

    await DataAccessLayer.safeWriteJSON(CONFIG.FILES.HOD_SIGNATURES, signatures);

    logger.audit('SIGNATURE_UPLOADED', hodId, {
      filename: file.filename,
      fileSize: file.size,
      mimeType: file.mimetype
    });

    res.json({
      success: true,
      message: 'Signature saved successfully',
      filename: file.filename,
      signatureUrl: `/${CONFIG.SIGNATURE.UPLOAD_DIR}/${file.filename}`,
      uploadedAt: now,
      fileSize: file.size
    });
  })
);

// Enhanced signature retrieval for HOD's own signature
router.get('/my-signature',
  roleAuth('hod'),
  asyncHandler(async (req, res) => {
    const { id: hodId } = req.session.user;
    
    const signatures = await DataAccessLayer.safeReadJSON(CONFIG.FILES.HOD_SIGNATURES);
    const signature = signatures.find(s => s.hodId === hodId);
    
    if (!signature) {
      return res.status(404).json(createErrorResponse('No saved signature found', 'SIGNATURE_NOT_FOUND', 404));
    }

    // Verify file still exists
    const filePath = path.join(__dirname, `../${CONFIG.SIGNATURE.UPLOAD_DIR}`, signature.filename);
    if (!fs.existsSync(filePath)) {
      logger.error('Signature file missing from disk', {
        hodId,
        filename: signature.filename
      });
      return res.status(404).json(createErrorResponse(
        'Signature file not found on server. Please re-upload.',
        'SIGNATURE_FILE_MISSING',
        404
      ));
    }

    res.json({
      success: true,
      filename: signature.filename,
      signatureUrl: `/${CONFIG.SIGNATURE.UPLOAD_DIR}/${signature.filename}`,
      uploadedAt: signature.uploadedAt,
      fileSize: signature.fileSize,
      version: signature.version || '1.0'
    });
  })
);

// Health check endpoint
router.get('/health',
  asyncHandler(async (req, res) => {
    const healthData = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      version: '2.0.0',
      services: {
        database: 'operational',
        fileSystem: 'operational'
      }
    };

    // Check file system health
    try {
      await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
      await DataAccessLayer.safeReadJSON(CONFIG.FILES.HOD_SIGNATURES);
    } catch (error) {
      healthData.services.database = 'degraded';
      healthData.warnings = ['Database access issues detected'];
    }

    res.json(healthData);
  })
);

// =========================================
// PRODUCTION ERROR HANDLING MIDDLEWARE
// =========================================

// Global error handler for HOD routes
router.use((error, req, res, next) => {
  logger.error('HOD route error', error, {
    path: req.path,
    method: req.method,
    userId: req.session?.user?.id,
    hodId: req.session?.user?.hodId,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  if (error.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json(createErrorResponse('File too large for signature upload', 'FILE_TOO_LARGE', 413));
  }

  if (error.code === 'LIMIT_UNEXPECTED_FILE') {
    return res.status(400).json(createErrorResponse('Unexpected file in upload', 'UNEXPECTED_FILE', 400));
  }

  if (error.message && error.message.includes('Only image files')) {
    return res.status(400).json(createErrorResponse(error.message, 'INVALID_FILE_TYPE', 400));
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

module.exports = router;
