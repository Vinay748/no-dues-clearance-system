const express = require('express');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const Joi = require('joi');
const { promisify } = require('util');
const { generateFormCertificates } = require('../utils/pdfGenerator');
const NotificationManager = require('../utils/notificationManager');
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

// Rate limiting for different IT operations
const itRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // Higher limit for IT operations
  message: { success: false, message: 'Too many requests. Please try again later.', code: 'RATE_LIMITED' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`IT rate limit exceeded`, {
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

// Stricter rate limiting for processing operations
const processingRateLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 20, // 20 processing operations per 5 minutes
  message: { success: false, message: 'Too many processing requests. Please try again later.', code: 'PROCESSING_RATE_LIMITED' }
});

// Apply rate limiting
router.use(itRateLimiter);
router.use('/final-process', processingRateLimiter);
router.use('/decision', processingRateLimiter);

// =========================================
// PRODUCTION LOGGING & MONITORING
// =========================================

const logger = {
  info: (message, meta = {}) => console.log(`[INFO] ${new Date().toISOString()} - ${message}`, JSON.stringify(meta)),
  warn: (message, meta = {}) => console.warn(`[WARN] ${new Date().toISOString()} - ${message}`, JSON.stringify(meta)),
  error: (message, error, meta = {}) => console.error(`[ERROR] ${new Date().toISOString()} - ${message}`, error?.stack || error, JSON.stringify(meta)),
  audit: (action, userId, meta = {}) => console.log(`[AUDIT] ${new Date().toISOString()} - ${action} - User: ${userId}`, JSON.stringify(meta))
};

// Audit middleware for sensitive IT operations
const auditMiddleware = (action) => (req, res, next) => {
  const userId = req.session?.user?.id || 'anonymous';
  const ip = req.ip || req.connection?.remoteAddress;
  
  logger.audit(action, userId, {
    ip,
    userAgent: req.get('User-Agent'),
    path: req.path,
    method: req.method,
    sessionId: req.session?.id,
    itAdmin: req.session?.user?.name
  });
  
  next();
};

// =========================================
// PRODUCTION DATA VALIDATION
// =========================================

const schemas = {
  formDecision: Joi.object({
    formId: Joi.string().pattern(/^F\d+_[A-Z0-9]{6}$/).required(),
    status: Joi.string().valid('approved', 'rejected', 'complete').required(),
    remark: Joi.string().max(1000).optional().allow('')
  }),
  
  finalProcess: Joi.object({
    formId: Joi.string().pattern(/^F\d+_[A-Z0-9]{6}$/).required(),
    formResponses: Joi.alternatives().try(
      Joi.string().max(500000), // JSON string - 500KB limit
      Joi.object().max(100) // Direct object
    ).optional(),
    action: Joi.string().valid('complete', 'reject').required(),
    remarks: Joi.string().max(1000).optional().allow('')
  }),
  
  bulkNotification: Joi.object({
    title: Joi.string().min(1).max(100).required(),
    message: Joi.string().min(1).max(1000).required(),
    employeeIds: Joi.array().items(Joi.string().min(1).max(50)).max(100).optional(),
    priority: Joi.string().valid('low', 'medium', 'high').default('medium')
  })
};

// Validation middleware
const validateRequest = (schema) => (req, res, next) => {
  const { error, value } = schema.validate(req.body, { abortEarly: false, stripUnknown: true });
  
  if (error) {
    logger.warn('IT request validation failed', {
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
      const readFile = promisify(fs.readFile);
      const data = await readFile(filePath, 'utf8');
      const parsed = JSON.parse(data);
      return Array.isArray(parsed) ? parsed : defaultValue;
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
        
        // Keep only last 10 backups
        const dir = path.dirname(filePath);
        const basename = path.basename(filePath);
        const backupFiles = fs.readdirSync(dir)
          .filter(f => f.startsWith(`${basename}.backup.`))
          .sort()
          .reverse();
        
        if (backupFiles.length > 10) {
          backupFiles.slice(10).forEach(f => {
            fs.unlinkSync(path.join(dir, f));
          });
        }
      }
      
      const writeFile = promisify(fs.writeFile);
      await writeFile(filePath, JSON.stringify(data, null, 2), 'utf8');
      return true;
    } catch (error) {
      logger.error(`Failed to write JSON file: ${filePath}`, error);
      throw new Error('Database write operation failed');
    }
  }

  static validateITAccess(userId, operation) {
    if (!userId) {
      throw new Error('IT user ID is required for access validation');
    }
    
    logger.audit('IT_ACCESS_CHECK', userId, { operation });
  }
}

// =========================================
// PRODUCTION CONSTANTS & CONFIG
// =========================================

const CONFIG = {
  FILES: {
    PENDING_FORMS: path.join(__dirname, '../data/pending_forms.json'),
    CERTIFICATES: path.join(__dirname, '../data/certificates.json')
  },
  STATUS: {
    PENDING: 'pending',
    SUBMITTED_TO_IT: 'Submitted to IT',
    IT_COMPLETED: 'IT Completed',
    REJECTED: 'rejected',
    APPROVED: 'approved'
  },
  LIMITS: {
    MAX_FORM_SIZE: 500000, // 500KB
    MAX_NOTIFICATION_RECIPIENTS: 100,
    CERTIFICATE_RETENTION_DAYS: 1095 // 3 years
  }
};

// All routes below are protected for IT Admin only
router.use(roleAuth('it'));

// =========================================
// PRODUCTION HELPER FUNCTIONS
// =========================================

class ITHelpers {
  static getLatestFormForEmployee(allForms, employeeId, allowedStatuses = []) {
    let forms = allForms.filter(f => f && f.employeeId === employeeId);
    if (allowedStatuses.length) {
      forms = forms.filter(f => allowedStatuses.includes(f.status));
    }
    return forms.sort((a, b) => new Date(b.submissionDate || b.lastUpdated) - new Date(a.submissionDate || a.lastUpdated))[0] || null;
  }

  static async storeCertificates(formId, certificates, employeeId) {
    try {
      const certificatesData = await DataAccessLayer.safeReadJSON(CONFIG.FILES.CERTIFICATES);

      for (const cert of certificates) {
        certificatesData.push({
          id: `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          formId,
          employeeId,
          formType: cert.formType,
          filename: cert.filename,
          filepath: cert.filepath,
          generatedAt: cert.generatedAt,
          status: 'available',
          version: '1.0'
        });
      }

      await DataAccessLayer.safeWriteJSON(CONFIG.FILES.CERTIFICATES, certificatesData);
      logger.info('Certificate records stored successfully', {
        formId,
        employeeId,
        certificateCount: certificates.length
      });

    } catch (error) {
      logger.error('Error storing certificates', error, { formId, employeeId });
      throw error;
    }
  }

  static validateFormForProcessing(form, action) {
    if (!form) {
      throw new Error('Form not found');
    }

    if (action === 'complete' && form.status !== CONFIG.STATUS.SUBMITTED_TO_IT) {
      throw new Error(`Form is not in correct status for completion. Current status: ${form.status}`);
    }

    if (action === 'reject' && !['pending', 'Submitted to IT'].includes(form.status)) {
      throw new Error(`Form is not in correct status for rejection. Current status: ${form.status}`);
    }
  }

  static sanitizeFormForResponse(form) {
    // Remove sensitive internal data before sending to client
    const sanitized = { ...form };
    delete sanitized.internalNotes;
    delete sanitized.systemMetadata;
    delete sanitized.auditLog;
    return sanitized;
  }

  static createITActionData(sessionUser, action, remarks, req) {
    return {
      processedBy: sessionUser?.name || 'IT Admin',
      processedAt: new Date().toISOString(),
      action,
      remarks: remarks || '',
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      sessionId: req.session?.id,
      itDetails: {
        userId: sessionUser?.id,
        name: sessionUser?.name,
        email: sessionUser?.email,
        department: sessionUser?.department || 'IT'
      }
    };
  }
}

// =========================================
// PRODUCTION API ENDPOINTS
// =========================================

// Enhanced review requests endpoint with pagination
router.get('/review-requests',
  asyncHandler(async (req, res) => {
    const { page = 1, limit = 50, status, department } = req.query;
    
    DataAccessLayer.validateITAccess(req.session.user.id, 'VIEW_REVIEW_REQUESTS');
    
    let requests = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    
    // Apply filters
    if (status) {
      requests = requests.filter(r => r.status === status);
    }
    
    if (department) {
      requests = requests.filter(r => r.department === department);
    }
    
    // Sort by submission date (oldest first for priority)
    requests.sort((a, b) => new Date(a.submissionDate || a.lastUpdated) - new Date(b.submissionDate || b.lastUpdated));
    
    // Apply pagination
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + parseInt(limit);
    const paginatedRequests = requests.slice(startIndex, endIndex);
    
    // Sanitize data
    const sanitizedRequests = paginatedRequests.map(r => ITHelpers.sanitizeFormForResponse(r));
    
    logger.info('IT review requests accessed', {
      userId: req.session.user.id,
      totalRequests: requests.length,
      pageRequested: page,
      filters: { status, department }
    });
    
    res.json({
      success: true,
      requests: sanitizedRequests,
      pagination: {
        total: requests.length,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(requests.length / limit),
        hasNextPage: endIndex < requests.length,
        hasPrevPage: page > 1
      }
    });
  })
);

// Enhanced pending forms endpoint
router.get('/pending',
  asyncHandler(async (req, res) => {
    DataAccessLayer.validateITAccess(req.session.user.id, 'VIEW_PENDING_FORMS');
    
    const requests = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    const pendingForIT = requests.filter(form => form.status === CONFIG.STATUS.SUBMITTED_TO_IT);
    
    // Sort by submission date (oldest first for priority)
    pendingForIT.sort((a, b) => new Date(a.submissionDate || a.lastUpdated) - new Date(b.submissionDate || b.lastUpdated));
    
    const sanitizedForms = pendingForIT.map(f => ITHelpers.sanitizeFormForResponse(f));
    
    logger.info('IT pending forms accessed', {
      userId: req.session.user.id,
      pendingCount: pendingForIT.length
    });
    
    res.json({
      success: true,
      list: sanitizedForms,
      summary: {
        totalPending: pendingForIT.length,
        oldestPending: pendingForIT.length > 0 ? pendingForIT[0].submissionDate : null,
        avgProcessingTime: '2-3 business days'
      }
    });
  })
);

// Enhanced form details endpoint with security checks
router.get('/form-details/:formId',
  asyncHandler(async (req, res) => {
    const { formId } = req.params;
    
    if (!formId || !/^F\d+_[A-Z0-9]{6}$/.test(formId)) {
      return res.status(400).json(createErrorResponse('Invalid form ID format', 'INVALID_FORM_ID', 400));
    }
    
    DataAccessLayer.validateITAccess(req.session.user.id, 'VIEW_FORM_DETAILS');
    
    const requests = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    const form = requests.find(f => f.formId === formId);

    if (!form) {
      return res.status(404).json(createErrorResponse('Form not found', 'FORM_NOT_FOUND', 404));
    }

    logger.info('IT form details accessed', {
      formId,
      userId: req.session.user.id,
      employeeId: form.employeeId,
      status: form.status
    });

    res.json({
      success: true,
      forms: form.formResponses || {},
      noDuesType: form.noDuesType || 'Transfer',
      employee: {
        name: form.employeeName || form.name,
        employeeId: form.employeeId,
        department: form.department
      },
      hodApproval: form.hodApproval || null,
      submittedDate: form.submittedDate,
      submissionDate: form.submissionDate,
      status: form.status,
      metadata: {
        version: form.version || '1.0',
        lastUpdated: form.lastUpdated,
        accessedAt: new Date().toISOString()
      }
    });
  })
);

// Enhanced final processing with comprehensive validation and security
router.post('/final-process',
  validateRequest(schemas.finalProcess),
  auditMiddleware('IT_FINAL_PROCESS'),
  asyncHandler(async (req, res) => {
    let { formId, formResponses, action, remarks } = req.body;
    const sessionUser = req.session.user;
    
    DataAccessLayer.validateITAccess(sessionUser.id, 'FINAL_PROCESS_FORM');

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

    const requests = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    const formIndex = requests.findIndex(f => f.formId === formId);

    if (formIndex === -1) {
      return res.status(404).json(createErrorResponse('Form not found', 'FORM_NOT_FOUND', 404));
    }

    const form = requests[formIndex];

    try {
      ITHelpers.validateFormForProcessing(form, action);
    } catch (validationError) {
      return res.status(400).json(createErrorResponse(
        validationError.message,
        'FORM_VALIDATION_ERROR',
        400
      ));
    }

    if (action === 'complete') {
      logger.info('Processing IT completion with PDF generation', {
        formId,
        userId: sessionUser.id
      });

      // Merge HOD data with form responses for PDF generation
      const enrichedFormResponses = {};

      if (formResponses) {
        for (const [formType, formData] of Object.entries(formResponses)) {
          enrichedFormResponses[formType] = {
            ...formData,
            hodApprovalDate: form.hodApproval?.approvedAt,
            hodApprovedBy: form.hodApproval?.approvedBy,
            employeeName: form.employeeName || form.name,
            employeeId: form.employeeId,
            department: form.department,
            noDuesType: form.noDuesType
          };
        }

        // Validate IT sections are filled
        const requiredForms = ['disposalForm', 'efileForm'];
        const form365Key = formResponses.form365Trans ? 'form365Trans' : 'form365Disp';
        requiredForms.push(form365Key);

        for (const formKey of requiredForms) {
          const formData = formResponses[formKey];
          if (!formData) continue;

          const hasITData = Object.keys(formData).some(key =>
            key.toLowerCase().includes('it') ||
            key.includes('itSignature') ||
            key.includes('itName') ||
            key.includes('itApproval')
          );

          logger.info(`IT sections validation`, {
            formKey,
            hasITData,
            formId
          });
        }

        form.formResponses = formResponses;

        // Generate PDF Certificates with error handling
        try {
          logger.info('Generating PDF certificates', { formId });
          const pdfCertificates = await generateFormCertificates(formId, enrichedFormResponses);

          await ITHelpers.storeCertificates(formId, pdfCertificates, form.employeeId);

          logger.info('PDF certificates generated successfully', {
            formId,
            certificateCount: pdfCertificates.length
          });

          form.certificates = pdfCertificates.map(cert => ({
            formType: cert.formType,
            filename: cert.filename,
            generatedAt: cert.generatedAt,
            status: 'available'
          }));

          // Send certificate ready notification
          try {
            NotificationManager.notifyCertificatesReady(
              form.employeeId,
              formId,
              form.certificates,
              {
                processedBy: sessionUser?.name || 'IT Admin',
                itDepartment: sessionUser?.department || 'IT',
                completedAt: new Date().toISOString()
              }
            );
          } catch (notificationError) {
            logger.warn('Failed to send certificate notification', notificationError, { formId });
          }

        } catch (pdfError) {
          logger.error('PDF generation failed', pdfError, { formId });
          return res.status(500).json(createErrorResponse(
            'Certificate generation failed. Please try again.',
            'PDF_GENERATION_ERROR',
            500
          ));
        }
      }

      form.status = CONFIG.STATUS.IT_COMPLETED;
      form.itProcessing = ITHelpers.createITActionData(sessionUser, 'completed', remarks, req);
      form.lastUpdated = new Date().toISOString();
      form.version = (parseFloat(form.version || '1.0') + 0.1).toFixed(1);

      logger.audit('FORM_COMPLETED', sessionUser.id, {
        formId,
        employeeId: form.employeeId,
        certificatesGenerated: form.certificates?.length || 0
      });

    } else if (action === 'reject') {
      if (!remarks || remarks.trim() === '') {
        return res.status(400).json(createErrorResponse(
          'Remarks are required for rejection',
          'MISSING_REMARKS',
          400
        ));
      }

      form.status = CONFIG.STATUS.REJECTED;
      form.rejectionReason = remarks;
      form.rejectedAt = new Date().toISOString();
      form.rejectedBy = sessionUser?.name || 'IT Admin';
      form.rejectionStage = 'IT Review';
      form.assignedForms = [];
      form.formResponses = {};
      form.itProcessing = ITHelpers.createITActionData(sessionUser, 'rejected', remarks, req);
      form.lastUpdated = new Date().toISOString();
      form.version = (parseFloat(form.version || '1.0') + 0.1).toFixed(1);

      // Send rejection notification
      try {
        NotificationManager.notifyFormRejection(
          form.employeeId,
          formId,
          remarks,
          {
            rejectedBy: sessionUser?.name || 'IT Admin',
            rejectionStage: 'IT Review',
            itDepartment: sessionUser?.department || 'IT',
            canResubmit: true
          }
        );
      } catch (notificationError) {
        logger.warn('Failed to send rejection notification', notificationError, { formId });
      }

      logger.audit('FORM_REJECTED', sessionUser.id, {
        formId,
        employeeId: form.employeeId,
        reason: remarks
      });
    }

    // Save updated data
    requests[formIndex] = form;
    await DataAccessLayer.safeWriteJSON(CONFIG.FILES.PENDING_FORMS, requests);

    const responseMessage = action === 'complete' 
      ? 'Form completed successfully and certificates generated'
      : 'Form rejected and returned to employee';

    res.json({
      success: true,
      message: responseMessage,
      formId,
      status: form.status,
      processedAt: form.itProcessing.processedAt,
      certificates: form.certificates || [],
      version: form.version
    });
  })
);

// Enhanced decision endpoint with validation
router.post('/decision',
  validateRequest(schemas.formDecision),
  auditMiddleware('IT_DECISION'),
  asyncHandler(async (req, res) => {
    const { formId, status, remark } = req.body;
    const sessionUser = req.session.user;
    
    DataAccessLayer.validateITAccess(sessionUser.id, 'MAKE_DECISION');

    const requests = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    const index = requests.findIndex(r => r.formId === formId);

    if (index === -1) {
      return res.status(404).json(createErrorResponse('Form not found', 'FORM_NOT_FOUND', 404));
    }

    const form = requests[index];
    const decision = status.toLowerCase();

    // Validate form status
    if (form.status !== CONFIG.STATUS.PENDING) {
      return res.status(400).json(createErrorResponse(
        `Form is not in pending status. Current status: ${form.status}`,
        'INVALID_FORM_STATUS',
        400
      ));
    }

    form.status = decision;
    form.remark = remark || '';
    form.lastUpdated = new Date().toISOString();
    form.version = (parseFloat(form.version || '1.0') + 0.1).toFixed(1);

    if (decision === CONFIG.STATUS.APPROVED) {
      const noDuesType = form.noDuesType?.toLowerCase();

      form.assignedForms = [
        { title: 'E-File', path: '/forms/efile.html' },
        { title: 'Disposal Form', path: '/forms/disposalform.html' },
        {
          title: noDuesType === 'transfer' ? 'Form 365 - Transfer' : 'Form 365 - Disposal',
          path: noDuesType === 'transfer'
            ? '/forms/form365transfer.html'
            : '/forms/form365disposal.html'
        }
      ];

      // Send approval notification
      try {
        NotificationManager.getInstance().sendMultiChannelNotification({
          type: 'forms_assigned',
          employeeId: form.employeeId,
          formId: formId,
          timestamp: new Date().toISOString(),
          priority: 'medium',
          title: 'Forms Assigned',
          message: `Your application ${formId} has been approved. Complete the assigned forms to proceed.`,
          details: {
            assignedForms: form.assignedForms,
            approvedBy: sessionUser?.name || 'IT Admin',
            nextStep: 'Complete assigned forms and submit to HOD'
          }
        });
      } catch (notificationError) {
        logger.warn('Failed to send approval notification', notificationError, { formId });
      }

      logger.audit('FORM_APPROVED', sessionUser.id, {
        formId,
        employeeId: form.employeeId,
        assignedFormsCount: form.assignedForms.length
      });

    } else if (decision === CONFIG.STATUS.REJECTED) {
      form.status = CONFIG.STATUS.REJECTED;
      form.rejectionReason = remark || 'No reason provided';
      form.rejectedAt = new Date().toISOString();
      form.rejectedBy = sessionUser?.name || 'IT Admin';
      form.rejectionStage = 'Initial IT Review';
      delete form.assignedForms;
      form.formResponses = {};

      try {
        NotificationManager.notifyFormRejection(
          form.employeeId,
          formId,
          remark || 'No reason provided',
          {
            rejectedBy: sessionUser?.name || 'IT Admin',
            rejectionStage: 'Initial IT Review',
            itDepartment: sessionUser?.department || 'IT',
            canResubmit: true
          }
        );
      } catch (notificationError) {
        logger.warn('Failed to send rejection notification', notificationError, { formId });
      }

      logger.audit('FORM_REJECTED_INITIAL', sessionUser.id, {
        formId,
        employeeId: form.employeeId,
        reason: remark || 'No reason provided'
      });
    }

    requests[index] = form;
    await DataAccessLayer.safeWriteJSON(CONFIG.FILES.PENDING_FORMS, requests);

    res.json({
      success: true,
      message: `Form ${decision} successfully`,
      formId,
      status: form.status,
      processedAt: form.lastUpdated,
      version: form.version
    });
  })
);

// Enhanced statistics endpoint with comprehensive metrics
router.get('/stats',
  asyncHandler(async (req, res) => {
    DataAccessLayer.validateITAccess(req.session.user.id, 'VIEW_STATISTICS');
    
    const requests = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    
    let certificatesCount = 0;
    let notificationStats = {
      connectedEmployees: 0,
      totalNotificationsSent: 0
    };

    try {
      const certificates = await DataAccessLayer.safeReadJSON(CONFIG.FILES.CERTIFICATES);
      certificatesCount = certificates.length;
    } catch (certError) {
      logger.warn('Could not read certificates for stats', certError);
    }

    // Get notification system statistics
    try {
      const notificationManager = NotificationManager.getInstance();
      notificationStats.connectedEmployees = notificationManager.getConnectedClientsCount();

      const recentNotifications = notificationManager.getNotificationHistory('', 1000)
        .filter(n => new Date(n.timestamp) > new Date(Date.now() - 24 * 60 * 60 * 1000));
      notificationStats.totalNotificationsSent = recentNotifications.length;
    } catch (notificationError) {
      logger.warn('Could not get notification stats', notificationError);
    }

    const stats = {
      total: requests.length,
      pendingIT: requests.filter(f => f.status === CONFIG.STATUS.SUBMITTED_TO_IT).length,
      completedByIT: requests.filter(f => f.status === CONFIG.STATUS.IT_COMPLETED).length,
      rejectedByIT: requests.filter(f => f.status === CONFIG.STATUS.REJECTED).length,
      pendingInitialReview: requests.filter(f => f.status === CONFIG.STATUS.PENDING).length,
      certificatesGenerated: certificatesCount,
      notifications: notificationStats,
      systemHealth: {
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage(),
        timestamp: new Date().toISOString()
      }
    };

    logger.info('IT statistics accessed', {
      userId: req.session.user.id,
      statsRequested: Object.keys(stats).join(', ')
    });

    res.json({ success: true, stats });
  })
);

// Enhanced completed forms endpoint
router.get('/completed',
  asyncHandler(async (req, res) => {
    const { page = 1, limit = 50 } = req.query;
    
    DataAccessLayer.validateITAccess(req.session.user.id, 'VIEW_COMPLETED_FORMS');
    
    const requests = await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
    const completedForms = requests.filter(form => form.status === CONFIG.STATUS.IT_COMPLETED);
    
    // Sort by completion date (newest first)
    completedForms.sort((a, b) => new Date(b.itProcessing?.processedAt || b.lastUpdated) - new Date(a.itProcessing?.processedAt || a.lastUpdated));
    
    // Apply pagination
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + parseInt(limit);
    const paginatedForms = completedForms.slice(startIndex, endIndex);
    
    const sanitizedForms = paginatedForms.map(f => ITHelpers.sanitizeFormForResponse(f));
    
    logger.info('IT completed forms accessed', {
      userId: req.session.user.id,
      completedCount: completedForms.length,
      pageRequested: page
    });
    
    res.json({
      success: true,
      list: sanitizedForms,
      pagination: {
        total: completedForms.length,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(completedForms.length / limit),
        hasNextPage: endIndex < completedForms.length,
        hasPrevPage: page > 1
      },
      summary: {
        totalCompleted: completedForms.length,
        certificatesGenerated: completedForms.reduce((sum, f) => sum + (f.certificates?.length || 0), 0)
      }
    });
  })
);

// Enhanced bulk notification endpoint
router.post('/send-notification',
  validateRequest(schemas.bulkNotification),
  auditMiddleware('BULK_NOTIFICATION'),
  asyncHandler(async (req, res) => {
    const { title, message, employeeIds, priority } = req.body;
    const sessionUser = req.session.user;
    
    DataAccessLayer.validateITAccess(sessionUser.id, 'SEND_NOTIFICATIONS');

    const notificationData = {
      type: 'it_announcement',
      timestamp: new Date().toISOString(),
      priority: priority,
      title: title,
      message: message,
      details: {
        sentBy: sessionUser?.name || 'IT Admin',
        itDepartment: sessionUser?.department || 'IT',
        sessionId: req.session?.id
      }
    };

    let sentCount = 0;

    try {
      if (employeeIds && Array.isArray(employeeIds)) {
        // Send to specific employees
        for (const employeeId of employeeIds) {
          NotificationManager.getInstance().sendMultiChannelNotification({
            ...notificationData,
            employeeId: employeeId
          });
          sentCount++;
        }
      } else {
        // Broadcast to all connected employees
        sentCount = NotificationManager.getInstance().broadcastNotification(notificationData);
      }

      logger.audit('BULK_NOTIFICATION_SENT', sessionUser.id, {
        title,
        recipientCount: sentCount,
        targetedEmployees: employeeIds ? employeeIds.length : 'broadcast',
        priority
      });

      res.json({
        success: true,
        message: `Notification sent to ${sentCount} employee(s)`,
        sentCount: sentCount,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Bulk notification failed', error, {
        userId: sessionUser.id,
        title,
        recipientCount: employeeIds?.length || 'broadcast'
      });
      
      res.status(500).json(createErrorResponse('Failed to send notification', 'NOTIFICATION_ERROR', 500));
    }
  })
);

// Enhanced notification statistics endpoint
router.get('/notification-stats',
  asyncHandler(async (req, res) => {
    DataAccessLayer.validateITAccess(req.session.user.id, 'VIEW_NOTIFICATION_STATS');
    
    try {
      const notificationManager = NotificationManager.getInstance();

      const stats = {
        connectedEmployees: notificationManager.getConnectedClientsCount(),
        queuedNotifications: notificationManager.notificationQueue?.length || 0,
        recentNotifications: notificationManager.getNotificationHistory('', 50).slice(0, 10),
        systemStatus: {
          webSocketActive: true,
          lastCleanup: new Date().toISOString(),
          serverUptime: process.uptime()
        },
        performance: {
          memoryUsage: process.memoryUsage(),
          cpuUsage: process.cpuUsage()
        }
      };

      res.json({
        success: true,
        stats: stats,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Failed to get notification stats', error, {
        userId: req.session.user.id
      });
      
      res.status(500).json(createErrorResponse('Failed to get notification statistics', 'NOTIFICATION_STATS_ERROR', 500));
    }
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
        fileSystem: 'operational',
        notifications: 'operational',
        pdfGeneration: 'operational'
      }
    };

    // Check critical services
    try {
      await DataAccessLayer.safeReadJSON(CONFIG.FILES.PENDING_FORMS);
      await DataAccessLayer.safeReadJSON(CONFIG.FILES.CERTIFICATES);
    } catch (error) {
      healthData.services.database = 'degraded';
      healthData.warnings = ['Database access issues detected'];
    }

    try {
      const notificationManager = NotificationManager.getInstance();
      healthData.services.notifications = notificationManager ? 'operational' : 'degraded';
    } catch (error) {
      healthData.services.notifications = 'degraded';
    }

    res.json(healthData);
  })
);

// =========================================
// PRODUCTION ERROR HANDLING MIDDLEWARE
// =========================================

// Global error handler for IT routes
router.use((error, req, res, next) => {
  logger.error('IT route error', error, {
    path: req.path,
    method: req.method,
    userId: req.session?.user?.id,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  if (error.code === 'ENOENT') {
    return res.status(404).json(createErrorResponse('Required file not found', 'FILE_NOT_FOUND', 404));
  }

  if (error.name === 'SyntaxError' && error.message.includes('JSON')) {
    return res.status(400).json(createErrorResponse('Invalid JSON format', 'INVALID_JSON', 400));
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
