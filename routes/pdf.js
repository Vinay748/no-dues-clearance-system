const express = require('express');
const PDFDocument = require('pdfkit');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const Joi = require('joi');
const { promisify } = require('util');
const { loadJSON } = require('../utils/fileUtils');
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
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
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

// Rate limiting for PDF generation
const pdfRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // 50 PDF generations per IP per windowMs
  message: {
    success: false,
    message: 'Too many PDF generation requests. Please try again later.',
    code: 'PDF_RATE_LIMITED'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`PDF generation rate limit exceeded`, {
      ip: req.ip,
      path: req.path,
      userId: req.session?.user?.id
    });
    res.status(429).json({
      success: false,
      message: 'Too many PDF generation requests. Please try again later.',
      code: 'PDF_RATE_LIMITED',
      retryAfter: Math.ceil(res.getHeader('Retry-After'))
    });
  }
});

// Apply rate limiting
router.use(pdfRateLimiter);

// =========================================
// PRODUCTION LOGGING & MONITORING
// =========================================

const logger = {
  info: (message, meta = {}) => console.log(`[INFO] ${new Date().toISOString()} - ${message}`, JSON.stringify(meta)),
  warn: (message, meta = {}) => console.warn(`[WARN] ${new Date().toISOString()} - ${message}`, JSON.stringify(meta)),
  error: (message, error, meta = {}) => console.error(`[ERROR] ${new Date().toISOString()} - ${message}`, error?.stack || error, JSON.stringify(meta)),
  audit: (action, userId, meta = {}) => console.log(`[AUDIT] ${new Date().toISOString()} - ${action} - User: ${userId}`, JSON.stringify(meta))
};

// Audit middleware for PDF operations
const auditMiddleware = (action) => (req, res, next) => {
  const userId = req.session?.user?.id || 'anonymous';
  const ip = req.ip || req.connection?.remoteAddress;

  logger.audit(action, userId, {
    ip,
    userAgent: req.get('User-Agent'),
    path: req.path,
    method: req.method,
    sessionId: req.session?.id,
    formId: req.params.formId
  });

  next();
};

// =========================================
// PRODUCTION DATA VALIDATION
// =========================================

const schemas = {
  formIdParam: Joi.object({
    formId: Joi.string().pattern(/^F\d+_[A-Z0-9]{6}$/).required()
  })
};

// Validation middleware for parameters
const validateParams = (schema) => (req, res, next) => {
  const { error, value } = schema.validate(req.params, { abortEarly: false, stripUnknown: true });

  if (error) {
    logger.warn('PDF parameter validation failed', {
      errors: error.details.map(d => ({ field: d.path.join('.'), message: d.message })),
      userId: req.session?.user?.id,
      ip: req.ip
    });

    return res.status(400).json({
      success: false,
      message: 'Invalid form ID format',
      code: 'INVALID_FORM_ID'
    });
  }

  req.params = value;
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
// PRODUCTION DATA ACCESS
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

  static validateEmployeeAccess(employeeId, form) {
    if (!form) {
      throw new Error('Form not found');
    }

    if (form.employeeId !== employeeId) {
      throw new Error('Access denied: Employee ID mismatch');
    }
  }
}

// =========================================
// PRODUCTION CONSTANTS & CONFIG
// =========================================

const CONFIG = {
  FILES: {
    FORM_DATA: './data/pending_forms.json'
  },
  PDF: {
    MAX_SIZE_MB: 10, // 10MB max PDF size
    TIMEOUT_MS: 30000, // 30 second timeout
    DEFAULT_FONT_SIZE: 12,
    HEADER_FONT_SIZE: 18,
    PAGE_MARGINS: {
      top: 72,
      bottom: 72,
      left: 72,
      right: 72
    }
  },
  SECURITY: {
    SANITIZE_FIELDS: true,
    STRIP_HTML: true,
    MAX_FIELD_LENGTH: 1000
  }
};

// =========================================
// PRODUCTION PDF GENERATION
// =========================================

class PDFGenerator {
  static sanitizeText(text) {
    if (!text) return 'N/A';

    // Convert to string and limit length
    let sanitized = String(text).substring(0, CONFIG.SECURITY.MAX_FIELD_LENGTH);

    // Strip HTML tags if enabled
    if (CONFIG.SECURITY.STRIP_HTML) {
      sanitized = sanitized.replace(/<[^>]*>/g, '');
    }

    // Remove potentially dangerous characters
    sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

    return sanitized.trim() || 'N/A';
  }

  static formatDate(dateString) {
    if (!dateString) return 'N/A';

    try {
      const date = new Date(dateString);
      if (isNaN(date.getTime())) return 'Invalid Date';

      return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch (error) {
      logger.warn('Date formatting error', error, { dateString });
      return 'Invalid Date';
    }
  }

  static async generateFormPDF(form, options = {}) {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument({
          size: 'A4',
          margins: CONFIG.PDF.PAGE_MARGINS,
          info: {
            Title: `No Dues Clearance Form - ${form.formId}`,
            Author: 'No Dues System',
            Subject: 'No Dues Clearance Certificate',
            Creator: 'No Dues System v2.0'
          }
        });

        // Set timeout for PDF generation
        const timeout = setTimeout(() => {
          reject(new Error('PDF generation timeout'));
        }, CONFIG.PDF.TIMEOUT_MS);

        const chunks = [];
        doc.on('data', chunk => chunks.push(chunk));
        doc.on('end', () => {
          clearTimeout(timeout);
          const pdfBuffer = Buffer.concat(chunks);

          // Check PDF size
          if (pdfBuffer.length > CONFIG.PDF.MAX_SIZE_MB * 1024 * 1024) {
            reject(new Error('Generated PDF exceeds size limit'));
            return;
          }

          resolve(pdfBuffer);
        });
        doc.on('error', (error) => {
          clearTimeout(timeout);
          reject(error);
        });

        // Generate PDF content
        this.renderFormContent(doc, form);

        doc.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  static renderFormContent(doc, form) {
    const data = form.applicationData || form;
    let yPosition = CONFIG.PDF.PAGE_MARGINS.top;

    // Header
    doc.fontSize(CONFIG.PDF.HEADER_FONT_SIZE)
      .font('Helvetica-Bold')
      .text('No Dues Clearance Form', { align: 'center' });

    yPosition += 40;

    // Form metadata
    doc.fontSize(CONFIG.PDF.DEFAULT_FONT_SIZE).font('Helvetica');

    const formFields = [
      { label: 'Form ID', value: this.sanitizeText(form.formId) },
      { label: 'Employee Name', value: this.sanitizeText(data.name || form.name) },
      { label: 'Employee ID', value: this.sanitizeText(form.employeeId) },
      { label: 'Department', value: this.sanitizeText(data.department || form.department) },
      { label: 'No Dues Type', value: this.sanitizeText(data.noDuesType || form.noDuesType) },
      { label: 'Email', value: this.sanitizeText(data.email || form.email) },
      { label: 'Submitted At', value: this.formatDate(form.submissionDate || form.appliedAt) },
      { label: 'Status', value: this.sanitizeText(form.status) }
    ];

    // Add optional fields if they exist
    if (form.reviewedAt) {
      formFields.push({ label: 'Reviewed At', value: this.formatDate(form.reviewedAt) });
    }

    if (form.remark) {
      formFields.push({ label: 'Remark', value: this.sanitizeText(form.remark) });
    }

    if (form.hodApproval) {
      formFields.push(
        { label: 'HOD Approved By', value: this.sanitizeText(form.hodApproval.approvedBy) },
        { label: 'HOD Approval Date', value: this.formatDate(form.hodApproval.approvedAt) }
      );
    }

    if (form.itProcessing) {
      formFields.push(
        { label: 'IT Processed By', value: this.sanitizeText(form.itProcessing.processedBy) },
        { label: 'IT Processing Date', value: this.formatDate(form.itProcessing.processedAt) }
      );
    }

    // Render form fields
    formFields.forEach(field => {
      if (yPosition > 700) { // Start new page if needed
        doc.addPage();
        yPosition = CONFIG.PDF.PAGE_MARGINS.top;
      }

      doc.font('Helvetica-Bold').text(`${field.label}:`, CONFIG.PDF.PAGE_MARGINS.left, yPosition);
      doc.font('Helvetica').text(field.value, CONFIG.PDF.PAGE_MARGINS.left + 120, yPosition);
      yPosition += 25;
    });

    // Footer
    yPosition = Math.max(yPosition + 40, 720);
    doc.fontSize(10)
      .font('Helvetica')
      .text(`Generated on: ${new Date().toLocaleString()}`, CONFIG.PDF.PAGE_MARGINS.left, yPosition)
      .text(`Document ID: ${form.formId}-${Date.now()}`, { align: 'right' });
  }
}

// =========================================
// PRODUCTION API ENDPOINTS
// =========================================

// Enhanced download specific form by ID
router.get('/download/:formId',
  roleAuth('employee'),
  validateParams(schemas.formIdParam),
  auditMiddleware('PDF_DOWNLOAD'),
  asyncHandler(async (req, res) => {
    const { formId } = req.params;
    const { id: employeeId, employeeId: altEmployeeId } = req.session.user;
    const actualEmployeeId = employeeId || altEmployeeId;

    if (!actualEmployeeId) {
      return res.status(401).json(createErrorResponse('Employee ID not found in session', 'MISSING_EMPLOYEE_ID', 401));
    }

    const forms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.FORM_DATA);
    const form = forms.find(f => f.formId === formId);

    if (!form) {
      logger.warn('Form not found for PDF download', {
        formId,
        employeeId: actualEmployeeId,
        availableForms: forms.length
      });

      return res.status(404).json(createErrorResponse('Form not found', 'FORM_NOT_FOUND', 404));
    }

    try {
      DataAccessLayer.validateEmployeeAccess(actualEmployeeId, form);
    } catch (accessError) {
      logger.warn('Access denied for PDF download', {
        formId,
        requestedBy: actualEmployeeId,
        formOwner: form.employeeId
      });

      return res.status(403).json(createErrorResponse('Access denied', 'ACCESS_DENIED', 403));
    }

    try {
      const pdfBuffer = await PDFGenerator.generateFormPDF(form);

      // Set secure headers for PDF download
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="No-Dues-${formId}.pdf"`);
      res.setHeader('Content-Length', pdfBuffer.length);
      res.setHeader('Cache-Control', 'private, no-cache, no-store, must-revalidate');
      res.setHeader('X-Content-Type-Options', 'nosniff');

      logger.info('PDF download successful', {
        formId,
        employeeId: actualEmployeeId,
        pdfSize: pdfBuffer.length
      });

      res.send(pdfBuffer);

    } catch (pdfError) {
      logger.error('PDF generation failed', pdfError, {
        formId,
        employeeId: actualEmployeeId
      });

      res.status(500).json(createErrorResponse('Failed to generate PDF', 'PDF_GENERATION_ERROR', 500));
    }
  })
);

// Enhanced direct access to form PDF by ID (inline viewing)
router.get('/:formId',
  roleAuth('employee'),
  validateParams(schemas.formIdParam),
  auditMiddleware('PDF_VIEW'),
  asyncHandler(async (req, res) => {
    const { formId } = req.params;
    const { id: employeeId, employeeId: altEmployeeId } = req.session.user;
    const actualEmployeeId = employeeId || altEmployeeId;

    if (!actualEmployeeId) {
      return res.status(401).json(createErrorResponse('Employee ID not found in session', 'MISSING_EMPLOYEE_ID', 401));
    }

    const forms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.FORM_DATA);
    const form = forms.find(f => f.formId === formId);

    if (!form) {
      logger.warn('Form not found for PDF view', {
        formId,
        employeeId: actualEmployeeId
      });

      return res.status(404).json(createErrorResponse('Form not found', 'FORM_NOT_FOUND', 404));
    }

    try {
      DataAccessLayer.validateEmployeeAccess(actualEmployeeId, form);
    } catch (accessError) {
      logger.warn('Access denied for PDF view', {
        formId,
        requestedBy: actualEmployeeId,
        formOwner: form.employeeId
      });

      return res.status(403).json(createErrorResponse('Access denied', 'ACCESS_DENIED', 403));
    }

    try {
      const pdfBuffer = await PDFGenerator.generateFormPDF(form);

      // Set secure headers for PDF viewing
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `inline; filename="No-Dues-${formId}.pdf"`);
      res.setHeader('Content-Length', pdfBuffer.length);
      res.setHeader('Cache-Control', 'private, no-cache, no-store, must-revalidate');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'SAMEORIGIN');

      logger.info('PDF view successful', {
        formId,
        employeeId: actualEmployeeId,
        pdfSize: pdfBuffer.length
      });

      res.send(pdfBuffer);

    } catch (pdfError) {
      logger.error('PDF generation failed', pdfError, {
        formId,
        employeeId: actualEmployeeId
      });

      res.status(500).json(createErrorResponse('Failed to generate PDF', 'PDF_GENERATION_ERROR', 500));
    }
  })
);

// Enhanced generate PDF for current user's latest form
router.get('/generate/latest',
  roleAuth('employee'),
  auditMiddleware('PDF_LATEST_GENERATE'),
  asyncHandler(async (req, res) => {
    const { id: employeeId, employeeId: altEmployeeId } = req.session.user;
    const actualEmployeeId = employeeId || altEmployeeId;

    if (!actualEmployeeId) {
      return res.status(401).json(createErrorResponse('Employee ID not found in session', 'MISSING_EMPLOYEE_ID', 401));
    }

    const forms = await DataAccessLayer.safeReadJSON(CONFIG.FILES.FORM_DATA);

    // Find the latest form for the employee
    const employeeForms = forms.filter(f => f && f.employeeId === actualEmployeeId);

    if (employeeForms.length === 0) {
      logger.warn('No forms found for latest PDF generation', {
        employeeId: actualEmployeeId,
        totalForms: forms.length
      });

      return res.status(404).json(createErrorResponse('No form found for your account', 'NO_FORMS_FOUND', 404));
    }

    // Get the most recent form
    const latestForm = employeeForms.sort((a, b) =>
      new Date(b.submissionDate || b.lastUpdated) - new Date(a.submissionDate || a.lastUpdated)
    )[0];

    try {
      const pdfBuffer = await PDFGenerator.generateFormPDF(latestForm);

      // Set secure headers for PDF viewing
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `inline; filename="No-Dues-${latestForm.formId}.pdf"`);
      res.setHeader('Content-Length', pdfBuffer.length);
      res.setHeader('Cache-Control', 'private, no-cache, no-store, must-revalidate');
      res.setHeader('X-Content-Type-Options', 'nosniff');

      logger.info('Latest PDF generation successful', {
        formId: latestForm.formId,
        employeeId: actualEmployeeId,
        pdfSize: pdfBuffer.length,
        totalEmployeeForms: employeeForms.length
      });

      res.send(pdfBuffer);

    } catch (pdfError) {
      logger.error('Latest PDF generation failed', pdfError, {
        formId: latestForm.formId,
        employeeId: actualEmployeeId
      });

      res.status(500).json(createErrorResponse('Failed to generate PDF', 'PDF_GENERATION_ERROR', 500));
    }
  })
);

// Health check endpoint
router.get('/health/check',
  asyncHandler(async (req, res) => {
    const healthData = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      version: '2.0.0',
      services: {
        pdfGeneration: 'operational',
        dataAccess: 'operational'
      }
    };

    // Test PDF generation capability
    try {
      const testDoc = new PDFDocument();
      testDoc.end();
      healthData.services.pdfGeneration = 'operational';
    } catch (error) {
      healthData.services.pdfGeneration = 'degraded';
      healthData.warnings = ['PDF generation service issues detected'];
    }

    // Test data access
    try {
      await DataAccessLayer.safeReadJSON(CONFIG.FILES.FORM_DATA);
      healthData.services.dataAccess = 'operational';
    } catch (error) {
      healthData.services.dataAccess = 'degraded';
      if (!healthData.warnings) healthData.warnings = [];
      healthData.warnings.push('Data access issues detected');
    }

    res.json(healthData);
  })
);

// =========================================
// PRODUCTION ERROR HANDLING MIDDLEWARE
// =========================================

// Global error handler for PDF routes
router.use((error, req, res, next) => {
  logger.error('PDF route error', error, {
    path: req.path,
    method: req.method,
    userId: req.session?.user?.id,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  if (error.message && error.message.includes('timeout')) {
    return res.status(408).json(createErrorResponse('PDF generation timeout', 'PDF_TIMEOUT', 408));
  }

  if (error.message && error.message.includes('exceeds size limit')) {
    return res.status(413).json(createErrorResponse('Generated PDF is too large', 'PDF_TOO_LARGE', 413));
  }

  if (error.code === 'ENOENT') {
    return res.status(404).json(createErrorResponse('Required file not found', 'FILE_NOT_FOUND', 404));
  }

  if (!res.headersSent) {
    res.status(500).json(createErrorResponse(
      process.env.NODE_ENV === 'production' ? 'PDF generation failed' : error.message,
      'PDF_ERROR',
      500,
      process.env.NODE_ENV === 'development' ? error.stack : null
    ));
  }
});

module.exports = router;
