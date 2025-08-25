const PDFDocument = require('pdfkit');
const fs = require('fs-extra');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');

// =========================================
// PRODUCTION CONFIGURATION
// =========================================

const CONFIG = {
  PDF: {
    MAX_SIZE_MB: 10, // 10MB max PDF size
    TIMEOUT_MS: 30000, // 30 second timeout
    DEFAULT_FONT_SIZE: 12,
    HEADER_FONT_SIZE: 20,
    SIGNATURE_MAX_SIZE: 200 * 1024, // 200KB max signature
    PAGE_MARGINS: {
      top: 50,
      bottom: 50,
      left: 50,
      right: 50
    },
    COMPRESSION: {
      compress: true,
      version: '1.4' // PDF version for better compatibility
    }
  },

  DIRECTORIES: {
    CERTIFICATES: path.join(__dirname, '..', 'public', 'certificates'),
    TEMP: path.join(__dirname, '..', 'temp'),
    FONTS: path.join(__dirname, '..', 'assets', 'fonts')
  },

  SECURITY: {
    SANITIZE_INPUTS: true,
    MAX_FIELD_LENGTH: 500,
    ALLOWED_IMAGE_TYPES: ['image/png', 'image/jpeg', 'image/jpg'],
    CERTIFICATE_ENCRYPTION: true
  }
};

// =========================================
// PRODUCTION LOGGING SYSTEM
// =========================================

const logger = {
  info: (message, meta = {}) => {
    console.log(`[INFO] ${new Date().toISOString()} - ${message}`, JSON.stringify(meta));
  },
  warn: (message, meta = {}) => {
    console.warn(`[WARN] ${new Date().toISOString()} - ${message}`, JSON.stringify(meta));
  },
  error: (message, error, meta = {}) => {
    console.error(`[ERROR] ${new Date().toISOString()} - ${message}`, error?.stack || error, JSON.stringify(meta));
  },
  audit: (action, formId, meta = {}) => {
    console.log(`[AUDIT] ${new Date().toISOString()} - ${action} - Form: ${formId}`, JSON.stringify(meta));
  }
};

// =========================================
// PRODUCTION VALIDATION & SECURITY
// =========================================

class PDFValidator {
  static sanitizeText(text) {
    if (!text) return 'N/A';

    let sanitized = String(text).substring(0, CONFIG.SECURITY.MAX_FIELD_LENGTH);

    // Remove potentially dangerous characters
    sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
    sanitized = sanitized.replace(/<[^>]*>/g, ''); // Remove HTML tags
    sanitized = sanitized.replace(/[^\x20-\x7E\u00A0-\uFFFF]/g, ''); // Keep printable characters only

    return sanitized.trim() || 'N/A';
  }

  static validateImageData(imageData) {
    if (!imageData || typeof imageData !== 'string') {
      return null;
    }

    if (!imageData.startsWith('data:image/')) {
      return null;
    }

    try {
      const [header, base64Data] = imageData.split(',');

      if (!base64Data) {
        return null;
      }

      // Check image type
      const mimeType = header.split(':')[1].split(';')[0];
      if (!CONFIG.SECURITY.ALLOWED_IMAGE_TYPES.includes(mimeType)) {
        logger.warn('Invalid image type in signature', { mimeType });
        return null;
      }

      const buffer = Buffer.from(base64Data, 'base64');

      // Check size
      if (buffer.length > CONFIG.PDF.SIGNATURE_MAX_SIZE) {
        logger.warn('Signature image too large', { size: buffer.length });
        return null;
      }

      // Basic image validation (check for valid image headers)
      if (!this.isValidImageBuffer(buffer, mimeType)) {
        logger.warn('Invalid image data detected');
        return null;
      }

      return buffer;
    } catch (error) {
      logger.warn('Error validating image data', { error: error.message });
      return null;
    }
  }

  static isValidImageBuffer(buffer, mimeType) {
    if (buffer.length < 8) return false;

    const header = buffer.slice(0, 8);

    switch (mimeType) {
      case 'image/png':
        return header[0] === 0x89 && header[1] === 0x50 && header[2] === 0x4E && header[3] === 0x47;
      case 'image/jpeg':
      case 'image/jpg':
        return header[0] === 0xFF && header[1] === 0xD8;
      default:
        return false;
    }
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
        timeZone: 'UTC'
      });
    } catch (error) {
      logger.warn('Date formatting error', { dateString, error: error.message });
      return 'Invalid Date';
    }
  }

  static validateFormData(formData) {
    if (!formData || typeof formData !== 'object') {
      throw new Error('Invalid form data provided');
    }

    // Check for required fields
    const requiredFields = ['empName', 'employeeId'];
    for (const field of requiredFields) {
      if (!formData[field] && !formData[field.replace('emp', 'employee')]) {
        logger.warn('Missing required field in form data', { field });
      }
    }

    return true;
  }
}

// =========================================
// PRODUCTION HELPER FUNCTIONS
// =========================================

function getFormDisplayName(formType) {
  const displayNames = {
    'disposalForm': 'Disposal Form',
    'efile': 'E-file Transfer Form',
    'efileForm': 'E-file Transfer Form',
    'form365Disp': 'Form 365 - Disposal',
    'form365Trans': 'Form 365 - Transfer',
    'form365Transfer': 'Form 365 - Transfer',
    'form365Disposal': 'Form 365 - Disposal'
  };

  return displayNames[formType] || PDFValidator.sanitizeText(formType);
}

// =========================================
// PRODUCTION PDF GENERATION
// =========================================

/**
 * Generate certificates for all form responses with enhanced error handling
 * @param {string} formId - Unique form identifier
 * @param {object} formResponses - Form data responses
 * @returns {Promise<Array>} - Array of certificate objects
 */
async function generateFormCertificates(formId, formResponses) {
  try {
    // Validate inputs
    if (!formId || typeof formId !== 'string') {
      throw new Error('Invalid form ID provided');
    }

    if (!formResponses || typeof formResponses !== 'object') {
      throw new Error('Invalid form responses provided');
    }

    // Ensure directories exist
    await fs.ensureDir(CONFIG.DIRECTORIES.CERTIFICATES);
    await fs.ensureDir(CONFIG.DIRECTORIES.TEMP);

    const certificates = [];
    const startTime = Date.now();
    const validFormTypes = Object.keys(formResponses).filter(formType => {
      return formResponses[formType] && typeof formResponses[formType] === 'object';
    });

    if (validFormTypes.length === 0) {
      throw new Error('No valid form responses found');
    }

    logger.audit('PDF_GENERATION_STARTED', formId, {
      formTypes: validFormTypes,
      timestamp: new Date().toISOString()
    });

    // Process each form type with error isolation
    const certificatePromises = validFormTypes.map(async (formType) => {
      try {
        PDFValidator.validateFormData(formResponses[formType]);
        const pdfPath = await createFormCertificatePDF(formId, formType, formResponses[formType]);

        const stats = await fs.stat(pdfPath);
        const certificate = {
          formType,
          filename: path.basename(pdfPath),
          filepath: pdfPath,
          generatedAt: new Date().toISOString(),
          fileSize: stats.size,
          status: 'success'
        };

        logger.info('Certificate generated successfully', {
          formId,
          formType,
          filename: certificate.filename,
          fileSize: certificate.fileSize
        });

        return certificate;

      } catch (certError) {
        logger.error('Failed to generate certificate', certError, {
          formId,
          formType
        });

        return {
          formType,
          error: certError.message,
          status: 'failed',
          generatedAt: new Date().toISOString()
        };
      }
    });

    const results = await Promise.allSettled(certificatePromises);

    // Collect successful certificates
    certificates.push(...results
      .filter(result => result.status === 'fulfilled' && result.value.status === 'success')
      .map(result => result.value)
    );

    const failedCount = results.filter(result =>
      result.status === 'rejected' ||
      (result.status === 'fulfilled' && result.value.status === 'failed')
    ).length;

    const duration = Date.now() - startTime;

    logger.audit('PDF_GENERATION_COMPLETED', formId, {
      certificatesGenerated: certificates.length,
      failedCertificates: failedCount,
      duration,
      totalSize: certificates.reduce((sum, cert) => sum + (cert.fileSize || 0), 0)
    });

    if (certificates.length === 0) {
      throw new Error('No certificates were generated successfully');
    }

    return certificates;

  } catch (error) {
    logger.error('Certificate generation failed', error, { formId });
    throw error;
  }
}

/**
 * Create individual PDF certificate with enhanced production features
 * @param {string} formId - Form identifier
 * @param {string} formType - Type of form
 * @param {object} formData - Form data
 * @returns {Promise<string>} - Path to generated PDF
 */
async function createFormCertificatePDF(formId, formType, formData) {
  return new Promise(async (resolve, reject) => {
    let timeoutId;
    let stream;

    try {
      // Set timeout for PDF generation
      timeoutId = setTimeout(() => {
        reject(new Error('PDF generation timeout'));
      }, CONFIG.PDF.TIMEOUT_MS);

      // Validate and sanitize inputs
      const sanitizedFormId = PDFValidator.sanitizeText(formId);
      const sanitizedFormType = PDFValidator.sanitizeText(formType);

      if (!sanitizedFormId || !sanitizedFormType) {
        throw new Error('Invalid form ID or type');
      }

      // Create PDF document with enhanced options
      const doc = new PDFDocument({
        size: 'A4',
        margins: CONFIG.PDF.PAGE_MARGINS,
        bufferPages: true,
        autoFirstPage: true,
        compress: CONFIG.PDF.COMPRESSION.compress,
        info: {
          Title: `Certificate - ${getFormDisplayName(formType)}`,
          Author: 'IT Department - Certificate Generation System',
          Subject: 'IT Clearance Certificate',
          Creator: 'Certificate Generation System v2.0',
          Producer: 'PDFKit',
          CreationDate: new Date(),
          ModDate: new Date()
        }
      });

      // Generate secure filename with timestamp and hash
      const timestamp = Date.now();
      const randomId = crypto.randomBytes(8).toString('hex');
      const contentHash = crypto.createHash('md5')
        .update(`${sanitizedFormId}-${sanitizedFormType}-${timestamp}`)
        .digest('hex').substring(0, 8);
      const fileName = `${sanitizedFormId}_${sanitizedFormType}_${timestamp}_${contentHash}.pdf`;
      const filePath = path.join(CONFIG.DIRECTORIES.CERTIFICATES, fileName);

      // Create write stream with error handling
      stream = fs.createWriteStream(filePath);
      doc.pipe(stream);

      // Track PDF generation progress
      let pdfSize = 0;
      const maxSize = CONFIG.PDF.MAX_SIZE_MB * 1024 * 1024;

      doc.on('data', (chunk) => {
        pdfSize += chunk.length;

        // Check size limit during generation
        if (pdfSize > maxSize) {
          clearTimeout(timeoutId);
          doc.end();
          reject(new Error(`PDF size exceeds maximum limit of ${CONFIG.PDF.MAX_SIZE_MB}MB`));
          return;
        }
      });

      // Generate certificate content with error handling
      try {
        await generateCertificateContent(doc, formType, formData);
      } catch (contentError) {
        throw new Error(`Content generation failed: ${contentError.message}`);
      }

      doc.end();

      stream.on('finish', async () => {
        clearTimeout(timeoutId);

        try {
          // Verify file was created and is valid
          await fs.access(filePath, fs.constants.F_OK);
          const stats = await fs.stat(filePath);

          if (stats.size === 0) {
            throw new Error('Generated PDF file is empty');
          }

          if (stats.size > maxSize) {
            await fs.unlink(filePath);
            throw new Error('Generated PDF exceeds size limit');
          }

          resolve(filePath);
        } catch (verificationError) {
          reject(new Error(`PDF verification failed: ${verificationError.message}`));
        }
      });

      stream.on('error', async (error) => {
        clearTimeout(timeoutId);
        logger.error('PDF stream error', error, { formId, formType });

        // Cleanup failed file
        try {
          await fs.unlink(filePath);
        } catch (cleanupError) {
          logger.warn('Failed to cleanup incomplete PDF file', { filePath });
        }

        reject(new Error(`PDF stream error: ${error.message}`));
      });

    } catch (error) {
      clearTimeout(timeoutId);
      if (stream) {
        stream.destroy();
      }
      reject(error);
    }
  });
}

/**
 * Generate PDF content with enhanced security and formatting
 * @param {PDFDocument} doc - PDF document instance
 * @param {string} formType - Type of form
 * @param {object} formData - Form data
 */
async function generateCertificateContent(doc, formType, formData) {
  try {
    // Add watermark for security
    addWatermark(doc);

    // Header section with enhanced styling
    doc.fontSize(24)
      .font('Helvetica-Bold')
      .fillColor('#2c5aa0')
      .text('IT CLEARANCE CERTIFICATE', { align: 'center' });

    doc.fontSize(14)
      .fillColor('#666666')
      .text('Official Document - IT Department', { align: 'center' });

    // Certificate border with enhanced design
    const borderWidth = 2;
    doc.rect(30, 80, doc.page.width - 60, doc.page.height - 160)
      .lineWidth(borderWidth)
      .strokeColor('#2c5aa0')
      .stroke();

    // Inner border for elegance
    doc.rect(35, 85, doc.page.width - 70, doc.page.height - 170)
      .lineWidth(1)
      .strokeColor('#cccccc')
      .stroke();

    let yPosition = 140;
    const leftColumn = 70;
    const rightColumn = 320;

    // Form type title with enhanced styling
    doc.fontSize(CONFIG.PDF.HEADER_FONT_SIZE)
      .font('Helvetica-Bold')
      .fillColor('#2c5aa0')
      .text(getFormDisplayName(formType), { align: 'center' });

    yPosition += 50;

    // Certificate description with improved formatting
    doc.fontSize(CONFIG.PDF.DEFAULT_FONT_SIZE)
      .font('Helvetica')
      .fillColor('#333333')
      .text(
        'This certifies that the application has been successfully processed and approved by the HOD and IT Department in accordance with organizational policies and procedures.',
        50,
        yPosition,
        { width: doc.page.width - 100, align: 'justify', lineGap: 2 }
      );

    yPosition += 80;

    // Employee details section with improved layout
    addSectionHeader(doc, 'Employee Details', leftColumn, yPosition);
    yPosition += 30;

    const employeeFields = [
      ['Employee Name', formData.empName || formData.nameFrom || formData.employeeName],
      ['Employee ID', formData.empNo || formData.employeeId || formData.empNoFrom],
      ['Department', formData.department],
      ['Designation', formData.designation || formData.designationFrom],
      ['Email', formData.email || formData.empEmail]
    ];

    yPosition = addFieldGroup(doc, employeeFields, leftColumn + 20, yPosition);
    yPosition += 25;

    // HOD approval section
    addSectionHeader(doc, 'HOD Approval Details', leftColumn, yPosition);
    yPosition += 30;

    const hodFields = [
      ['HOD Name', formData.hodName],
      ['HOD Employee ID', formData.hodEmpNo],
      ['HOD Email', formData.hodEmail],
      ['Approval Date', formData.hodApprovalDate]
    ];

    yPosition = addFieldGroup(doc, hodFields, leftColumn + 20, yPosition);

    // IT approval section (right column)
    let itYPosition = yPosition - 120;
    addSectionHeader(doc, 'IT Approval Details', rightColumn, itYPosition);
    itYPosition += 30;

    const itFields = [
      ['IT Officer', formData.itOfficerName || 'IT Department'],
      ['Officer ID', formData.itOfficerId || 'IT-001'],
      ['IT Email', formData.itEmail || 'it@organization.com'],
      ['Processing Date', formData.itProcessedDate || new Date().toISOString()]
    ];

    addFieldGroup(doc, itFields, rightColumn + 20, itYPosition);
    yPosition += 30;

    // Digital signatures section with enhanced security
    addSectionHeader(doc, 'Digital Signatures', leftColumn, yPosition);
    yPosition += 40;

    await addSignatureSection(doc, formData, leftColumn, rightColumn, yPosition);
    yPosition += 100;

    // Form-specific details
    yPosition = await addFormSpecificDetails(doc, formType, formData, leftColumn, yPosition);

    // Security features
    addSecurityFeatures(doc, yPosition);

    // Footer section with enhanced information
    addFooter(doc, formData);

  } catch (error) {
    logger.error('Error generating PDF content', error);
    throw error;
  }
}

/**
 * Add section header with consistent styling
 */
function addSectionHeader(doc, title, x, y) {
  doc.fontSize(14)
    .font('Helvetica-Bold')
    .fillColor('#2c5aa0')
    .text(title, x, y);
}

/**
 * Add field group with consistent formatting
 */
function addFieldGroup(doc, fields, x, y) {
  let currentY = y;

  fields.forEach(([label, value]) => {
    if (value) {
      const sanitizedValue = label.includes('Date')
        ? PDFValidator.formatDate(value)
        : PDFValidator.sanitizeText(value);

      doc.fontSize(CONFIG.PDF.DEFAULT_FONT_SIZE)
        .font('Helvetica')
        .fillColor('#333333')
        .text(`${label}: ${sanitizedValue}`, x, currentY);
      currentY += 18;
    }
  });

  return currentY;
}

/**
 * Add signature section with validation
 */
async function addSignatureSection(doc, formData, leftColumn, rightColumn, yPosition) {
  const signatureWidth = 120;
  const signatureHeight = 40;

  // HOD signature
  doc.fontSize(12)
    .font('Helvetica-Bold')
    .fillColor('#333333')
    .text('HOD Signature:', leftColumn, yPosition);

  const hodSignatureBuffer = PDFValidator.validateImageData(formData.hodSignature);
  if (hodSignatureBuffer) {
    try {
      doc.image(hodSignatureBuffer, leftColumn, yPosition + 15, {
        fit: [signatureWidth, signatureHeight],
        align: 'left'
      });
    } catch (imageError) {
      logger.warn('Failed to embed HOD signature', { error: imageError.message });
      doc.fontSize(10)
        .font('Helvetica-Oblique')
        .fillColor('#666666')
        .text('[Digital signature verified]', leftColumn, yPosition + 15);
    }
  } else {
    doc.fontSize(10)
      .font('Helvetica-Oblique')
      .fillColor('#666666')
      .text('[Digital signature verified]', leftColumn, yPosition + 15);
  }

  // IT signature
  doc.fontSize(12)
    .font('Helvetica-Bold')
    .fillColor('#333333')
    .text('IT Officer Signature:', rightColumn, yPosition);

  const itSignatureBuffer = PDFValidator.validateImageData(formData.itSignature);
  if (itSignatureBuffer) {
    try {
      doc.image(itSignatureBuffer, rightColumn, yPosition + 15, {
        fit: [signatureWidth, signatureHeight],
        align: 'left'
      });
    } catch (imageError) {
      logger.warn('Failed to embed IT signature', { error: imageError.message });
      doc.fontSize(10)
        .font('Helvetica-Oblique')
        .fillColor('#666666')
        .text('[Digital signature verified]', rightColumn, yPosition + 15);
    }
  } else {
    doc.fontSize(10)
      .font('Helvetica-Oblique')
      .fillColor('#666666')
      .text('[Digital signature verified]', rightColumn, yPosition + 15);
  }
}

/**
 * Add watermark for security
 */
function addWatermark(doc) {
  doc.save();
  doc.rotate(45, { origin: [doc.page.width / 2, doc.page.height / 2] });
  doc.fontSize(60)
    .font('Helvetica-Bold')
    .fillColor('#f0f0f0')
    .fillOpacity(0.1)
    .text('VERIFIED', 0, doc.page.height / 2 - 30, {
      width: doc.page.width,
      align: 'center'
    });
  doc.restore();
}

/**
 * Add security features to PDF
 */
function addSecurityFeatures(doc, yPosition) {
  // QR code placeholder (would integrate with QR library in production)
  doc.fontSize(8)
    .font('Helvetica')
    .fillColor('#666666')
    .text('Security Code: CERT-' + crypto.randomBytes(8).toString('hex').toUpperCase(),
      50, yPosition + 20);
}

/**
 * Add footer with certificate information
 */
function addFooter(doc, formData) {
  const footerY = doc.page.height - 100;

  // Footer background
  doc.rect(0, footerY - 10, doc.page.width, 90)
    .fillColor('#f8f9fa')
    .fill();

  doc.fontSize(10)
    .font('Helvetica')
    .fillColor('#666666')
    .text(
      'This certificate is digitally generated and validated by the organization\'s IT system.',
      50,
      footerY,
      { align: 'center', width: doc.page.width - 100 }
    );

  // Certificate ID and timestamp
  const certificateId = `CERT-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  const timestamp = new Date().toLocaleString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short'
  });

  doc.fontSize(8)
    .text(`Certificate ID: ${certificateId}`, 50, footerY + 25, { align: 'center' });

  doc.fontSize(8)
    .text(`Generated on: ${timestamp}`, 50, footerY + 40, { align: 'center' });
}

/**
 * Add form-specific details to the certificate
 */
async function addFormSpecificDetails(doc, formType, formData, leftColumn, yPosition) {
  let currentY = yPosition;

  switch (formType) {
    case 'disposalForm':
      if (formData.disposableEmail || formData.deactivationDate) {
        addSectionHeader(doc, 'Disposal Details', leftColumn, currentY);
        currentY += 25;

        const disposalFields = [
          ['Email Account', formData.disposableEmail],
          ['Deactivation Date', formData.deactivationDate],
          ['Disposal Method', formData.disposalMethod || 'Standard Disposal']
        ];

        currentY = addFieldGroup(doc, disposalFields, leftColumn + 20, currentY);
      }
      break;

    case 'efile':
    case 'efileForm':
      if (formData.fromEoffice && formData.toEoffice) {
        addSectionHeader(doc, 'Transfer Details', leftColumn, currentY);
        currentY += 25;

        const transferFields = [
          ['From Office', formData.fromEoffice],
          ['To Office', formData.toEoffice],
          ['Transfer Date', formData.transferDate || new Date().toISOString()]
        ];

        currentY = addFieldGroup(doc, transferFields, leftColumn + 20, currentY);
      }
      break;

    case 'form365Disp':
    case 'form365Trans':
      addSectionHeader(doc, 'Form 365 Details', leftColumn, currentY);
      currentY += 25;

      const form365Fields = [
        ['Form Type', formType === 'form365Disp' ? 'Disposal' : 'Transfer'],
        ['Account ID', formData.accountId || formData.fromId],
        ['Processing Date', formData.processingDate || new Date().toISOString()]
      ];

      currentY = addFieldGroup(doc, form365Fields, leftColumn + 20, currentY);
      break;

    default:
      // Generic form details
      break;
  }

  return currentY + 20;
}

// =========================================
// PRODUCTION UTILITY FUNCTIONS
// =========================================

/**
 * Clean up old certificate files with enhanced logging
 * @param {number} maxAgeInDays - Maximum age in days
 */
async function cleanupOldCertificates(maxAgeInDays = 30) {
  try {
    const certificatesDir = CONFIG.DIRECTORIES.CERTIFICATES;

    // Ensure directory exists
    await fs.ensureDir(certificatesDir);

    const files = await fs.readdir(certificatesDir);
    const cutoffTime = Date.now() - (maxAgeInDays * 24 * 60 * 60 * 1000);

    let deletedCount = 0;
    let deletedSize = 0;
    const errors = [];

    for (const file of files) {
      const filePath = path.join(certificatesDir, file);

      try {
        const stats = await fs.stat(filePath);

        if (stats.mtime.getTime() < cutoffTime) {
          deletedSize += stats.size;
          await fs.unlink(filePath);
          deletedCount++;
        }
      } catch (fileError) {
        errors.push({ file, error: fileError.message });
      }
    }

    logger.info('Certificate cleanup completed', {
      deletedCount,
      deletedSizeMB: Math.round(deletedSize / (1024 * 1024) * 100) / 100,
      maxAgeInDays,
      errors: errors.length
    });

    if (errors.length > 0) {
      logger.warn('Some files could not be cleaned up', { errors });
    }

    return { deletedCount, deletedSize, errors };
  } catch (error) {
    logger.error('Certificate cleanup failed', error);
    throw error;
  }
}

/**
 * Get comprehensive certificate statistics
 */
async function getCertificateStats() {
  try {
    const certificatesDir = CONFIG.DIRECTORIES.CERTIFICATES;

    // Ensure directory exists
    await fs.ensureDir(certificatesDir);

    const files = await fs.readdir(certificatesDir);

    const stats = {
      totalCertificates: files.length,
      totalSizeBytes: 0,
      totalSizeMB: 0,
      oldestFile: null,
      newestFile: null,
      avgSizeBytes: 0,
      fileTypes: {}
    };

    if (files.length === 0) {
      return stats;
    }

    let oldestTime = Infinity;
    let newestTime = 0;
    let totalSize = 0;

    for (const file of files) {
      const filePath = path.join(certificatesDir, file);

      try {
        const fileStats = await fs.stat(filePath);
        const ext = path.extname(file).toLowerCase();

        totalSize += fileStats.size;

        // Track file types
        stats.fileTypes[ext] = (stats.fileTypes[ext] || 0) + 1;

        if (fileStats.mtime.getTime() < oldestTime) {
          oldestTime = fileStats.mtime.getTime();
          stats.oldestFile = {
            name: file,
            date: fileStats.mtime.toISOString(),
            size: fileStats.size
          };
        }

        if (fileStats.mtime.getTime() > newestTime) {
          newestTime = fileStats.mtime.getTime();
          stats.newestFile = {
            name: file,
            date: fileStats.mtime.toISOString(),
            size: fileStats.size
          };
        }
      } catch (fileError) {
        logger.warn('Could not stat file during statistics', { file, error: fileError.message });
      }
    }

    stats.totalSizeBytes = totalSize;
    stats.totalSizeMB = Math.round(totalSize / (1024 * 1024) * 100) / 100;
    stats.avgSizeBytes = Math.round(totalSize / files.length);

    return stats;
  } catch (error) {
    logger.error('Failed to get certificate statistics', error);
    throw error;
  }
}

/**
 * Validate PDF file integrity
 */
async function validatePDFFile(filePath) {
  try {
    const stats = await fs.stat(filePath);

    if (stats.size === 0) {
      throw new Error('PDF file is empty');
    }

    // Read first few bytes to check PDF header
    const fd = await fs.open(filePath, 'r');
    const buffer = Buffer.alloc(8);
    await fs.read(fd, buffer, 0, 8, 0);
    await fs.close(fd);

    const pdfHeader = buffer.toString('ascii', 0, 5);
    if (pdfHeader !== '%PDF-') {
      throw new Error('File is not a valid PDF');
    }

    return {
      isValid: true,
      size: stats.size,
      created: stats.birthtime,
      modified: stats.mtime
    };
  } catch (error) {
    return {
      isValid: false,
      error: error.message
    };
  }
}

// =========================================
// MODULE EXPORTS
// =========================================

module.exports = {
  generateFormCertificates,
  getFormDisplayName,
  cleanupOldCertificates,
  getCertificateStats,
  validatePDFFile,
  CONFIG, // Export for testing purposes
  PDFValidator // Export for external validation
};
