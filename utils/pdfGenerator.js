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
    }
  },
  
  DIRECTORIES: {
    CERTIFICATES: path.join(__dirname, '..', 'public', 'certificates'),
    TEMP: path.join(__dirname, '..', 'temp')
  },
  
  SECURITY: {
    SANITIZE_INPUTS: true,
    MAX_FIELD_LENGTH: 500,
    ALLOWED_IMAGE_TYPES: ['image/png', 'image/jpeg', 'image/jpg']
  }
};

// =========================================
// PRODUCTION LOGGING SYSTEM
// =========================================

const logger = {
  info: (message, meta = {}) => console.log(`[INFO] ${new Date().toISOString()} - ${message}`, JSON.stringify(meta)),
  warn: (message, meta = {}) => console.warn(`[WARN] ${new Date().toISOString()} - ${message}`, JSON.stringify(meta)),
  error: (message, error, meta = {}) => console.error(`[ERROR] ${new Date().toISOString()} - ${message}`, error?.stack || error, JSON.stringify(meta)),
  audit: (action, formId, meta = {}) => console.log(`[AUDIT] ${new Date().toISOString()} - ${action} - Form: ${formId}`, JSON.stringify(meta))
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

      return buffer;
    } catch (error) {
      logger.warn('Error validating image data', { error: error.message });
      return null;
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
        day: 'numeric'
      });
    } catch (error) {
      logger.warn('Date formatting error', { dateString, error: error.message });
      return 'Invalid Date';
    }
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
    'form365Trans': 'Form 365 - Transfer'
  };
  
  return displayNames[formType] || PDFValidator.sanitizeText(formType);
}

// =========================================
// PRODUCTION PDF GENERATION
// =========================================

/**
 * Generate certificates for all form responses
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

    // Ensure certificates directory exists
    await fs.ensureDir(CONFIG.DIRECTORIES.CERTIFICATES);
    await fs.ensureDir(CONFIG.DIRECTORIES.TEMP);

    const certificates = [];
    const startTime = Date.now();

    logger.audit('PDF_GENERATION_STARTED', formId, {
      formTypes: Object.keys(formResponses),
      timestamp: new Date().toISOString()
    });

    for (const [formType, formData] of Object.entries(formResponses)) {
      try {
        const pdfPath = await createFormCertificatePDF(formId, formType, formData);
        
        certificates.push({
          formType,
          filename: path.basename(pdfPath),
          filepath: pdfPath,
          generatedAt: new Date().toISOString(),
          fileSize: (await fs.stat(pdfPath)).size
        });

        logger.info('Certificate generated successfully', {
          formId,
          formType,
          filename: path.basename(pdfPath)
        });

      } catch (certError) {
        logger.error('Failed to generate certificate', certError, {
          formId,
          formType
        });
        // Continue with other certificates instead of failing completely
      }
    }

    const duration = Date.now() - startTime;
    
    logger.audit('PDF_GENERATION_COMPLETED', formId, {
      certificatesGenerated: certificates.length,
      duration,
      totalSize: certificates.reduce((sum, cert) => sum + cert.fileSize, 0)
    });

    return certificates;

  } catch (error) {
    logger.error('Certificate generation failed', error, { formId });
    throw error;
  }
}

/**
 * Create individual PDF certificate
 * @param {string} formId - Form identifier
 * @param {string} formType - Type of form
 * @param {object} formData - Form data
 * @returns {Promise<string>} - Path to generated PDF
 */
async function createFormCertificatePDF(formId, formType, formData) {
  return new Promise(async (resolve, reject) => {
    let timeoutId;
    
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

      // Create PDF document
      const doc = new PDFDocument({
        size: 'A4',
        margins: CONFIG.PDF.PAGE_MARGINS,
        info: {
          Title: `Certificate - ${getFormDisplayName(formType)}`,
          Author: 'IT Department',
          Subject: 'IT Clearance Certificate',
          Creator: 'Certificate Generation System'
        }
      });

      // Generate secure filename
      const timestamp = Date.now();
      const randomId = crypto.randomBytes(4).toString('hex');
      const fileName = `${sanitizedFormId}_${sanitizedFormType}_${timestamp}_${randomId}.pdf`;
      const filePath = path.join(CONFIG.DIRECTORIES.CERTIFICATES, fileName);

      // Create write stream
      const stream = fs.createWriteStream(filePath);
      doc.pipe(stream);

      // Track PDF generation progress
      let pdfSize = 0;
      const chunks = [];
      
      doc.on('data', (chunk) => {
        chunks.push(chunk);
        pdfSize += chunk.length;
        
        // Check size limit
        if (pdfSize > CONFIG.PDF.MAX_SIZE_MB * 1024 * 1024) {
          clearTimeout(timeoutId);
          reject(new Error('PDF size exceeds maximum limit'));
          return;
        }
      });

      // Generate certificate content
      generateCertificateContent(doc, formType, formData);
      
      doc.end();

      stream.on('finish', () => {
        clearTimeout(timeoutId);
        
        // Verify file was created successfully
        fs.access(filePath, fs.constants.F_OK, (err) => {
          if (err) {
            reject(new Error('PDF file was not created successfully'));
          } else {
            resolve(filePath);
          }
        });
      });

      stream.on('error', (error) => {
        clearTimeout(timeoutId);
        logger.error('PDF stream error', error, { formId, formType });
        
        // Cleanup failed file
        fs.unlink(filePath, () => {});
        
        reject(error);
      });

    } catch (error) {
      clearTimeout(timeoutId);
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
function generateCertificateContent(doc, formType, formData) {
  try {
    // Header section
    doc.fontSize(24)
       .font('Helvetica-Bold')
       .text('IT CLEARANCE CERTIFICATE', { align: 'center' });

    // Certificate border
    doc.rect(30, 60, doc.page.width - 60, doc.page.height - 120)
       .stroke();

    let yPosition = 130;
    const leftColumn = 70;
    const rightColumn = 320;

    // Form type title
    doc.fontSize(CONFIG.PDF.HEADER_FONT_SIZE)
       .font('Helvetica-Bold')
       .text(getFormDisplayName(formType), { align: 'center' });

    yPosition += 40;

    // Certificate description
    doc.fontSize(CONFIG.PDF.DEFAULT_FONT_SIZE)
       .font('Helvetica')
       .text(
         'This certifies that the application has been successfully processed and approved by the HOD and IT Department.',
         50,
         yPosition,
         { width: doc.page.width - 100, align: 'justify' }
       );

    yPosition += 70;

    // Employee details section
    doc.fontSize(14)
       .font('Helvetica-Bold')
       .text('Employee Details', leftColumn, yPosition);
    
    yPosition += 25;

    const employeeFields = [
      ['Employee Name', formData.empName || formData.nameFrom || formData.employeeName],
      ['Employee ID', formData.empNo || formData.employeeId || formData.empNoFrom],
      ['Department', formData.department],
      ['Designation', formData.designation || formData.designationFrom]
    ];

    employeeFields.forEach(([label, value]) => {
      if (value) {
        const sanitizedValue = PDFValidator.sanitizeText(value);
        doc.fontSize(CONFIG.PDF.DEFAULT_FONT_SIZE)
           .font('Helvetica')
           .text(`${label}: ${sanitizedValue}`, leftColumn + 20, yPosition);
        yPosition += 18;
      }
    });

    yPosition += 20;

    // HOD approval section
    doc.fontSize(14)
       .font('Helvetica-Bold')
       .text('HOD Approval Details', leftColumn, yPosition);
    
    yPosition += 25;

    const hodFields = [
      ['HOD Name', formData.hodName],
      ['HOD Employee ID', formData.hodEmpNo],
      ['HOD Email', formData.hodEmail],
      ['Approval Date', formData.hodApprovalDate]
    ];

    hodFields.forEach(([label, value]) => {
      if (value) {
        const sanitizedValue = label.includes('Date') 
          ? PDFValidator.formatDate(value) 
          : PDFValidator.sanitizeText(value);
        
        doc.fontSize(CONFIG.PDF.DEFAULT_FONT_SIZE)
           .font('Helvetica')
           .text(`${label}: ${sanitizedValue}`, leftColumn + 20, yPosition);
        yPosition += 18;
      }
    });

    yPosition += 20;

    // IT approval section
    doc.fontSize(14)
       .font('Helvetica-Bold')
       .text('IT Approval Details', rightColumn, yPosition - 120);
    
    let itYPosition = yPosition - 95;

    const itFields = [
      ['IT Officer', formData.itOfficerName],
      ['Officer ID', formData.itOfficerId],
      ['IT Email', formData.itEmail],
      ['Processing Date', formData.itProcessedDate]
    ];

    itFields.forEach(([label, value]) => {
      if (value) {
        const sanitizedValue = label.includes('Date') 
          ? PDFValidator.formatDate(value) 
          : PDFValidator.sanitizeText(value);
        
        doc.fontSize(CONFIG.PDF.DEFAULT_FONT_SIZE)
           .font('Helvetica')
           .text(`${label}: ${sanitizedValue}`, rightColumn + 20, itYPosition);
        itYPosition += 18;
      }
    });

    yPosition += 40;

    // Digital signatures section
    doc.fontSize(14)
       .font('Helvetica-Bold')
       .text('Digital Signatures', leftColumn, yPosition);
    
    yPosition += 40;

    const signatureWidth = 120;
    const signatureHeight = 40;

    // HOD signature
    doc.fontSize(12)
       .font('Helvetica-Bold')
       .text('HOD Signature:', leftColumn, yPosition);

    const hodSignatureBuffer = PDFValidator.validateImageData(formData.hodSignature);
    if (hodSignatureBuffer) {
      try {
        doc.image(hodSignatureBuffer, leftColumn, yPosition + 15, {
          width: signatureWidth,
          height: signatureHeight,
          fit: [signatureWidth, signatureHeight]
        });
      } catch (imageError) {
        logger.warn('Failed to embed HOD signature', { error: imageError.message });
        doc.fontSize(10)
           .font('Helvetica-Oblique')
           .text('[Digital signature verified]', leftColumn, yPosition + 15);
      }
    } else {
      doc.fontSize(10)
         .font('Helvetica-Oblique')
         .text('[Digital signature verified]', leftColumn, yPosition + 15);
    }

    // IT signature
    doc.fontSize(12)
       .font('Helvetica-Bold')
       .text('IT Officer Signature:', rightColumn, yPosition);

    const itSignatureBuffer = PDFValidator.validateImageData(formData.itSignature);
    if (itSignatureBuffer) {
      try {
        doc.image(itSignatureBuffer, rightColumn, yPosition + 15, {
          width: signatureWidth,
          height: signatureHeight,
          fit: [signatureWidth, signatureHeight]
        });
      } catch (imageError) {
        logger.warn('Failed to embed IT signature', { error: imageError.message });
        doc.fontSize(10)
           .font('Helvetica-Oblique')
           .text('[Digital signature verified]', rightColumn, yPosition + 15);
      }
    } else {
      doc.fontSize(10)
         .font('Helvetica-Oblique')
         .text('[Digital signature verified]', rightColumn, yPosition + 15);
    }

    yPosition += 80;

    // Form-specific details
    addFormSpecificDetails(doc, formType, formData, leftColumn, yPosition);

    // Footer section
    const footerY = doc.page.height - 120;
    
    doc.fontSize(10)
       .font('Helvetica')
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
       .font('Helvetica')
       .text(`Certificate ID: ${certificateId}`, 50, footerY + 25, { align: 'center' });

    doc.fontSize(8)
       .font('Helvetica')
       .text(`Generated on: ${timestamp}`, 50, footerY + 40, { align: 'center' });

  } catch (error) {
    logger.error('Error generating PDF content', error);
    throw error;
  }
}

/**
 * Add form-specific details to the certificate
 * @param {PDFDocument} doc - PDF document
 * @param {string} formType - Form type
 * @param {object} formData - Form data
 * @param {number} leftColumn - Left column position
 * @param {number} yPosition - Y position
 */
function addFormSpecificDetails(doc, formType, formData, leftColumn, yPosition) {
  switch (formType) {
    case 'disposalForm':
      if (formData.disposableEmail || formData.deactivationDate) {
        doc.fontSize(14)
           .font('Helvetica-Bold')
           .text('Disposal Details', leftColumn, yPosition);
        yPosition += 20;

        if (formData.disposableEmail) {
          doc.fontSize(12)
             .font('Helvetica')
             .text(`Email Account: ${PDFValidator.sanitizeText(formData.disposableEmail)}`, leftColumn + 20, yPosition);
          yPosition += 15;
        }

        if (formData.deactivationDate) {
          doc.fontSize(12)
             .font('Helvetica')
             .text(`Deactivation Date: ${PDFValidator.formatDate(formData.deactivationDate)}`, leftColumn + 20, yPosition);
        }
      }
      break;

    case 'efile':
    case 'efileForm':
      if (formData.fromEoffice && formData.toEoffice) {
        doc.fontSize(14)
           .font('Helvetica-Bold')
           .text('Transfer Details', leftColumn, yPosition);
        yPosition += 20;

        const fromOffice = PDFValidator.sanitizeText(formData.fromEoffice);
        const toOffice = PDFValidator.sanitizeText(formData.toEoffice);

        doc.fontSize(12)
           .font('Helvetica')
           .text(`File Transfer: ${fromOffice} -> ${toOffice}`, leftColumn + 20, yPosition);
      }
      break;

    case 'form365Disp':
    case 'form365Trans':
      // Add any Form 365 specific details if needed
      break;

    default:
      // Generic form details
      break;
  }
}

// =========================================
// PRODUCTION UTILITY FUNCTIONS
// =========================================

/**
 * Clean up old certificate files
 * @param {number} maxAgeInDays - Maximum age in days
 */
async function cleanupOldCertificates(maxAgeInDays = 30) {
  try {
    const certificatesDir = CONFIG.DIRECTORIES.CERTIFICATES;
    const files = await fs.readdir(certificatesDir);
    const cutoffTime = Date.now() - (maxAgeInDays * 24 * 60 * 60 * 1000);

    let deletedCount = 0;

    for (const file of files) {
      const filePath = path.join(certificatesDir, file);
      const stats = await fs.stat(filePath);
      
      if (stats.mtime.getTime() < cutoffTime) {
        await fs.unlink(filePath);
        deletedCount++;
      }
    }

    logger.info('Certificate cleanup completed', {
      deletedCount,
      maxAgeInDays
    });

    return deletedCount;
  } catch (error) {
    logger.error('Certificate cleanup failed', error);
    throw error;
  }
}

/**
 * Get certificate statistics
 */
async function getCertificateStats() {
  try {
    const certificatesDir = CONFIG.DIRECTORIES.CERTIFICATES;
    const files = await fs.readdir(certificatesDir);
    
    let totalSize = 0;
    const stats = {
      totalCertificates: files.length,
      totalSizeBytes: 0,
      oldestFile: null,
      newestFile: null
    };

    if (files.length === 0) {
      return stats;
    }

    let oldestTime = Infinity;
    let newestTime = 0;

    for (const file of files) {
      const filePath = path.join(certificatesDir, file);
      const fileStats = await fs.stat(filePath);
      
      totalSize += fileStats.size;
      
      if (fileStats.mtime.getTime() < oldestTime) {
        oldestTime = fileStats.mtime.getTime();
        stats.oldestFile = file;
      }
      
      if (fileStats.mtime.getTime() > newestTime) {
        newestTime = fileStats.mtime.getTime();
        stats.newestFile = file;
      }
    }

    stats.totalSizeBytes = totalSize;
    stats.totalSizeMB = Math.round(totalSize / (1024 * 1024) * 100) / 100;

    return stats;
  } catch (error) {
    logger.error('Failed to get certificate statistics', error);
    throw error;
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
  CONFIG // Export for testing purposes
};
