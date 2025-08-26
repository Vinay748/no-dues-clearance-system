const express = require('express');
const multer = require('multer');
const { loadJSON, saveJSON } = require('../utils/fileUtils');
const { roleAuth } = require('../middlewares/sessionAuth');

const router = express.Router();

const PENDING_FORMS = './data/pending_forms.json';
const HOD_SIGNATURES = './data/hod_signatures.json';

// Multer setup for signature uploads with enhanced validation
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});

// Enhanced file upload validation
const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
    files: 1 // Only one file at a time
  },
  fileFilter: (req, file, cb) => {
    // Only allow image files for signatures
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only image files (JPEG, PNG, GIF) are allowed for signatures'));
    }
  }
});

// Helper to get latest form with allowed statuses (for consistency with employee.js)
function getLatestFormForEmployee(allForms, employeeId, allowedStatuses = []) {
  let forms = allForms.filter(f => f && f.employeeId === employeeId);
  if (allowedStatuses.length) {
    forms = forms.filter(f => allowedStatuses.includes(f.status));
  }
  return forms.sort((a, b) => new Date(b.submissionDate || b.lastUpdated) - new Date(a.submissionDate || a.lastUpdated))[0] || null;
}

// GET HOD's own details for prefilling forms
router.get('/my-details', roleAuth('hod'), (req, res) => {
  try {
    const sessionUser = req.session?.user;

    if (!sessionUser || sessionUser.role !== 'hod') {
      return res.status(401).json({
        success: false,
        message: 'HOD authentication required'
      });
    }

    // Return HOD's own details for prefilling
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
      }
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching HOD details'
    });
  }
});

// HOD Profile endpoint
router.get('/profile', roleAuth('hod'), (req, res) => {
  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) {
      return res.status(401).json({ success: false, message: 'Session expired' });
    }

    res.json({
      success: true,
      hodData: {
        name: sessionUser.name,
        employeeId: sessionUser.employeeId || sessionUser.id,
        email: sessionUser.email,
        department: sessionUser.department,
        designation: sessionUser.designation || 'HOD'
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error fetching profile' });
  }
});

// HOD signature endpoint
router.get('/get-signature', roleAuth('hod'), (req, res) => {
  try {
    const { id: hodId, name } = req.session.user;
    let signatures = [];
    try {
      signatures = loadJSON(HOD_SIGNATURES);
    } catch {
      // No existing signatures file
    }
    const signature = signatures.find(s => s.hodId === hodId);
    if (!signature) {
      return res.status(404).json({
        success: false,
        message: 'No signature found. Please upload a signature first.'
      });
    }
    res.json({
      success: true,
      signature: signature.filename,
      signatureUrl: `/uploads/${signature.filename}`,
      hodName: name
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error fetching signature' });
  }
});

// Form details route (backward compatibility)
router.get('/form-details', roleAuth('hod'), (req, res) => {
  const { formId } = req.query;
  if (!formId) return res.status(400).json({ success: false, message: 'Missing formId' });

  try {
    const pendingForms = loadJSON(PENDING_FORMS);
    const form = pendingForms.find(f => f.formId === formId);
    const sessionUser = req.session?.user;

    if (!form) {
      return res.status(404).json({ success: false, message: 'Form not found' });
    }

    // Include HOD details in response
    const response = {
      success: true,
      form: {
        ...form,
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
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error fetching form details' });
  }
});

// Form details route for hod-form-review.html with HOD prefill
router.get('/form-details/:formId', roleAuth('hod'), (req, res) => {
  const { formId } = req.params;
  if (!formId) return res.status(400).json({ success: false, message: 'Missing formId' });

  try {
    const pendingForms = loadJSON(PENDING_FORMS);
    const form = pendingForms.find(f => f.formId === formId);
    const sessionUser = req.session?.user;

    if (!form) return res.status(404).json({ success: false, message: 'Form not found' });

    res.json({
      success: true,
      form: {
        ...form,
        // ADD HOD DETAILS FOR AUTO-FILL
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
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error fetching form details' });
  }
});

// Get ALL forms regardless of status (for tab functionality)
router.get('/all', roleAuth('hod'), (req, res) => {
  try {
    const allForms = loadJSON(PENDING_FORMS);
    res.json({ success: true, data: allForms });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch all forms' });
  }
});

// Get pending forms for HOD approval (existing - only returns pending)
router.get('/pending', roleAuth('hod'), (req, res) => {
  try {
    const pendingForms = loadJSON(PENDING_FORMS);
    const forms = pendingForms.filter(f => f.status === 'Submitted to HOD');
    res.json({ success: true, data: forms });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch pending forms' });
  }
});

// Enhanced form validation middleware
const validateFormSubmission = (req, res, next) => {
  const { formId, formResponses } = req.body;

  if (!formId || !formResponses) {
    return res.status(400).json({
      success: false,
      message: 'Missing required fields: formId and formResponses'
    });
  }

  // Parse formResponses if it's a string
  try {
    if (typeof formResponses === 'string') {
      req.body.formResponses = JSON.parse(formResponses);
    }
  } catch (error) {
    return res.status(400).json({
      success: false,
      message: 'Invalid formResponses format'
    });
  }

  next();
};

// Final approval route with comprehensive HOD data storage
router.post('/final-approve', roleAuth('hod'), validateFormSubmission, (req, res) => {
  try {
    let { formId, formResponses, action, remarks } = req.body;

    const forms = loadJSON(PENDING_FORMS);
    const formIndex = forms.findIndex(f => f.formId === formId);
    if (formIndex === -1) {
      return res.status(404).json({ success: false, message: 'Form not found' });
    }

    const form = forms[formIndex];
    const sessionUser = req.session.user;

    const requiredForms = ['disposalForm', 'efileForm'];
    const form365Key = formResponses.form365Trans ? 'form365Trans' : 'form365Disp';
    requiredForms.push(form365Key);

    // Enhanced form validation
    for (const formKey of requiredForms) {
      const formData = formResponses[formKey];
      if (!formData || Object.keys(formData).length === 0) {
        return res.status(400).json({
          success: false,
          message: `Missing or empty ${formKey} data`
        });
      }

      const hasHodData = Object.keys(formData).some(key =>
        key.toLowerCase().includes('hod') ||
        key.includes('hodSignature') ||
        key.includes('hodName') ||
        key.includes('hodEmp')
      );

      if (!hasHodData) {
        return res.status(400).json({
          success: false,
          message: `HOD section not completed for ${formKey}`
        });
      }
    }

    form.formResponses = formResponses;
    form.status = 'Submitted to IT';

    // Store comprehensive HOD details
    form.hodApproval = {
      approvedBy: sessionUser.name,
      approverEmployeeId: sessionUser.employeeId || sessionUser.id,
      approverEmail: sessionUser.email,
      approverDepartment: sessionUser.department || 'Academic Department',
      approverDesignation: sessionUser.designation || 'HOD',
      approvedAt: new Date().toISOString(),
      action: action || 'approved',
      remarks: remarks || '',
      completedForms: requiredForms,
      ipAddress: req.ip,
      autoFilled: true,
      // STORE DETAILED HOD INFO
      hodDetails: {
        hodId: sessionUser.hodId,
        name: sessionUser.name,
        employeeId: sessionUser.employeeId || sessionUser.id,
        email: sessionUser.email,
        department: sessionUser.department,
        designation: sessionUser.designation || 'HOD'
      }
    };

    forms[formIndex] = form;
    saveJSON(PENDING_FORMS, forms);

    res.json({
      success: true,
      message: 'Form approved and sent to IT',
      hodData: {
        name: sessionUser.name,
        employeeId: sessionUser.employeeId || sessionUser.id,
        email: sessionUser.email,
        department: sessionUser.department,
        designation: sessionUser.designation || 'HOD'
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error during final approval' });
  }
});

// Simple approval endpoint with comprehensive HOD data
router.post('/approve-form', roleAuth('hod'), (req, res) => {
  try {
    const { formId, action, remarks } = req.body;
    const sessionUser = req.session?.user;

    if (!formId || !action) {
      return res.status(400).json({ success: false, message: 'Missing formId or action' });
    }

    // Validate action parameter
    const validActions = ['approved', 'approve', 'rejected', 'reject'];
    if (!validActions.includes(action)) {
      return res.status(400).json({ success: false, message: 'Invalid action parameter' });
    }

    const forms = loadJSON(PENDING_FORMS);
    const formIndex = forms.findIndex(f => f.formId === formId);
    if (formIndex === -1) {
      return res.status(404).json({ success: false, message: 'Form not found' });
    }

    const form = forms[formIndex];

    // Comprehensive HOD action data
    const hodActionData = {
      actionBy: sessionUser.name,
      actionEmployeeId: sessionUser.employeeId || sessionUser.id,
      actionEmail: sessionUser.email,
      actionDepartment: sessionUser.department || 'Academic Department',
      actionDesignation: sessionUser.designation || 'HOD',
      actionAt: new Date().toISOString(),
      action: action,
      remarks: remarks || '',
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      // DETAILED HOD INFORMATION
      hodDetails: {
        hodId: sessionUser.hodId,
        name: sessionUser.name,
        employeeId: sessionUser.employeeId || sessionUser.id,
        email: sessionUser.email,
        department: sessionUser.department,
        designation: sessionUser.designation || 'HOD'
      }
    };

    if (action === 'approved' || action === 'approve') {
      form.status = 'Submitted to IT';
      form.hodApproval = hodActionData;
    } else if (action === 'rejected' || action === 'reject') {
      form.status = 'rejected';
      form.rejectionReason = remarks || 'No reason provided';
      form.rejectedAt = new Date().toISOString();
      form.rejectedBy = sessionUser.name;
      form.hodRejection = hodActionData;
      form.assignedForms = [];
      form.formResponses = {};
    }

    forms[formIndex] = form;
    saveJSON(PENDING_FORMS, forms);

    res.json({
      success: true,
      message: `Form ${action}d successfully`,
      hodData: {
        name: sessionUser.name,
        employeeId: sessionUser.employeeId || sessionUser.id,
        email: sessionUser.email,
        department: sessionUser.department,
        designation: sessionUser.designation || 'HOD'
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Approval failed' });
  }
});

// Enhanced upload signature with better error handling
router.post('/upload-signature', roleAuth('hod'), (req, res) => {
  upload.single('signature')(req, res, (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({
          success: false,
          message: 'File too large. Maximum size allowed is 5MB.'
        });
      }
      return res.status(400).json({
        success: false,
        message: err.message || 'File upload error'
      });
    }

    try {
      const file = req.file;
      const { id: hodId, name } = req.session.user;

      if (!file) {
        return res.status(400).json({
          success: false,
          message: 'No file uploaded'
        });
      }

      let signatures = [];
      try {
        signatures = loadJSON(HOD_SIGNATURES);
      } catch {
        // Creating new signatures file
      }

      const existingIndex = signatures.findIndex(sig => sig.hodId === hodId);
      if (existingIndex !== -1) {
        signatures[existingIndex].filename = file.filename;
        signatures[existingIndex].uploadedAt = new Date().toISOString();
        signatures[existingIndex].fileSize = file.size;
        signatures[existingIndex].mimeType = file.mimetype;
      } else {
        signatures.push({
          hodId,
          name,
          filename: file.filename,
          originalName: file.originalname,
          fileSize: file.size,
          mimeType: file.mimetype,
          uploadedAt: new Date().toISOString()
        });
      }

      saveJSON(HOD_SIGNATURES, signatures);

      res.json({
        success: true,
        message: 'Signature saved successfully',
        filename: file.filename,
        signatureUrl: `/uploads/${file.filename}`,
        fileInfo: {
          originalName: file.originalname,
          size: file.size,
          type: file.mimetype
        }
      });
    } catch (err) {
      res.status(500).json({ success: false, message: 'Error uploading signature' });
    }
  });
});

// Get HOD's own signature
router.get('/my-signature', roleAuth('hod'), (req, res) => {
  try {
    const { id: hodId } = req.session.user;
    let signatures = [];
    try {
      signatures = loadJSON(HOD_SIGNATURES);
    } catch {
      return res.status(404).json({ success: false, message: 'No signatures found' });
    }

    const match = signatures.find(s => s.hodId === hodId);
    if (!match) {
      return res.status(404).json({ success: false, message: 'No saved signature found' });
    }

    res.json({
      success: true,
      filename: match.filename,
      signatureUrl: `/uploads/${match.filename}`,
      uploadedAt: match.uploadedAt,
      fileInfo: {
        originalName: match.originalName || match.filename,
        size: match.fileSize || 'Unknown',
        type: match.mimeType || 'Unknown'
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error retrieving signature' });
  }
});

// Enhanced form save endpoints for HOD
router.post('/save-disposal', roleAuth('hod'), (req, res) => {
  try {
    const { formId, disposalFormData } = req.body;
    if (!formId || !disposalFormData) {
      return res.status(400).json({
        success: false,
        message: 'Missing formId or disposalFormData'
      });
    }

    const forms = loadJSON(PENDING_FORMS);
    const formIndex = forms.findIndex(f => f.formId === formId);

    if (formIndex === -1) {
      return res.status(404).json({
        success: false,
        message: 'Form not found'
      });
    }

    if (!forms[formIndex].formResponses) {
      forms[formIndex].formResponses = {};
    }

    forms[formIndex].formResponses.disposalFormData = disposalFormData;
    forms[formIndex].lastUpdated = new Date().toISOString();

    saveJSON(PENDING_FORMS, forms);

    res.json({
      success: true,
      message: 'Disposal form data saved successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error saving disposal form data'
    });
  }
});

router.post('/save-efile', roleAuth('hod'), (req, res) => {
  try {
    const { formId, efileFormData } = req.body;
    if (!formId || !efileFormData) {
      return res.status(400).json({
        success: false,
        message: 'Missing formId or efileFormData'
      });
    }

    const forms = loadJSON(PENDING_FORMS);
    const formIndex = forms.findIndex(f => f.formId === formId);

    if (formIndex === -1) {
      return res.status(404).json({
        success: false,
        message: 'Form not found'
      });
    }

    if (!forms[formIndex].formResponses) {
      forms[formIndex].formResponses = {};
    }

    forms[formIndex].formResponses.efileFormData = efileFormData;
    forms[formIndex].lastUpdated = new Date().toISOString();

    saveJSON(PENDING_FORMS, forms);

    res.json({
      success: true,
      message: 'E-file form data saved successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error saving e-file form data'
    });
  }
});

router.post('/save-form365-transfer', roleAuth('hod'), (req, res) => {
  try {
    const { formId, form365TransferData } = req.body;
    if (!formId || !form365TransferData) {
      return res.status(400).json({
        success: false,
        message: 'Missing formId or form365TransferData'
      });
    }

    const forms = loadJSON(PENDING_FORMS);
    const formIndex = forms.findIndex(f => f.formId === formId);

    if (formIndex === -1) {
      return res.status(404).json({
        success: false,
        message: 'Form not found'
      });
    }

    if (!forms[formIndex].formResponses) {
      forms[formIndex].formResponses = {};
    }

    forms[formIndex].formResponses.form365TransferData = form365TransferData;
    forms[formIndex].lastUpdated = new Date().toISOString();

    saveJSON(PENDING_FORMS, forms);

    res.json({
      success: true,
      message: 'Form 365 Transfer data saved successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error saving Form 365 Transfer data'
    });
  }
});

router.post('/save-form365-disposal', roleAuth('hod'), (req, res) => {
  try {
    const { formId, form365DisposalData } = req.body;
    if (!formId || !form365DisposalData) {
      return res.status(400).json({
        success: false,
        message: 'Missing formId or form365DisposalData'
      });
    }

    const forms = loadJSON(PENDING_FORMS);
    const formIndex = forms.findIndex(f => f.formId === formId);

    if (formIndex === -1) {
      return res.status(404).json({
        success: false,
        message: 'Form not found'
      });
    }

    if (!forms[formIndex].formResponses) {
      forms[formIndex].formResponses = {};
    }

    forms[formIndex].formResponses.form365Data = form365DisposalData;
    forms[formIndex].lastUpdated = new Date().toISOString();

    saveJSON(PENDING_FORMS, forms);

    res.json({
      success: true,
      message: 'Form 365 Disposal data saved successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error saving Form 365 Disposal data'
    });
  }
});

module.exports = router;
