const express = require('express');
const multer = require('multer');
const { loadJSON, saveJSON } = require('../utils/fileUtils');
const { roleAuth } = require('../middlewares/sessionAuth');

const router = express.Router();

const PENDING_FORMS = './data/pending_forms.json';
const HOD_SIGNATURES = './data/hod_signatures.json';

console.log('[HOD_ROUTER] Initializing HOD router with file paths:', {
  pendingForms: PENDING_FORMS,
  hodSignatures: HOD_SIGNATURES
});

// Multer setup for signature uploads with enhanced validation
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    console.log('[MULTER] Setting upload destination to uploads/');
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const filename = Date.now() + '-' + file.originalname;
    console.log('[MULTER] Generated filename:', filename);
    cb(null, filename);
  }
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
      console.log('[MULTER] File type accepted:', file.mimetype);
      cb(null, true);
    } else {
      console.log('[MULTER] File type rejected:', file.mimetype);
      cb(new Error('Only image files (JPEG, PNG, GIF) are allowed for signatures'));
    }
  }
});

console.log('[HOD_ROUTER] Multer configuration complete');

// Helper to get latest form with allowed statuses (for consistency with employee.js)
function getLatestFormForEmployee(allForms, employeeId, allowedStatuses = []) {
  console.log('[HELPER] Searching for latest form for employee:', employeeId);
  console.log('[HELPER] Allowed statuses:', allowedStatuses);

  let forms = allForms.filter(f => f && f.employeeId === employeeId);
  console.log('[HELPER] Found employee forms:', forms.length);

  if (allowedStatuses.length) {
    forms = forms.filter(f => allowedStatuses.includes(f.status));
    console.log('[HELPER] After status filtering:', forms.length);
  }

  const latestForm = forms.sort((a, b) => new Date(b.submissionDate || b.lastUpdated) - new Date(a.submissionDate || a.lastUpdated))[0] || null;
  console.log('[HELPER] Latest form found:', latestForm ? latestForm.formId : 'None');
  return latestForm;
}

// GET HOD's own details for prefilling forms
router.get('/my-details', roleAuth('hod'), (req, res) => {
  console.log('[HOD_DETAILS] GET /my-details request from IP:', req.ip);

  try {
    const sessionUser = req.session?.user;

    if (!sessionUser || sessionUser.role !== 'hod') {
      console.log('[HOD_DETAILS] ❌ Unauthorized access attempt');
      return res.status(401).json({
        success: false,
        message: 'HOD authentication required'
      });
    }

    console.log('[HOD_DETAILS] ✅ Providing HOD details for prefilling:', sessionUser.name);
    console.log('[HOD_DETAILS] HOD ID:', sessionUser.hodId);

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
    console.error('[HOD_DETAILS] ❌ Error getting HOD details:', error.message);
    res.status(500).json({
      success: false,
      message: 'Error fetching HOD details'
    });
  }
});

// HOD Profile endpoint
router.get('/profile', roleAuth('hod'), (req, res) => {
  console.log('[HOD_PROFILE] GET /profile request from IP:', req.ip);

  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) {
      console.log('[HOD_PROFILE] ❌ Session expired');
      return res.status(401).json({ success: false, message: 'Session expired' });
    }

    console.log('[HOD_PROFILE] ✅ Returning profile for HOD:', sessionUser.name);

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
    console.error('[HOD_PROFILE] ❌ Error fetching HOD profile:', error.message);
    res.status(500).json({ success: false, message: 'Error fetching profile' });
  }
});

// HOD signature endpoint
router.get('/get-signature', roleAuth('hod'), (req, res) => {
  console.log('[HOD_SIGNATURE] GET /get-signature request from IP:', req.ip);

  try {
    const { id: hodId, name } = req.session.user;
    console.log('[HOD_SIGNATURE] Looking for signature for HOD:', name, 'ID:', hodId);

    let signatures = [];
    try {
      signatures = loadJSON(HOD_SIGNATURES);
      console.log('[HOD_SIGNATURE] Loaded', signatures.length, 'signatures from database');
    } catch {
      console.log('[HOD_SIGNATURE] No existing signatures file');
    }

    const signature = signatures.find(s => s.hodId === hodId);
    if (!signature) {
      console.log('[HOD_SIGNATURE] ❌ No signature found for HOD:', hodId);
      return res.status(404).json({
        success: false,
        message: 'No signature found. Please upload a signature first.'
      });
    }

    console.log('[HOD_SIGNATURE] ✅ Signature found:', signature.filename);
    res.json({
      success: true,
      signature: signature.filename,
      signatureUrl: `/uploads/${signature.filename}`,
      hodName: name
    });
  } catch (err) {
    console.error('[HOD_SIGNATURE] ❌ Error fetching HOD signature:', err.message);
    res.status(500).json({ success: false, message: 'Error fetching signature' });
  }
});

// Form details route (backward compatibility)
router.get('/form-details', roleAuth('hod'), (req, res) => {
  console.log('[FORM_DETAILS] GET /form-details request from IP:', req.ip);

  const { formId } = req.query;
  console.log('[FORM_DETAILS] Requested form ID:', formId);

  if (!formId) {
    console.log('[FORM_DETAILS] ❌ Missing formId parameter');
    return res.status(400).json({ success: false, message: 'Missing formId' });
  }

  try {
    const pendingForms = loadJSON(PENDING_FORMS);
    console.log('[FORM_DETAILS] Loaded', pendingForms.length, 'forms from database');

    const form = pendingForms.find(f => f.formId === formId);
    const sessionUser = req.session?.user;

    if (!form) {
      console.log('[FORM_DETAILS] ❌ Form not found:', formId);
      return res.status(404).json({ success: false, message: 'Form not found' });
    }

    console.log('[FORM_DETAILS] ✅ Found form:', formId, 'status:', form.status);
    console.log('[FORM_DETAILS] Form employee:', form.employeeName || form.name);

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
    console.error('[FORM_DETAILS] ❌ Error loading form details:', err.message);
    res.status(500).json({ success: false, message: 'Error fetching form details' });
  }
});

// Form details route for hod-form-review.html with HOD prefill
router.get('/form-details/:formId', roleAuth('hod'), (req, res) => {
  console.log('[FORM_DETAILS_PARAM] GET /form-details/:formId request from IP:', req.ip);

  const { formId } = req.params;
  console.log('[FORM_DETAILS_PARAM] Form ID parameter:', formId);

  if (!formId) {
    console.log('[FORM_DETAILS_PARAM] ❌ Missing formId parameter');
    return res.status(400).json({ success: false, message: 'Missing formId' });
  }

  try {
    const pendingForms = loadJSON(PENDING_FORMS);
    console.log('[FORM_DETAILS_PARAM] Loaded', pendingForms.length, 'forms from database');

    const form = pendingForms.find(f => f.formId === formId);
    const sessionUser = req.session?.user;

    if (!form) {
      console.log('[FORM_DETAILS_PARAM] ❌ Form not found:', formId);
      return res.status(404).json({ success: false, message: 'Form not found' });
    }

    console.log('[FORM_DETAILS_PARAM] ✅ Providing form', formId, 'with HOD details for', sessionUser.name);

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
    console.error('[FORM_DETAILS_PARAM] ❌ Error loading form details:', err.message);
    res.status(500).json({ success: false, message: 'Error fetching form details' });
  }
});

// Get ALL forms regardless of status (for tab functionality)
router.get('/all', roleAuth('hod'), (req, res) => {
  console.log('[HOD_ALL_FORMS] GET /all request from IP:', req.ip);

  try {
    const allForms = loadJSON(PENDING_FORMS);
    console.log('[HOD_ALL_FORMS] 📋 Found', allForms.length, 'total forms for HOD dashboard');

    // Log form status distribution
    const statusCounts = {};
    allForms.forEach(form => {
      statusCounts[form.status] = (statusCounts[form.status] || 0) + 1;
    });
    console.log('[HOD_ALL_FORMS] Status distribution:', statusCounts);

    res.json({ success: true, data: allForms });
  } catch (err) {
    console.error('[HOD_ALL_FORMS] ❌ Error fetching all forms:', err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch all forms' });
  }
});

// Get pending forms for HOD approval (existing - only returns pending)
router.get('/pending', roleAuth('hod'), (req, res) => {
  console.log('[HOD_PENDING] GET /pending request from IP:', req.ip);

  try {
    const pendingForms = loadJSON(PENDING_FORMS);
    console.log('[HOD_PENDING] Loaded', pendingForms.length, 'total forms');

    const forms = pendingForms.filter(f => f.status === 'Submitted to HOD');
    console.log('[HOD_PENDING] 📋 Found', forms.length, 'forms pending HOD approval');

    // Log pending forms details
    forms.forEach(form => {
      console.log('[HOD_PENDING] Pending form:', form.formId, 'Employee:', form.employeeName || form.name);
    });

    res.json({ success: true, data: forms });
  } catch (err) {
    console.error('[HOD_PENDING] ❌ Error fetching pending forms:', err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch pending forms' });
  }
});

// Enhanced form validation middleware
const validateFormSubmission = (req, res, next) => {
  console.log('[VALIDATE_FORM] Validating form submission');

  const { formId, formResponses } = req.body;
  console.log('[VALIDATE_FORM] Form ID:', formId);
  console.log('[VALIDATE_FORM] Form responses provided:', !!formResponses);

  if (!formId || !formResponses) {
    console.log('[VALIDATE_FORM] ❌ Missing required fields');
    return res.status(400).json({
      success: false,
      message: 'Missing required fields: formId and formResponses'
    });
  }

  // Parse formResponses if it's a string
  try {
    if (typeof formResponses === 'string') {
      console.log('[VALIDATE_FORM] Parsing string formResponses');
      req.body.formResponses = JSON.parse(formResponses);
    }
    console.log('[VALIDATE_FORM] ✅ Form responses keys:', Object.keys(req.body.formResponses));
  } catch (error) {
    console.error('[VALIDATE_FORM] ❌ Invalid formResponses format:', error.message);
    return res.status(400).json({
      success: false,
      message: 'Invalid formResponses format'
    });
  }

  next();
};

// Final approval route with comprehensive HOD data storage
router.post('/final-approve', roleAuth('hod'), validateFormSubmission, (req, res) => {
  console.log('[FINAL_APPROVE] POST /final-approve request from IP:', req.ip);

  try {
    let { formId, formResponses, action, remarks } = req.body;

    console.log('[FINAL_APPROVE] 📋 HOD Final Approve - formId:', formId);
    console.log('[FINAL_APPROVE] 📋 HOD Final Approve - formResponses keys:', Object.keys(formResponses));
    console.log('[FINAL_APPROVE] Action:', action, 'Remarks:', remarks);

    const forms = loadJSON(PENDING_FORMS);
    console.log('[FINAL_APPROVE] Loaded', forms.length, 'forms from database');

    const formIndex = forms.findIndex(f => f.formId === formId);
    if (formIndex === -1) {
      console.log('[FINAL_APPROVE] ❌ Form not found:', formId);
      return res.status(404).json({ success: false, message: 'Form not found' });
    }

    const form = forms[formIndex];
    const sessionUser = req.session.user;
    console.log('[FINAL_APPROVE] Processing form for HOD:', sessionUser.name);

    const requiredForms = ['disposalForm', 'efileForm'];
    const form365Key = formResponses.form365Trans ? 'form365Trans' : 'form365Disp';
    requiredForms.push(form365Key);
    console.log('[FINAL_APPROVE] Required forms:', requiredForms);

    // Enhanced form validation
    for (const formKey of requiredForms) {
      const formData = formResponses[formKey];
      console.log('[FINAL_APPROVE] Validating form:', formKey);

      if (!formData || Object.keys(formData).length === 0) {
        console.log('[FINAL_APPROVE] ❌ Missing or empty form data:', formKey);
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
        console.log('[FINAL_APPROVE] ❌ HOD section not completed for:', formKey);
        return res.status(400).json({
          success: false,
          message: `HOD section not completed for ${formKey}`
        });
      }

      console.log('[FINAL_APPROVE] ✅ Form validation passed:', formKey);
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

    console.log('[FINAL_APPROVE] ✅ Form', formId, 'approved by HOD', sessionUser.name, 'and forwarded to IT');

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
    console.error('[FINAL_APPROVE] ❌ Error in HOD final approval:', err.message);
    res.status(500).json({ success: false, message: 'Error during final approval' });
  }
});

// Simple approval endpoint with comprehensive HOD data
router.post('/approve-form', roleAuth('hod'), (req, res) => {
  console.log('[APPROVE_FORM] POST /approve-form request from IP:', req.ip);

  try {
    const { formId, action, remarks } = req.body;
    const sessionUser = req.session?.user;

    console.log('[APPROVE_FORM] Form ID:', formId, 'Action:', action);
    console.log('[APPROVE_FORM] HOD:', sessionUser.name, 'Remarks:', remarks);

    if (!formId || !action) {
      console.log('[APPROVE_FORM] ❌ Missing formId or action');
      return res.status(400).json({ success: false, message: 'Missing formId or action' });
    }

    // Validate action parameter
    const validActions = ['approved', 'approve', 'rejected', 'reject'];
    if (!validActions.includes(action)) {
      console.log('[APPROVE_FORM] ❌ Invalid action parameter:', action);
      return res.status(400).json({ success: false, message: 'Invalid action parameter' });
    }

    const forms = loadJSON(PENDING_FORMS);
    console.log('[APPROVE_FORM] Loaded', forms.length, 'forms from database');

    const formIndex = forms.findIndex(f => f.formId === formId);
    if (formIndex === -1) {
      console.log('[APPROVE_FORM] ❌ Form not found:', formId);
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
      console.log('[APPROVE_FORM] ✅ Form', formId, 'approved by HOD', sessionUser.name);
    } else if (action === 'rejected' || action === 'reject') {
      form.status = 'rejected';
      form.rejectionReason = remarks || 'No reason provided';
      form.rejectedAt = new Date().toISOString();
      form.rejectedBy = sessionUser.name;
      form.hodRejection = hodActionData;
      form.assignedForms = [];
      form.formResponses = {};
      console.log('[APPROVE_FORM] ❌ Form', formId, 'rejected by HOD', sessionUser.name, '- Reason:', remarks);
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
    console.error('[APPROVE_FORM] ❌ Error in HOD approval:', error.message);
    res.status(500).json({ success: false, message: 'Approval failed' });
  }
});

// Enhanced upload signature with better error handling
router.post('/upload-signature', roleAuth('hod'), (req, res) => {
  console.log('[UPLOAD_SIGNATURE] POST /upload-signature request from IP:', req.ip);

  upload.single('signature')(req, res, (err) => {
    if (err) {
      console.error('[UPLOAD_SIGNATURE] ❌ Multer error:', err.message);
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

      console.log('[UPLOAD_SIGNATURE] HOD:', name, 'uploading signature');

      if (!file) {
        console.log('[UPLOAD_SIGNATURE] ❌ No file uploaded');
        return res.status(400).json({
          success: false,
          message: 'No file uploaded'
        });
      }

      console.log('[UPLOAD_SIGNATURE] File details:', {
        filename: file.filename,
        originalname: file.originalname,
        size: file.size,
        mimetype: file.mimetype
      });

      let signatures = [];
      try {
        signatures = loadJSON(HOD_SIGNATURES);
        console.log('[UPLOAD_SIGNATURE] Loaded existing signatures:', signatures.length);
      } catch {
        console.log('[UPLOAD_SIGNATURE] Creating new signatures file');
      }

      const existingIndex = signatures.findIndex(sig => sig.hodId === hodId);
      if (existingIndex !== -1) {
        console.log('[UPLOAD_SIGNATURE] Updating existing signature for HOD:', name);
        signatures[existingIndex].filename = file.filename;
        signatures[existingIndex].uploadedAt = new Date().toISOString();
        signatures[existingIndex].fileSize = file.size;
        signatures[existingIndex].mimeType = file.mimetype;
      } else {
        console.log('[UPLOAD_SIGNATURE] Creating new signature entry for HOD:', name);
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
      console.log('[UPLOAD_SIGNATURE] ✅ Signature uploaded for HOD', name);

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
      console.error('[UPLOAD_SIGNATURE] ❌ Error uploading signature:', err.message);
      res.status(500).json({ success: false, message: 'Error uploading signature' });
    }
  });
});

// Get HOD's own signature
router.get('/my-signature', roleAuth('hod'), (req, res) => {
  console.log('[MY_SIGNATURE] GET /my-signature request from IP:', req.ip);

  try {
    const { id: hodId } = req.session.user;
    console.log('[MY_SIGNATURE] Looking for signature for HOD ID:', hodId);

    let signatures = [];
    try {
      signatures = loadJSON(HOD_SIGNATURES);
      console.log('[MY_SIGNATURE] Loaded', signatures.length, 'signatures');
    } catch {
      console.log('[MY_SIGNATURE] ❌ No signatures found');
      return res.status(404).json({ success: false, message: 'No signatures found' });
    }

    const match = signatures.find(s => s.hodId === hodId);
    if (!match) {
      console.log('[MY_SIGNATURE] ❌ No saved signature found for HOD:', hodId);
      return res.status(404).json({ success: false, message: 'No saved signature found' });
    }

    console.log('[MY_SIGNATURE] ✅ Signature found:', match.filename);

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
    console.error('[MY_SIGNATURE] ❌ Error retrieving signature:', err.message);
    res.status(500).json({ success: false, message: 'Error retrieving signature' });
  }
});

// Enhanced form save endpoints for HOD
router.post('/save-disposal', roleAuth('hod'), (req, res) => {
  console.log('[SAVE_DISPOSAL] POST /save-disposal request from IP:', req.ip);

  try {
    const { formId, disposalFormData } = req.body;
    console.log('[SAVE_DISPOSAL] Form ID:', formId);
    console.log('[SAVE_DISPOSAL] Data keys:', disposalFormData ? Object.keys(disposalFormData) : 'None');

    if (!formId || !disposalFormData) {
      console.log('[SAVE_DISPOSAL] ❌ Missing formId or disposalFormData');
      return res.status(400).json({
        success: false,
        message: 'Missing formId or disposalFormData'
      });
    }

    const forms = loadJSON(PENDING_FORMS);
    console.log('[SAVE_DISPOSAL] Loaded', forms.length, 'forms');

    const formIndex = forms.findIndex(f => f.formId === formId);

    if (formIndex === -1) {
      console.log('[SAVE_DISPOSAL] ❌ Form not found:', formId);
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
    console.log('[SAVE_DISPOSAL] ✅ Disposal form data saved successfully');

    res.json({
      success: true,
      message: 'Disposal form data saved successfully'
    });
  } catch (error) {
    console.error('[SAVE_DISPOSAL] ❌ Error saving disposal form:', error.message);
    res.status(500).json({
      success: false,
      message: 'Error saving disposal form data'
    });
  }
});

router.post('/save-efile', roleAuth('hod'), (req, res) => {
  console.log('[SAVE_EFILE] POST /save-efile request from IP:', req.ip);

  try {
    const { formId, efileFormData } = req.body;
    console.log('[SAVE_EFILE] Form ID:', formId);
    console.log('[SAVE_EFILE] Data keys:', efileFormData ? Object.keys(efileFormData) : 'None');

    if (!formId || !efileFormData) {
      console.log('[SAVE_EFILE] ❌ Missing formId or efileFormData');
      return res.status(400).json({
        success: false,
        message: 'Missing formId or efileFormData'
      });
    }

    const forms = loadJSON(PENDING_FORMS);
    console.log('[SAVE_EFILE] Loaded', forms.length, 'forms');

    const formIndex = forms.findIndex(f => f.formId === formId);

    if (formIndex === -1) {
      console.log('[SAVE_EFILE] ❌ Form not found:', formId);
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
    console.log('[SAVE_EFILE] ✅ E-file form data saved successfully');

    res.json({
      success: true,
      message: 'E-file form data saved successfully'
    });
  } catch (error) {
    console.error('[SAVE_EFILE] ❌ Error saving efile form:', error.message);
    res.status(500).json({
      success: false,
      message: 'Error saving e-file form data'
    });
  }
});

router.post('/save-form365-transfer', roleAuth('hod'), (req, res) => {
  console.log('[SAVE_FORM365_TRANSFER] POST /save-form365-transfer request from IP:', req.ip);

  try {
    const { formId, form365TransferData } = req.body;
    console.log('[SAVE_FORM365_TRANSFER] Form ID:', formId);
    console.log('[SAVE_FORM365_TRANSFER] Data keys:', form365TransferData ? Object.keys(form365TransferData) : 'None');

    if (!formId || !form365TransferData) {
      console.log('[SAVE_FORM365_TRANSFER] ❌ Missing formId or form365TransferData');
      return res.status(400).json({
        success: false,
        message: 'Missing formId or form365TransferData'
      });
    }

    const forms = loadJSON(PENDING_FORMS);
    console.log('[SAVE_FORM365_TRANSFER] Loaded', forms.length, 'forms');

    const formIndex = forms.findIndex(f => f.formId === formId);

    if (formIndex === -1) {
      console.log('[SAVE_FORM365_TRANSFER] ❌ Form not found:', formId);
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
    console.log('[SAVE_FORM365_TRANSFER] ✅ Form 365 Transfer data saved successfully');

    res.json({
      success: true,
      message: 'Form 365 Transfer data saved successfully'
    });
  } catch (error) {
    console.error('[SAVE_FORM365_TRANSFER] ❌ Error saving form365 transfer:', error.message);
    res.status(500).json({
      success: false,
      message: 'Error saving Form 365 Transfer data'
    });
  }
});

router.post('/save-form365-disposal', roleAuth('hod'), (req, res) => {
  console.log('[SAVE_FORM365_DISPOSAL] POST /save-form365-disposal request from IP:', req.ip);

  try {
    const { formId, form365DisposalData } = req.body;
    console.log('[SAVE_FORM365_DISPOSAL] Form ID:', formId);
    console.log('[SAVE_FORM365_DISPOSAL] Data keys:', form365DisposalData ? Object.keys(form365DisposalData) : 'None');

    if (!formId || !form365DisposalData) {
      console.log('[SAVE_FORM365_DISPOSAL] ❌ Missing formId or form365DisposalData');
      return res.status(400).json({
        success: false,
        message: 'Missing formId or form365DisposalData'
      });
    }

    const forms = loadJSON(PENDING_FORMS);
    console.log('[SAVE_FORM365_DISPOSAL] Loaded', forms.length, 'forms');

    const formIndex = forms.findIndex(f => f.formId === formId);

    if (formIndex === -1) {
      console.log('[SAVE_FORM365_DISPOSAL] ❌ Form not found:', formId);
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
    console.log('[SAVE_FORM365_DISPOSAL] ✅ Form 365 Disposal data saved successfully');

    res.json({
      success: true,
      message: 'Form 365 Disposal data saved successfully'
    });
  } catch (error) {
    console.error('[SAVE_FORM365_DISPOSAL] ❌ Error saving form365 disposal:', error.message);
    res.status(500).json({
      success: false,
      message: 'Error saving Form 365 Disposal data'
    });
  }
});

console.log('[HOD_ROUTER] HOD router initialization complete with enhanced logging');

module.exports = router;
