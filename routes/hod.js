const express = require('express');
const multer = require('multer');
const { loadJSON, saveJSON } = require('../utils/fileUtils');
const { roleAuth } = require('../middlewares/sessionAuth');


const router = express.Router();


const PENDING_FORMS = './data/pending_forms.json';
const HOD_SIGNATURES = './data/hod_signatures.json';


// Multer setup for signature uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });


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


    console.log('✅ Providing HOD details for prefilling:', sessionUser.name);


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
    console.error('Error getting HOD details:', error);
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
    console.error('Error fetching HOD profile:', error);
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
      console.log('No existing signatures file');
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
    console.error('Error fetching HOD signature:', err);
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
      console.log(`Form ${formId} not found`);
      return res.status(404).json({ success: false, message: 'Form not found' });
    }


    console.log(`✅ Found form ${formId}, status: ${form.status}`);


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
    console.error('Error loading form details:', err);
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


    console.log(`✅ Providing form ${formId} with HOD details for ${sessionUser.name}`);


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
    console.error('Error loading form details:', err);
    res.status(500).json({ success: false, message: 'Error fetching form details' });
  }
});


// ⭐ NEW: Get ALL forms regardless of status (for tab functionality)
router.get('/all', roleAuth('hod'), (req, res) => {
  try {
    const allForms = loadJSON(PENDING_FORMS);
    console.log(`📋 Found ${allForms.length} total forms for HOD dashboard`);
    res.json({ success: true, data: allForms });
  } catch (err) {
    console.error('Error fetching all forms:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch all forms' });
  }
});


// Get pending forms for HOD approval (existing - only returns pending)
router.get('/pending', roleAuth('hod'), (req, res) => {
  try {
    const pendingForms = loadJSON(PENDING_FORMS);
    const forms = pendingForms.filter(f => f.status === 'Submitted to HOD');
    console.log(`📋 Found ${forms.length} forms pending HOD approval`);
    res.json({ success: true, data: forms });
  } catch (err) {
    console.error('Error fetching pending forms:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch pending forms' });
  }
});


// Final approval route with comprehensive HOD data storage
router.post('/final-approve', roleAuth('hod'), (req, res) => {
  try {
    let { formId, formResponses, action, remarks } = req.body;
    if (!formId || !formResponses) {
      return res.status(400).json({ success: false, message: 'Missing formId or formResponses' });
    }
    if (typeof formResponses === 'string') {
      formResponses = JSON.parse(formResponses);
    }


    console.log('📋 HOD Final Approve - formId:', formId);
    console.log('📋 HOD Final Approve - formResponses keys:', Object.keys(formResponses));


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


    console.log(`✅ Form ${formId} approved by HOD ${sessionUser.name} and forwarded to IT`);


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
    console.error('Error in HOD final approval:', err);
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
      console.log(`✅ Form ${formId} approved by HOD ${sessionUser.name}`);
    } else if (action === 'rejected' || action === 'reject') {
      form.status = 'rejected';
      form.rejectionReason = remarks || 'No reason provided';
      form.rejectedAt = new Date().toISOString();
      form.rejectedBy = sessionUser.name;
      form.hodRejection = hodActionData;
      form.assignedForms = [];
      form.formResponses = {};
      console.log(`Form ${formId} rejected by HOD ${sessionUser.name} - Reason: ${remarks}`);
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
    console.error('Error in HOD approval:', error);
    res.status(500).json({ success: false, message: 'Approval failed' });
  }
});


// Upload signature
router.post('/upload-signature', upload.single('signature'), roleAuth('hod'), (req, res) => {
  try {
    const file = req.file;
    const { id: hodId, name } = req.session.user;
    if (!file) return res.status(400).json({ success: false, message: 'No file uploaded' });


    let signatures = [];
    try {
      signatures = loadJSON(HOD_SIGNATURES);
    } catch {
      console.log('Creating new signatures file');
    }


    const existingIndex = signatures.findIndex(sig => sig.hodId === hodId);
    if (existingIndex !== -1) {
      signatures[existingIndex].filename = file.filename;
      signatures[existingIndex].uploadedAt = new Date().toISOString();
    } else {
      signatures.push({
        hodId,
        name,
        filename: file.filename,
        uploadedAt: new Date().toISOString()
      });
    }


    saveJSON(HOD_SIGNATURES, signatures);
    console.log(`✅ Signature uploaded for HOD ${name}`);


    res.json({
      success: true,
      message: 'Signature saved successfully',
      filename: file.filename,
      signatureUrl: `/uploads/${file.filename}`
    });
  } catch (err) {
    console.error('Error uploading signature:', err);
    res.status(500).json({ success: false, message: 'Error uploading signature' });
  }
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
      uploadedAt: match.uploadedAt
    });
  } catch (err) {
    console.error('Error retrieving signature:', err);
    res.status(500).json({ success: false, message: 'Error retrieving signature' });
  }
});


module.exports = router;