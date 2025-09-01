const express = require('express');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const { loadJSON, saveJSON } = require('../utils/fileUtils');
const { roleAuth } = require('../middlewares/sessionAuth');
const { getFormDisplayName } = require('../utils/pdfGenerator');

const router = express.Router();

const PENDING_FORMS = './data/pending_forms.json';
const FORM_HISTORY = './data/form_history.json';
const USERS = './data/users.json';
const CERTIFICATES = './data/certificates.json';

console.log('[EMPLOYEE_ROUTER] Initializing employee router with file paths:', {
  pendingForms: PENDING_FORMS,
  formHistory: FORM_HISTORY,
  users: USERS,
  certificates: CERTIFICATES
});

// Setup multer for file uploads
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
const upload = multer({ storage });

console.log('[EMPLOYEE_ROUTER] Multer configuration complete');

// ✅ NEW: Helper function to move completed form to history
async function moveCompletedFormToHistory(employeeId, formData) {
  console.log('[HISTORY_MOVE] Moving completed form to history for employee:', employeeId);
  console.log('[HISTORY_MOVE] Form data:', { formId: formData.formId, status: formData.status });

  try {
    let history = [];
    try {
      const data = loadJSON(FORM_HISTORY);
      history = Array.isArray(data) ? data : [];
      console.log('[HISTORY_MOVE] Loaded existing history entries:', history.length);
    } catch {
      console.log('[HISTORY_MOVE] No existing history file, starting fresh');
      history = [];
    }

    // Add completed form to history with full status preservation
    const historyEntry = {
      ...formData,
      completedAt: new Date().toISOString(),
      finalStatus: formData.status,
      historyType: 'completed_application',
      preservedData: {
        certificates: formData.certificates || [],
        hodApproval: formData.hodApproval || null,
        itProcessing: formData.itProcessing || null,
        assignedForms: formData.assignedForms || [],
        formResponses: formData.formResponses || {}
      }
    };

    history.push(historyEntry);
    saveJSON(FORM_HISTORY, history);

    console.log(`[HISTORY_MOVE] 📚 Successfully moved form ${formData.formId} to history for employee ${employeeId}`);
    return true;
  } catch (error) {
    console.error('[HISTORY_MOVE] ❌ Error moving form to history:', error.message);
    return false;
  }
}

// Helper function to get latest form for employee
function getLatestFormForEmployee(allForms, employeeId, allowedStatuses = null) {
  console.log('[GET_LATEST_FORM] Finding latest form for employee:', employeeId);
  console.log('[GET_LATEST_FORM] Allowed statuses:', allowedStatuses);
  console.log('[GET_LATEST_FORM] Total forms to search:', allForms.length);

  let employeeForms = allForms.filter(f => f && f.employeeId === employeeId);
  console.log('[GET_LATEST_FORM] Employee forms found:', employeeForms.length);

  if (allowedStatuses) {
    employeeForms = employeeForms.filter(f => allowedStatuses.includes(f.status));
    console.log('[GET_LATEST_FORM] After status filtering:', employeeForms.length);
  }

  const latestForm = employeeForms
    .sort((a, b) => new Date(b.submissionDate || b.lastUpdated) - new Date(a.submissionDate || a.lastUpdated))[0] || null;

  console.log('[GET_LATEST_FORM] Latest form result:', latestForm ? latestForm.formId : 'None found');
  return latestForm;
}

// --------------------- OTP ---------------------
router.post('/verify-otp', roleAuth('employee'), (req, res) => {
  console.log('[VERIFY_OTP] OTP verification request from IP:', req.ip);

  const { otp } = req.body;
  console.log('[VERIFY_OTP] OTP length:', otp ? otp.length : 'null');

  const isValid = otp === '123456';
  console.log('[VERIFY_OTP] OTP validation result:', isValid);

  res.json({
    success: isValid,
    message: isValid ? undefined : 'Invalid OTP'
  });
});

// --------------------- No Dues Form Submission ---------------------
router.post('/submit-no-dues', roleAuth('employee'), upload.single('orderLetter'), (req, res) => {
  console.log('[NO_DUES_SUBMIT] === Form Submission Debug ===');
  console.log('[NO_DUES_SUBMIT] Request from IP:', req.ip);
  console.log('[NO_DUES_SUBMIT] User agent:', req.headers['user-agent']);

  try {
    // Basic validation
    if (!req.body) {
      console.log('[NO_DUES_SUBMIT] ❌ Request body is missing');
      return res.status(400).json({ success: false, message: 'Request body is missing' });
    }

    if (!req.session?.user) {
      console.log('[NO_DUES_SUBMIT] ❌ Session not found');
      return res.status(401).json({ success: false, message: 'Session not found' });
    }

    if (!req.file) {
      console.log('[NO_DUES_SUBMIT] ❌ Order letter file is required');
      return res.status(400).json({ success: false, message: 'Order letter file is required' });
    }

    const bodyData = req.body;
    const sessionUser = req.session.user;

    console.log('[NO_DUES_SUBMIT] Session user:', {
      name: sessionUser.name,
      id: sessionUser.id,
      employeeId: sessionUser.employeeId
    });

    const name = bodyData.name || sessionUser.name || '';
    const employeeId = bodyData.employeeId || sessionUser.id || sessionUser.employeeId || '';
    const email = bodyData.email || '';
    const department = bodyData.department || '';
    const noDuesType = bodyData.noDuesType || '';
    const reason = bodyData.reason || '';

    console.log('[NO_DUES_SUBMIT] Extracted data:', { name, employeeId, email, department, noDuesType, reason });
    console.log('[NO_DUES_SUBMIT] Uploaded file:', {
      filename: req.file.filename,
      size: req.file.size,
      mimetype: req.file.mimetype
    });

    if (!name || !employeeId || !email || !department || !noDuesType) {
      console.log('[NO_DUES_SUBMIT] ❌ Missing required fields');
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    // Load existing forms
    let pendingForms = [];
    try {
      const loadedData = loadJSON(PENDING_FORMS);
      if (Array.isArray(loadedData)) {
        pendingForms = loadedData;
        console.log('[NO_DUES_SUBMIT] ✅ Successfully loaded', pendingForms.length, 'existing forms');
      }
    } catch (loadError) {
      console.error('[NO_DUES_SUBMIT] ❌ Error loading JSON:', loadError.message);
      pendingForms = [];
    }

    // Check for existing active applications using latest form logic
    const activeStatuses = ['Pending', 'pending', 'Submitted to HOD', 'Submitted to IT', 'approved'];
    const existingForm = getLatestFormForEmployee(pendingForms, employeeId, activeStatuses);

    if (existingForm) {
      console.log('[NO_DUES_SUBMIT] ❌ Existing active application found:', existingForm.formId);
      return res.status(400).json({
        success: false,
        message: `You already have a ${existingForm.status} application (${existingForm.formId})`
      });
    }

    // Create new form
    const formId = 'F' + Date.now();
    const newForm = {
      formId,
      name,
      employeeName: name,
      employeeId,
      email,
      department,
      noDuesType,
      reason,
      orderLetter: req.file.filename,
      status: 'pending',
      submissionDate: new Date().toISOString(),
      submittedBy: employeeId,
      lastUpdated: new Date().toISOString(),
      assignedForms: [],
      formResponses: {},
      remark: ''
    };

    console.log('[NO_DUES_SUBMIT] Creating new form:', formId);

    pendingForms.push(newForm);

    try {
      saveJSON(PENDING_FORMS, pendingForms);
      console.log('[NO_DUES_SUBMIT] ✅ Form saved to database');
    } catch (saveError) {
      console.error('[NO_DUES_SUBMIT] ❌ Error saving form:', saveError.message);
      return res.status(500).json({ success: false, message: 'Failed to save form' });
    }

    // Update session with formId
    req.session.user.formId = formId;
    req.session.user.applicationStatus = 'pending';

    console.log('[NO_DUES_SUBMIT] 🎉 Success! Form', formId, 'created and session updated');

    res.json({
      success: true,
      message: 'Application submitted successfully',
      formId,
      status: 'pending'
    });

  } catch (error) {
    console.error('[NO_DUES_SUBMIT] 💥 FATAL ERROR in submit-no-dues:', error.message);
    console.error('[NO_DUES_SUBMIT] Stack trace:', error.stack);
    res.status(500).json({
      success: false,
      message: 'Internal server error: ' + error.message
    });
  }
});

// --------------------- Check Previous Application ---------------------
router.get('/previous-application', roleAuth('employee'), (req, res) => {
  console.log('[PREV_APP] Checking previous application for user');

  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) {
      console.log('[PREV_APP] ❌ Session expired');
      return res.status(401).json({ success: false, message: 'Session expired' });
    }

    const employeeId = sessionUser.id || sessionUser.employeeId;
    if (!employeeId) {
      console.log('[PREV_APP] ❌ No employee ID found in session');
      return res.status(400).json({ success: false, message: 'No employee ID found in session' });
    }

    console.log('[PREV_APP] Searching for employee:', employeeId);

    let pendingForms = [];
    try {
      const data = loadJSON(PENDING_FORMS);
      pendingForms = Array.isArray(data) ? data : [];
      console.log('[PREV_APP] Loaded', pendingForms.length, 'forms from database');
    } catch {
      console.log('[PREV_APP] No pending forms found');
      return res.json({ success: true, hasApplication: false, message: 'No previous applications found' });
    }

    const latestApp = getLatestFormForEmployee(pendingForms, employeeId);

    if (!latestApp) {
      console.log('[PREV_APP] No applications found for employee');
      return res.json({ success: true, hasApplication: false, message: 'No applications found' });
    }

    console.log('[PREV_APP] ✅ Found application:', latestApp.formId);
    res.json({ success: true, hasApplication: true, application: latestApp });
  } catch (error) {
    console.error('[PREV_APP] ❌ Error checking previous application:', error.message);
    res.status(500).json({ success: false, message: 'Error checking previous application: ' + error.message });
  }
});

// --------------------- Detailed Tracking Endpoint ---------------------
router.get('/tracking-details', roleAuth('employee'), (req, res) => {
  console.log('[TRACKING] 🎯 Fetching detailed tracking information...');
  console.log('[TRACKING] Request from IP:', req.ip);

  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) {
      console.log('[TRACKING] ❌ Not authenticated');
      return res.status(401).json({ success: false, message: 'Not authenticated' });
    }

    const employeeId = sessionUser.id || sessionUser.employeeId;
    console.log('[TRACKING] Employee ID:', employeeId);

    let formsData = [];
    try {
      const data = loadJSON(PENDING_FORMS);
      formsData = Array.isArray(data) ? data : [];
      console.log('[TRACKING] Loaded', formsData.length, 'forms from database');
    } catch {
      console.log('[TRACKING] No forms data found');
      formsData = [];
    }

    // Get latest form for employee
    const employeeForm = getLatestFormForEmployee(formsData, employeeId);

    if (!employeeForm) {
      console.log('[TRACKING] No application found for employee');
      return res.json({
        success: true,
        hasApplication: false,
        status: 'Not Submitted',
        timeline: [],
        forms: [],
        message: 'No application found for this employee'
      });
    }

    // Update session formId if needed
    if (req.session.user.formId !== employeeForm.formId) {
      console.log('[TRACKING] Updating session formId from', req.session.user.formId, 'to', employeeForm.formId);
      req.session.user.formId = employeeForm.formId;
    }

    const timeline = buildTimelineData(employeeForm);
    const formsStatus = getFormsCompletionStatus(employeeForm);

    console.log(`[TRACKING] ✅ Found application ${employeeForm.formId} for employee ${employeeId}`);
    console.log(`[TRACKING] 📊 Timeline has ${timeline.length} events, ${formsStatus.length} forms`);

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
      noDuesType: employeeForm.noDuesType
    });

  } catch (error) {
    console.error('[TRACKING] ❌ Error getting tracking details:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Helper function to build timeline data
function buildTimelineData(formData) {
  console.log('[TIMELINE] Building timeline for form:', formData.formId);
  const timeline = [];

  if (formData.submissionDate) {
    timeline.push({
      step: 'submitted',
      title: 'Application Submitted',
      date: formData.submissionDate,
      status: 'completed',
      details: `Application ${formData.formId} submitted for ${formData.noDuesType} clearance`
    });
    console.log('[TIMELINE] Added submission step');
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
    console.log('[TIMELINE] Added IT review step with status:', reviewStatus);
  }

  if (formData.assignedForms && formData.assignedForms.length > 0) {
    timeline.push({
      step: 'forms_assigned',
      title: 'Forms Assigned',
      date: formData.lastUpdated,
      status: 'completed',
      details: `${formData.assignedForms.length} forms assigned: ${formData.assignedForms.map(f => f.title).join(', ')}`
    });
    console.log('[TIMELINE] Added forms assigned step:', formData.assignedForms.length, 'forms');
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
    console.log('[TIMELINE] Added forms completed step:', completedForms.length, 'forms');
  }

  if (formData.hodApproval) {
    timeline.push({
      step: 'hod_approved',
      title: 'HOD Approval',
      date: formData.hodApproval.approvedAt,
      status: 'completed',
      details: `Approved by HOD: ${formData.hodApproval.approvedBy}`
    });
    console.log('[TIMELINE] Added HOD approval step');
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
    console.log('[TIMELINE] Added IT processing step with status:', processingStatus);
  }

  if (formData.status === 'IT Completed' && formData.certificates) {
    timeline.push({
      step: 'certificates_generated',
      title: 'Certificates Generated',
      date: formData.itProcessing?.processedAt || new Date().toISOString(),
      status: 'completed',
      details: `${formData.certificates.length} digital certificates generated and ready for download`
    });
    console.log('[TIMELINE] Added certificates generation step:', formData.certificates.length, 'certificates');
  }

  const sortedTimeline = timeline.sort((a, b) => new Date(a.date) - new Date(b.date));
  console.log('[TIMELINE] Timeline built with', sortedTimeline.length, 'steps');
  return sortedTimeline;
}

// Helper function to get forms completion status
function getFormsCompletionStatus(formData) {
  console.log('[FORMS_STATUS] Getting completion status for assigned forms');

  if (!formData.assignedForms) {
    console.log('[FORMS_STATUS] No assigned forms found');
    return [];
  }

  console.log('[FORMS_STATUS] Processing', formData.assignedForms.length, 'assigned forms');

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

    console.log('[FORMS_STATUS] Form:', form.title, 'Status:', isCompleted ? 'completed' : 'pending');

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

// --------------------- Save Form APIs ---------------------
const savePartialForm = (reqKey, storageKey) => {
  return async (req, res) => {
    console.log(`[SAVE_FORM] 💾 Saving ${storageKey}...`);
    console.log(`[SAVE_FORM] Request from IP:`, req.ip);

    try {
      const sessionUser = req.session?.user;
      if (!sessionUser) {
        console.log(`[SAVE_FORM] ❌ Session expired for ${storageKey}`);
        return res.status(401).json({ success: false, message: "Session expired" });
      }

      const employeeId = sessionUser.id || sessionUser.employeeId;
      if (!employeeId) {
        console.log(`[SAVE_FORM] ❌ No employee ID found for ${storageKey}`);
        return res.status(400).json({ success: false, message: "No employee ID found in session" });
      }

      console.log(`[SAVE_FORM] Employee ID: ${employeeId}, Storage Key: ${storageKey}`);

      let allForms = [];
      try {
        const data = loadJSON(PENDING_FORMS);
        allForms = Array.isArray(data) ? data : [];
        console.log(`[SAVE_FORM] Loaded ${allForms.length} forms from database`);
      } catch {
        console.log(`[SAVE_FORM] No existing forms found`);
        allForms = [];
      }

      // Get latest form for employee
      const latestForm = getLatestFormForEmployee(allForms, employeeId);
      const formIndex = latestForm ? allForms.findIndex(f => f.formId === latestForm.formId) : -1;

      if (formIndex === -1) {
        console.log(`[SAVE_FORM] ❌ No pending form found for employee ${employeeId}`);
        return res.status(404).json({
          success: false,
          message: "No pending form found for this employee. Please submit initial application first."
        });
      }

      console.log(`[SAVE_FORM] Found form ${latestForm.formId} for employee`);

      // Update session formId if needed
      if (req.session.user.formId !== latestForm.formId) {
        console.log(`[SAVE_FORM] Updating session formId to ${latestForm.formId}`);
        req.session.user.formId = latestForm.formId;
      }

      if (!allForms[formIndex].formResponses) {
        allForms[formIndex].formResponses = {};
        console.log(`[SAVE_FORM] Initialized formResponses object`);
      }

      let parsedData;
      try {
        const inputData = req.body[reqKey] || req.body;

        if (!inputData) {
          console.log(`[SAVE_FORM] ❌ No data provided for ${storageKey}`);
          return res.status(400).json({
            success: false,
            message: `No data provided for ${storageKey}`
          });
        }

        parsedData = typeof inputData === "string" ? JSON.parse(inputData) : inputData;

        if (!parsedData || typeof parsedData !== 'object') {
          console.log(`[SAVE_FORM] ❌ Invalid data format for ${storageKey}`);
          return res.status(400).json({
            success: false,
            message: `Invalid data format for ${storageKey}`
          });
        }

        console.log(`[SAVE_FORM] Successfully parsed data with keys:`, Object.keys(parsedData));

      } catch (parseError) {
        console.error(`[SAVE_FORM] ❌ JSON parse error for ${storageKey}:`, parseError.message);
        return res.status(400).json({
          success: false,
          message: `Invalid JSON format for ${storageKey}: ${parseError.message}`
        });
      }

      allForms[formIndex].formResponses[storageKey] = parsedData;
      allForms[formIndex].lastUpdated = new Date().toISOString();

      try {
        saveJSON(PENDING_FORMS, allForms);
        console.log(`[SAVE_FORM] ✅ Successfully saved ${storageKey} to database`);
      } catch (saveError) {
        console.error(`[SAVE_FORM] ❌ Error saving ${storageKey}:`, saveError.message);
        return res.status(500).json({
          success: false,
          message: `Failed to save ${storageKey}`
        });
      }

      console.log(`[SAVE_FORM] ✅ ${storageKey} saved successfully for employee ${employeeId}`);
      res.json({
        success: true,
        message: `${storageKey} saved successfully`,
        dataKeys: Object.keys(parsedData),
        timestamp: new Date().toISOString()
      });

    } catch (err) {
      console.error(`[SAVE_FORM] ❌ Error saving ${storageKey}:`, err.message);
      res.status(500).json({
        success: false,
        message: 'Internal Server Error: ' + err.message
      });
    }
  };
};

router.post('/save-disposal', roleAuth('employee'), savePartialForm('disposalForm', 'disposalFormData'));
router.post('/save-efile', roleAuth('employee'), savePartialForm('efileForm', 'efileFormData'));
router.post('/save-form365-transfer', roleAuth('employee'), savePartialForm('form365Transfer', 'form365TransferData'));
router.post('/save-form365-disposal', roleAuth('employee'), savePartialForm('form365Disposal', 'form365Data'));

// --------------------- Final Submit ---------------------
router.post('/final-submit', roleAuth('employee'), (req, res) => {
  console.log('[FINAL_SUBMIT] 📤 Employee final submit request...');
  console.log('[FINAL_SUBMIT] Request from IP:', req.ip);

  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) {
      console.log('[FINAL_SUBMIT] ❌ Session expired');
      return res.status(401).json({ success: false, message: 'Session expired' });
    }

    const employeeId = sessionUser.id || sessionUser.employeeId;
    if (!employeeId) {
      console.log('[FINAL_SUBMIT] ❌ No employee ID found in session');
      return res.status(400).json({ success: false, message: 'No employee ID found in session' });
    }

    console.log('[FINAL_SUBMIT] Employee ID:', employeeId);

    const { disposalForm, efileForm, form365Transfer, form365Disposal } = req.body || {};
    console.log('[FINAL_SUBMIT] Form data received:', {
      disposalForm: !!disposalForm,
      efileForm: !!efileForm,
      form365Transfer: !!form365Transfer,
      form365Disposal: !!form365Disposal
    });

    let pendingForms = [];
    try {
      const data = loadJSON(PENDING_FORMS);
      pendingForms = Array.isArray(data) ? data : [];
      console.log('[FINAL_SUBMIT] Loaded', pendingForms.length, 'pending forms');
    } catch {
      console.log('[FINAL_SUBMIT] ❌ No pending forms found');
      return res.status(404).json({ success: false, message: 'No pending forms found' });
    }

    // Get latest form for employee
    const latestForm = getLatestFormForEmployee(pendingForms, employeeId);
    const formIndex = latestForm ? pendingForms.findIndex(f => f.formId === latestForm.formId) : -1;

    if (formIndex === -1) {
      console.log('[FINAL_SUBMIT] ❌ No pending form found for employee');
      return res.status(404).json({ success: false, message: 'No pending form found for this employee' });
    }

    const form = pendingForms[formIndex];
    console.log('[FINAL_SUBMIT] Processing form:', form.formId);

    // Validate required forms
    if (!disposalForm || typeof disposalForm !== 'object') {
      console.log('[FINAL_SUBMIT] ❌ Invalid disposal form data');
      return res.status(400).json({ success: false, message: 'Valid disposal form data is required' });
    }

    if (!efileForm || typeof efileForm !== 'object') {
      console.log('[FINAL_SUBMIT] ❌ Invalid e-file form data');
      return res.status(400).json({ success: false, message: 'Valid e-file form data is required' });
    }

    if ((!form365Transfer || typeof form365Transfer !== 'object') &&
      (!form365Disposal || typeof form365Disposal !== 'object')) {
      console.log('[FINAL_SUBMIT] ❌ Invalid Form 365 data');
      return res.status(400).json({ success: false, message: 'Valid Form 365 (Transfer or Disposal) data is required' });
    }

    if (!form.formResponses) {
      form.formResponses = {};
      console.log('[FINAL_SUBMIT] Initialized formResponses object');
    }

    // Save form data
    form.formResponses.disposalFormData = disposalForm;
    form.formResponses.efileFormData = efileForm;

    if (form365Transfer && typeof form365Transfer === 'object') {
      form.formResponses.form365TransferData = form365Transfer;
      console.log('[FINAL_SUBMIT] Added Form 365 Transfer data');
    }
    if (form365Disposal && typeof form365Disposal === 'object') {
      form.formResponses.form365Data = form365Disposal;
      console.log('[FINAL_SUBMIT] Added Form 365 Disposal data');
    }

    form.status = 'Submitted to HOD';
    form.finalSubmittedAt = new Date().toISOString();
    form.lastUpdated = new Date().toISOString();

    pendingForms[formIndex] = form;

    // Update session formId if needed
    if (req.session.user.formId !== form.formId) {
      console.log('[FINAL_SUBMIT] Updating session formId');
      req.session.user.formId = form.formId;
    }

    try {
      saveJSON(PENDING_FORMS, pendingForms);
      console.log('[FINAL_SUBMIT] ✅ Form submission saved to database');
    } catch (saveError) {
      console.error('[FINAL_SUBMIT] ❌ Failed to save form submission:', saveError.message);
      return res.status(500).json({ success: false, message: 'Failed to save form submission' });
    }

    console.log(`[FINAL_SUBMIT] ✅ Form ${form.formId} submitted to HOD successfully`);

    res.json({
      success: true,
      message: 'Forms submitted to HOD for review',
      formId: form.formId,
      status: 'Submitted to HOD'
    });

  } catch (err) {
    console.error('[FINAL_SUBMIT] ❌ Final Submit Error:', err.message);
    console.error('[FINAL_SUBMIT] Stack trace:', err.stack);
    res.status(500).json({ success: false, message: 'Internal Server Error: ' + err.message });
  }
});

// ✅ ENHANCED: Certificate Endpoints with History Support
router.get('/certificates', roleAuth('employee'), (req, res) => {
  console.log('[CERTIFICATES] 📜 Fetching certificates for employee (including history)...');
  console.log('[CERTIFICATES] Request from IP:', req.ip);

  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) {
      console.log('[CERTIFICATES] ❌ Not authenticated');
      return res.status(401).json({ success: false, message: 'Not authenticated' });
    }

    const employeeId = sessionUser.id || sessionUser.employeeId;
    if (!employeeId) {
      console.log('[CERTIFICATES] ❌ Employee ID not found in session');
      return res.status(401).json({ success: false, message: 'Employee ID not found in session' });
    }

    console.log('[CERTIFICATES] Employee ID:', employeeId);

    let allCertificates = [];

    // Get active certificates
    try {
      const data = loadJSON(CERTIFICATES);
      if (Array.isArray(data)) {
        const activeCertificates = data.filter(cert => cert.employeeId === employeeId);
        allCertificates = [...allCertificates, ...activeCertificates.map(cert => ({
          ...cert,
          source: 'active',
          displayName: getFormDisplayName(cert.formType),
          status: 'Active'
        }))];
        console.log('[CERTIFICATES] Found', activeCertificates.length, 'active certificates');
      }
    } catch {
      console.log('[CERTIFICATES] No active certificates file found');
    }

    // ✅ NEW: Get historical certificates
    try {
      const historyData = loadJSON(FORM_HISTORY);
      if (Array.isArray(historyData)) {
        const historicalEntries = historyData.filter(h => h.employeeId === employeeId && h.preservedData?.certificates);
        console.log('[CERTIFICATES] Found', historicalEntries.length, 'historical entries with certificates');

        historicalEntries.forEach(historyEntry => {
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
      }
    } catch {
      console.log('[CERTIFICATES] No history file found for certificates');
    }

    // Sort certificates by generation date (newest first)
    allCertificates.sort((a, b) => new Date(b.generatedAt || b.completedAt) - new Date(a.generatedAt || a.completedAt));

    console.log(`[CERTIFICATES] ✅ Found ${allCertificates.length} total certificates for employee ${employeeId} (${allCertificates.filter(c => c.source === 'active').length} active, ${allCertificates.filter(c => c.source === 'history').length} historical)`);

    res.json({ success: true, certificates: allCertificates });

  } catch (error) {
    console.error('[CERTIFICATES] ❌ Error fetching certificates:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
});

// ✅ ENHANCED: Certificate download with history support
router.get('/certificates/:certId/download', roleAuth('employee'), (req, res) => {
  console.log('[CERT_DOWNLOAD] Certificate download request');

  try {
    const { certId } = req.params;
    const sessionUser = req.session?.user;

    console.log('[CERT_DOWNLOAD] Certificate ID:', certId);

    if (!sessionUser) {
      console.log('[CERT_DOWNLOAD] ❌ Not authenticated');
      return res.status(401).json({ success: false, message: 'Not authenticated' });
    }

    const employeeId = sessionUser.id || sessionUser.employeeId;
    if (!employeeId) {
      console.log('[CERT_DOWNLOAD] ❌ Employee ID not found in session');
      return res.status(401).json({ success: false, message: 'Employee ID not found in session' });
    }

    console.log('[CERT_DOWNLOAD] Employee ID:', employeeId);

    let certificate = null;

    // Check active certificates first
    try {
      const data = loadJSON(CERTIFICATES);
      if (Array.isArray(data)) {
        certificate = data.find(cert => cert.id === certId && cert.employeeId === employeeId);
        if (certificate) {
          console.log('[CERT_DOWNLOAD] Found certificate in active records');
        }
      }
    } catch { }

    // If not found in active, check history
    if (!certificate && certId.startsWith('hist_')) {
      console.log('[CERT_DOWNLOAD] Searching in historical records');
      try {
        const historyData = loadJSON(FORM_HISTORY);
        if (Array.isArray(historyData)) {
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
                  console.log('[CERT_DOWNLOAD] Found certificate in history records');
                  break;
                }
              }
            }
            if (certificate) break;
          }
        }
      } catch { }
    }

    if (!certificate) {
      console.log('[CERT_DOWNLOAD] ❌ Certificate not found');
      return res.status(404).json({ success: false, message: 'Certificate not found' });
    }

    if (certificate.employeeId !== employeeId) {
      console.log('[CERT_DOWNLOAD] ❌ Access denied - employee mismatch');
      return res.status(403).json({ success: false, message: 'Access denied' });
    }

    const filePath = certificate.filepath;
    console.log('[CERT_DOWNLOAD] File path:', filePath);

    if (!fs.existsSync(filePath)) {
      console.error(`[CERT_DOWNLOAD] ❌ Certificate file not found: ${filePath}`);
      return res.status(404).json({ success: false, message: 'Certificate file not found on server' });
    }

    console.log(`[CERT_DOWNLOAD] 📥 Downloading certificate: ${certificate.filename} for employee ${employeeId} (${certificate.source || 'active'})`);

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${certificate.filename}"`);
    res.setHeader('Cache-Control', 'no-cache');

    const fileStream = fs.createReadStream(filePath);

    fileStream.on('error', (error) => {
      console.error('[CERT_DOWNLOAD] ❌ Error streaming certificate file:', error.message);
      if (!res.headersSent) {
        res.status(500).json({ success: false, message: 'Error streaming certificate file' });
      }
    });

    fileStream.pipe(res);

  } catch (error) {
    console.error('[CERT_DOWNLOAD] ❌ Error downloading certificate:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
});

// ✅ ENHANCED: Dashboard Status with Certificate Preservation
router.get('/dashboard-status', roleAuth('employee'), async (req, res) => {
  console.log('[DASHBOARD] Fetching dashboard status...');
  console.log('[DASHBOARD] Request from IP:', req.ip);

  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) {
      console.log('[DASHBOARD] ❌ Session expired');
      return res.status(401).json({ success: false, message: 'Session expired' });
    }

    const employeeId = sessionUser.id || sessionUser.employeeId;
    const { name, role } = sessionUser;

    console.log('[DASHBOARD] Employee details:', { employeeId, name, role });

    let pendingForms = [];
    try {
      const data = loadJSON(PENDING_FORMS);
      pendingForms = Array.isArray(data) ? data : [];
      console.log('[DASHBOARD] Loaded', pendingForms.length, 'pending forms');
    } catch { }

    // Get latest active form
    const form = getLatestFormForEmployee(pendingForms, employeeId);

    // Update session formId if needed
    if (form && req.session.user.formId !== form.formId) {
      console.log('[DASHBOARD] Updating session formId to', form.formId);
      req.session.user.formId = form.formId;
    }

    // ✅ ENHANCED: Get certificates from ALL sources (active + history)
    let allCertificates = [];

    // Get active certificates
    try {
      const certData = loadJSON(CERTIFICATES);
      if (Array.isArray(certData)) {
        const activeCerts = certData.filter(cert => cert.employeeId === employeeId);
        allCertificates = [...activeCerts];
        console.log('[DASHBOARD] Found', activeCerts.length, 'active certificates');
      }
    } catch { }

    // Get certificates from history
    try {
      const historyData = loadJSON(FORM_HISTORY);
      if (Array.isArray(historyData)) {
        const historicalCertificates = historyData
          .filter(h => h.employeeId === employeeId && h.preservedData?.certificates)
          .flatMap(h => h.preservedData.certificates || []);
        allCertificates = [...allCertificates, ...historicalCertificates];
        console.log('[DASHBOARD] Found', historicalCertificates.length, 'historical certificates');
      }
    } catch { }

    const certificateCount = allCertificates.length;
    console.log('[DASHBOARD] Total certificates available:', certificateCount);

    // Handle rejection status
    if (form && form.status && form.status.toLowerCase().includes('rejected')) {
      console.log('[DASHBOARD] Form status is rejected');
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
        sessionCleanup: !!sessionUser.cleanupPerformed
      });
    }

    console.log('[DASHBOARD] ✅ Dashboard status prepared successfully');

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
      sessionCleanup: !!sessionUser.cleanupPerformed
    });

  } catch (err) {
    console.error('[DASHBOARD] ❌ Dashboard status error:', err.message);
    res.status(500).json({
      success: false,
      message: 'Error fetching dashboard status: ' + err.message
    });
  }
});

// --------------------- FIXED: Assigned Forms ---------------------
router.get('/assigned-forms', roleAuth('employee'), (req, res) => {
  console.log('[ASSIGNED_FORMS] Fetching assigned forms...');
  console.log('[ASSIGNED_FORMS] Request from IP:', req.ip);

  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) {
      console.log('[ASSIGNED_FORMS] ❌ Session expired');
      return res.status(401).json({ success: false, message: 'Session expired' });
    }

    const employeeId = sessionUser.id || sessionUser.employeeId;
    if (!employeeId) {
      console.log('[ASSIGNED_FORMS] ❌ Employee ID missing in session');
      return res.status(400).json({ success: false, message: 'Employee ID missing in session' });
    }

    console.log('[ASSIGNED_FORMS] Employee ID:', employeeId);

    let allForms = [];
    try {
      const data = loadJSON(PENDING_FORMS);
      allForms = Array.isArray(data) ? data : [];
      console.log('[ASSIGNED_FORMS] Loaded', allForms.length, 'total forms');
    } catch (loadError) {
      console.error('[ASSIGNED_FORMS] ❌ Database error:', loadError.message);
      return res.status(500).json({ success: false, message: 'Database error: Unable to load forms data' });
    }

    console.log(`[ASSIGNED_FORMS] 🔍 All forms for employee ${employeeId}:`,
      allForms.filter(f => f && f.employeeId === employeeId)
        .map(f => ({ formId: f.formId, status: f.status, submissionDate: f.submissionDate }))
    );

    // ✅ CRITICAL FIX: Filter only NON-COMPLETED forms for assigned forms display
    const allowedStatuses = ['approved', 'Submitted to HOD', 'pending', 'Pending'];  // ❌ Removed 'IT Completed'
    const myForms = allForms.filter(f => {
      return f &&
        f.employeeId === employeeId &&
        f.status &&
        allowedStatuses.includes(f.status);
    });

    console.log(`[ASSIGNED_FORMS] 📋 Filtered forms for employee ${employeeId}:`,
      myForms.map(f => ({ formId: f.formId, status: f.status, assignedFormsCount: f.assignedForms?.length || 0 }))
    );

    if (myForms.length === 0) {
      console.log('[ASSIGNED_FORMS] No active forms found');
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

    console.log(`[ASSIGNED_FORMS] ✅ Selected form for ${employeeId}: ${myForm.formId} (${myForm.status}) - ${myForm.assignedForms?.length || 0} assigned forms`);

    // Update session formId if needed
    if (req.session.user.formId !== myForm.formId) {
      console.log('[ASSIGNED_FORMS] Updating session formId to', myForm.formId);
      req.session.user.formId = myForm.formId;
    }

    if (myForm.status && myForm.status.toLowerCase().includes('rejected')) {
      console.log('[ASSIGNED_FORMS] Form status is rejected');
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

    return res.json({
      success: true,
      formId: myForm.formId,
      applicationStatus: myForm.status,
      assignedFormsCount: myForm.assignedForms?.length || 0,
      assignedForms: myForm.assignedForms || []
    });

  } catch (error) {
    console.error('[ASSIGNED_FORMS] 💥 Unexpected error:', error.message);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

// --------------------- Form Data Retrieval ---------------------
router.get('/form-data', roleAuth('employee'), (req, res) => {
  console.log('[FORM_DATA] Form data retrieval request');
  console.log('[FORM_DATA] Request from IP:', req.ip);

  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) {
      console.log('[FORM_DATA] ❌ Session expired');
      return res.status(401).json({ success: false, message: 'Session expired' });
    }

    const employeeId = sessionUser.id || sessionUser.employeeId;
    const { formName } = req.query;

    console.log('[FORM_DATA] Employee ID:', employeeId, 'Form Name:', formName);

    if (!formName) {
      console.log('[FORM_DATA] ❌ Missing formName in query');
      return res.status(400).json({
        success: false,
        message: 'Missing formName in query'
      });
    }

    let pendingForms = [];
    try {
      const data = loadJSON(PENDING_FORMS);
      pendingForms = Array.isArray(data) ? data : [];
      console.log('[FORM_DATA] Loaded', pendingForms.length, 'pending forms');
    } catch {
      console.log('[FORM_DATA] No pending forms found');
      pendingForms = [];
    }

    // Get latest form for employee
    const formEntry = getLatestFormForEmployee(pendingForms, employeeId);

    // Update session formId if needed
    if (formEntry && req.session.user.formId !== formEntry.formId) {
      console.log('[FORM_DATA] Updating session formId to', formEntry.formId);
      req.session.user.formId = formEntry.formId;
    }

    if (!formEntry) {
      console.log('[FORM_DATA] ❌ No pending form found');
      return res.status(404).json({
        success: false,
        message: 'No pending form found'
      });
    }

    const formMap = {
      disposalForm: 'disposalFormData',
      efileForm: 'efileFormData',
      form365Transfer: 'form365TransferData',
      form365Disposal: 'form365Data'
    };

    const formKey = formMap[formName];
    if (!formKey) {
      console.log('[FORM_DATA] ❌ Invalid formName:', formName);
      return res.status(400).json({
        success: false,
        message: 'Invalid formName: ' + formName
      });
    }

    const formData = formEntry.formResponses?.[formKey] || null;

    console.log(`[FORM_DATA] 📄 Returning form data for ${formName}:`, formData ? 'Found' : 'Not found');

    res.json({
      success: true,
      formData: formData,
      hasData: !!formData
    });

  } catch (error) {
    console.error('[FORM_DATA] ❌ Error fetching form data:', error.message);
    res.status(500).json({
      success: false,
      message: 'Internal server error: ' + error.message
    });
  }
});

//FORM STATUS
router.get('/form-status', roleAuth('employee'), async (req, res) => {
  console.log('[FORM_STATUS] Form status request');
  console.log('[FORM_STATUS] Request from IP:', req.ip);

  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) {
      console.log('[FORM_STATUS] ❌ Session expired');
      return res.status(401).json({ success: false, message: 'Session expired' });
    }

    const employeeId = sessionUser.id || sessionUser.employeeId;
    console.log('[FORM_STATUS] Employee ID:', employeeId);

    let pendingForms = [];
    try {
      const data = loadJSON(PENDING_FORMS);
      pendingForms = Array.isArray(data) ? data : [];
      console.log('[FORM_STATUS] Loaded', pendingForms.length, 'pending forms');
    } catch { }

    const form = getLatestFormForEmployee(pendingForms, employeeId);

    if (!form) {
      console.log('[FORM_STATUS] No active form found');
      return res.json({
        success: true,
        status: 'pending',
        context: { message: 'No active form found' }
      });
    }

    console.log('[FORM_STATUS] ✅ Form status:', form.status, 'for form:', form.formId);

    res.json({
      success: true,
      status: form.status,
      context: {
        formId: form.formId,
        lastUpdated: form.lastUpdated,
        rejectionReason: form.rejectionReason
      }
    });

  } catch (error) {
    console.error('[FORM_STATUS] ❌ Error getting form status:', error.message);
    res.status(500).json({
      success: false,
      message: 'Failed to get form status'
    });
  }
});

// --------------------- Track Forms ---------------------
router.get('/track', roleAuth('employee'), (req, res) => {
  console.log('[TRACK] Form tracking request');
  console.log('[TRACK] Request from IP:', req.ip);

  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) {
      console.log('[TRACK] ❌ Session expired');
      return res.status(401).json({ success: false, message: 'Session expired' });
    }

    const employeeId = sessionUser.id || sessionUser.employeeId;
    console.log('[TRACK] Employee ID:', employeeId);

    let pendingForms = [];
    try {
      const data = loadJSON(PENDING_FORMS);
      pendingForms = Array.isArray(data) ? data : [];
      console.log('[TRACK] Loaded', pendingForms.length, 'pending forms');
    } catch {
      console.log('[TRACK] No pending forms found');
      pendingForms = [];
    }

    // Get all forms for employee, sorted by latest first
    const myForms = pendingForms
      .filter(f => f && f.employeeId === employeeId)
      .sort((a, b) => new Date(b.submissionDate || b.lastUpdated) - new Date(a.submissionDate || a.lastUpdated));

    console.log('[TRACK] ✅ Found', myForms.length, 'forms for employee');

    res.json({ success: true, forms: myForms });
  } catch (err) {
    console.error('[TRACK] ❌ Track error:', err.message);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve track data: ' + err.message
    });
  }
});

// ✅ ENHANCED: History with Comprehensive Data
router.get('/history', roleAuth('employee'), (req, res) => {
  console.log('[HISTORY] Form history request');
  console.log('[HISTORY] Request from IP:', req.ip);

  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) {
      console.log('[HISTORY] ❌ Session expired');
      return res.status(401).json({ success: false, message: 'Session expired' });
    }

    const employeeId = sessionUser.id || sessionUser.employeeId;
    console.log('[HISTORY] Employee ID:', employeeId);

    let history = [];
    try {
      const data = loadJSON(FORM_HISTORY);
      history = Array.isArray(data) ? data : [];
      console.log('[HISTORY] Loaded', history.length, 'history entries');
    } catch {
      console.log('[HISTORY] No history found');
      history = [];
    }

    // ✅ Get comprehensive history for employee
    const myHistory = history
      .filter(f => f && f.employeeId === employeeId)
      .map(form => ({
        ...form,
        // Enhanced history information
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

    console.log('[HISTORY] ✅ Found', myHistory.length, 'history entries for employee');

    const summary = {
      totalApplications: myHistory.length,
      totalCertificates: myHistory.reduce((sum, h) => sum + (h.historyInfo.certificateCount || 0), 0),
      completedApplications: myHistory.filter(h => h.finalStatus === 'IT Completed').length,
      rejectedApplications: myHistory.filter(h => h.finalStatus && h.finalStatus.toLowerCase().includes('rejected')).length
    };

    console.log('[HISTORY] History summary:', summary);

    res.json({
      success: true,
      history: myHistory,
      summary
    });
  } catch (err) {
    console.error('[HISTORY] ❌ History error:', err.message);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve form history: ' + err.message
    });
  }
});

// --------------------- Confirmation ---------------------
router.get('/confirmation', roleAuth('employee'), (req, res) => {
  console.log('[CONFIRMATION] Confirmation request');
  console.log('[CONFIRMATION] Request from IP:', req.ip);

  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) {
      console.log('[CONFIRMATION] ❌ Session expired');
      return res.status(401).json({ success: false, message: 'Session expired' });
    }

    const employeeId = sessionUser.id || sessionUser.employeeId;
    console.log('[CONFIRMATION] Employee ID:', employeeId);

    let pendingForms = [];
    try {
      const data = loadJSON(PENDING_FORMS);
      pendingForms = Array.isArray(data) ? data : [];
      console.log('[CONFIRMATION] Loaded', pendingForms.length, 'pending forms');
    } catch {
      console.log('[CONFIRMATION] ❌ No forms data found');
      return res.status(404).json({
        success: false,
        message: 'No forms data found'
      });
    }

    // Get latest form for employee
    const form = getLatestFormForEmployee(pendingForms, employeeId);

    // Update session formId if needed
    if (form && req.session.user.formId !== form.formId) {
      console.log('[CONFIRMATION] Updating session formId to', form.formId);
      req.session.user.formId = form.formId;
    }

    if (!form) {
      console.log('[CONFIRMATION] ❌ Form not found');
      return res.status(404).json({
        success: false,
        message: 'Form not found'
      });
    }

    console.log('[CONFIRMATION] ✅ Form data retrieved for:', form.formId);
    res.json({ success: true, data: form });
  } catch (err) {
    console.error('[CONFIRMATION] ❌ Confirmation error:', err.message);
    res.status(500).json({
      success: false,
      message: 'Internal Server Error: ' + err.message
    });
  }
});

// --------------------- PDF Download ---------------------
router.get('/form-pdf/:formId', roleAuth('employee'), (req, res) => {
  console.log('[PDF_DOWNLOAD] PDF download request for form:', req.params.formId);
  console.log('[PDF_DOWNLOAD] Request from IP:', req.ip);

  const pdfPath = path.join(__dirname, '../public/forms/sample_form.pdf');
  console.log('[PDF_DOWNLOAD] PDF path:', pdfPath);

  res.sendFile(pdfPath, (err) => {
    if (err) {
      console.error('[PDF_DOWNLOAD] ❌ Error sending PDF:', err.message);
      res.status(404).json({ success: false, message: 'PDF not found' });
    } else {
      console.log('[PDF_DOWNLOAD] ✅ PDF sent successfully');
    }
  });
});

// --------------------- Employee Info ---------------------
router.get('/employee-info', roleAuth('employee'), (req, res) => {
  console.log('[EMPLOYEE_INFO] Employee info request');
  console.log('[EMPLOYEE_INFO] Request from IP:', req.ip);

  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) {
      console.log('[EMPLOYEE_INFO] ❌ Session expired');
      return res.status(401).json({ success: false, message: 'Session expired' });
    }

    const employeeId = sessionUser.id || sessionUser.employeeId;
    console.log('[EMPLOYEE_INFO] Employee ID:', employeeId);

    let users = [];
    try {
      const data = loadJSON(USERS);
      users = Array.isArray(data) ? data : [];
      console.log('[EMPLOYEE_INFO] Loaded', users.length, 'users');
    } catch {
      console.log('[EMPLOYEE_INFO] ❌ Users data not found');
      return res.status(404).json({
        success: false,
        message: 'Users data not found'
      });
    }

    const employee = users.find(u =>
      u && (u.employeeId === employeeId || u.id === employeeId)
    );

    if (!employee) {
      console.log('[EMPLOYEE_INFO] ❌ Employee not found in users database');
      return res.status(404).json({
        success: false,
        message: 'Employee not found'
      });
    }

    console.log('[EMPLOYEE_INFO] ✅ Employee info retrieved for:', employee.name);

    res.json({
      success: true,
      employee: {
        name: employee.name || 'Unknown',
        employeeId: employee.employeeId || employee.id || 'Unknown',
        department: employee.department || 'Unknown'
      }
    });
  } catch (err) {
    console.error('[EMPLOYEE_INFO] ❌ Employee info error:', err.message);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve employee info: ' + err.message
    });
  }
});

console.log('[EMPLOYEE_ROUTER] Employee router initialization complete with enhanced logging');

module.exports = router;
