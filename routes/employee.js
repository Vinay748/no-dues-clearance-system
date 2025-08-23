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

// Setup multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// âœ… NEW: Helper function to move completed form to history
async function moveCompletedFormToHistory(employeeId, formData) {
  try {
    let history = [];
    try {
      const data = loadJSON(FORM_HISTORY);
      history = Array.isArray(data) ? data : [];
    } catch {
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

    console.log(`ðŸ“š Moved form ${formData.formId} to history for employee ${employeeId}`);
    return true;
  } catch (error) {
    console.error('Error moving form to history:', error);
    return false;
  }
}

// Helper function to get latest form for employee
function getLatestFormForEmployee(allForms, employeeId, allowedStatuses = null) {
  let employeeForms = allForms.filter(f => f && f.employeeId === employeeId);  // âœ… FIXED: let instead of const

  if (allowedStatuses) {
    employeeForms = employeeForms.filter(f => allowedStatuses.includes(f.status));
  }

  return employeeForms
    .sort((a, b) => new Date(b.submissionDate || b.lastUpdated) - new Date(a.submissionDate || a.lastUpdated))[0] || null;
}

// --------------------- OTP ---------------------
router.post('/verify-otp', roleAuth('employee'), (req, res) => {
  const { otp } = req.body;
  res.json({ success: otp === '123456', message: otp === '123456' ? undefined : 'Invalid OTP' });
});

// --------------------- No Dues Form Submission ---------------------
router.post('/submit-no-dues', roleAuth('employee'), upload.single('orderLetter'), (req, res) => {
  console.log('ðŸ” === Form Submission Debug ===');

  try {
    // Basic validation
    if (!req.body) return res.status(400).json({ success: false, message: 'Request body is missing' });
    if (!req.session?.user) return res.status(401).json({ success: false, message: 'Session not found' });
    if (!req.file) return res.status(400).json({ success: false, message: 'Order letter file is required' });

    const bodyData = req.body;
    const sessionUser = req.session.user;

    const name = bodyData.name || sessionUser.name || '';
    const employeeId = bodyData.employeeId || sessionUser.id || sessionUser.employeeId || '';
    const email = bodyData.email || '';
    const department = bodyData.department || '';
    const noDuesType = bodyData.noDuesType || '';
    const reason = bodyData.reason || '';

    console.log('  Extracted safely:', { name, employeeId, email, department, noDuesType, reason });

    if (!name || !employeeId || !email || !department || !noDuesType) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    // Load existing forms
    let pendingForms = [];
    try {
      const loadedData = loadJSON(PENDING_FORMS);
      if (Array.isArray(loadedData)) {
        pendingForms = loadedData;
        console.log('  âœ… Successfully loaded', pendingForms.length, 'forms');
      }
    } catch (loadError) {
      console.error('  âŒ Error loading JSON:', loadError.message);
      pendingForms = [];
    }

    // Check for existing active applications using latest form logic
    const activeStatuses = ['Pending', 'pending', 'Submitted to HOD', 'Submitted to IT', 'approved'];
    const existingForm = getLatestFormForEmployee(pendingForms, employeeId, activeStatuses);

    if (existingForm) {
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

    pendingForms.push(newForm);
    saveJSON(PENDING_FORMS, pendingForms);

    // Update session with formId
    req.session.user.formId = formId;
    req.session.user.applicationStatus = 'pending';

    console.log('ðŸŽ‰ Success! Form', formId, 'created');

    res.json({
      success: true,
      message: 'Application submitted successfully',
      formId,
      status: 'pending'
    });

  } catch (error) {
    console.error('ðŸ’¥ FATAL ERROR in submit-no-dues:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error: ' + error.message
    });
  }
});

// --------------------- Check Previous Application ---------------------
router.get('/previous-application', roleAuth('employee'), (req, res) => {
  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) return res.status(401).json({ success: false, message: 'Session expired' });

    const employeeId = sessionUser.id || sessionUser.employeeId;
    if (!employeeId) return res.status(400).json({ success: false, message: 'No employee ID found in session' });

    let pendingForms = [];
    try {
      const data = loadJSON(PENDING_FORMS);
      pendingForms = Array.isArray(data) ? data : [];
    } catch {
      return res.json({ success: true, hasApplication: false, message: 'No previous applications found' });
    }

    const latestApp = getLatestFormForEmployee(pendingForms, employeeId);

    if (!latestApp) {
      return res.json({ success: true, hasApplication: false, message: 'No applications found' });
    }

    res.json({ success: true, hasApplication: true, application: latestApp });
  } catch (error) {
    console.error('Error checking previous application:', error);
    res.status(500).json({ success: false, message: 'Error checking previous application: ' + error.message });
  }
});

// --------------------- Detailed Tracking Endpoint ---------------------
router.get('/tracking-details', roleAuth('employee'), (req, res) => {
  try {
    console.log('ðŸŽ¯ Fetching detailed tracking information...');

    const sessionUser = req.session?.user;
    if (!sessionUser) return res.status(401).json({ success: false, message: 'Not authenticated' });

    const employeeId = sessionUser.id || sessionUser.employeeId;

    let formsData = [];
    try {
      const data = loadJSON(PENDING_FORMS);
      formsData = Array.isArray(data) ? data : [];
    } catch {
      formsData = [];
    }

    // Get latest form for employee
    const employeeForm = getLatestFormForEmployee(formsData, employeeId);

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

    // Update session formId if needed
    if (req.session.user.formId !== employeeForm.formId) {
      req.session.user.formId = employeeForm.formId;
    }

    const timeline = buildTimelineData(employeeForm);
    const formsStatus = getFormsCompletionStatus(employeeForm);

    console.log(`âœ… Found application ${employeeForm.formId} for employee ${employeeId}`);
    console.log(`ðŸ“Š Timeline has ${timeline.length} events, ${formsStatus.length} forms`);

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
    console.error('âŒ Error getting tracking details:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Helper function to build timeline data
function buildTimelineData(formData) {
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

// Helper function to get forms completion status
function getFormsCompletionStatus(formData) {
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

// --------------------- Save Form APIs ---------------------
const savePartialForm = (reqKey, storageKey) => {
  return async (req, res) => {
    try {
      console.log(`ðŸ’¾ Saving ${storageKey}...`);

      const sessionUser = req.session?.user;
      if (!sessionUser) return res.status(401).json({ success: false, message: "Session expired" });

      const employeeId = sessionUser.id || sessionUser.employeeId;
      if (!employeeId) return res.status(400).json({ success: false, message: "No employee ID found in session" });

      let allForms = [];
      try {
        const data = loadJSON(PENDING_FORMS);
        allForms = Array.isArray(data) ? data : [];
      } catch {
        allForms = [];
      }

      // Get latest form for employee
      const latestForm = getLatestFormForEmployee(allForms, employeeId);
      const formIndex = latestForm ? allForms.findIndex(f => f.formId === latestForm.formId) : -1;

      if (formIndex === -1) {
        return res.status(404).json({
          success: false,
          message: "No pending form found for this employee. Please submit initial application first."
        });
      }

      // Update session formId if needed
      if (req.session.user.formId !== latestForm.formId) {
        req.session.user.formId = latestForm.formId;
      }

      if (!allForms[formIndex].formResponses) {
        allForms[formIndex].formResponses = {};
      }

      let parsedData;
      try {
        const inputData = req.body[reqKey] || req.body;

        if (!inputData) {
          return res.status(400).json({
            success: false,
            message: `No data provided for ${storageKey}`
          });
        }

        parsedData = typeof inputData === "string" ? JSON.parse(inputData) : inputData;

        if (!parsedData || typeof parsedData !== 'object') {
          return res.status(400).json({
            success: false,
            message: `Invalid data format for ${storageKey}`
          });
        }

      } catch (parseError) {
        console.error(`JSON parse error for ${storageKey}:`, parseError);
        return res.status(400).json({
          success: false,
          message: `Invalid JSON format for ${storageKey}: ${parseError.message}`
        });
      }

      allForms[formIndex].formResponses[storageKey] = parsedData;
      allForms[formIndex].lastUpdated = new Date().toISOString();

      try {
        saveJSON(PENDING_FORMS, allForms);
      } catch (saveError) {
        console.error(`Error saving ${storageKey}:`, saveError);
        return res.status(500).json({
          success: false,
          message: `Failed to save ${storageKey}`
        });
      }

      console.log(`âœ… ${storageKey} saved successfully for employee ${employeeId}`);
      res.json({
        success: true,
        message: `${storageKey} saved successfully`,
        dataKeys: Object.keys(parsedData),
        timestamp: new Date().toISOString()
      });

    } catch (err) {
      console.error(`âŒ Error saving ${storageKey}:`, err);
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
  try {
    console.log('ðŸ“¤ Employee final submit request...');

    const sessionUser = req.session?.user;
    if (!sessionUser) return res.status(401).json({ success: false, message: 'Session expired' });

    const employeeId = sessionUser.id || sessionUser.employeeId;
    if (!employeeId) return res.status(400).json({ success: false, message: 'No employee ID found in session' });

    const { disposalForm, efileForm, form365Transfer, form365Disposal } = req.body || {};

    let pendingForms = [];
    try {
      const data = loadJSON(PENDING_FORMS);
      pendingForms = Array.isArray(data) ? data : [];
    } catch {
      return res.status(404).json({ success: false, message: 'No pending forms found' });
    }

    // Get latest form for employee
    const latestForm = getLatestFormForEmployee(pendingForms, employeeId);
    const formIndex = latestForm ? pendingForms.findIndex(f => f.formId === latestForm.formId) : -1;

    if (formIndex === -1) {
      return res.status(404).json({ success: false, message: 'No pending form found for this employee' });
    }

    const form = pendingForms[formIndex];

    if (!disposalForm || typeof disposalForm !== 'object') {
      return res.status(400).json({ success: false, message: 'Valid disposal form data is required' });
    }

    if (!efileForm || typeof efileForm !== 'object') {
      return res.status(400).json({ success: false, message: 'Valid e-file form data is required' });
    }

    if ((!form365Transfer || typeof form365Transfer !== 'object') &&
      (!form365Disposal || typeof form365Disposal !== 'object')) {
      return res.status(400).json({ success: false, message: 'Valid Form 365 (Transfer or Disposal) data is required' });
    }

    if (!form.formResponses) {
      form.formResponses = {};
    }

    form.formResponses.disposalFormData = disposalForm;
    form.formResponses.efileFormData = efileForm;

    if (form365Transfer && typeof form365Transfer === 'object') {
      form.formResponses.form365TransferData = form365Transfer;
    }
    if (form365Disposal && typeof form365Disposal === 'object') {
      form.formResponses.form365Data = form365Disposal;
    }

    form.status = 'Submitted to HOD';
    form.finalSubmittedAt = new Date().toISOString();
    form.lastUpdated = new Date().toISOString();

    pendingForms[formIndex] = form;

    // Update session formId if needed
    if (req.session.user.formId !== form.formId) {
      req.session.user.formId = form.formId;
    }

    try {
      saveJSON(PENDING_FORMS, pendingForms);
    } catch (saveError) {
      return res.status(500).json({ success: false, message: 'Failed to save form submission' });
    }

    console.log(`âœ… Form ${form.formId} submitted to HOD successfully`);

    res.json({
      success: true,
      message: 'Forms submitted to HOD for review',
      formId: form.formId,
      status: 'Submitted to HOD'
    });

  } catch (err) {
    console.error('âŒ Final Submit Error:', err);
    res.status(500).json({ success: false, message: 'Internal Server Error: ' + err.message });
  }
});

// âœ… ENHANCED: Certificate Endpoints with History Support
router.get('/certificates', roleAuth('employee'), (req, res) => {
  try {
    console.log('ðŸ“œ Fetching certificates for employee (including history)...');

    const sessionUser = req.session?.user;
    if (!sessionUser) return res.status(401).json({ success: false, message: 'Not authenticated' });

    const employeeId = sessionUser.id || sessionUser.employeeId;
    if (!employeeId) return res.status(401).json({ success: false, message: 'Employee ID not found in session' });

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
      }
    } catch {
      console.log('No active certificates file found');
    }

    // âœ… NEW: Get historical certificates
    try {
      const historyData = loadJSON(FORM_HISTORY);
      if (Array.isArray(historyData)) {
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
                  filepath: cert.filepath // âœ… Preserve file path for downloads
                });
              });
            }
          });
      }
    } catch {
      console.log('No history file found for certificates');
    }

    // Sort certificates by generation date (newest first)
    allCertificates.sort((a, b) => new Date(b.generatedAt || b.completedAt) - new Date(a.generatedAt || a.completedAt));

    console.log(`âœ… Found ${allCertificates.length} total certificates for employee ${employeeId} (${allCertificates.filter(c => c.source === 'active').length} active, ${allCertificates.filter(c => c.source === 'history').length} historical)`);

    res.json({ success: true, certificates: allCertificates });

  } catch (error) {
    console.error('âŒ Error fetching certificates:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// âœ… ENHANCED: Certificate download with history support
router.get('/certificates/:certId/download', roleAuth('employee'), (req, res) => {
  try {
    const { certId } = req.params;
    const sessionUser = req.session?.user;

    if (!sessionUser) return res.status(401).json({ success: false, message: 'Not authenticated' });

    const employeeId = sessionUser.id || sessionUser.employeeId;
    if (!employeeId) return res.status(401).json({ success: false, message: 'Employee ID not found in session' });

    let certificate = null;

    // Check active certificates first
    try {
      const data = loadJSON(CERTIFICATES);
      if (Array.isArray(data)) {
        certificate = data.find(cert => cert.id === certId && cert.employeeId === employeeId);
      }
    } catch { }

    // If not found in active, check history
    if (!certificate && certId.startsWith('hist_')) {
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
      return res.status(404).json({ success: false, message: 'Certificate not found' });
    }

    if (certificate.employeeId !== employeeId) {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }

    const filePath = certificate.filepath;

    if (!fs.existsSync(filePath)) {
      console.error(`Certificate file not found: ${filePath}`);
      return res.status(404).json({ success: false, message: 'Certificate file not found on server' });
    }

    console.log(`ðŸ“¥ Downloading certificate: ${certificate.filename} for employee ${employeeId} (${certificate.source || 'active'})`);

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${certificate.filename}"`);
    res.setHeader('Cache-Control', 'no-cache');

    const fileStream = fs.createReadStream(filePath);

    fileStream.on('error', (error) => {
      console.error('Error streaming certificate file:', error);
      if (!res.headersSent) {
        res.status(500).json({ success: false, message: 'Error streaming certificate file' });
      }
    });

    fileStream.pipe(res);

  } catch (error) {
    console.error('âŒ Error downloading certificate:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// âœ… ENHANCED: Dashboard Status with Certificate Preservation
router.get('/dashboard-status', roleAuth('employee'), async (req, res) => {
  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) return res.status(401).json({ success: false, message: 'Session expired' });

    const employeeId = sessionUser.id || sessionUser.employeeId;
    const { name, role } = sessionUser;

    let pendingForms = [];
    try {
      const data = loadJSON(PENDING_FORMS);
      pendingForms = Array.isArray(data) ? data : [];
    } catch { }

    // Get latest active form
    const form = getLatestFormForEmployee(pendingForms, employeeId);

    // Update session formId if needed
    if (form && req.session.user.formId !== form.formId) {
      req.session.user.formId = form.formId;
    }

    // âœ… ENHANCED: Get certificates from ALL sources (active + history)
    let allCertificates = [];

    // Get active certificates
    try {
      const certData = loadJSON(CERTIFICATES);
      if (Array.isArray(certData)) {
        allCertificates = certData.filter(cert => cert.employeeId === employeeId);
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
      }
    } catch { }

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
        certificatesAvailable: certificateCount, // âœ… Include ALL certificates
        canSubmitNew: true,
        sessionCleanup: !!sessionUser.cleanupPerformed
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
      certificatesAvailable: certificateCount, // âœ… Include ALL certificates
      sessionCleanup: !!sessionUser.cleanupPerformed
    });

  } catch (err) {
    console.error('âŒ /dashboard-status error:', err);
    res.status(500).json({
      success: false,
      message: 'Error fetching dashboard status: ' + err.message
    });
  }
});

// --------------------- FIXED: Assigned Forms ---------------------
router.get('/assigned-forms', roleAuth('employee'), (req, res) => {
  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) return res.status(401).json({ success: false, message: 'Session expired' });

    const employeeId = sessionUser.id || sessionUser.employeeId;
    if (!employeeId) return res.status(400).json({ success: false, message: 'Employee ID missing in session' });

    let allForms = [];
    try {
      const data = loadJSON(PENDING_FORMS);
      allForms = Array.isArray(data) ? data : [];
    } catch (loadError) {
      return res.status(500).json({ success: false, message: 'Database error: Unable to load forms data' });
    }

    console.log(`ðŸ” All forms for employee ${employeeId}:`,
      allForms.filter(f => f && f.employeeId === employeeId)
        .map(f => ({ formId: f.formId, status: f.status, submissionDate: f.submissionDate }))
    );

    // âœ… CRITICAL FIX: Filter only NON-COMPLETED forms for assigned forms display
    const allowedStatuses = ['approved', 'Submitted to HOD', 'pending', 'Pending'];  // âŒ Removed 'IT Completed'
    const myForms = allForms.filter(f => {
      return f &&
        f.employeeId === employeeId &&
        f.status &&
        allowedStatuses.includes(f.status);
    });

    console.log(`ðŸ“‹ Filtered forms for employee ${employeeId}:`,
      myForms.map(f => ({ formId: f.formId, status: f.status, assignedFormsCount: f.assignedForms?.length || 0 }))
    );

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

    console.log(`âœ… Selected form for ${employeeId}: ${myForm.formId} (${myForm.status}) - ${myForm.assignedForms?.length || 0} assigned forms`);

    // Update session formId if needed
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

    return res.json({
      success: true,
      formId: myForm.formId,
      applicationStatus: myForm.status,
      assignedFormsCount: myForm.assignedForms?.length || 0,
      assignedForms: myForm.assignedForms || []
    });

  } catch (error) {
    console.error('ðŸ’¥ Unexpected error in /assigned-forms:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

// --------------------- Form Data Retrieval ---------------------
router.get('/form-data', roleAuth('employee'), (req, res) => {
  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) return res.status(401).json({ success: false, message: 'Session expired' });

    const employeeId = sessionUser.id || sessionUser.employeeId;
    const { formName } = req.query;

    if (!formName) {
      return res.status(400).json({
        success: false,
        message: 'Missing formName in query'
      });
    }

    let pendingForms = [];
    try {
      const data = loadJSON(PENDING_FORMS);
      pendingForms = Array.isArray(data) ? data : [];
    } catch {
      pendingForms = [];
    }

    // Get latest form for employee
    const formEntry = getLatestFormForEmployee(pendingForms, employeeId);

    // Update session formId if needed
    if (formEntry && req.session.user.formId !== formEntry.formId) {
      req.session.user.formId = formEntry.formId;
    }

    if (!formEntry) {
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
      return res.status(400).json({
        success: false,
        message: 'Invalid formName: ' + formName
      });
    }

    const formData = formEntry.formResponses?.[formKey] || null;

    console.log(`ðŸ“„ Returning form data for ${formName}:`, formData ? 'Found' : 'Not found');

    res.json({
      success: true,
      formData: formData,
      hasData: !!formData
    });

  } catch (error) {
    console.error('âŒ Error fetching form data:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error: ' + error.message
    });
  }
});

//FORM STATUS
router.get('/form-status', roleAuth('employee'), async (req, res) => {
  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) return res.status(401).json({ success: false, message: 'Session expired' });

    const employeeId = sessionUser.id || sessionUser.employeeId;

    let pendingForms = [];
    try {
      const data = loadJSON(PENDING_FORMS);
      pendingForms = Array.isArray(data) ? data : [];
    } catch { }

    const form = getLatestFormForEmployee(pendingForms, employeeId);

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
        rejectionReason: form.rejectionReason
      }
    });

  } catch (error) {
    console.error('Error getting form status:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get form status'
    });
  }
});


// --------------------- Track Forms ---------------------
router.get('/track', roleAuth('employee'), (req, res) => {
  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) return res.status(401).json({ success: false, message: 'Session expired' });

    const employeeId = sessionUser.id || sessionUser.employeeId;

    let pendingForms = [];
    try {
      const data = loadJSON(PENDING_FORMS);
      pendingForms = Array.isArray(data) ? data : [];
    } catch {
      pendingForms = [];
    }

    // Get all forms for employee, sorted by latest first
    const myForms = pendingForms
      .filter(f => f && f.employeeId === employeeId)
      .sort((a, b) => new Date(b.submissionDate || b.lastUpdated) - new Date(a.submissionDate || a.lastUpdated));

    res.json({ success: true, forms: myForms });
  } catch (err) {
    console.error('âŒ /track error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve track data: ' + err.message
    });
  }
});

// âœ… ENHANCED: History with Comprehensive Data
router.get('/history', roleAuth('employee'), (req, res) => {
  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) return res.status(401).json({ success: false, message: 'Session expired' });

    const employeeId = sessionUser.id || sessionUser.employeeId;

    let history = [];
    try {
      const data = loadJSON(FORM_HISTORY);
      history = Array.isArray(data) ? data : [];
    } catch {
      history = [];
    }

    // âœ… Get comprehensive history for employee
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

    res.json({
      success: true,
      history: myHistory,
      summary: {
        totalApplications: myHistory.length,
        totalCertificates: myHistory.reduce((sum, h) => sum + (h.historyInfo.certificateCount || 0), 0),
        completedApplications: myHistory.filter(h => h.finalStatus === 'IT Completed').length,
        rejectedApplications: myHistory.filter(h => h.finalStatus && h.finalStatus.toLowerCase().includes('rejected')).length
      }
    });
  } catch (err) {
    console.error('âŒ /history error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve form history: ' + err.message
    });
  }
});

// --------------------- Confirmation ---------------------
router.get('/confirmation', roleAuth('employee'), (req, res) => {
  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) return res.status(401).json({ success: false, message: 'Session expired' });

    const employeeId = sessionUser.id || sessionUser.employeeId;

    let pendingForms = [];
    try {
      const data = loadJSON(PENDING_FORMS);
      pendingForms = Array.isArray(data) ? data : [];
    } catch {
      return res.status(404).json({
        success: false,
        message: 'No forms data found'
      });
    }

    // Get latest form for employee
    const form = getLatestFormForEmployee(pendingForms, employeeId);

    // Update session formId if needed
    if (form && req.session.user.formId !== form.formId) {
      req.session.user.formId = form.formId;
    }

    if (!form) {
      return res.status(404).json({
        success: false,
        message: 'Form not found'
      });
    }

    res.json({ success: true, data: form });
  } catch (err) {
    console.error('âŒ /confirmation error:', err);
    res.status(500).json({
      success: false,
      message: 'Internal Server Error: ' + err.message
    });
  }
});

// --------------------- PDF Download ---------------------
router.get('/form-pdf/:formId', roleAuth('employee'), (req, res) => {
  const pdfPath = path.join(__dirname, '../public/forms/sample_form.pdf');
  res.sendFile(pdfPath, (err) => {
    if (err) {
      console.error('Error sending PDF:', err);
      res.status(404).json({ success: false, message: 'PDF not found' });
    }
  });
});

// --------------------- Employee Info ---------------------
router.get('/employee-info', roleAuth('employee'), (req, res) => {
  try {
    const sessionUser = req.session?.user;
    if (!sessionUser) return res.status(401).json({ success: false, message: 'Session expired' });

    const employeeId = sessionUser.id || sessionUser.employeeId;

    let users = [];
    try {
      const data = loadJSON(USERS);
      users = Array.isArray(data) ? data : [];
    } catch {
      return res.status(404).json({
        success: false,
        message: 'Users data not found'
      });
    }

    const employee = users.find(u =>
      u && (u.employeeId === employeeId || u.id === employeeId)
    );

    if (!employee) {
      return res.status(404).json({
        success: false,
        message: 'Employee not found'
      });
    }

    res.json({
      success: true,
      employee: {
        name: employee.name || 'Unknown',
        employeeId: employee.employeeId || employee.id || 'Unknown',
        department: employee.department || 'Unknown'
      }
    });
  } catch (err) {
    console.error('âŒ /employee-info error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve employee info: ' + err.message
    });
  }
});

module.exports = router;