const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();

// Import PDF generation utility
const { generateFormCertificates } = require('../utils/pdfGenerator');

// Import NotificationManager for real-time notifications
const NotificationManager = require('../utils/notificationManager');

const { roleAuth } = require('../middlewares/sessionAuth');
const pendingFormsPath = path.join(__dirname, '../data/pending_forms.json');
const certificatesPath = path.join(__dirname, '../data/certificates.json');

console.log('[IT_ADMIN_ROUTER] Initializing IT Admin router with file paths:', {
  pendingForms: pendingFormsPath,
  certificates: certificatesPath
});

// All routes below are protected for IT Admin only
router.use(roleAuth('it'));

console.log('[IT_ADMIN_ROUTER] IT role authentication middleware applied');

// ------------ Helpers ------------
function loadJSONFile(filePath) {
  console.log('[JSON_LOADER] Loading JSON file:', filePath);

  try {
    const data = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(data);
    console.log('[JSON_LOADER] ✅ Successfully loaded', Array.isArray(parsed) ? parsed.length : 'object', 'entries from', path.basename(filePath));
    return parsed;
  } catch (err) {
    console.error('[JSON_LOADER] ❌ Error loading', filePath, ':', err.message);
    return [];
  }
}

function saveJSONFile(filePath, data) {
  console.log('[JSON_SAVER] Saving JSON file:', filePath);
  console.log('[JSON_SAVER] Data to save:', Array.isArray(data) ? data.length + ' items' : 'object');

  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    console.log('[JSON_SAVER] ✅ Successfully saved to', path.basename(filePath));
    return true;
  } catch (err) {
    console.error('[JSON_SAVER] ❌ Error saving', filePath, ':', err.message);
    return false;
  }
}

// Get latest form for employee (kept for compatibility)
function getLatestFormForEmployee(allForms, employeeId, allowedStatuses = []) {
  console.log('[HELPER] Getting latest form for employee:', employeeId);
  console.log('[HELPER] Allowed statuses:', allowedStatuses);

  let forms = allForms.filter(f => f && f.employeeId === employeeId);
  console.log('[HELPER] Found employee forms:', forms.length);

  if (allowedStatuses.length) {
    forms = forms.filter(f => allowedStatuses.includes(f.status));
    console.log('[HELPER] After status filtering:', forms.length);
  }

  const latestForm = forms.sort(
    (a, b) =>
      new Date(b.submissionDate || b.lastUpdated) -
      new Date(a.submissionDate || a.lastUpdated)
  )[0] || null;

  console.log('[HELPER] Latest form found:', latestForm ? latestForm.formId : 'None');
  return latestForm;
}

// ------------ Validation Middlewares ------------
// Validation for IT final processing endpoint (expects action)
const validateFinalProcess = (req, res, next) => {
  console.log('[VALIDATE_FINAL] Validating final process request');

  const { formId, action } = req.body;
  console.log('[VALIDATE_FINAL] Form ID:', formId, 'Action:', action);

  if (!formId || !action) {
    console.log('[VALIDATE_FINAL] ❌ Missing required fields');
    return res.status(400).json({
      success: false,
      message: 'Missing required fields: formId and action'
    });
  }

  const validActions = ['complete', 'reject'];
  if (!validActions.includes(String(action).toLowerCase())) {
    console.log('[VALIDATE_FINAL] ❌ Invalid action:', action);
    return res.status(400).json({
      success: false,
      message: 'Invalid action. Allowed: complete, reject'
    });
  }

  if (String(action).toLowerCase() === 'reject') {
    const { remarks } = req.body;
    if (!remarks || !String(remarks).trim()) {
      console.log('[VALIDATE_FINAL] ❌ Missing remarks for rejection');
      return res.status(400).json({
        success: false,
        message: 'Remarks are required for rejection'
      });
    }
    console.log('[VALIDATE_FINAL] Rejection remarks provided');
  }

  console.log('[VALIDATE_FINAL] ✅ Validation passed');
  next();
};

// Validation for decision endpoint (expects status, not action)
const validateDecision = (req, res, next) => {
  console.log('[VALIDATE_DECISION] Validating decision request');

  const { formId, status, remark } = req.body;
  console.log('[VALIDATE_DECISION] Form ID:', formId, 'Status:', status);

  if (!formId || !status) {
    console.log('[VALIDATE_DECISION] ❌ Missing required fields');
    return res.status(400).json({
      success: false,
      message: 'Missing required fields: formId and status'
    });
  }

  const normalized = String(status).trim().toLowerCase();
  if (!['approved', 'rejected'].includes(normalized)) {
    console.log('[VALIDATE_DECISION] ❌ Invalid status:', status);
    return res.status(400).json({
      success: false,
      message: "Invalid status. Allowed values: 'Approved' or 'Rejected'"
    });
  }

  if (normalized === 'rejected' && (!remark || !String(remark).trim())) {
    console.log('[VALIDATE_DECISION] ❌ Missing remark for rejection');
    return res.status(400).json({
      success: false,
      message: 'Remark is required when status is Rejected'
    });
  }

  console.log('[VALIDATE_DECISION] ✅ Validation passed');
  next();
};

// ------------ Routes ------------

// GET: Fetch All Review Requests
router.get('/review-requests', (req, res) => {
  console.log('[REVIEW_REQUESTS] GET /review-requests from IP:', req.ip);

  try {
    const requests = loadJSONFile(pendingFormsPath);
    if (!Array.isArray(requests)) {
      console.log('[REVIEW_REQUESTS] ❌ Corrupted data format');
      return res
        .status(500)
        .json({ success: false, message: 'Corrupted data format.' });
    }

    console.log('[REVIEW_REQUESTS] ✅ Returning', requests.length, 'review requests');
    res.json({ success: true, requests });
  } catch (err) {
    console.error('[REVIEW_REQUESTS] ❌ Error reading review requests:', err.message);
    res.status(500).json({ success: false, message: 'Failed to load requests.' });
  }
});

// GET: Fetch Forms Ready for IT Review (from HOD)
router.get('/pending', (req, res) => {
  console.log('[IT_PENDING] GET /pending from IP:', req.ip);

  try {
    const requests = loadJSONFile(pendingFormsPath);
    if (!Array.isArray(requests)) {
      console.log('[IT_PENDING] ❌ Corrupted data format');
      return res
        .status(500)
        .json({ success: false, message: 'Corrupted data format.' });
    }

    const pendingForIT = requests.filter(form => form.status === 'Submitted to IT');
    console.log('[IT_PENDING] 📋 IT Dashboard: Found', pendingForIT.length, 'forms pending IT review');

    // Log details of pending forms
    pendingForIT.forEach(form => {
      console.log('[IT_PENDING] - Form:', form.formId, 'Employee:', form.employeeName || form.name, 'Type:', form.noDuesType);
    });

    res.json({ success: true, list: pendingForIT });
  } catch (err) {
    console.error('[IT_PENDING] ❌ Error reading IT pending forms:', err.message);
    res.status(500).json({ success: false, message: 'Failed to load pending forms.' });
  }
});

// GET: Get Complete Form Details for IT Review
router.get('/form-details/:formId', (req, res) => {
  console.log('[FORM_DETAILS] GET /form-details/:formId from IP:', req.ip);

  const { formId } = req.params;
  console.log('[FORM_DETAILS] Requested form ID:', formId);

  if (!formId) {
    console.log('[FORM_DETAILS] ❌ Missing formId parameter');
    return res.status(400).json({ success: false, message: 'Missing formId' });
  }

  try {
    const requests = loadJSONFile(pendingFormsPath);
    const form = requests.find(f => f.formId === formId);

    if (!form) {
      console.log('[FORM_DETAILS] ❌ Form not found:', formId);
      return res.status(404).json({ success: false, message: 'Form not found' });
    }

    console.log('[FORM_DETAILS] ✅ Found form:', formId);
    console.log('[FORM_DETAILS] Form status:', form.status);
    console.log('[FORM_DETAILS] Employee:', form.employeeName || form.name);
    console.log('[FORM_DETAILS] No-dues type:', form.noDuesType);
    console.log('[FORM_DETAILS] Form responses available:', !!form.formResponses);
    console.log('[FORM_DETAILS] HOD approval:', !!form.hodApproval);

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
      status: form.status
    });
  } catch (err) {
    console.error('[FORM_DETAILS] ❌ Error loading IT form details:', err.message);
    res.status(500).json({ success: false, message: 'Error fetching form details' });
  }
});

// POST: IT Final Processing with PDF Generation and Notifications
router.post('/final-process', validateFinalProcess, async (req, res) => {
  console.log('[FINAL_PROCESS] POST /final-process from IP:', req.ip);

  try {
    let { formId, formResponses, action, remarks } = req.body;

    console.log('[FINAL_PROCESS] Processing form:', formId);
    console.log('[FINAL_PROCESS] Action:', action);
    console.log('[FINAL_PROCESS] Has form responses:', !!formResponses);
    console.log('[FINAL_PROCESS] Remarks:', remarks);

    if (typeof formResponses === 'string') {
      try {
        console.log('[FINAL_PROCESS] Parsing form responses from string');
        formResponses = JSON.parse(formResponses);
      } catch {
        console.log('[FINAL_PROCESS] ❌ Invalid JSON format in formResponses');
        return res.status(400).json({
          success: false,
          message: 'Invalid JSON format in formResponses'
        });
      }
    }

    const requests = loadJSONFile(pendingFormsPath);
    const formIndex = requests.findIndex(f => f.formId === formId);
    if (formIndex === -1) {
      console.log('[FINAL_PROCESS] ❌ Form not found:', formId);
      return res.status(404).json({ success: false, message: 'Form not found' });
    }

    const form = requests[formIndex];
    const sessionUser = req.session.user;

    console.log('[FINAL_PROCESS] Processing by IT user:', sessionUser?.name || 'Unknown');

    if (String(action).toLowerCase() === 'complete') {
      console.log('[FINAL_PROCESS] 🔄 Processing IT completion with PDF generation...');

      const enrichedFormResponses = {};

      if (formResponses) {
        console.log('[FINAL_PROCESS] Enriching form responses with metadata');

        for (const [formType, fr] of Object.entries(formResponses)) {
          enrichedFormResponses[formType] = {
            ...fr,
            hodApprovalDate: form.hodApproval?.approvedAt,
            hodApprovedBy: form.hodApproval?.approvedBy,
            employeeName: form.employeeName || form.name,
            employeeId: form.employeeId,
            department: form.department,
            noDuesType: form.noDuesType
          };
        }

        // Example IT-section checks (log only)
        const requiredForms = ['disposalForm', 'efileForm'];
        const form365Key = formResponses.form365Trans ? 'form365Trans' : 'form365Disp';
        requiredForms.push(form365Key);

        console.log('[FINAL_PROCESS] Checking IT sections in required forms:', requiredForms);

        for (const formKey of requiredForms) {
          const fr = formResponses[formKey];
          if (!fr) {
            console.log('[FINAL_PROCESS] - Missing form:', formKey);
            continue;
          }

          const hasITData = Object.keys(fr).some(
            k =>
              k.toLowerCase().includes('it') ||
              k.includes('itSignature') ||
              k.includes('itName') ||
              k.includes('itApproval')
          );
          console.log('[FINAL_PROCESS] - IT sections in', formKey + ':', hasITData);
        }

        // Persist responses
        form.formResponses = formResponses;

        // Generate PDF Certificates
        try {
          console.log('[FINAL_PROCESS] 📜 Generating PDF certificates...');
          const pdfCertificates = await generateFormCertificates(formId, enrichedFormResponses);
          await storeCertificates(formId, pdfCertificates, form.employeeId);

          console.log('[FINAL_PROCESS] ✅ Generated', pdfCertificates.length, 'PDF certificates');
          form.certificates = pdfCertificates.map(cert => ({
            formType: cert.formType,
            filename: cert.filename,
            generatedAt: cert.generatedAt,
            filepath: cert.filepath
          }));

          // Notify employee certificates ready
          try {
            console.log('[FINAL_PROCESS] 📬 Sending certificate ready notification');
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
            console.log('[FINAL_PROCESS] ✅ Certificate notification sent');
          } catch (notificationError) {
            console.warn('[FINAL_PROCESS] ⚠️ Failed to send certificate notification:', notificationError.message);
          }
        } catch (pdfError) {
          console.error('[FINAL_PROCESS] ❌ PDF generation failed:', pdfError.message);
          // Continue without failing the whole process
        }
      }

      form.status = 'IT Completed';
      form.itProcessing = {
        processedBy: sessionUser?.name || 'IT Admin',
        processedAt: new Date().toISOString(),
        action: 'completed',
        remarks: remarks || '',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      };

      console.log('[FINAL_PROCESS] ✅ Form', formId, 'completed by IT with certificate generation');

      if (!saveJSONFile(pendingFormsPath, requests)) {
        console.log('[FINAL_PROCESS] ❌ Failed to save form data');
        return res.status(500).json({ success: false, message: 'Failed to save form data' });
      }

      return res.json({
        success: true,
        message: 'Form completed successfully and certificates generated',
        certificates: form.certificates || []
      });
    }

    // Reject on final process
    console.log('[FINAL_PROCESS] 🚫 Processing rejection');

    form.status = 'rejected';
    form.rejectionReason = remarks;
    form.rejectedAt = new Date().toISOString();
    form.rejectedBy = sessionUser?.name || 'IT Admin';
    form.rejectionStage = 'IT Review';
    form.assignedForms = [];
    form.formResponses = {};
    form.itProcessing = {
      processedBy: sessionUser?.name || 'IT Admin',
      processedAt: new Date().toISOString(),
      action: 'rejected',
      remarks,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    };

    try {
      console.log('[FINAL_PROCESS] 📬 Sending rejection notification');
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
      console.log('[FINAL_PROCESS] ✅ Rejection notification sent');
    } catch (notificationError) {
      console.warn('[FINAL_PROCESS] ⚠️ Failed to send rejection notification:', notificationError.message);
    }

    console.log('[FINAL_PROCESS] ❌ Form', formId, 'rejected by IT:', remarks);

    if (!saveJSONFile(pendingFormsPath, requests)) {
      console.log('[FINAL_PROCESS] ❌ Failed to save form data');
      return res.status(500).json({ success: false, message: 'Failed to save form data' });
    }

    return res.json({
      success: true,
      message: 'Form rejected and returned to employee'
    });
  } catch (err) {
    console.error('[FINAL_PROCESS] ❌ Error in IT final processing:', err.message);
    console.error('[FINAL_PROCESS] Stack trace:', err.stack);
    res.status(500).json({
      success: false,
      message: 'Error during IT processing: ' + err.message
    });
  }
});

// Helper function to store certificates
async function storeCertificates(formId, certificates, employeeId) {
  console.log('[STORE_CERTIFICATES] Storing certificates for form:', formId);
  console.log('[STORE_CERTIFICATES] Employee ID:', employeeId);
  console.log('[STORE_CERTIFICATES] Certificates to store:', certificates.length);

  try {
    let certificatesData = loadJSONFile(certificatesPath);

    for (const cert of certificates) {
      const certRecord = {
        id: Date.now() + Math.random().toString(36).substr(2, 9),
        formId: formId,
        employeeId: employeeId,
        formType: cert.formType,
        filename: cert.filename,
        filepath: cert.filepath,
        generatedAt: cert.generatedAt,
        status: 'available'
      };

      certificatesData.push(certRecord);
      console.log('[STORE_CERTIFICATES] - Added certificate:', cert.formType, 'File:', cert.filename);
    }

    if (!saveJSONFile(certificatesPath, certificatesData)) {
      throw new Error('Failed to save certificate records');
    }
    console.log('[STORE_CERTIFICATES] ✅ Certificate records stored successfully');
  } catch (error) {
    console.error('[STORE_CERTIFICATES] ❌ Error storing certificates:', error.message);
    throw error;
  }
}

// POST: Approve or Reject (initial IT decision) - uses status
router.post('/decision', validateDecision, (req, res) => {
  console.log('[IT_DECISION] POST /decision from IP:', req.ip);

  const { formId, status, remark } = req.body;
  console.log('[IT_DECISION] Form ID:', formId, 'Status:', status);

  try {
    const requests = loadJSONFile(pendingFormsPath);
    const index = requests.findIndex(r => r.formId === formId);
    if (index === -1) {
      console.log('[IT_DECISION] ❌ Form ID not found:', formId);
      return res.status(404).json({ success: false, message: 'Form ID not found.' });
    }

    const form = requests[index];
    const decision = String(status).toLowerCase();
    const sessionUser = req.session.user;

    console.log('[IT_DECISION] Processing decision by:', sessionUser?.name || 'IT Admin');
    console.log('[IT_DECISION] Decision:', decision);

    form.status = decision; // persist normalized status
    form.remark = remark || '';
    form.lastUpdated = new Date().toISOString();

    if (decision === 'approved') {
      console.log('[IT_DECISION] 📋 Approving form and assigning forms');

      const noDuesType = form.noDuesType?.toLowerCase();
      form.assignedForms = [
        { title: 'E-File', path: '/forms/efile.html' },
        { title: 'Disposal Form', path: '/forms/disposalform.html' },
        {
          title: noDuesType === 'transfer' ? 'Form 365 - Transfer' : 'Form 365 - Disposal',
          path:
            noDuesType === 'transfer'
              ? '/forms/form365transfer.html'
              : '/forms/form365disposal.html'
        }
      ];

      console.log('[IT_DECISION] Assigned forms:', form.assignedForms.map(f => f.title));

      try {
        console.log('[IT_DECISION] 📬 Sending form assignment notification');
        const notificationManager = NotificationManager.getInstance();
        notificationManager.sendMultiChannelNotification({
          type: 'forms_assigned',
          employeeId: form.employeeId,
          formId: formId,
          timestamp: new Date().toISOString(),
          priority: 'medium',
          title: '📋 Forms Assigned',
          message: `Your application ${formId} has been approved. Complete the assigned forms to proceed.`,
          details: {
            assignedForms: form.assignedForms,
            approvedBy: sessionUser?.name || 'IT Admin',
            nextStep: 'Complete assigned forms and submit to HOD'
          }
        });
        console.log('[IT_DECISION] ✅ Form assignment notification sent');
      } catch (notificationError) {
        console.warn('[IT_DECISION] ⚠️ Failed to send form assignment notification:', notificationError.message);
      }
    } else if (decision === 'rejected') {
      console.log('[IT_DECISION] 🚫 Rejecting form');

      form.status = 'rejected';
      form.rejectionReason = remark || 'No reason provided';
      form.rejectedAt = new Date().toISOString();
      form.rejectedBy = sessionUser?.name || 'IT Admin';
      form.rejectionStage = 'Initial IT Review';
      delete form.assignedForms;
      form.formResponses = {};

      try {
        console.log('[IT_DECISION] 📬 Sending rejection notification');
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
        console.log('[IT_DECISION] ✅ Rejection notification sent');
      } catch (notificationError) {
        console.warn('[IT_DECISION] ⚠️ Failed to send rejection notification:', notificationError.message);
      }
    }

    if (!saveJSONFile(pendingFormsPath, requests)) {
      console.log('[IT_DECISION] ❌ Failed to save form data');
      return res.status(500).json({ success: false, message: 'Failed to save form data' });
    }

    console.log('[IT_DECISION] ✅ Form ID', formId, 'marked as', decision);
    res.json({ success: true, message: `Form ${decision} successfully` });
  } catch (err) {
    console.error('[IT_DECISION] ❌ Error processing decision:', err.message);
    res.status(500).json({ success: false, message: 'Failed to process request.' });
  }
});

// GET: IT Dashboard Statistics (Enhanced)
router.get('/stats', (req, res) => {
  console.log('[IT_STATS] GET /stats from IP:', req.ip);

  try {
    const requests = loadJSONFile(pendingFormsPath);
    console.log('[IT_STATS] Loaded', requests.length, 'total forms');

    let certificatesCount = 0;
    let notificationStats = {
      connectedEmployees: 0,
      totalNotificationsSent: 0
    };

    try {
      const certificates = loadJSONFile(certificatesPath);
      certificatesCount = certificates.length;
      console.log('[IT_STATS] Certificate count:', certificatesCount);
    } catch (certError) {
      console.warn('[IT_STATS] ⚠️ Could not read certificates for stats:', certError.message);
    }

    try {
      const notificationManager = NotificationManager.getInstance();
      notificationStats.connectedEmployees = notificationManager.getConnectedClientsCount();
      const recentNotifications = notificationManager
        .getNotificationHistory('', 1000)
        .filter(n => new Date(n.timestamp) > new Date(Date.now() - 24 * 60 * 60 * 1000));
      notificationStats.totalNotificationsSent = recentNotifications.length;
      console.log('[IT_STATS] Notification stats:', notificationStats);
    } catch (notificationError) {
      console.warn('[IT_STATS] ⚠️ Could not get notification stats:', notificationError.message);
    }

    const stats = {
      total: requests.length,
      pendingIT: requests.filter(f => f.status === 'Submitted to IT').length,
      completedByIT: requests.filter(f => f.status === 'IT Completed').length,
      rejectedByIT: requests.filter(
        f => f.status === 'Rejected by IT' || f.status === 'rejected'
      ).length,
      pendingInitialReview: requests.filter(f => f.status === 'pending').length,
      certificatesGenerated: certificatesCount,
      notifications: notificationStats
    };

    console.log('[IT_STATS] ✅ Statistics compiled:', stats);
    res.json({ success: true, stats });
  } catch (err) {
    console.error('[IT_STATS] ❌ Error getting IT stats:', err.message);
    res.status(500).json({ success: false, message: 'Error fetching statistics' });
  }
});

// GET: Completed forms with certificates (for IT completed tab)
router.get('/completed', (req, res) => {
  console.log('[IT_COMPLETED] GET /completed from IP:', req.ip);

  try {
    const requests = loadJSONFile(pendingFormsPath);
    if (!Array.isArray(requests)) {
      console.log('[IT_COMPLETED] ❌ Corrupted data format');
      return res
        .status(500)
        .json({ success: false, message: 'Corrupted data format.' });
    }

    const completedForms = requests.filter(form => form.status === 'IT Completed');

    console.log('[IT_COMPLETED] 📋 IT Completed: Found', completedForms.length, 'completed forms');

    // Log completed form details
    completedForms.forEach(form => {
      console.log('[IT_COMPLETED] - Form:', form.formId, 'Employee:', form.employeeName || form.name, 'Certificates:', form.certificates?.length || 0);
    });

    res.json({ success: true, list: completedForms });
  } catch (err) {
    console.error('[IT_COMPLETED] ❌ Error reading IT completed forms:', err.message);
    res.status(500).json({ success: false, message: 'Failed to load completed forms.' });
  }
});

// POST: Enhanced bulk notification endpoint with validation
router.post('/send-notification', (req, res) => {
  console.log('[SEND_NOTIFICATION] POST /send-notification from IP:', req.ip);

  try {
    const { title, message, employeeIds, priority = 'medium' } = req.body;
    const sessionUser = req.session.user;

    console.log('[SEND_NOTIFICATION] Notification details:', {
      title: title?.substring(0, 50) + '...',
      messageLength: message?.length,
      employeeCount: Array.isArray(employeeIds) ? employeeIds.length : 'broadcast',
      priority,
      sender: sessionUser?.name
    });

    if (!title || !message) {
      console.log('[SEND_NOTIFICATION] ❌ Missing title or message');
      return res.status(400).json({
        success: false,
        message: 'Title and message are required'
      });
    }

    if (title.length > 100) {
      console.log('[SEND_NOTIFICATION] ❌ Title too long:', title.length);
      return res.status(400).json({
        success: false,
        message: 'Title must be 100 characters or less'
      });
    }

    if (message.length > 500) {
      console.log('[SEND_NOTIFICATION] ❌ Message too long:', message.length);
      return res.status(400).json({
        success: false,
        message: 'Message must be 500 characters or less'
      });
    }

    const validPriorities = ['low', 'medium', 'high', 'urgent'];
    if (!validPriorities.includes(priority)) {
      console.log('[SEND_NOTIFICATION] ❌ Invalid priority:', priority);
      return res.status(400).json({
        success: false,
        message: 'Invalid priority level'
      });
    }

    const notificationData = {
      type: 'it_announcement',
      timestamp: new Date().toISOString(),
      priority: priority,
      title: title.trim(),
      message: message.trim(),
      details: {
        sentBy: sessionUser?.name || 'IT Admin',
        itDepartment: sessionUser?.department || 'IT'
      }
    };

    let sentCount = 0;
    if (employeeIds && Array.isArray(employeeIds) && employeeIds.length > 0) {
      console.log('[SEND_NOTIFICATION] Sending to specific employees:', employeeIds.length);
      employeeIds.forEach(employeeId => {
        if (employeeId && typeof employeeId === 'string') {
          NotificationManager.getInstance().sendMultiChannelNotification({
            ...notificationData,
            employeeId: employeeId
          });
          sentCount++;
        }
      });
    } else {
      console.log('[SEND_NOTIFICATION] Broadcasting to all connected employees');
      sentCount =
        NotificationManager.getInstance().broadcastNotification(notificationData);
    }

    console.log('[SEND_NOTIFICATION] ✅ Notification sent to', sentCount, 'employee(s)');

    res.json({
      success: true,
      message: `Notification sent to ${sentCount} employee(s)`,
      sentCount: sentCount
    });
  } catch (error) {
    console.error('[SEND_NOTIFICATION] ❌ Error sending bulk notification:', error.message);
    res.status(500).json({
      success: false,
      message: 'Failed to send notification'
    });
  }
});

// Notification stats
router.get('/notification-stats', (req, res) => {
  console.log('[NOTIFICATION_STATS] GET /notification-stats from IP:', req.ip);

  try {
    const notificationManager = NotificationManager.getInstance();
    const stats = {
      connectedEmployees: notificationManager.getConnectedClientsCount(),
      queuedNotifications: notificationManager.notificationQueue?.length || 0,
      recentNotifications: notificationManager.getNotificationHistory('', 50).slice(0, 10),
      systemStatus: {
        webSocketActive: true,
        lastCleanup: new Date().toISOString(),
        uptime: process.uptime()
      }
    };

    console.log('[NOTIFICATION_STATS] ✅ Notification stats compiled:', {
      connected: stats.connectedEmployees,
      queued: stats.queuedNotifications,
      recent: stats.recentNotifications.length
    });

    res.json({ success: true, stats });
  } catch (error) {
    console.error('[NOTIFICATION_STATS] ❌ Error getting notification stats:', error.message);
    res.status(500).json({
      success: false,
      message: 'Failed to get notification statistics'
    });
  }
});

// Enhanced error handling middleware for IT routes
router.use((error, req, res, next) => {
  console.error('[IT_ERROR_HANDLER] ❌ IT router error:', error.message);
  console.error('[IT_ERROR_HANDLER] Stack trace:', error.stack);
  console.error('[IT_ERROR_HANDLER] Request URL:', req.url);
  console.error('[IT_ERROR_HANDLER] Request method:', req.method);

  if (error.code === 'ENOENT') {
    return res.status(500).json({
      success: false,
      message: 'Required data files not found'
    });
  }
  if (error.name === 'SyntaxError') {
    return res.status(400).json({
      success: false,
      message: 'Invalid JSON format in request'
    });
  }
  res.status(500).json({
    success: false,
    message: 'Internal server error in IT operations',
    error: process.env.NODE_ENV === 'development' ? error.message : 'Contact system administrator'
  });
});

console.log('[IT_ADMIN_ROUTER] IT Admin router initialization complete with enhanced logging');

module.exports = router;
