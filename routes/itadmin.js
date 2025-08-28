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

// All routes below are protected for IT Admin only
router.use(roleAuth('it'));

// ------------ Helpers ------------
function loadJSONFile(filePath) {
  try {
    const data = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error(`Error loading ${filePath}:`, err);
    return [];
  }
}

function saveJSONFile(filePath, data) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    return true;
  } catch (err) {
    console.error(`Error saving ${filePath}:`, err);
    return false;
  }
}

// Get latest form for employee (kept for compatibility)
function getLatestFormForEmployee(allForms, employeeId, allowedStatuses = []) {
  let forms = allForms.filter(f => f && f.employeeId === employeeId);
  if (allowedStatuses.length) {
    forms = forms.filter(f => allowedStatuses.includes(f.status));
  }
  return (
    forms.sort(
      (a, b) =>
        new Date(b.submissionDate || b.lastUpdated) -
        new Date(a.submissionDate || a.lastUpdated)
    )[0] || null
  );
}

// ------------ Validation Middlewares ------------
// Validation for IT final processing endpoint (expects action)
const validateFinalProcess = (req, res, next) => {
  const { formId, action } = req.body;

  if (!formId || !action) {
    return res.status(400).json({
      success: false,
      message: 'Missing required fields: formId and action'
    });
  }

  const validActions = ['complete', 'reject'];
  if (!validActions.includes(String(action).toLowerCase())) {
    return res.status(400).json({
      success: false,
      message: 'Invalid action. Allowed: complete, reject'
    });
  }

  if (String(action).toLowerCase() === 'reject') {
    const { remarks } = req.body;
    if (!remarks || !String(remarks).trim()) {
      return res.status(400).json({
        success: false,
        message: 'Remarks are required for rejection'
      });
    }
  }

  next();
};

// Validation for decision endpoint (expects status, not action)
const validateDecision = (req, res, next) => {
  const { formId, status, remark } = req.body;

  if (!formId || !status) {
    return res.status(400).json({
      success: false,
      message: 'Missing required fields: formId and status'
    });
  }

  const normalized = String(status).trim().toLowerCase();
  if (!['approved', 'rejected'].includes(normalized)) {
    return res.status(400).json({
      success: false,
      message: "Invalid status. Allowed values: 'Approved' or 'Rejected'"
    });
  }

  if (normalized === 'rejected' && (!remark || !String(remark).trim())) {
    return res.status(400).json({
      success: false,
      message: 'Remark is required when status is Rejected'
    });
  }

  next();
};

// ------------ Routes ------------

// GET: Fetch All Review Requests
router.get('/review-requests', (req, res) => {
  try {
    const requests = loadJSONFile(pendingFormsPath);
    if (!Array.isArray(requests)) {
      return res
        .status(500)
        .json({ success: false, message: 'Corrupted data format.' });
    }
    res.json({ success: true, requests });
  } catch (err) {
    console.error('❌ Error reading review requests:', err);
    res.status(500).json({ success: false, message: 'Failed to load requests.' });
  }
});

// GET: Fetch Forms Ready for IT Review (from HOD)
router.get('/pending', (req, res) => {
  try {
    const requests = loadJSONFile(pendingFormsPath);
    if (!Array.isArray(requests)) {
      return res
        .status(500)
        .json({ success: false, message: 'Corrupted data format.' });
    }
    const pendingForIT = requests.filter(form => form.status === 'Submitted to IT');
    console.log(`📋 IT Dashboard: Found ${pendingForIT.length} forms pending IT review`);
    res.json({ success: true, list: pendingForIT });
  } catch (err) {
    console.error('❌ Error reading IT pending forms:', err);
    res.status(500).json({ success: false, message: 'Failed to load pending forms.' });
  }
});

// GET: Get Complete Form Details for IT Review
router.get('/form-details/:formId', (req, res) => {
  const { formId } = req.params;
  if (!formId) {
    return res.status(400).json({ success: false, message: 'Missing formId' });
  }

  try {
    const requests = loadJSONFile(pendingFormsPath);
    const form = requests.find(f => f.formId === formId);
    if (!form) {
      return res.status(404).json({ success: false, message: 'Form not found' });
    }

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
    console.error('❌ Error loading IT form details:', err);
    res.status(500).json({ success: false, message: 'Error fetching form details' });
  }
});

// POST: IT Final Processing with PDF Generation and Notifications
router.post('/final-process', validateFinalProcess, async (req, res) => {
  try {
    let { formId, formResponses, action, remarks } = req.body;

    if (typeof formResponses === 'string') {
      try {
        formResponses = JSON.parse(formResponses);
      } catch {
        return res.status(400).json({
          success: false,
          message: 'Invalid JSON format in formResponses'
        });
      }
    }

    const requests = loadJSONFile(pendingFormsPath);
    const formIndex = requests.findIndex(f => f.formId === formId);
    if (formIndex === -1) {
      return res.status(404).json({ success: false, message: 'Form not found' });
    }

    const form = requests[formIndex];
    const sessionUser = req.session.user;

    if (String(action).toLowerCase() === 'complete') {
      console.log('🔄 Processing IT completion with PDF generation...');
      const enrichedFormResponses = {};

      if (formResponses) {
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
        for (const formKey of requiredForms) {
          const fr = formResponses[formKey];
          if (!fr) continue;
          const hasITData = Object.keys(fr).some(
            k =>
              k.toLowerCase().includes('it') ||
              k.includes('itSignature') ||
              k.includes('itName') ||
              k.includes('itApproval')
          );
          console.log(`IT sections in ${formKey}:`, hasITData);
        }

        // Persist responses
        form.formResponses = formResponses;

        // Generate PDF Certificates
        try {
          console.log('📜 Generating PDF certificates...');
          const pdfCertificates = await generateFormCertificates(formId, enrichedFormResponses);
          await storeCertificates(formId, pdfCertificates, form.employeeId);

          console.log(`✅ Generated ${pdfCertificates.length} PDF certificates`);
          form.certificates = pdfCertificates.map(cert => ({
            formType: cert.formType,
            filename: cert.filename,
            generatedAt: cert.generatedAt,
            filepath: cert.filepath
          }));

          // Notify employee certificates ready
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
            console.warn('Failed to send certificate notification:', notificationError);
          }
        } catch (pdfError) {
          console.error('❌ PDF generation failed:', pdfError.message);
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

      console.log(`✅ Form ${formId} completed by IT with certificate generation`);

      if (!saveJSONFile(pendingFormsPath, requests)) {
        return res.status(500).json({ success: false, message: 'Failed to save form data' });
      }

      return res.json({
        success: true,
        message: 'Form completed successfully and certificates generated',
        certificates: form.certificates || []
      });
    }

    // Reject on final process
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
      console.warn('Failed to send rejection notification:', notificationError);
    }

    console.log(`❌ Form ${formId} rejected by IT: ${remarks}`);

    if (!saveJSONFile(pendingFormsPath, requests)) {
      return res.status(500).json({ success: false, message: 'Failed to save form data' });
    }

    return res.json({
      success: true,
      message: 'Form rejected and returned to employee'
    });
  } catch (err) {
    console.error('❌ Error in IT final processing:', err);
    res.status(500).json({
      success: false,
      message: 'Error during IT processing: ' + err.message
    });
  }
});

// Helper function to store certificates
async function storeCertificates(formId, certificates, employeeId) {
  try {
    let certificatesData = loadJSONFile(certificatesPath);
    for (const cert of certificates) {
      certificatesData.push({
        id: Date.now() + Math.random().toString(36).substr(2, 9),
        formId: formId,
        employeeId: employeeId,
        formType: cert.formType,
        filename: cert.filename,
        filepath: cert.filepath,
        generatedAt: cert.generatedAt,
        status: 'available'
      });
    }
    if (!saveJSONFile(certificatesPath, certificatesData)) {
      throw new Error('Failed to save certificate records');
    }
    console.log('✅ Certificate records stored successfully');
  } catch (error) {
    console.error('❌ Error storing certificates:', error);
    throw error;
  }
}

// POST: Approve or Reject (initial IT decision) - uses status
router.post('/decision', validateDecision, (req, res) => {
  const { formId, status, remark } = req.body;

  try {
    const requests = loadJSONFile(pendingFormsPath);
    const index = requests.findIndex(r => r.formId === formId);
    if (index === -1) {
      return res.status(404).json({ success: false, message: 'Form ID not found.' });
    }

    const form = requests[index];
    const decision = String(status).toLowerCase();
    const sessionUser = req.session.user;

    form.status = decision; // persist normalized status
    form.remark = remark || '';
    form.lastUpdated = new Date().toISOString();

    if (decision === 'approved') {
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

      try {
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
      } catch (notificationError) {
        console.warn('Failed to send form assignment notification:', notificationError);
      }
    } else if (decision === 'rejected') {
      form.status = 'rejected';
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
        console.warn('Failed to send rejection notification:', notificationError);
      }
    }

    if (!saveJSONFile(pendingFormsPath, requests)) {
      return res.status(500).json({ success: false, message: 'Failed to save form data' });
    }

    console.log(`✅ Form ID ${formId} marked as ${decision}`);
    res.json({ success: true, message: `Form ${decision} successfully` });
  } catch (err) {
    console.error('❌ Error processing decision:', err);
    res.status(500).json({ success: false, message: 'Failed to process request.' });
  }
});

// GET: IT Dashboard Statistics (Enhanced)
router.get('/stats', (req, res) => {
  try {
    const requests = loadJSONFile(pendingFormsPath);

    let certificatesCount = 0;
    let notificationStats = {
      connectedEmployees: 0,
      totalNotificationsSent: 0
    };

    try {
      const certificates = loadJSONFile(certificatesPath);
      certificatesCount = certificates.length;
    } catch (certError) {
      console.warn('Could not read certificates for stats:', certError.message);
    }

    try {
      const notificationManager = NotificationManager.getInstance();
      notificationStats.connectedEmployees = notificationManager.getConnectedClientsCount();
      const recentNotifications = notificationManager
        .getNotificationHistory('', 1000)
        .filter(n => new Date(n.timestamp) > new Date(Date.now() - 24 * 60 * 60 * 1000));
      notificationStats.totalNotificationsSent = recentNotifications.length;
    } catch (notificationError) {
      console.warn('Could not get notification stats:', notificationError.message);
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

    res.json({ success: true, stats });
  } catch (err) {
    console.error('❌ Error getting IT stats:', err);
    res.status(500).json({ success: false, message: 'Error fetching statistics' });
  }
});

// GET: Completed forms with certificates (for IT completed tab)
router.get('/completed', (req, res) => {
  try {
    const requests = loadJSONFile(pendingFormsPath);
    if (!Array.isArray(requests)) {
      return res
        .status(500)
        .json({ success: false, message: 'Corrupted data format.' });
    }

    const completedForms = requests.filter(form => form.status === 'IT Completed');

    console.log(`📋 IT Completed: Found ${completedForms.length} completed forms`);
    res.json({ success: true, list: completedForms });
  } catch (err) {
    console.error('❌ Error reading IT completed forms:', err);
    res.status(500).json({ success: false, message: 'Failed to load completed forms.' });
  }
});

// POST: Enhanced bulk notification endpoint with validation
router.post('/send-notification', (req, res) => {
  try {
    const { title, message, employeeIds, priority = 'medium' } = req.body;
    const sessionUser = req.session.user;

    if (!title || !message) {
      return res.status(400).json({
        success: false,
        message: 'Title and message are required'
      });
    }
    if (title.length > 100) {
      return res.status(400).json({
        success: false,
        message: 'Title must be 100 characters or less'
      });
    }
    if (message.length > 500) {
      return res.status(400).json({
        success: false,
        message: 'Message must be 500 characters or less'
      });
    }

    const validPriorities = ['low', 'medium', 'high', 'urgent'];
    if (!validPriorities.includes(priority)) {
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
      sentCount =
        NotificationManager.getInstance().broadcastNotification(notificationData);
    }

    res.json({
      success: true,
      message: `Notification sent to ${sentCount} employee(s)`,
      sentCount: sentCount
    });
  } catch (error) {
    console.error('Error sending bulk notification:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send notification'
    });
  }
});

// Notification stats
router.get('/notification-stats', (req, res) => {
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
    res.json({ success: true, stats });
  } catch (error) {
    console.error('Error getting notification stats:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get notification statistics'
    });
  }
});

// Enhanced error handling middleware for IT routes
router.use((error, req, res, next) => {
  console.error('❌ IT router error:', error);

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

module.exports = router;
