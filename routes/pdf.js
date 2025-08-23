const express = require('express');
const PDFDocument = require('pdfkit');
const { loadJSON } = require('../utils/fileUtils');
const { roleAuth } = require('../middlewares/sessionAuth');


const FORM_DATA = './data/pending_forms.json';
const router = express.Router();


// 🔁 Reusable PDF generation function
const generatePdf = (doc, form) => {
  const data = form.applicationData || form; // Handle both structures


  doc.fontSize(18).text('No Dues Clearance Form', { align: 'center' }).moveDown();
  doc.fontSize(12);
  doc.text(`Form ID: ${form.formId}`);
  doc.text(`Name: ${data.name || form.name}`);
  doc.text(`Employee ID: ${form.employeeId}`);
  doc.text(`Department: ${data.department || form.department}`);
  doc.text(`No Dues Type: ${data.noDuesType || form.noDuesType}`);
  doc.text(`Email: ${data.email || form.email}`);
  doc.text(`Submitted At: ${form.submissionDate || form.appliedAt}`);
  doc.text(`Status: ${form.status}`);
  if (form.reviewedAt) doc.text(`Reviewed At: ${form.reviewedAt}`);
  if (form.remark) doc.text(`Remark: ${form.remark}`);
};


// FIXED: Remove /api/ from routes since they're already mounted at /api/pdf
// 📥 Download specific form by ID
router.get('/download/:formId', roleAuth('employee'), (req, res) => {
  const { formId } = req.params;
  const { id: employeeId, employeeId: altEmployeeId } = req.session.user;
  const actualEmployeeId = employeeId || altEmployeeId;

  try {
    const forms = loadJSON(FORM_DATA);
    const form = forms.find(f => f.formId === formId && f.employeeId === actualEmployeeId);

    if (!form) {
      console.warn(`⚠️ Form not found for formId=${formId}, employeeId=${actualEmployeeId}`);
      return res.status(404).json({
        success: false,
        message: 'Form not found or access denied'
      });
    }


    const doc = new PDFDocument();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="No-Dues-${formId}.pdf"`);

    doc.pipe(res);
    generatePdf(doc, form);
    doc.end();

  } catch (error) {
    console.error('PDF generation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to generate PDF'
    });
  }
});


// FIXED: Direct access to form PDF by ID
router.get('/:formId', roleAuth('employee'), (req, res) => {
  const { formId } = req.params;
  const { id: employeeId, employeeId: altEmployeeId } = req.session.user;
  const actualEmployeeId = employeeId || altEmployeeId;

  try {
    const forms = loadJSON(FORM_DATA);
    const form = forms.find(f => f.formId === formId && f.employeeId === actualEmployeeId);

    if (!form) {
      console.warn(`⚠️ Form not found for formId=${formId}, employeeId=${actualEmployeeId}`);
      return res.status(404).json({
        success: false,
        message: 'Form not found or access denied'
      });
    }


    const doc = new PDFDocument();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="No-Dues-${formId}.pdf"`);

    doc.pipe(res);
    generatePdf(doc, form);
    doc.end();

  } catch (error) {
    console.error('PDF generation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to generate PDF'
    });
  }
});


// 👀 Generate PDF for current user's latest form
router.get('/generate/latest', roleAuth('employee'), (req, res) => {
  const { id: employeeId, employeeId: altEmployeeId } = req.session.user;
  const actualEmployeeId = employeeId || altEmployeeId;

  try {
    const forms = loadJSON(FORM_DATA);
    const form = forms.find(f => f.employeeId === actualEmployeeId);


    if (!form) {
      console.warn(`⚠️ No form found for employeeId=${actualEmployeeId}`);
      return res.status(404).json({
        success: false,
        message: 'No form found for your account'
      });
    }


    const doc = new PDFDocument();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="No-Dues-${form.formId}.pdf"`);

    doc.pipe(res);
    generatePdf(doc, form);
    doc.end();

  } catch (error) {
    console.error('PDF generation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to generate PDF'
    });
  }
});


module.exports = router;