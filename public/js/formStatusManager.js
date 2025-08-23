class FormStatusManager {
    constructor() {
        this.currentStatus = null;
        this.statusHistory = [];
        this.init();
    }
    
    async init() {
        await this.checkFormStatus();
        this.setupEventListeners();
        
        // Check status periodically (only for active forms)
        if (this.shouldAutoCheck()) {
            setInterval(() => this.checkFormStatus(), 30000); // Every 30 seconds
        }
    }
    
    async checkFormStatus() {
        try {
            const response = await fetch('/api/employee/form-status', {
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Form-ID': this.getFormId()
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                this.updateStatus(data.status, data.context);
            }
        } catch (error) {
            console.warn('Failed to check form status:', error);
        }
    }
    
    updateStatus(newStatus, context = {}) {
        if (this.currentStatus !== newStatus) {
            this.statusHistory.push({
                from: this.currentStatus,
                to: newStatus,
                timestamp: new Date().toISOString(),
                context
            });
            
            this.currentStatus = newStatus;
            updateFormBanner(newStatus, context);
            this.notifyStatusChange(newStatus);
        }
    }
    
    notifyStatusChange(status) {
        const event = new CustomEvent('formStatusChange', {
            detail: { status, history: this.statusHistory }
        });
        document.dispatchEvent(event);
    }
    
    shouldAutoCheck() {
        return ['pending', 'approved', 'Submitted to HOD'].includes(this.currentStatus);
    }
    
    getFormId() {
        return document.querySelector('[data-form-id]')?.dataset.formId || 
               new URLSearchParams(window.location.search).get('formId');
    }
    
    setupEventListeners() {
        document.addEventListener('formStatusChange', (e) => {
            console.log('Form status changed:', e.detail);
        });
        
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden && this.shouldAutoCheck()) {
                this.checkFormStatus();
            }
        });
    }
}

// Status messages configuration
const STATUS_MESSAGES = {
    'pending': null,
    'approved': {
        icon: '📝',
        title: 'Ready to Complete',
        message: 'Your application has been approved. Complete the required forms below.',
        type: 'info'
    },
    'Submitted to HOD': {
        icon: '📋',
        title: 'Under HOD Review',
        message: 'Your forms have been submitted and are being reviewed by your Head of Department.',
        type: 'warning'
    },
    'IT Completed': {
        icon: '✅',
        title: 'Process Complete',
        message: 'Your no-dues clearance has been processed successfully.',
        type: 'success'
    },
    'rejected': {
        icon: '❌',
        title: 'Application Rejected',
        message: 'This application was rejected. You can submit a new application.',
        type: 'error'
    }
};

// Banner management functions
function updateFormBanner(status, context) {
    const banner = document.querySelector('.form-status-banner') || createStatusBanner();
    
    const config = STATUS_MESSAGES[status];
    
    if (config) {
        banner.innerHTML = `
            <div class="status-content">
                <span class="status-icon">${config.icon}</span>
                <div class="status-text">
                    <strong>${config.title}</strong>
                    <div>${config.message}</div>
                </div>
            </div>
            <button class="close-btn" onclick="closeBanner()" aria-label="Close banner">×</button>
        `;
        
        banner.className = `form-status-banner status-${config.type}`;
        banner.style.display = 'flex';
        
        setFormInteractivity(status !== 'pending' && status !== 'approved');
    } else {
        banner.style.display = 'none';
        setFormInteractivity(false);
    }
}

function createStatusBanner() {
    const banner = document.createElement('div');
    banner.className = 'form-status-banner';
    banner.setAttribute('role', 'alert');
    banner.setAttribute('aria-live', 'polite');
    
    const form = document.querySelector('form') || document.querySelector('.form-container') || document.body;
    form.insertBefore(banner, form.firstChild);
    
    return banner;
}

function setFormInteractivity(isReadOnly) {
    const inputs = document.querySelectorAll('input, select, textarea, button[type="submit"]');
    inputs.forEach(input => {
        if (isReadOnly) {
            input.setAttribute('readonly', 'true');
            input.setAttribute('disabled', 'true');
            input.classList.add('read-only');
        } else {
            input.removeAttribute('readonly');
            input.removeAttribute('disabled');
            input.classList.remove('read-only');
        }
    });
}

function closeBanner() {
    const banner = document.querySelector('.form-status-banner');
    if (banner) {
        banner.style.display = 'none';
    }
}

// Initialize when DOM is ready
let formStatusManager;
document.addEventListener('DOMContentLoaded', () => {
    formStatusManager = new FormStatusManager();
});
