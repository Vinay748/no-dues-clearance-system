// navigationManager.js - Core navigation (no global back button). Deterministic return to dashboard.html

class NavigationManager {
    constructor() {
        this.navigationHistory = [];
        this.currentContext = null;
        this.unsavedDataHandlers = new Map();
        this.navigationListeners = new Set();
        this.deviceInfo = {
            isMobile: window.innerWidth <= 768,
            isTablet: window.innerWidth <= 1024 && window.innerWidth > 768,
            isDesktop: window.innerWidth > 1024,
            isTouchDevice: 'ontouchstart' in window || navigator.maxTouchPoints > 0
        };
        this.init();
    }

    init() {
        const boot = () => {
            this.updateDeviceInfo();
            this.setupKeyboardShortcuts();
            this.trackPageNavigation();
            this.setupPopstateHandler();
            this.setupWindowResizeHandler();
            this.setupTouchHandlers();
            // No global back button
        };
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
        else boot();
    }

    // ---------- Device ----------
    updateDeviceInfo() {
        const width = window.innerWidth;
        this.deviceInfo = {
            isMobile: width <= 768,
            isTablet: width <= 1024 && width > 768,
            isDesktop: width > 1024,
            isTouchDevice: 'ontouchstart' in window || navigator.maxTouchPoints > 0,
            screenWidth: width,
            screenHeight: window.innerHeight
        };
        if (document.body) {
            document.body.classList.toggle('mobile-device', this.deviceInfo.isMobile);
            document.body.classList.toggle('tablet-device', this.deviceInfo.isTablet);
            document.body.classList.toggle('desktop-device', this.deviceInfo.isDesktop);
            document.body.classList.toggle('touch-device', this.deviceInfo.isTouchDevice);
        }
    }

    setupWindowResizeHandler() {
        let t;
        window.addEventListener('resize', () => {
            clearTimeout(t);
            t = setTimeout(() => {
                this.updateDeviceInfo();
            }, 150);
        });
    }

    setupTouchHandlers() {
        if (!this.deviceInfo.isTouchDevice) return;
        let lastEnd = 0;
        document.addEventListener('touchend', (e) => {
            const now = Date.now();
            if (now - lastEnd <= 300) e.preventDefault();
            lastEnd = now;
        }, false);
    }

    setupPopstateHandler() {
        window.addEventListener('popstate', (event) => {
            if (this.deviceInfo.isMobile) this.handleMobileNavigation(event);
        });
    }

    handleMobileNavigation(event) {
        if (event.state && event.state.fromMobileNav) this.showMobileNavigationFeedback();
    }

    showMobileNavigationFeedback() {
        if (this.deviceInfo.isMobile && document.body) {
            document.body.style.transform = 'translateX(-2px)';
            setTimeout(() => { document.body.style.transform = ''; }, 100);
        }
    }

    // ---------- Page/Context ----------
    registerPage(pageInfo) {
        const urlParams = new URLSearchParams(window.location.search);
        const qReturnTo = urlParams.get('returnTo') || null;
        const qReturnToLabel = urlParams.get('returnToLabel') || null;
        const qReturnToPage = urlParams.get('returnToPage') || null;

        const parentSlug = pageInfo.parentPage
            || (qReturnToPage ? qReturnToPage.replace(/\.html$/i, '') : null);

        this.currentContext = {
            pageId: pageInfo.pageId,
            pageName: pageInfo.pageName,
            formType: pageInfo.formType || null,
            parentPage: parentSlug || null,
            returnTo: pageInfo.returnTo || qReturnTo || null,
            returnToLabel: pageInfo.returnToLabel || qReturnToLabel || null,
            saveHandler: pageInfo.saveHandler || null,
            customBackAction: pageInfo.customBackAction || null,
            timestamp: new Date().toISOString(),
            deviceInfo: { ...this.deviceInfo }
        };

        this.navigationHistory.push(this.currentContext);
        sessionStorage.setItem('navigationContext', JSON.stringify(this.currentContext));
        sessionStorage.setItem('navigationHistory', JSON.stringify(this.navigationHistory));
    }

    setCurrentPage(pageInfo) { this.registerPage(pageInfo); }

    // ---------- Keyboard (safe stub) ----------
    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (event) => {
            // Ctrl + S attempts to save; does not navigate
            if (event.ctrlKey && event.key.toLowerCase() === 's') {
                event.preventDefault();
                this.saveCurrentPage?.().catch(() => { });
            }
        });
    }

    // ---------- Back / Navigate ----------
    async confirmBackWithDialog() {
        const hasUnsaved = await this.checkUnsavedData();
        if (!hasUnsaved) {
            const dest = this.determineBackDestination();
            await this.navigateTo(dest);
            return 'no-unsaved';
        }

        return new Promise((resolve) => {
            const modal = this.createModal({
                title: 'Unsaved Changes Detected',
                content: `
          <div class="unsaved-data-dialog">
            <p>You have unsaved changes in this form. What would you like to do?</p>
            <div class="form-preview" id="formPreview">
              ${this.generateFormPreview()}
            </div>
          </div>
        `,
                buttons: [
                    {
                        text: this.deviceInfo.isMobile ? 'Save' : 'Save & Continue',
                        class: 'btn-success',
                        action: async () => {
                            try {
                                this.showNavigationLoading();
                                await this.saveCurrentPage();
                                await this.clearUnsavedData();
                                modal.remove();
                                const loader = document.getElementById('navigationLoader'); if (loader) loader.remove();
                                const destination = this.determineBackDestination();
                                await this.navigateTo(destination);
                                resolve('saved');
                            } catch {
                                const loader = document.getElementById('navigationLoader'); if (loader) loader.remove();
                                this.showErrorMessage('Failed to save changes. Please try again.');
                                resolve('save-failed');
                            }
                        }
                    },
                    {
                        text: this.deviceInfo.isMobile ? 'Discard' : 'Discard Changes',
                        class: 'btn-danger',
                        action: async () => {
                            try {
                                await this.clearUnsavedData();
                                modal.remove();
                                const destination = this.determineBackDestination();
                                await this.navigateTo(destination);
                                resolve('discarded');
                            } catch {
                                modal.remove();
                                const destination = this.determineBackDestination();
                                await this.navigateTo(destination);
                                resolve('discarded');
                            }
                        }
                    },
                    {
                        text: this.deviceInfo.isMobile ? 'Stay' : 'Stay Here',
                        class: 'btn-secondary',
                        action: () => {
                            modal.remove();
                            resolve('cancel');
                        }
                    }
                ]
            });
        });
    }

    async goBack({ customDestination = null } = {}) {
        const destination = customDestination || this.determineBackDestination();
        await this.navigateTo(destination);
        return 'success';
    }

    // Priority: explicit returnTo → parentPage → referrer → history → /dashboard.html
    determineBackDestination() {
        const urlParams = new URLSearchParams(window.location.search);
        const referrer = document.referrer;
        const storedContext = JSON.parse(sessionStorage.getItem('navigationContext') || '{}');

        const qReturnTo = urlParams.get('returnTo');
        if (qReturnTo) return qReturnTo;

        if (storedContext.returnTo) return storedContext.returnTo;

        if (storedContext.parentPage) return `/${storedContext.parentPage}.html`;

        if (referrer && this.isInternalUrl(referrer)) return referrer;

        const hist = JSON.parse(sessionStorage.getItem('navigationHistory') || '[]');
        if (hist.length > 1) {
            const previous = hist[hist.length - 2];
            if (previous?.returnTo) return previous.returnTo;
            if (previous?.parentPage) return `/${previous.parentPage}.html`;
        }
        return '/dashboard.html';
    }

    async checkUnsavedData() {
        for (const [, handler] of this.unsavedDataHandlers) {
            if (await handler()) return true;
        }
        return this.defaultUnsavedDataCheck();
    }

    defaultUnsavedDataCheck() {
        const formElements = document.querySelectorAll('input, select, textarea');
        const fileInputs = document.querySelectorAll('input[type="file"]');

        for (const element of formElements) {
            if (element.type === 'file') continue;
            const currentValue = element.value?.trim() || '';
            const defaultValue = element.defaultValue?.trim() || '';
            if (currentValue !== defaultValue && currentValue !== '') return true;
        }

        for (const fileInput of fileInputs) {
            if (fileInput.files && fileInput.files.length > 0) return true;
        }

        const formDataKeys = Object.keys(localStorage).filter(
            key => key.toLowerCase().includes('formdata') || key.toLowerCase().includes('form-data')
        );
        for (const key of formDataKeys) {
            const data = localStorage.getItem(key);
            if (data && data !== '{}' && data !== '[]') return true;
        }
        return false;
    }

    async clearUnsavedData() {
        return new Promise((resolve) => {
            try {
                Object.keys(localStorage).forEach(key => {
                    const k = key.toLowerCase();
                    if (k.includes('formdata') || k.includes('form-data') || k.includes('unsaved')) {
                        localStorage.removeItem(key);
                    }
                });
                Object.keys(sessionStorage).forEach(key => {
                    const k = key.toLowerCase();
                    if (k.includes('formdata') || k.includes('form-data') || k.includes('unsaved')) {
                        sessionStorage.removeItem(key);
                    }
                });

                const forms = document.querySelectorAll('form');
                forms.forEach(form => { if (typeof form.reset === 'function') form.reset(); });

                const formElements = document.querySelectorAll('input, select, textarea');
                formElements.forEach(element => {
                    if (element.type === 'file') element.value = '';
                    else if (element.type === 'checkbox' || element.type === 'radio') element.checked = element.defaultChecked;
                    else element.value = element.defaultValue || '';
                });

                this.unsavedDataHandlers.clear();
                resolve();
            } catch {
                resolve();
            }
        });
    }

    registerUnsavedDataHandler(formType, handler) {
        this.unsavedDataHandlers.set(formType, handler);
    }

    showErrorMessage(message) {
        const errorDiv = document.createElement('div');
        errorDiv.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: #f8d7da;
      color: #721c24;
      padding: 15px 20px;
      border: 1px solid #f5c6cb;
      border-radius: 8px;
      z-index: 100000;
      max-width: 300px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      font-size: ${this.deviceInfo.isMobile ? '14px' : '16px'};
    `;
        errorDiv.textContent = message;
        document.body.appendChild(errorDiv);
        setTimeout(() => { if (errorDiv.parentNode) errorDiv.parentNode.removeChild(errorDiv); }, 5000);
    }

    generateFormPreview() {
        const formElements = document.querySelectorAll('input, select, textarea');
        const preview = [];
        formElements.forEach(element => {
            const value = element.value?.trim();
            if (value && value !== element.defaultValue) {
                const label = this.getElementLabel(element);
                const truncated = this.deviceInfo.isMobile && value.length > 30 ? value.substring(0, 27) + '...' : value;
                preview.push(`<div class="preview-item"><strong>${label}:</strong> ${truncated}</div>`);
            }
        });
        return preview.length
            ? `<div class="form-data-preview">${preview.join('')}</div>`
            : '<p>Some form data has been entered.</p>';
    }

    createModal({ title, content, buttons = [], customClass = '' }) {
        const modal = document.createElement('div');
        modal.className = `navigation-modal ${customClass}`;
        const buttonsHtml = buttons.map(btn => `
      <button class="modal-btn ${btn.class}" data-action="${btn.text}">
        ${btn.text}
      </button>
    `).join('');

        modal.innerHTML = `
      <div class="modal-content" style="position:fixed;left:50%;top:50%;transform:translate(-50%,-50%);z-index:100001;background:#fff;border-radius:12px;min-width:300px;max-width:90vw;box-shadow:0 12px 48px rgba(0,0,0,0.25);color:#333;">
        <div style="padding:16px 20px;border-bottom:1px solid #eee;color:#2c3e50;"><h3 style="margin:0;font-size:18px;color:#2c3e50;">${title}</h3></div>
        <div class="modal-body" style="padding:16px 20px;color:#495057;">${content}</div>
        <div class="modal-buttons" style="display:flex;gap:10px;justify-content:flex-end;padding:12px 20px;border-top:1px solid #eee;">
          ${buttonsHtml}
        </div>
      </div>
      <div style="position:fixed;inset:0;background:rgba(0,0,0,0.35);backdrop-filter:saturate(120%) blur(2px);z-index:100000;"></div>
    `;

        buttons.forEach((btn, index) => {
            const el = modal.querySelectorAll('.modal-btn')[index];
            if (!el) return;
            el.style.cssText = `
        padding:8px 14px;border-radius:8px;border:0;cursor:pointer;
        font-size:${this.deviceInfo.isMobile ? '14px' : '14px'};
        color:#fff;
      `;
            if (btn.class?.includes('btn-success')) el.style.background = '#28a745';
            if (btn.class?.includes('btn-danger')) el.style.background = '#dc3545';
            if (btn.class?.includes('btn-secondary')) el.style.background = '#6c757d';

            el.addEventListener('click', btn.action);
            if (this.deviceInfo.isTouchDevice) {
                el.addEventListener('touchstart', () => { el.style.transform = 'scale(0.97)'; });
                el.addEventListener('touchend', () => { el.style.transform = ''; });
            }
        });

        modal.addEventListener('click', (e) => {
            const contentEl = modal.querySelector('.modal-content');
            if (e.target !== contentEl && !contentEl.contains(e.target)) modal.remove();
        });

        document.body.appendChild(modal);
        return modal;
    }

    getElementLabel(element) {
        const label = document.querySelector(`label[for="${element.id}"]`);
        if (label) return label.textContent.trim();
        if (element.placeholder) return element.placeholder;
        if (element.name) return this.capitalizeFirst(element.name.replace(/([A-Z])/g, ' $1'));
        return 'Field';
    }

    async saveCurrentPage() {
        if (this.currentContext?.saveHandler) return await this.currentContext.saveHandler();
        if (typeof window.FormNavigationIntegration?.saveFormData === 'function' && this.currentContext?.formType) {
            return await window.FormNavigationIntegration.saveFormData(this.currentContext.formType);
        }
        if (typeof window.saveFormData === 'function') return await window.saveFormData();
        throw new Error('No save handler available');
    }

    async navigateTo(destination, options = {}) {
        const { showLoading = true, transition = 'fade' } = options;
        if (showLoading) this.showNavigationLoading();
        if (transition === 'fade' && document.body) {
            document.body.style.opacity = this.deviceInfo.isMobile ? '0.8' : '0.7';
            document.body.style.transition = 'opacity 0.2s ease';
        }
        if (this.deviceInfo.isMobile && history.pushState) {
            history.pushState({ fromMobileNav: true }, '', window.location.href);
        }
        setTimeout(() => { window.location.href = destination; }, this.deviceInfo.isMobile ? 150 : 100);
    }

    showNavigationLoading() {
        const existing = document.getElementById('navigationLoader');
        if (existing) existing.remove();
        const loader = document.createElement('div');
        loader.id = 'navigationLoader';
        loader.style.cssText = `
      position:fixed;left:50%;top:50%;transform:translate(-50%,-50%);
      background:#2d2d2d;color:#fff;padding:12px 16px;border-radius:10px;
      z-index:100002;font-size:${this.deviceInfo.isMobile ? '14px' : '14px'};
      display:flex;gap:10px;align-items:center;box-shadow:0 10px 30px rgba(0,0,0,0.25);
    `;
        loader.innerHTML = `<div class="loading-spinner" style="width:16px;height:16px;border:2px solid #fff;border-top-color:transparent;border-radius:50%;animation:spin 0.8s linear infinite"></div><div>${this.deviceInfo.isMobile ? 'Loading...' : 'Navigating...'}</div>`;
        const style = document.createElement('style');
        style.innerHTML = `@keyframes spin{to{transform:rotate(360deg)}}`;
        document.head.appendChild(style);
        document.body.appendChild(loader);
        setTimeout(() => {
            if (loader && loader.parentNode) loader.parentNode.removeChild(loader);
        }, 10000);
    }

    trackPageNavigation() {
        const pageData = {
            url: window.location.href,
            timestamp: new Date().toISOString(),
            referrer: document.referrer,
            userAgent: navigator.userAgent,
            deviceInfo: { ...this.deviceInfo },
            connectionType: navigator.connection?.effectiveType || 'unknown'
        };
        const log = JSON.parse(sessionStorage.getItem('navigationLog') || '[]');
        log.push(pageData);
        if (log.length > 50) log.splice(0, log.length - 50);
        sessionStorage.setItem('navigationLog', JSON.stringify(log));
    }

    isInternalUrl(url) { return typeof url === 'string' && url.indexOf(window.location.origin) === 0; }
    capitalizeFirst(str) { return str ? str.charAt(0).toUpperCase() + str.slice(1) : ''; }

    optimizeForMobile() { /* noop */ }
    pauseMobileOperations() { clearTimeout(this.mobileTimeout); }
    resumeMobileOperations() { this.updateDeviceInfo(); }
    setupRouting() { }
    setupBreadcrumbs() { }
    setupProgressTracking() { }
}

// Global
window.navigationManager = new NavigationManager();

// Export (CommonJS)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = NavigationManager;
}
