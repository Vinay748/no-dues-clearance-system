// navigationManager.js - Production navigation system with mobile responsiveness (CSS-free version)
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
        // Wait for DOM to be ready before initializing device info
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                this.updateDeviceInfo();
                this.setupKeyboardShortcuts();
                this.trackPageNavigation();
                this.setupPopstateHandler();
                this.setupWindowResizeHandler();
                this.setupTouchHandlers();
                this.createGlobalBackButton();
            });
        } else {
            this.updateDeviceInfo();
            this.setupKeyboardShortcuts();
            this.trackPageNavigation();
            this.setupPopstateHandler();
            this.setupWindowResizeHandler();
            this.setupTouchHandlers();
            this.createGlobalBackButton();
        }
    }

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
        
        // Update CSS classes for device-specific styling - ONLY if body exists
        if (document.body) {
            document.body.classList.toggle('mobile-device', this.deviceInfo.isMobile);
            document.body.classList.toggle('tablet-device', this.deviceInfo.isTablet);
            document.body.classList.toggle('desktop-device', this.deviceInfo.isDesktop);
            document.body.classList.toggle('touch-device', this.deviceInfo.isTouchDevice);
        }
    }

    setupWindowResizeHandler() {
        let resizeTimeout;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(() => {
                this.updateDeviceInfo();
                this.updateBackButtonPosition();
            }, 150);
        });
    }

    setupTouchHandlers() {
        if (this.deviceInfo.isTouchDevice) {
            // Prevent zoom on double tap for better UX
            let lastTouchEnd = 0;
            document.addEventListener('touchend', (event) => {
                const now = (new Date()).getTime();
                if (now - lastTouchEnd <= 300) {
                    event.preventDefault();
                }
                lastTouchEnd = now;
            }, false);

            // Add touch feedback class
            document.addEventListener('touchstart', (e) => {
                const target = e.target.closest('.back-btn, .modal-btn');
                if (target) {
                    target.classList.add('touch-active');
                }
            });

            document.addEventListener('touchend', (e) => {
                setTimeout(() => {
                    document.querySelectorAll('.touch-active').forEach(el => {
                        el.classList.remove('touch-active');
                    });
                }, 150);
            });
        }
    }

    setupPopstateHandler() {
        window.addEventListener('popstate', (event) => {
            // Handle popstate events with mobile considerations
            if (this.deviceInfo.isMobile) {
                // Add mobile-specific popstate handling
                this.handleMobileNavigation(event);
            }
        });
    }

    handleMobileNavigation(event) {
        // Mobile-specific navigation handling
        if (event.state && event.state.fromMobileNav) {
            // Handle mobile navigation state
            this.showMobileNavigationFeedback();
        }
    }

    showMobileNavigationFeedback() {
        if (this.deviceInfo.isMobile && document.body) {
            // Show subtle feedback for mobile navigation
            document.body.style.transform = 'translateX(-2px)';
            setTimeout(() => {
                document.body.style.transform = '';
            }, 100);
        }
    }

    registerPage(pageInfo) {
        this.currentContext = {
            pageId: pageInfo.pageId,
            pageName: pageInfo.pageName,
            formType: pageInfo.formType || null,
            parentPage: pageInfo.parentPage || 'dashboard',
            saveHandler: pageInfo.saveHandler || null,
            customBackAction: pageInfo.customBackAction || null,
            timestamp: new Date().toISOString(),
            deviceInfo: { ...this.deviceInfo }
        };
        this.navigationHistory.push(this.currentContext);
        this.updateBackButton();
        sessionStorage.setItem('navigationContext', JSON.stringify(this.currentContext));
        sessionStorage.setItem('navigationHistory', JSON.stringify(this.navigationHistory));
    }

    goBack(options = {}) {
        const { force = false, skipUnsavedCheck = false, customDestination = null } = options;
        return new Promise(async (resolve, reject) => {
            try {
                // Mobile-specific haptic feedback
                if (this.deviceInfo.isMobile && navigator.vibrate) {
                    navigator.vibrate(50);
                }

                if (!skipUnsavedCheck && !force) {
                    const hasUnsavedData = await this.checkUnsavedData();
                    if (hasUnsavedData) {
                        const userChoice = await this.showUnsavedDataDialog();
                        
                        // The dialog now handles navigation internally
                        if (userChoice === 'cancel') {
                            resolve('cancelled');
                            return;
                        } else {
                            // Dialog already handled navigation for save/discard
                            resolve(userChoice);
                            return;
                        }
                    }
                }
                
                // Direct navigation (no unsaved data or force mode)
                const destination = customDestination || this.determineBackDestination();
                await this.navigateTo(destination);
                resolve('success');
            } catch (error) {
                reject(error);
            }
        });
    }

    determineBackDestination() {
        const urlParams = new URLSearchParams(window.location.search);
        const referrer = document.referrer;
        const storedContext = JSON.parse(sessionStorage.getItem('navigationContext') || '{}');

        if (urlParams.get('returnTo')) {
            return urlParams.get('returnTo');
        }
        if (storedContext.parentPage) {
            return `/${storedContext.parentPage}.html`;
        }
        if (referrer && this.isInternalUrl(referrer)) {
            return referrer;
        }
        if (this.navigationHistory.length > 1) {
            const previousPage = this.navigationHistory[this.navigationHistory.length - 2];
            return `/${previousPage.parentPage}.html`;
        }
        return '/dashboard.html';
    }

    async checkUnsavedData() {
        for (const [formType, handler] of this.unsavedDataHandlers) {
            if (await handler()) {
                return true;
            }
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
            if (currentValue !== defaultValue && currentValue !== '') {
                return true;
            }
        }

        for (const fileInput of fileInputs) {
            if (fileInput.files && fileInput.files.length > 0) {
                return true;
            }
        }

        const formDataKeys = Object.keys(localStorage).filter(
            key => key.includes('FormData') || key.includes('formData')
        );
        for (const key of formDataKeys) {
            const data = localStorage.getItem(key);
            if (data && data !== '{}' && data !== '[]') {
                return true;
            }
        }
        return false;
    }

    showUnsavedDataDialog() {
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
                                // Show loading state
                                this.showNavigationLoading();
                                
                                // Save the current page
                                await this.saveCurrentPage();
                                
                                // Clear unsaved data flags after successful save
                                await this.clearUnsavedData();
                                
                                // Remove modal
                                modal.remove();
                                
                                // Hide loading
                                const loader = document.getElementById('navigationLoader');
                                if (loader) loader.remove();
                                
                                // Navigate with force (skip unsaved check)
                                const destination = this.determineBackDestination();
                                await this.navigateTo(destination);
                                
                                resolve('saved');
                            } catch (error) {
                                console.error('Save failed:', error);
                                
                                // Hide loading
                                const loader = document.getElementById('navigationLoader');
                                if (loader) loader.remove();
                                
                                // Show error message
                                this.showErrorMessage('Failed to save changes. Please try again.');
                                
                                // Keep modal open for retry
                                resolve('save-failed');
                            }
                        }
                    },
                    {
                        text: this.deviceInfo.isMobile ? 'Discard' : 'Discard Changes',
                        class: 'btn-danger',
                        action: async () => {
                            try {
                                // Clear all unsaved data
                                await this.clearUnsavedData();
                                
                                // Remove modal
                                modal.remove();
                                
                                // Navigate immediately (no save needed)
                                const destination = this.determineBackDestination();
                                await this.navigateTo(destination);
                                
                                resolve('discarded');
                            } catch (error) {
                                console.error('Discard failed:', error);
                                
                                // Even if discard fails, proceed with navigation
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

    // NEW METHOD: Clear unsaved data from all sources
    async clearUnsavedData() {
        return new Promise((resolve) => {
            try {
                // Clear localStorage entries containing form data
                Object.keys(localStorage).forEach(key => {
                    if (key.toLowerCase().includes('formdata') || 
                        key.toLowerCase().includes('form-data') ||
                        key.toLowerCase().includes('unsaved')) {
                        localStorage.removeItem(key);
                    }
                });

                // Clear sessionStorage entries
                Object.keys(sessionStorage).forEach(key => {
                    if (key.toLowerCase().includes('formdata') || 
                        key.toLowerCase().includes('form-data') ||
                        key.toLowerCase().includes('unsaved')) {
                        sessionStorage.removeItem(key);
                    }
                });

                // Reset form fields to their default values
                const forms = document.querySelectorAll('form');
                forms.forEach(form => {
                    if (typeof form.reset === 'function') {
                        form.reset();
                    }
                });

                // Reset individual form elements
                const formElements = document.querySelectorAll('input, select, textarea');
                formElements.forEach(element => {
                    if (element.type === 'file') {
                        element.value = '';
                    } else if (element.type === 'checkbox' || element.type === 'radio') {
                        element.checked = element.defaultChecked;
                    } else {
                        element.value = element.defaultValue || '';
                    }
                });

                // Clear any custom unsaved data handlers
                this.unsavedDataHandlers.clear();

                console.log('Unsaved data cleared successfully');
                resolve();
            } catch (error) {
                console.error('Error clearing unsaved data:', error);
                resolve(); // Resolve anyway to prevent blocking
            }
        });
    }

    // NEW METHOD: Show error message
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
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (errorDiv.parentNode) {
                errorDiv.parentNode.removeChild(errorDiv);
            }
        }, 5000);
    }

    generateFormPreview() {
        const formElements = document.querySelectorAll('input, select, textarea');
        const preview = [];
        formElements.forEach(element => {
            const value = element.value?.trim();
            if (value && value !== element.defaultValue) {
                const label = this.getElementLabel(element);
                const truncatedValue = this.deviceInfo.isMobile && value.length > 30 
                    ? value.substring(0, 27) + '...' 
                    : value;
                preview.push(`<div class="preview-item"><strong>${label}:</strong> ${truncatedValue}</div>`);
            }
        });
        return preview.length > 0
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
      <div class="modal-content">
        <h3>${title}</h3>
        <div class="modal-body">${content}</div>
        <div class="modal-buttons">
          ${buttonsHtml}
        </div>
      </div>
    `;
        
        buttons.forEach((btn, index) => {
            const buttonEl = modal.querySelectorAll('.modal-btn')[index];
            if (buttonEl) {
                buttonEl.addEventListener('click', btn.action);
                
                // Add mobile touch feedback
                if (this.deviceInfo.isTouchDevice) {
                    buttonEl.addEventListener('touchstart', () => {
                        buttonEl.style.transform = 'scale(0.95)';
                    });
                    buttonEl.addEventListener('touchend', () => {
                        buttonEl.style.transform = '';
                    });
                }
            }
        });
        
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.remove();
        });
        
        // Add swipe to close on mobile
        if (this.deviceInfo.isMobile) {
            this.addSwipeToClose(modal);
        }
        
        if (document.body) {
            document.body.appendChild(modal);
        }
        return modal;
    }

    addSwipeToClose(modal) {
        let startY = 0;
        let currentY = 0;
        let isDragging = false;

        const modalContent = modal.querySelector('.modal-content');
        if (!modalContent) return;

        modalContent.addEventListener('touchstart', (e) => {
            startY = e.touches[0].clientY;
            isDragging = true;
        });

        modalContent.addEventListener('touchmove', (e) => {
            if (!isDragging) return;
            currentY = e.touches[0].clientY;
            const deltaY = currentY - startY;
            
            if (deltaY > 0) {
                modalContent.style.transform = `translateY(${deltaY}px)`;
            }
        });

        modalContent.addEventListener('touchend', () => {
            if (!isDragging) return;
            isDragging = false;
            
            const deltaY = currentY - startY;
            if (deltaY > 100) {
                modal.remove();
            } else {
                modalContent.style.transform = '';
            }
        });
    }

    registerUnsavedDataHandler(formType, handler) {
        this.unsavedDataHandlers.set(formType, handler);
    }

    async saveCurrentPage() {
        if (this.currentContext?.saveHandler) {
            return await this.currentContext.saveHandler();
        }
        if (typeof saveFormData === 'function') {
            return await saveFormData();
        }
        throw new Error('No save handler available');
    }

    async navigateTo(destination, options = {}) {
        const { showLoading = true, transition = 'fade' } = options;
        
        if (showLoading) {
            this.showNavigationLoading();
        }
        
        if (transition === 'fade' && document.body) {
            document.body.style.opacity = this.deviceInfo.isMobile ? '0.8' : '0.7';
            document.body.style.transition = 'opacity 0.2s ease';
        }
        
        // Add mobile-specific navigation state
        if (this.deviceInfo.isMobile && history.pushState) {
            history.pushState({ fromMobileNav: true }, '', window.location.href);
        }
        
        setTimeout(() => {
            window.location.href = destination;
        }, this.deviceInfo.isMobile ? 150 : 100);
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (event) => {
            // Disable keyboard shortcuts on mobile for better UX
            if (this.deviceInfo.isMobile) return;
            
            if (event.altKey && event.key.toLowerCase() === 'b') {
                event.preventDefault();
                this.goBack();
            }
            if (event.ctrlKey && event.key.toLowerCase() === 's') {
                event.preventDefault();
                this.saveCurrentPage().catch(() => { });
            }
            if (event.key === 'Escape') {
                const modal = document.querySelector('.navigation-modal');
                if (modal) modal.remove();
            }
        });
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
        const navigationLog = JSON.parse(sessionStorage.getItem('navigationLog') || '[]');
        navigationLog.push(pageData);
        if (navigationLog.length > 50) {
            navigationLog.splice(0, navigationLog.length - 50);
        }
        sessionStorage.setItem('navigationLog', JSON.stringify(navigationLog));
    }

    createGlobalBackButton() {
        if (document.getElementById('globalBackButton')) return;

        const backButton = document.createElement('div');
        backButton.id = 'globalBackButton';
        backButton.className = 'global-back-button';
        backButton.innerHTML = `
      <button onclick="window.navigationManager.goBack()" class="back-btn">
        <span class="back-arrow">←</span>
        <span class="back-text">Back</span>
      </button>
    `;

        if (document.body) {
            document.body.appendChild(backButton);
        }
        
        // Add mobile-specific event handlers
        if (this.deviceInfo.isTouchDevice) {
            // Wait a bit for the button to be added to DOM
            setTimeout(() => {
                this.setupMobileBackButton();
            }, 100);
        }
    }

    setupMobileBackButton() {
        const backBtn = document.querySelector('.back-btn');
        if (!backBtn) return;

        let touchStartTime = 0;
        let touchStartPos = { x: 0, y: 0 };

        backBtn.addEventListener('touchstart', (e) => {
            touchStartTime = Date.now();
            touchStartPos = { 
                x: e.touches[0].clientX, 
                y: e.touches.clientY 
            };
            backBtn.classList.add('touch-active');
        });

        backBtn.addEventListener('touchmove', (e) => {
            const currentPos = { 
                x: e.touches.clientX, 
                y: e.touches.clientY 
            };
            const distance = Math.sqrt(
                Math.pow(currentPos.x - touchStartPos.x, 2) + 
                Math.pow(currentPos.y - touchStartPos.y, 2)
            );
            
            // If moved more than 10px, cancel the touch
            if (distance > 10) {
                backBtn.classList.remove('touch-active');
            }
        });

        backBtn.addEventListener('touchend', (e) => {
            e.preventDefault();
            const touchEndTime = Date.now();
            const touchDuration = touchEndTime - touchStartTime;
            
            setTimeout(() => {
                backBtn.classList.remove('touch-active');
            }, 150);
            
            // Only trigger if it was a quick tap (< 500ms) and didn't move much
            if (touchDuration < 500) {
                window.navigationManager.goBack();
            }
        });

        backBtn.addEventListener('touchcancel', () => {
            backBtn.classList.remove('touch-active');
        });
    }

    updateBackButton() {
        const backButton = document.querySelector('.back-text');
        if (backButton && this.currentContext) {
            const destination = this.determineBackDestination();
            const pageName = destination.split('/').pop().replace('.html', '');
            
            // Shorten text on mobile
            if (this.deviceInfo.isMobile) {
                backButton.textContent = this.deviceInfo.screenWidth < 400 ? 'Back' : `Back to ${this.capitalizeFirst(pageName)}`;
            } else {
                backButton.textContent = `Back to ${this.capitalizeFirst(pageName)}`;
            }
        }
    }

    updateBackButtonPosition() {
        // Position is now handled by CSS classes
        this.updateBackButton();
    }

    isInternalUrl(url) {
        return url.includes(window.location.origin);
    }

    capitalizeFirst(str) {
        return str.charAt(0).toUpperCase() + str.slice(1);
    }

    getElementLabel(element) {
        const label = document.querySelector(`label[for="${element.id}"]`);
        if (label) return label.textContent.trim();
        if (element.placeholder) return element.placeholder;
        if (element.name) return this.capitalizeFirst(element.name.replace(/([A-Z])/g, ' $1'));
        return 'Field';
    }

    showNavigationLoading() {
        // Remove any existing loader
        const existingLoader = document.getElementById('navigationLoader');
        if (existingLoader) existingLoader.remove();
        
        const loader = document.createElement('div');
        loader.id = 'navigationLoader';
        loader.innerHTML = `
            <div class="loading-spinner"></div>
            <div>${this.deviceInfo.isMobile ? 'Loading...' : 'Navigating...'}</div>
        `;
        
        if (document.body) {
            document.body.appendChild(loader);
        }
        
        // Auto-remove after 10 seconds (in case of network issues)
        setTimeout(() => {
            if (loader && loader.parentNode) {
                loader.parentNode.removeChild(loader);
            }
        }, 10000);
    }

    setCurrentPage(pageInfo) {
        this.registerPage(pageInfo);
    }

    addNavigationListener(callback) {
        this.navigationListeners.add(callback);
    }

    removeNavigationListener(callback) {
        this.navigationListeners.delete(callback);
    }

    // Mobile-specific methods
    getMobileNavigationInfo() {
        return {
            deviceInfo: this.deviceInfo,
            navigationHistory: this.navigationHistory.slice(-5), // Last 5 entries
            currentContext: this.currentContext
        };
    }

    optimizeForMobile() {
        if (this.deviceInfo.isMobile) {
            // Add mobile-specific optimizations
            document.addEventListener('visibilitychange', () => {
                if (document.hidden) {
                    // Pause any animations or heavy operations
                    this.pauseMobileOperations();
                } else {
                    // Resume operations
                    this.resumeMobileOperations();
                }
            });
        }
    }

    pauseMobileOperations() {
        // Pause any heavy operations when app goes to background
        clearTimeout(this.mobileTimeout);
    }

    resumeMobileOperations() {
        // Resume operations when app comes back to foreground
        this.updateDeviceInfo();
    }

    setupRouting() {
        // Future implementation for routing
    }

    setupBreadcrumbs() {
        // Future implementation for breadcrumbs
    }

    setupProgressTracking() {
        // Future implementation for progress tracking
    }
}

// Make navigationManager globally accessible for all scripts with mobile info
window.navigationManager = new NavigationManager();

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = NavigationManager;
}
