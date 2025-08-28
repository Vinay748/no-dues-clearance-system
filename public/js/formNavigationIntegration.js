// formNavigationIntegration.js – Form-only Back + 3-option dialog (Save & Continue, Discard, Stay)

class FormNavigationIntegration {
    static initializeForForm(formType) {
        if (!window.navigationManager) {
            console.error('[FormNav] navigationManager is not defined');
            return;
        }

        // Resolve deterministic destination
        const q = new URLSearchParams(window.location.search);
        const returnTo = (q.get('returnTo') || '').trim() || '/dashboard.html';
        const returnToLabel = (q.get('returnToLabel') || 'Dashboard').trim();

        // Register page context with a save handler
        window.navigationManager.setCurrentPage({
            pageId: window.location.pathname + window.location.search,
            pageName: this.getFormDisplayName(formType),
            formType,
            returnTo,
            returnToLabel,
            saveHandler: () => this.saveFormData(formType)
        });

        // Unsaved data detection
        window.navigationManager.registerUnsavedDataHandler?.(formType, () => this.checkUnsavedData(formType));

        // Keyboard shortcut: Ctrl + Shift + S → Save & Continue
        this.setupFormShortcuts(formType);

        // Add local, form-only Back button at the top
        this.renderFormBackButton();
    }

    // Small Back button injected on form pages only
    static renderFormBackButton() {
        if (document.getElementById('formBackButton')) return;

        const wrap = document.createElement('div');
        wrap.id = 'formBackButton';
        wrap.className = 'form-back-button';

        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'back-btn';
        btn.innerHTML = `<span class="back-arrow">←</span><span class="back-text">Back</span>`;
        btn.addEventListener('click', async () => {
            await window.navigationManager.confirmBackWithDialog();
        });

        wrap.appendChild(btn);
        const container = document.querySelector('#formHeader') || document.body;
        container.insertBefore(wrap, container.firstChild);
    }

    // Keyboard: Ctrl + Shift + S to Save & Continue
    static setupFormShortcuts(formType) {
        document.addEventListener('keydown', (event) => {
            if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === 's') {
                event.preventDefault();
                this.saveAndContinue(formType);
            }
        });
    }

    // Save & Continue: save, then navigate deterministically
    static async saveAndContinue(formType) {
        const btn = document.getElementById('saveContinueBtn');
        if (btn) { btn.disabled = true; btn.textContent = 'Saving...'; }
        try {
            await this.saveFormData(formType);
            const q = new URLSearchParams(window.location.search);
            const dest = (q.get('returnTo') || '').trim() || '/dashboard.html';
            await window.navigationManager.goBack({ customDestination: dest });
        } catch (e) {
            alert('Failed to save form data. ' + (e?.message || ''));
        } finally {
            if (btn) { btn.disabled = false; btn.textContent = 'Save and Continue'; }
        }
    }

    // Unified saving entry
    static async saveFormData(formType) {
        const saveHandlers = {
            disposal: this.saveDisposalForm,
            efile: this.saveEfileForm,
            form365transfer: this.saveForm365Transfer,
            form365disposal: this.saveForm365Disposal
        };
        const handler = saveHandlers[formType];
        if (!handler) throw new Error(`No save handler for form type: ${formType}`);

        const result = await handler.call(this);

        // Clear any local cache footprint
        localStorage.removeItem(`${formType}FormData`);

        // Broadcast that a save completed (optional listeners on dashboard)
        try { document.dispatchEvent(new CustomEvent('formSaved', { detail: { formType, result } })); } catch { }

        return result;
    }

    // Prefer page-defined save; else click a known save button; else generic save
    static async callExistingSaveOrFallback(formType) {
        if (typeof window.saveFormData === 'function') {
            const result = await window.saveFormData();
            try { document.dispatchEvent(new CustomEvent('formSaved', { detail: { formType, result, reused: true } })); } catch { }
            return result;
        }

        const saveBtn =
            document.querySelector('.save-button') ||
            document.querySelector('button[type="submit"]') ||
            document.querySelector('#saveBtn');

        if (saveBtn) {
            const done = new Promise((resolve) => {
                const onSaved = () => {
                    document.removeEventListener('formSaved', onSaved);
                    resolve({ success: true, message: 'Saved via button click' });
                };
                document.addEventListener('formSaved', onSaved, { once: true });
                saveBtn.click();
            });
            return await done;
        }

        // Fallback: generic save
        return await this.performFormSave(formType);
    }

    // Concrete per-form save handlers
    static async saveDisposalForm() { return await this.callExistingSaveOrFallback('disposal'); }
    static async saveEfileForm() { return await this.callExistingSaveOrFallback('efile'); }
    static async saveForm365Transfer() { return await this.callExistingSaveOrFallback('form365transfer'); }
    static async saveForm365Disposal() { return await this.callExistingSaveOrFallback('form365disposal'); }

    // Unsaved-change detection
    static async checkUnsavedData(formType) {
        const savedData = localStorage.getItem(`${formType}FormData`);
        if (savedData && savedData !== '{}' && savedData !== '[]') return true;

        const els = document.querySelectorAll('input, select, textarea');
        for (const el of els) {
            if (el.type === 'file') {
                if (el.files && el.files.length > 0) return true;
            } else if (el.type === 'checkbox' || el.type === 'radio') {
                if (el.checked !== el.defaultChecked) return true;
            } else {
                const cur = el.value?.trim() || '';
                const def = el.defaultValue?.trim() || '';
                if (cur !== def && cur !== '') return true;
            }
        }
        return false;
    }

    // Generic save: POST multipart; fallback to localStorage
    static async performFormSave(formType) {
        return new Promise(async (resolve, reject) => {
            try {
                const form =
                    document.querySelector('form') ||
                    document.querySelector('#mainForm') ||
                    document.querySelector(`#${formType}Form`);

                if (!form) {
                    const formData = {};
                    const inputs = document.querySelectorAll('input, select, textarea');
                    inputs.forEach(input => {
                        if (input.name || input.id) {
                            const key = input.name || input.id;
                            if (input.type === 'file') formData[key] = input.files.length > 0 ? 'file_selected' : '';
                            else if (input.type === 'checkbox' || input.type === 'radio') formData[key] = input.checked;
                            else formData[key] = input.value;
                        }
                    });
                    localStorage.setItem(`${formType}FormData`, JSON.stringify(formData));
                    localStorage.setItem(`${formType}LastSaved`, new Date().toISOString());
                    try { document.dispatchEvent(new CustomEvent('formSaved', { detail: { formType, localOnly: true } })); } catch { }
                    resolve({ success: true, message: `${formType} form data saved to localStorage`, savedAt: new Date().toISOString() });
                    return;
                }

                const fd = new FormData(form);
                fd.append('formType', formType);
                fd.append('savedAt', new Date().toISOString());

                try {
                    const response = await fetch(`/api/save-${formType}`, {
                        method: 'POST',
                        body: fd,
                        credentials: 'include'
                    });
                    if (!response.ok) {
                        const txt = await response.text().catch(() => '');
                        throw new Error(`Server responded ${response.status}: ${response.statusText} ${txt}`.trim());
                    }
                    const result = await response.json();
                    try { document.dispatchEvent(new CustomEvent('formSaved', { detail: { formType, result } })); } catch { }
                    resolve(result);
                } catch (fetchError) {
                    const obj = {};
                    for (let [key, value] of fd.entries()) obj[key] = value;
                    localStorage.setItem(`${formType}FormData`, JSON.stringify(obj));
                    localStorage.setItem(`${formType}LastSaved`, new Date().toISOString());
                    try { document.dispatchEvent(new CustomEvent('formSaved', { detail: { formType, fallback: true } })); } catch { }
                    resolve({
                        success: true,
                        message: `${formType} form saved locally (API unavailable)`,
                        savedAt: new Date().toISOString(),
                        fallback: true
                    });
                }
            } catch (error) {
                reject(error);
            }
        });
    }

    // Utilities
    static getFormDisplayName(formType) {
        const names = {
            disposal: 'Disposal Form',
            efile: 'E-file Form',
            form365transfer: 'Form 365 Transfer',
            form365disposal: 'Form 365 Disposal'
        };
        return names[formType] || 'Form';
    }
}

// Global
window.FormNavigationIntegration = FormNavigationIntegration;

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = FormNavigationIntegration;
}
