// formNavigationIntegration.js - Fixed version with proper save handlers
class FormNavigationIntegration {
    static initializeForForm(formType) {
        const integrations = {
            'disposal': this.initDisposalForm,
            'efile': this.initEfileForm,
            'form365transfer': this.initForm365Transfer,
            'form365disposal': this.initForm365Disposal
        };

        const integration = integrations[formType];
        if (integration) {
            integration.call(this);
        }
        this.setupCommonFeatures(formType);
    }

    static setupCommonFeatures(formType) {
        if (!window.navigationManager) {
            console.error('navigationManager is not defined');
            return;
        }

        // Register the page
        window.navigationManager.setCurrentPage({
            pageId: window.location.pathname,
            pageName: this.getFormDisplayName(formType),
            formType: formType,
            parentPage: 'dashboard',
            saveHandler: () => this.saveFormData(formType)
        });

        // Register unsaved data handler
        window.navigationManager.registerUnsavedDataHandler(formType, () => {
            return this.checkUnsavedData(formType);
        });

        // Add form-specific shortcuts
        this.setupFormShortcuts(formType);
    }

    static initDisposalForm() {
        console.log('Initialized disposal form navigation');
    }

    static initEfileForm() {
        console.log('Initialized e-file form navigation');
    }

    static initForm365Transfer() {
        console.log('Initialized Form 365 Transfer navigation');
    }

    static initForm365Disposal() {
        console.log('Initialized Form 365 Disposal navigation');
    }

    static async saveFormData(formType) {
        try {
            console.log(`Attempting to save ${formType} form`);

            const saveHandlers = {
                'disposal': this.saveDisposalForm,
                'efile': this.saveEfileForm,
                'form365transfer': this.saveForm365Transfer,
                'form365disposal': this.saveForm365Disposal
            };

            const handler = saveHandlers[formType];
            if (handler) {
                const result = await handler.call(this);

                // After successful save, clear the localStorage cache
                const storageKey = `${formType}FormData`;
                localStorage.removeItem(storageKey);

                console.log(`${formType} form saved successfully`);
                return result;
            }

            throw new Error(`No save handler for form type: ${formType}`);
        } catch (error) {
            console.error(`Save failed for ${formType}:`, error);
            throw error;
        }
    }

    static async checkUnsavedData(formType) {
        // Check localStorage for specific form data
        const storageKey = `${formType}FormData`;
        const savedData = localStorage.getItem(storageKey);
        if (savedData && savedData !== '{}' && savedData !== '[]') {
            return true;
        }

        // Check for any modified form fields
        const formElements = document.querySelectorAll('input, select, textarea');
        for (const element of formElements) {
            if (element.type === 'file') {
                if (element.files && element.files.length > 0) {
                    return true;
                }
            } else if (element.type === 'checkbox' || element.type === 'radio') {
                if (element.checked !== element.defaultChecked) {
                    return true;
                }
            } else {
                const currentValue = element.value?.trim() || '';
                const defaultValue = element.defaultValue?.trim() || '';
                if (currentValue !== defaultValue && currentValue !== '') {
                    return true;
                }
            }
        }

        return false;
    }

    static getFormDisplayName(formType) {
        const names = {
            'disposal': 'Disposal Form',
            'efile': 'E-file Form',
            'form365transfer': 'Form 365 Transfer',
            'form365disposal': 'Form 365 Disposal'
        };
        return names[formType] || 'Form';
    }

    static setupFormShortcuts(formType) {
        document.addEventListener('keydown', (event) => {
            // Ctrl + Shift + S: Save and continue
            if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === 's') {
                event.preventDefault();
                this.saveAndContinue(formType);
            }
        });
    }

    static async saveAndContinue(formType) {
        try {
            await this.saveFormData(formType);
            if (window.navigationManager) {
                await window.navigationManager.goBack({ skipUnsavedCheck: true });
            }
        } catch (error) {
            console.error('Save and continue failed:', error);
            alert('Failed to save form data. Please try again.');
        }
    }

    // FIXED SAVE METHODS - Now properly implemented
    static async saveDisposalForm() {
        try {
            // Check if there's a global saveFormData function (your existing one)
            if (typeof window.saveFormData === 'function') {
                return await window.saveFormData();
            }

            // Alternative: implement basic save logic
            return await this.performFormSave('disposal');

        } catch (error) {
            console.error('Disposal form save failed:', error);
            throw new Error(`Disposal form save failed: ${error.message}`);
        }
    }

    static async saveEfileForm() {
        try {
            // Check if there's a global saveFormData function (your existing one)
            if (typeof window.saveFormData === 'function') {
                return await window.saveFormData();
            }

            // Alternative: implement basic save logic
            return await this.performFormSave('efile');

        } catch (error) {
            console.error('E-file form save failed:', error);
            throw new Error(`E-file form save failed: ${error.message}`);
        }
    }

    static async saveForm365Transfer() {
        try {
            // Check if there's a global saveFormData function (your existing one)
            if (typeof window.saveFormData === 'function') {
                return await window.saveFormData();
            }

            // Alternative: implement basic save logic
            return await this.performFormSave('form365transfer');

        } catch (error) {
            console.error('Form 365 Transfer save failed:', error);
            throw new Error(`Form 365 Transfer save failed: ${error.message}`);
        }
    }

    static async saveForm365Disposal() {
        try {
            // Check if there's a global saveFormData function (your existing one)
            if (typeof window.saveFormData === 'function') {
                return await window.saveFormData();
            }

            // Alternative: implement basic save logic
            return await this.performFormSave('form365disposal');

        } catch (error) {
            console.error('Form 365 Disposal save failed:', error);
            throw new Error(`Form 365 Disposal save failed: ${error.message}`);
        }
    }

    // NEW METHOD: Generic form save implementation
    static async performFormSave(formType) {
        return new Promise(async (resolve, reject) => {
            try {
                // Find the form element
                const form = document.querySelector('form') || document.querySelector('#mainForm') || document.querySelector(`#${formType}Form`);

                if (!form) {
                    // If no form found, just save current form data to localStorage
                    console.log(`No form element found for ${formType}, saving field data to localStorage`);

                    const formData = {};
                    const inputs = document.querySelectorAll('input, select, textarea');
                    inputs.forEach(input => {
                        if (input.name || input.id) {
                            const key = input.name || input.id;
                            if (input.type === 'file') {
                                formData[key] = input.files.length > 0 ? 'file_selected' : '';
                            } else if (input.type === 'checkbox' || input.type === 'radio') {
                                formData[key] = input.checked;
                            } else {
                                formData[key] = input.value;
                            }
                        }
                    });

                    localStorage.setItem(`${formType}FormData`, JSON.stringify(formData));
                    localStorage.setItem(`${formType}LastSaved`, new Date().toISOString());

                    resolve({
                        success: true,
                        message: `${formType} form data saved to localStorage`,
                        savedAt: new Date().toISOString()
                    });
                    return;
                }

                // If form found, try to submit or save it
                const formData = new FormData(form);
                formData.append('formType', formType);
                formData.append('savedAt', new Date().toISOString());

                // Try to make API call to save (adjust URL as needed)
                try {
                    const response = await fetch(`/api/save-${formType}`, {
                        method: 'POST',
                        body: formData,
                        credentials: 'include'
                    });

                    if (response.ok) {
                        const result = await response.json();
                        resolve(result);
                    } else {
                        throw new Error(`Server responded with ${response.status}: ${response.statusText}`);
                    }
                } catch (fetchError) {
                    // If API call fails, fallback to localStorage save
                    console.warn(`API save failed for ${formType}, falling back to localStorage:`, fetchError);

                    const formObject = {};
                    for (let [key, value] of formData.entries()) {
                        formObject[key] = value;
                    }

                    localStorage.setItem(`${formType}FormData`, JSON.stringify(formObject));
                    localStorage.setItem(`${formType}LastSaved`, new Date().toISOString());

                    resolve({
                        success: true,
                        message: `${formType} form saved locally (API unavailable)`,
                        savedAt: new Date().toISOString(),
                        fallback: true
                    });
                }

            } catch (error) {
                console.error(`Error in performFormSave for ${formType}:`, error);
                reject(error);
            }
        });
    }
}

// Make it globally accessible
window.FormNavigationIntegration = FormNavigationIntegration;

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = FormNavigationIntegration;
}
