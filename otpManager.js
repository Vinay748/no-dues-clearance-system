const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

// =========================================
// BASIC CONFIGURATION
// =========================================

const CONFIG = {
    OTP: {
        LENGTH: 6,
        EXPIRY_MINUTES: 5,
        MAX_ATTEMPTS: 3,
        RESEND_LIMIT: 3
    },

    SESSION: {
        EXPIRY_MINUTES: 10,
        TOKEN_LENGTH: 32,
        MAX_SESSIONS_PER_USER: 3
    },

    EMAIL: {
        RETRY_ATTEMPTS: 2,
        RETRY_DELAY: 1000,
        TIMEOUT: 10000
    },

    FILES: {
        OTP_DATA: path.join(__dirname, 'data', 'otp_data.json'),
        SESSIONS: path.join(__dirname, 'data', 'login_sessions.json'),
        USERS: path.join(__dirname, 'data', 'users.json')
    }
};

console.log('[CONFIG] OTP Manager configuration loaded:', JSON.stringify(CONFIG, null, 2));

// =========================================
// BASIC LOGGING SYSTEM
// =========================================

const logger = {
    info: (message) => console.log(`[INFO] ${new Date().toISOString()} - ${message}`),
    warn: (message) => console.warn(`[WARN] ${new Date().toISOString()} - ${message}`),
    error: (message, error) => console.error(`[ERROR] ${new Date().toISOString()} - ${message}`, error?.message || error)
};

// =========================================
// BASIC SECURITY UTILITIES
// =========================================

class SecurityManager {
    static hashOTP(otp) {
        console.log('[SECURITY] Hashing OTP with SHA256');
        const hash = crypto.createHash('sha256').update(otp).digest('hex');
        console.log('[SECURITY] OTP hashed successfully, length:', hash.length);
        return hash;
    }

    static sanitizeEmail(email) {
        console.log('[SECURITY] Sanitizing email:', email ? email.substring(0, 3) + '***' : 'null');

        if (!email || typeof email !== 'string') {
            console.log('[SECURITY] Invalid email input, returning null');
            return null;
        }

        const sanitized = email.toLowerCase().trim();
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const isValid = emailRegex.test(sanitized);

        console.log('[SECURITY] Email validation result:', isValid);
        return isValid ? sanitized : null;
    }

    static sanitizeEmployeeId(employeeId) {
        console.log('[SECURITY] Sanitizing employee ID:', employeeId);

        if (!employeeId || typeof employeeId !== 'string') {
            console.log('[SECURITY] Invalid employee ID input, returning null');
            return null;
        }

        const sanitized = employeeId.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
        console.log('[SECURITY] Employee ID sanitized:', sanitized);
        return sanitized;
    }
}

// =========================================
// BASIC FILE OPERATIONS
// =========================================

class FileManager {
    static async ensureDirectory(filePath) {
        const dir = path.dirname(filePath);
        console.log('[FILE] Ensuring directory exists:', dir);

        try {
            await fs.promises.access(dir);
            console.log('[FILE] Directory already exists:', dir);
        } catch (error) {
            if (error.code === 'ENOENT') {
                console.log('[FILE] Creating directory:', dir);
                await fs.promises.mkdir(dir, { recursive: true });
                console.log('[FILE] Directory created successfully:', dir);
            } else {
                console.error('[FILE] Error checking directory:', error.message);
            }
        }
    }

    static async loadJSON(filePath, defaultValue = {}) {
        console.log('[FILE] Loading JSON file:', filePath);

        try {
            await this.ensureDirectory(filePath);

            if (!fs.existsSync(filePath)) {
                console.log('[FILE] File does not exist, creating with default value:', filePath);
                await fs.promises.writeFile(filePath, JSON.stringify(defaultValue, null, 2));
                console.log('[FILE] Default file created successfully:', filePath);
                return defaultValue;
            }

            console.log('[FILE] Reading existing file:', filePath);
            const data = await fs.promises.readFile(filePath, 'utf8');
            const parsed = JSON.parse(data || JSON.stringify(defaultValue));
            console.log('[FILE] File loaded successfully, keys:', Object.keys(parsed));
            return parsed;
        } catch (error) {
            console.error('[FILE] Failed to load JSON file:', filePath, error.message);
            logger.error(`Failed to load JSON file: ${filePath}`, error);
            return defaultValue;
        }
    }

    static async saveJSON(filePath, data) {
        console.log('[FILE] Saving JSON file:', filePath, 'with keys:', Object.keys(data));

        try {
            await this.ensureDirectory(filePath);
            await fs.promises.writeFile(filePath, JSON.stringify(data, null, 2));
            console.log('[FILE] File saved successfully:', filePath);
            return true;
        } catch (error) {
            console.error('[FILE] Failed to save JSON file:', filePath, error.message);
            logger.error(`Failed to save JSON file: ${filePath}`, error);
            return false;
        }
    }
}

// =========================================
// SIMPLIFIED OTP MANAGER CLASS
// =========================================

class OTPManager {
    constructor() {
        console.log('[OTP_MANAGER] Initializing OTP Manager...');
        this.transporter = null;
        this.isInitialized = false;
        this.initialize();
    }

    /**
     * Initialize OTP Manager
     */
    async initialize() {
        console.log('[OTP_MANAGER] Starting initialization process...');

        try {
            console.log('[OTP_MANAGER] Checking environment variables...');
            if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
                throw new Error('EMAIL_USER and EMAIL_PASS environment variables are required');
            }
            console.log('[OTP_MANAGER] Environment variables found - EMAIL_USER:', process.env.EMAIL_USER);

            await this.createTransporter();
            await this.verifyConnection();

            this.isInitialized = true;
            console.log('[OTP_MANAGER] Initialization completed successfully');
            logger.info('OTP Manager initialized successfully');

        } catch (error) {
            console.error('[OTP_MANAGER] Initialization failed:', error.message);
            logger.error('OTP Manager initialization failed', error);
            throw error;
        }
    }

    /**
     * Create email transporter
     */
    async createTransporter() {
        console.log('[EMAIL] Creating email transporter...');

        const transporterConfig = {
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            },
            connectionTimeout: CONFIG.EMAIL.TIMEOUT,
            greetingTimeout: CONFIG.EMAIL.TIMEOUT,
            socketTimeout: CONFIG.EMAIL.TIMEOUT
        };

        console.log('[EMAIL] Transporter config:', {
            service: transporterConfig.service,
            user: transporterConfig.auth.user,
            timeout: transporterConfig.connectionTimeout
        });

        this.transporter = nodemailer.createTransport(transporterConfig);
        console.log('[EMAIL] Transporter created successfully');
    }

    /**
     * Verify email connection
     */
    async verifyConnection() {
        console.log('[EMAIL] Verifying email connection...');

        try {
            await this.transporter.verify();
            console.log('[EMAIL] Connection verification successful');
            logger.info('Email transporter verified successfully');
        } catch (error) {
            console.error('[EMAIL] Connection verification failed:', error.message);
            logger.error('Email transporter verification failed', error);
            throw new Error('Email service connection failed');
        }
    }

    /**
     * Generate secure OTP
     */
    generateOTP() {
        console.log('[OTP] Generating new OTP...');
        const otp = crypto.randomInt(100000, 999999).toString();
        console.log('[OTP] OTP generated successfully, length:', otp.length);
        return otp;
    }

    /**
     * Generate secure session token
     */
    generateSessionToken() {
        console.log('[SESSION] Generating session token...');
        const token = crypto.randomBytes(CONFIG.SESSION.TOKEN_LENGTH).toString('hex');
        console.log('[SESSION] Session token generated, length:', token.length);
        return token;
    }

    /**
     * Clean expired OTPs and sessions
     */
    async cleanExpired() {
        console.log('[CLEANUP] Starting cleanup process...');

        try {
            const now = new Date();
            console.log('[CLEANUP] Current time:', now.toISOString());

            // Clean expired OTPs
            console.log('[CLEANUP] Loading OTP data for cleanup...');
            const otps = await FileManager.loadJSON(CONFIG.FILES.OTP_DATA);
            let otpCleaned = false;
            let otpCount = 0;

            for (const [employeeId, otpData] of Object.entries(otps)) {
                if (new Date(otpData.expiresAt) < now) {
                    console.log('[CLEANUP] Removing expired OTP for employee:', employeeId);
                    delete otps[employeeId];
                    otpCleaned = true;
                    otpCount++;
                }
            }

            if (otpCleaned) {
                console.log('[CLEANUP] Saving cleaned OTP data, removed:', otpCount, 'entries');
                await FileManager.saveJSON(CONFIG.FILES.OTP_DATA, otps);
            } else {
                console.log('[CLEANUP] No expired OTPs found');
            }

            // Clean expired sessions
            console.log('[CLEANUP] Loading session data for cleanup...');
            const sessions = await FileManager.loadJSON(CONFIG.FILES.SESSIONS);
            let sessionCleaned = false;
            let sessionCount = 0;

            for (const [token, sessionData] of Object.entries(sessions)) {
                if (new Date(sessionData.expiresAt) < now) {
                    console.log('[CLEANUP] Removing expired session:', token.substring(0, 8) + '...');
                    delete sessions[token];
                    sessionCleaned = true;
                    sessionCount++;
                }
            }

            if (sessionCleaned) {
                console.log('[CLEANUP] Saving cleaned session data, removed:', sessionCount, 'entries');
                await FileManager.saveJSON(CONFIG.FILES.SESSIONS, sessions);
            } else {
                console.log('[CLEANUP] No expired sessions found');
            }

            console.log('[CLEANUP] Cleanup completed - OTPs removed:', otpCount, 'Sessions removed:', sessionCount);

        } catch (error) {
            console.error('[CLEANUP] Cleanup failed:', error.message);
            logger.error('Cleanup failed', error);
        }
    }

    /**
     * Create login session
     */
    async createLoginSession(employeeId, email, clientInfo = {}) {
        console.log('[LOGIN_SESSION] Creating login session for employee:', employeeId);
        console.log('[LOGIN_SESSION] Client info:', clientInfo);

        try {
            console.log('[LOGIN_SESSION] Sanitizing inputs...');
            const sanitizedEmployeeId = SecurityManager.sanitizeEmployeeId(employeeId);
            const sanitizedEmail = SecurityManager.sanitizeEmail(email);

            if (!sanitizedEmployeeId || !sanitizedEmail) {
                console.error('[LOGIN_SESSION] Input validation failed');
                throw new Error('Invalid employee ID or email format');
            }

            console.log('[LOGIN_SESSION] Running cleanup before creating session...');
            await this.cleanExpired();

            console.log('[LOGIN_SESSION] Generating session components...');
            const sessionToken = this.generateSessionToken();
            const otp = this.generateOTP();
            const otpHash = SecurityManager.hashOTP(otp);
            const now = new Date();
            const sessionExpiry = new Date(now.getTime() + CONFIG.SESSION.EXPIRY_MINUTES * 60 * 1000);
            const otpExpiry = new Date(now.getTime() + CONFIG.OTP.EXPIRY_MINUTES * 60 * 1000);

            console.log('[LOGIN_SESSION] Session expires at:', sessionExpiry.toISOString());
            console.log('[LOGIN_SESSION] OTP expires at:', otpExpiry.toISOString());

            // Store session
            console.log('[LOGIN_SESSION] Storing session data...');
            const sessions = await FileManager.loadJSON(CONFIG.FILES.SESSIONS);
            sessions[sessionToken] = {
                employeeId: sanitizedEmployeeId,
                sessionToken,
                status: 'pending_otp',
                expiresAt: sessionExpiry.toISOString(),
                createdAt: now.toISOString(),
                otpVerifiedAt: null,
                clientInfo: {
                    ip: clientInfo.ip,
                    userAgent: clientInfo.userAgent
                }
            };

            console.log('[LOGIN_SESSION] Saving session to file...');
            await FileManager.saveJSON(CONFIG.FILES.SESSIONS, sessions);

            // Store OTP
            console.log('[LOGIN_SESSION] Storing OTP data...');
            const otps = await FileManager.loadJSON(CONFIG.FILES.OTP_DATA);
            otps[sanitizedEmployeeId] = {
                otpHash,
                email: sanitizedEmail,
                createdAt: now.toISOString(),
                expiresAt: otpExpiry.toISOString(),
                attempts: 0,
                maxAttempts: CONFIG.OTP.MAX_ATTEMPTS,
                used: false,
                sessionToken
            };

            console.log('[LOGIN_SESSION] Saving OTP to file...');
            await FileManager.saveJSON(CONFIG.FILES.OTP_DATA, otps);

            // Send email
            console.log('[LOGIN_SESSION] Sending OTP email...');
            await this.sendEmailOTP(sanitizedEmail, otp, sanitizedEmployeeId);

            console.log('[LOGIN_SESSION] Login session created successfully');
            logger.info('OTP session created successfully');

            return {
                success: true,
                sessionToken,
                message: 'OTP sent to your email address',
                expiresIn: CONFIG.OTP.EXPIRY_MINUTES
            };

        } catch (error) {
            console.error('[LOGIN_SESSION] Failed to create login session:', error.message);
            logger.error('Failed to create login session', error);
            return {
                success: false,
                message: 'Failed to send OTP. Please try again later.'
            };
        }
    }

    /**
     * Send email OTP
     */
    async sendEmailOTP(email, otp, employeeId) {
        console.log('[EMAIL_OTP] Preparing to send OTP email to:', email.substring(0, 3) + '***');
        console.log('[EMAIL_OTP] Employee ID:', employeeId);

        const mailOptions = {
            from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
            to: email,
            subject: 'IT No-Dues System - Login Verification Code',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2>IT No-Dues System - Login Verification</h2>
                    <p>Your verification code is:</p>
                    <div style="font-size: 24px; font-weight: bold; background: #f5f5f5; padding: 20px; text-align: center; margin: 20px 0;">
                        ${otp}
                    </div>
                    <p>Employee ID: ${employeeId}</p>
                    <p>Valid for: ${CONFIG.OTP.EXPIRY_MINUTES} minutes</p>
                    <p>If you did not request this login, please ignore this email.</p>
                </div>
            `,
            text: `
                IT No-Dues System - Login Verification
                
                Your verification code is: ${otp}
                Employee ID: ${employeeId}
                Valid for: ${CONFIG.OTP.EXPIRY_MINUTES} minutes
                
                If you did not request this login, please ignore this email.
            `
        };

        console.log('[EMAIL_OTP] Mail options prepared:', {
            from: mailOptions.from,
            to: mailOptions.to.substring(0, 3) + '***',
            subject: mailOptions.subject
        });

        try {
            console.log('[EMAIL_OTP] Sending email...');
            const result = await this.transporter.sendMail(mailOptions);
            console.log('[EMAIL_OTP] Email sent successfully, message ID:', result.messageId);
            logger.info('OTP email sent successfully');
            return result;
        } catch (error) {
            console.error('[EMAIL_OTP] Failed to send email:', error.message);
            throw error;
        }
    }

    /**
     * Verify OTP
     */
    async verifyOTP(sessionToken, inputOTP, clientInfo = {}) {
        console.log('[VERIFY_OTP] Starting OTP verification...');
        console.log('[VERIFY_OTP] Session token:', sessionToken ? sessionToken.substring(0, 8) + '...' : 'null');
        console.log('[VERIFY_OTP] Input OTP length:', inputOTP ? inputOTP.length : 'null');

        try {
            if (!sessionToken || !inputOTP) {
                console.log('[VERIFY_OTP] Missing required parameters');
                return {
                    success: false,
                    message: 'Session token and OTP are required'
                };
            }

            console.log('[VERIFY_OTP] Sanitizing OTP input...');
            const sanitizedOTP = inputOTP.replace(/\D/g, '').substring(0, CONFIG.OTP.LENGTH);
            console.log('[VERIFY_OTP] Sanitized OTP length:', sanitizedOTP.length);

            if (sanitizedOTP.length !== CONFIG.OTP.LENGTH) {
                console.log('[VERIFY_OTP] Invalid OTP format');
                return {
                    success: false,
                    message: 'Invalid OTP format'
                };
            }

            console.log('[VERIFY_OTP] Running cleanup...');
            await this.cleanExpired();

            // Get session
            console.log('[VERIFY_OTP] Loading session data...');
            const sessions = await FileManager.loadJSON(CONFIG.FILES.SESSIONS);
            const session = sessions[sessionToken];

            if (!session || session.status !== 'pending_otp') {
                console.log('[VERIFY_OTP] Invalid or expired session, status:', session?.status);
                return {
                    success: false,
                    message: 'Invalid or expired session'
                };
            }

            console.log('[VERIFY_OTP] Session found for employee:', session.employeeId);

            // Get OTP data
            console.log('[VERIFY_OTP] Loading OTP data...');
            const otps = await FileManager.loadJSON(CONFIG.FILES.OTP_DATA);
            const otpData = otps[session.employeeId];

            if (!otpData || otpData.used) {
                console.log('[VERIFY_OTP] OTP not found or already used, exists:', !!otpData, 'used:', otpData?.used);
                return {
                    success: false,
                    message: 'OTP not found or already used'
                };
            }

            console.log('[VERIFY_OTP] OTP data found, expires at:', otpData.expiresAt);
            console.log('[VERIFY_OTP] Current attempts:', otpData.attempts);

            if (new Date() > new Date(otpData.expiresAt)) {
                console.log('[VERIFY_OTP] OTP expired, cleaning up...');
                delete otps[session.employeeId];
                await FileManager.saveJSON(CONFIG.FILES.OTP_DATA, otps);
                return {
                    success: false,
                    message: 'OTP expired. Please request a new one.'
                };
            }

            if (otpData.attempts >= otpData.maxAttempts) {
                console.log('[VERIFY_OTP] Maximum attempts exceeded');
                return {
                    success: false,
                    message: 'Too many failed attempts. Please request a new OTP.'
                };
            }

            // Verify OTP hash
            console.log('[VERIFY_OTP] Verifying OTP hash...');
            const inputOTPHash = SecurityManager.hashOTP(sanitizedOTP);
            if (otpData.otpHash !== inputOTPHash) {
                console.log('[VERIFY_OTP] OTP hash mismatch, incrementing attempts...');
                otps[session.employeeId].attempts++;
                await FileManager.saveJSON(CONFIG.FILES.OTP_DATA, otps);

                const remainingAttempts = otpData.maxAttempts - otps[session.employeeId].attempts;
                console.log('[VERIFY_OTP] Remaining attempts:', remainingAttempts);
                return {
                    success: false,
                    message: `Invalid OTP. ${remainingAttempts} attempts remaining.`
                };
            }

            // Success - mark OTP as used and activate session
            console.log('[VERIFY_OTP] OTP verified successfully, updating session...');
            otps[session.employeeId].used = true;
            sessions[sessionToken].status = 'verified';
            sessions[sessionToken].otpVerifiedAt = new Date().toISOString();

            console.log('[VERIFY_OTP] Saving updated data...');
            await FileManager.saveJSON(CONFIG.FILES.OTP_DATA, otps);
            await FileManager.saveJSON(CONFIG.FILES.SESSIONS, sessions);

            console.log('[VERIFY_OTP] Verification completed successfully');
            logger.info('OTP verification successful');

            return {
                success: true,
                message: 'Login successful',
                employeeId: session.employeeId,
                sessionToken
            };

        } catch (error) {
            console.error('[VERIFY_OTP] Verification failed:', error.message);
            logger.error('OTP verification failed', error);
            return {
                success: false,
                message: 'Verification failed. Please try again.'
            };
        }
    }

    /**
     * Resend OTP
     */
    async resendOTP(sessionToken, clientInfo = {}) {
        console.log('[RESEND_OTP] Starting OTP resend process...');
        console.log('[RESEND_OTP] Session token:', sessionToken ? sessionToken.substring(0, 8) + '...' : 'null');

        try {
            if (!sessionToken) {
                console.log('[RESEND_OTP] Missing session token');
                return {
                    success: false,
                    message: 'Session token is required'
                };
            }

            console.log('[RESEND_OTP] Loading session data...');
            const sessions = await FileManager.loadJSON(CONFIG.FILES.SESSIONS);
            const session = sessions[sessionToken];

            if (!session || session.status !== 'pending_otp') {
                console.log('[RESEND_OTP] Invalid session, status:', session?.status);
                return {
                    success: false,
                    message: 'Invalid session'
                };
            }

            console.log('[RESEND_OTP] Session found for employee:', session.employeeId);

            console.log('[RESEND_OTP] Loading OTP data...');
            const otps = await FileManager.loadJSON(CONFIG.FILES.OTP_DATA);
            const otpData = otps[session.employeeId];

            if (otpData && otpData.attempts >= CONFIG.OTP.RESEND_LIMIT) {
                console.log('[RESEND_OTP] Resend limit exceeded, attempts:', otpData.attempts);
                return {
                    success: false,
                    message: 'Too many OTP requests. Please try logging in again.'
                };
            }

            // Generate new OTP
            console.log('[RESEND_OTP] Generating new OTP...');
            const newOTP = this.generateOTP();
            const otpHash = SecurityManager.hashOTP(newOTP);
            const now = new Date();
            const otpExpiry = new Date(now.getTime() + CONFIG.OTP.EXPIRY_MINUTES * 60 * 1000);

            // Get user email from existing OTP data
            const userEmail = otpData?.email;
            console.log('[RESEND_OTP] User email found:', userEmail ? userEmail.substring(0, 3) + '***' : 'null');

            if (!userEmail) {
                console.log('[RESEND_OTP] User email not found');
                return {
                    success: false,
                    message: 'User email not found'
                };
            }

            // Update OTP
            console.log('[RESEND_OTP] Updating OTP data...');
            otps[session.employeeId] = {
                otpHash,
                email: userEmail,
                createdAt: now.toISOString(),
                expiresAt: otpExpiry.toISOString(),
                attempts: 0,
                maxAttempts: CONFIG.OTP.MAX_ATTEMPTS,
                used: false,
                sessionToken,
                resendCount: (otpData?.resendCount || 0) + 1
            };

            console.log('[RESEND_OTP] New resend count:', otps[session.employeeId].resendCount);
            await FileManager.saveJSON(CONFIG.FILES.OTP_DATA, otps);

            // Send new OTP
            console.log('[RESEND_OTP] Sending new OTP email...');
            await this.sendEmailOTP(userEmail, newOTP, session.employeeId);

            console.log('[RESEND_OTP] OTP resent successfully');
            logger.info('OTP resent successfully');

            return {
                success: true,
                message: 'New OTP sent to your email',
                expiresIn: CONFIG.OTP.EXPIRY_MINUTES
            };

        } catch (error) {
            console.error('[RESEND_OTP] Resend failed:', error.message);
            logger.error('OTP resend failed', error);
            return {
                success: false,
                message: 'Failed to resend OTP'
            };
        }
    }

    /**
     * Check if session is valid
     */
    async isValidSession(sessionToken) {
        console.log('[VALID_SESSION] Checking session validity:', sessionToken ? sessionToken.substring(0, 8) + '...' : 'null');

        try {
            console.log('[VALID_SESSION] Running cleanup...');
            await this.cleanExpired();

            console.log('[VALID_SESSION] Loading session data...');
            const sessions = await FileManager.loadJSON(CONFIG.FILES.SESSIONS);
            const session = sessions[sessionToken];

            const isValid = session &&
                session.status === 'verified' &&
                new Date() < new Date(session.expiresAt);

            console.log('[VALID_SESSION] Session validity result:', isValid);
            console.log('[VALID_SESSION] Session status:', session?.status);
            console.log('[VALID_SESSION] Session expires:', session?.expiresAt);

            return isValid;
        } catch (error) {
            console.error('[VALID_SESSION] Session validation failed:', error.message);
            logger.error('Session validation failed', error);
            return false;
        }
    }

    /**
     * Get session data
     */
    async getSessionData(sessionToken) {
        console.log('[SESSION_DATA] Getting session data for:', sessionToken ? sessionToken.substring(0, 8) + '...' : 'null');

        try {
            console.log('[SESSION_DATA] Loading sessions...');
            const sessions = await FileManager.loadJSON(CONFIG.FILES.SESSIONS);
            const session = sessions[sessionToken];

            if (!session) {
                console.log('[SESSION_DATA] Session not found');
                return null;
            }

            console.log('[SESSION_DATA] Session found for employee:', session.employeeId);
            console.log('[SESSION_DATA] Session status:', session.status);

            const sessionData = {
                employeeId: session.employeeId,
                status: session.status,
                createdAt: session.createdAt,
                expiresAt: session.expiresAt,
                otpVerifiedAt: session.otpVerifiedAt,
                isExpired: new Date() > new Date(session.expiresAt)
            };

            console.log('[SESSION_DATA] Returning session data:', sessionData);
            return sessionData;
        } catch (error) {
            console.error('[SESSION_DATA] Failed to get session data:', error.message);
            logger.error('Failed to get session data', error);
            return null;
        }
    }

    /**
     * Revoke session (logout)
     */
    async revokeSession(sessionToken, clientInfo = {}) {
        console.log('[REVOKE_SESSION] Revoking session:', sessionToken ? sessionToken.substring(0, 8) + '...' : 'null');
        console.log('[REVOKE_SESSION] Client info:', clientInfo);

        try {
            console.log('[REVOKE_SESSION] Loading sessions...');
            const sessions = await FileManager.loadJSON(CONFIG.FILES.SESSIONS);

            if (sessions[sessionToken]) {
                console.log('[REVOKE_SESSION] Session found, removing...');
                delete sessions[sessionToken];
                await FileManager.saveJSON(CONFIG.FILES.SESSIONS, sessions);
                console.log('[REVOKE_SESSION] Session revoked successfully');
                logger.info('Session revoked successfully');
            } else {
                console.log('[REVOKE_SESSION] Session not found');
            }

            return true;
        } catch (error) {
            console.error('[REVOKE_SESSION] Failed to revoke session:', error.message);
            logger.error('Failed to revoke session', error);
            return false;
        }
    }
}

console.log('[EXPORT] Exporting OTPManager module');
module.exports = OTPManager;
