const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { promisify } = require('util');
const rateLimit = require('express-rate-limit');

// =========================================
// PRODUCTION CONFIGURATION
// =========================================

const CONFIG = {
    OTP: {
        LENGTH: 6,
        EXPIRY_MINUTES: 5,
        MAX_ATTEMPTS: 3,
        RESEND_LIMIT: 3,
        CLEANUP_INTERVAL: 60 * 60 * 1000 // 1 hour
    },

    SESSION: {
        EXPIRY_MINUTES: 10,
        TOKEN_LENGTH: 32,
        MAX_SESSIONS_PER_USER: 3
    },

    EMAIL: {
        RATE_LIMIT_WINDOW: 15 * 60 * 1000, // 15 minutes
        RATE_LIMIT_MAX: 5, // 5 emails per window
        RETRY_ATTEMPTS: 3,
        RETRY_DELAY: 2000, // 2 seconds
        TIMEOUT: 30000 // 30 seconds
    },

    FILES: {
        OTP_DATA: path.join(__dirname, 'data', 'otp_data.json'),
        SESSIONS: path.join(__dirname, 'data', 'login_sessions.json'),
        USERS: path.join(__dirname, 'data', 'users.json'),
        AUDIT_LOG: path.join(__dirname, 'data', 'otp_audit.json')
    },

    SECURITY: {
        ENCRYPT_DATA: true,
        HASH_ALGORITHM: 'sha256',
        ENCRYPTION_ALGORITHM: 'aes-256-gcm',
        KEY_DERIVATION_ITERATIONS: 100000
    }
};

// =========================================
// PRODUCTION LOGGING SYSTEM
// =========================================

const logger = {
    info: (message, meta = {}) => console.log(`[INFO] ${new Date().toISOString()} - ${message}`, JSON.stringify(meta)),
    warn: (message, meta = {}) => console.warn(`[WARN] ${new Date().toISOString()} - ${message}`, JSON.stringify(meta)),
    error: (message, error, meta = {}) => console.error(`[ERROR] ${new Date().toISOString()} - ${message}`, error?.stack || error, JSON.stringify(meta)),
    audit: (action, userId, meta = {}) => console.log(`[AUDIT] ${new Date().toISOString()} - ${action} - User: ${userId}`, JSON.stringify(meta))
};

// =========================================
// PRODUCTION SECURITY UTILITIES
// =========================================

class SecurityManager {
    static generateSecureKey() {
        if (!this.key) {
            const keyMaterial = process.env.OTP_ENCRYPTION_KEY || crypto.randomBytes(32);
            this.key = crypto.pbkdf2Sync(keyMaterial, 'otp-salt', CONFIG.SECURITY.KEY_DERIVATION_ITERATIONS, 32, 'sha512');
        }
        return this.key;
    }

    static encryptData(data) {
        if (!CONFIG.SECURITY.ENCRYPT_DATA) return data;

        try {
            const key = this.generateSecureKey();
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipher(CONFIG.SECURITY.ENCRYPTION_ALGORITHM, key);

            let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
            encrypted += cipher.final('hex');

            const authTag = cipher.getAuthTag();

            return {
                encrypted: true,
                data: encrypted,
                iv: iv.toString('hex'),
                authTag: authTag.toString('hex')
            };
        } catch (error) {
            logger.error('Data encryption failed', error);
            return data;
        }
    }

    static decryptData(encryptedData) {
        if (!encryptedData.encrypted) return encryptedData;

        try {
            const key = this.generateSecureKey();
            const decipher = crypto.createDecipher(CONFIG.SECURITY.ENCRYPTION_ALGORITHM, key);

            decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));

            let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            return JSON.parse(decrypted);
        } catch (error) {
            logger.error('Data decryption failed', error);
            return {};
        }
    }

    static hashOTP(otp) {
        return crypto.createHash(CONFIG.SECURITY.HASH_ALGORITHM).update(otp).digest('hex');
    }

    static sanitizeEmail(email) {
        if (!email || typeof email !== 'string') return null;

        const sanitized = email.toLowerCase().trim();
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        return emailRegex.test(sanitized) ? sanitized : null;
    }

    static sanitizeEmployeeId(employeeId) {
        if (!employeeId || typeof employeeId !== 'string') return null;

        return employeeId.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
    }
}

// =========================================
// PRODUCTION FILE OPERATIONS
// =========================================

class FileManager {
    static async ensureDirectory(filePath) {
        const dir = path.dirname(filePath);

        try {
            await fs.promises.access(dir);
        } catch (error) {
            if (error.code === 'ENOENT') {
                await fs.promises.mkdir(dir, { recursive: true, mode: 0o755 });
                logger.info('Directory created', { directory: dir });
            }
        }
    }

    static async loadJSON(filePath, defaultValue = {}) {
        try {
            await this.ensureDirectory(filePath);

            if (!fs.existsSync(filePath)) {
                await fs.promises.writeFile(filePath, JSON.stringify(defaultValue, null, 2));
                return defaultValue;
            }

            const data = await fs.promises.readFile(filePath, 'utf8');
            const parsed = JSON.parse(data || JSON.stringify(defaultValue));

            return SecurityManager.decryptData(parsed);
        } catch (error) {
            logger.error(`Failed to load JSON file: ${filePath}`, error);
            return defaultValue;
        }
    }

    static async saveJSON(filePath, data) {
        try {
            await this.ensureDirectory(filePath);

            // Create backup
            if (fs.existsSync(filePath)) {
                const backupPath = `${filePath}.backup.${Date.now()}`;
                await fs.promises.copyFile(filePath, backupPath);

                // Keep only last 5 backups
                const dir = path.dirname(filePath);
                const basename = path.basename(filePath);
                const files = await fs.promises.readdir(dir);

                const backupFiles = files
                    .filter(f => f.startsWith(`${basename}.backup.`))
                    .sort()
                    .reverse();

                if (backupFiles.length > 5) {
                    for (const oldBackup of backupFiles.slice(5)) {
                        await fs.promises.unlink(path.join(dir, oldBackup));
                    }
                }
            }

            const encryptedData = SecurityManager.encryptData(data);
            await fs.promises.writeFile(filePath, JSON.stringify(encryptedData, null, 2));

            return true;
        } catch (error) {
            logger.error(`Failed to save JSON file: ${filePath}`, error);
            return false;
        }
    }
}

// =========================================
// PRODUCTION OTP MANAGER CLASS
// =========================================

class OTPManager {
    constructor() {
        this.transporter = null;
        this.isInitialized = false;
        this.rateLimiter = new Map(); // IP -> { count, resetTime }
        this.cleanupInterval = null;

        this.initialize();
    }

    /**
     * Initialize OTP Manager with enhanced security
     */
    async initialize() {
        try {
            // Validate environment variables
            if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
                throw new Error('EMAIL_USER and EMAIL_PASS environment variables are required');
            }

            // Create enhanced transporter with OAuth2 support
            await this.createTransporter();

            // Start cleanup interval
            this.startCleanupInterval();

            // Verify email connection
            await this.verifyConnection();

            this.isInitialized = true;

            logger.info('OTP Manager initialized successfully', {
                emailUser: process.env.EMAIL_USER,
                encryptionEnabled: CONFIG.SECURITY.ENCRYPT_DATA
            });

        } catch (error) {
            logger.error('OTP Manager initialization failed', error);
            throw error;
        }
    }

    /**
     * Create enhanced transporter with retry logic - FIXED: Changed createTransporter to createTransport
     */
    async createTransporter() {
        const transporterConfig = {
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            },
            tls: {
                rejectUnauthorized: false
            },
            connectionTimeout: CONFIG.EMAIL.TIMEOUT,
            greetingTimeout: CONFIG.EMAIL.TIMEOUT,
            socketTimeout: CONFIG.EMAIL.TIMEOUT
        };

        // Add OAuth2 support if configured
        if (process.env.OAUTH_CLIENT_ID && process.env.OAUTH_CLIENT_SECRET && process.env.OAUTH_REFRESH_TOKEN) {
            transporterConfig.auth = {
                type: 'OAuth2',
                user: process.env.EMAIL_USER,
                clientId: process.env.OAUTH_CLIENT_ID,
                clientSecret: process.env.OAUTH_CLIENT_SECRET,
                refreshToken: process.env.OAUTH_REFRESH_TOKEN
            };
        }

        // FIXED: Changed from createTransporter to createTransport
        this.transporter = nodemailer.createTransport(transporterConfig);
    }

    /**
     * Verify email connection
     */
    async verifyConnection() {
        try {
            await this.transporter.verify();
            logger.info('Email transporter verified successfully');
        } catch (error) {
            logger.error('Email transporter verification failed', error);
            throw new Error('Email service connection failed');
        }
    }

    /**
     * Start cleanup interval for expired data
     */
    startCleanupInterval() {
        this.cleanupInterval = setInterval(() => {
            this.cleanExpired();
            this.cleanupRateLimiter();
        }, CONFIG.OTP.CLEANUP_INTERVAL);
    }

    /**
     * Check rate limiting for email sending
     */
    checkRateLimit(identifier) {
        const now = Date.now();
        const rateLimitData = this.rateLimiter.get(identifier);

        if (!rateLimitData || now > rateLimitData.resetTime) {
            this.rateLimiter.set(identifier, {
                count: 1,
                resetTime: now + CONFIG.EMAIL.RATE_LIMIT_WINDOW
            });
            return true;
        }

        if (rateLimitData.count >= CONFIG.EMAIL.RATE_LIMIT_MAX) {
            return false;
        }

        rateLimitData.count++;
        return true;
    }

    /**
     * Clean up rate limiter data
     */
    cleanupRateLimiter() {
        const now = Date.now();
        for (const [identifier, data] of this.rateLimiter.entries()) {
            if (now > data.resetTime) {
                this.rateLimiter.delete(identifier);
            }
        }
    }

    /**
     * Generate secure OTP
     */
    generateOTP() {
        return crypto.randomInt(100000, 999999).toString();
    }

    /**
     * Generate secure session token
     */
    generateSessionToken() {
        return crypto.randomBytes(CONFIG.SESSION.TOKEN_LENGTH).toString('hex');
    }

    /**
     * Clean expired OTPs and sessions
     */
    async cleanExpired() {
        try {
            const now = new Date();

            // Clean expired OTPs
            const otps = await FileManager.loadJSON(CONFIG.FILES.OTP_DATA);
            let otpCleaned = false;

            for (const [employeeId, otpData] of Object.entries(otps)) {
                if (new Date(otpData.expiresAt) < now) {
                    delete otps[employeeId];
                    otpCleaned = true;
                }
            }

            if (otpCleaned) {
                await FileManager.saveJSON(CONFIG.FILES.OTP_DATA, otps);
            }

            // Clean expired sessions
            const sessions = await FileManager.loadJSON(CONFIG.FILES.SESSIONS);
            let sessionCleaned = false;

            for (const [token, sessionData] of Object.entries(sessions)) {
                if (new Date(sessionData.expiresAt) < now) {
                    delete sessions[token];
                    sessionCleaned = true;
                }
            }

            if (sessionCleaned) {
                await FileManager.saveJSON(CONFIG.FILES.SESSIONS, sessions);
            }

            if (otpCleaned || sessionCleaned) {
                logger.info('Expired data cleaned up', {
                    otpsRemoved: otpCleaned,
                    sessionsRemoved: sessionCleaned
                });
            }

        } catch (error) {
            logger.error('Cleanup failed', error);
        }
    }

    /**
     * Audit log for security events
     */
    async auditLog(action, employeeId, metadata = {}) {
        try {
            const auditData = await FileManager.loadJSON(CONFIG.FILES.AUDIT_LOG, []);

            auditData.push({
                timestamp: new Date().toISOString(),
                action,
                employeeId,
                ip: metadata.ip || 'unknown',
                userAgent: metadata.userAgent || 'unknown',
                success: metadata.success || false,
                details: metadata.details || {}
            });

            // Keep only last 10000 entries
            if (auditData.length > 10000) {
                auditData.splice(0, auditData.length - 10000);
            }

            await FileManager.saveJSON(CONFIG.FILES.AUDIT_LOG, auditData);

            logger.audit(action, employeeId, metadata);

        } catch (error) {
            logger.error('Audit logging failed', error);
        }
    }

    /**
     * Enhanced login session creation
     */
    async createLoginSession(employeeId, email, clientInfo = {}) {
        try {
            // Sanitize inputs
            const sanitizedEmployeeId = SecurityManager.sanitizeEmployeeId(employeeId);
            const sanitizedEmail = SecurityManager.sanitizeEmail(email);

            if (!sanitizedEmployeeId || !sanitizedEmail) {
                throw new Error('Invalid employee ID or email format');
            }

            // Check rate limiting
            const rateLimitKey = `${sanitizedEmployeeId}:${clientInfo.ip || 'unknown'}`;
            if (!this.checkRateLimit(rateLimitKey)) {
                await this.auditLog('OTP_RATE_LIMITED', sanitizedEmployeeId, {
                    ...clientInfo,
                    success: false,
                    details: { reason: 'Rate limit exceeded' }
                });

                return {
                    success: false,
                    message: 'Too many OTP requests. Please try again later.',
                    retryAfter: Math.ceil(CONFIG.EMAIL.RATE_LIMIT_WINDOW / 1000 / 60) // minutes
                };
            }

            await this.cleanExpired();

            // Check for existing sessions
            const sessions = await FileManager.loadJSON(CONFIG.FILES.SESSIONS);
            const userSessions = Object.values(sessions).filter(s => s.employeeId === sanitizedEmployeeId);

            // Limit concurrent sessions
            if (userSessions.length >= CONFIG.SESSION.MAX_SESSIONS_PER_USER) {
                // Remove oldest session
                const oldestSession = userSessions.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))[0];
                delete sessions[oldestSession.sessionToken];
            }

            const sessionToken = this.generateSessionToken();
            const otp = this.generateOTP();
            const otpHash = SecurityManager.hashOTP(otp);
            const now = new Date();
            const sessionExpiry = new Date(now.getTime() + CONFIG.SESSION.EXPIRY_MINUTES * 60 * 1000);
            const otpExpiry = new Date(now.getTime() + CONFIG.OTP.EXPIRY_MINUTES * 60 * 1000);

            // Store session
            sessions[sessionToken] = {
                employeeId: sanitizedEmployeeId,
                sessionToken,
                status: 'pending_otp',
                expiresAt: sessionExpiry.toISOString(),
                createdAt: now.toISOString(),
                otpVerifiedAt: null,
                clientInfo: {
                    ip: clientInfo.ip,
                    userAgent: clientInfo.userAgent?.substring(0, 200) // Limit length
                }
            };

            await FileManager.saveJSON(CONFIG.FILES.SESSIONS, sessions);

            // Store OTP (hashed for security)
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

            await FileManager.saveJSON(CONFIG.FILES.OTP_DATA, otps);

            // Send email with retry logic
            await this.sendEmailOTPWithRetry(sanitizedEmail, otp, sanitizedEmployeeId);

            await this.auditLog('OTP_GENERATED', sanitizedEmployeeId, {
                ...clientInfo,
                success: true,
                details: { email: sanitizedEmail }
            });

            logger.info('OTP session created successfully', {
                employeeId: sanitizedEmployeeId,
                email: sanitizedEmail,
                sessionToken: sessionToken.substring(0, 8) + '...'
            });

            return {
                success: true,
                sessionToken,
                message: 'OTP sent to your email address',
                expiresIn: CONFIG.OTP.EXPIRY_MINUTES
            };

        } catch (error) {
            logger.error('Failed to create login session', error, { employeeId, email });

            await this.auditLog('OTP_GENERATION_FAILED', employeeId, {
                ...clientInfo,
                success: false,
                details: { error: error.message }
            });

            return {
                success: false,
                message: 'Failed to send OTP. Please try again later.'
            };
        }
    }

    /**
     * Send email OTP with retry mechanism
     */
    async sendEmailOTPWithRetry(email, otp, employeeId, attempt = 1) {
        try {
            await this.sendEmailOTP(email, otp, employeeId);
        } catch (error) {
            if (attempt < CONFIG.EMAIL.RETRY_ATTEMPTS) {
                logger.warn(`Email send failed, retrying (${attempt}/${CONFIG.EMAIL.RETRY_ATTEMPTS})`, {
                    error: error.message,
                    employeeId
                });

                await new Promise(resolve => setTimeout(resolve, CONFIG.EMAIL.RETRY_DELAY * attempt));
                return this.sendEmailOTPWithRetry(email, otp, employeeId, attempt + 1);
            }

            throw error;
        }
    }

    /**
     * Enhanced email OTP sending
     */
    async sendEmailOTP(email, otp, employeeId) {
        const mailOptions = {
            from: {
                name: 'IT No-Dues System',
                address: process.env.EMAIL_FROM || process.env.EMAIL_USER
            },
            to: email,
            subject: 'IT No-Dues System - Login Verification Code',
            html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Login Verification Code</title>
        </head>
        <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f5f5f5;">
          <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
            
            <!-- Header -->
            <div style="background: linear-gradient(135deg, #2c5aa0 0%, #1e3a5f 100%); padding: 30px 20px; text-align: center;">
              <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: 600;">IT No-Dues System</h1>
              <p style="color: #e8f1ff; margin: 10px 0 0 0; font-size: 16px;">Security Verification</p>
            </div>
            
            <!-- Content -->
            <div style="padding: 40px 30px;">
              <h2 style="color: #2c3e50; margin: 0 0 20px 0; font-size: 24px; font-weight: 600;">Your Login Verification Code</h2>
              
              <p style="color: #555; font-size: 16px; line-height: 1.6; margin: 0 0 30px 0;">
                You have requested to log into the IT No-Dues System. Use the verification code below to complete your login:
              </p>
              
              <!-- OTP Box -->
              <div style="background: #f8f9fa; border: 2px solid #2c5aa0; border-radius: 8px; padding: 25px; text-align: center; margin: 30px 0;">
                <div style="font-size: 36px; font-weight: 700; color: #2c5aa0; letter-spacing: 8px; font-family: 'Courier New', monospace; margin: 0;">${otp}</div>
                <p style="color: #666; font-size: 14px; margin: 10px 0 0 0;">Enter this code on the login page</p>
              </div>
              
              <!-- Details -->
              <div style="background: #f8f9fa; border-radius: 6px; padding: 20px; margin: 30px 0;">
                <h3 style="color: #2c3e50; margin: 0 0 15px 0; font-size: 18px;">Security Details:</h3>
                <table style="width: 100%; font-size: 14px; color: #555;">
                  <tr>
                    <td style="padding: 5px 0; font-weight: 600;">Employee ID:</td>
                    <td style="padding: 5px 0;">${employeeId}</td>
                  </tr>
                  <tr>
                    <td style="padding: 5px 0; font-weight: 600;">Valid for:</td>
                    <td style="padding: 5px 0;">${CONFIG.OTP.EXPIRY_MINUTES} minutes</td>
                  </tr>
                  <tr>
                    <td style="padding: 5px 0; font-weight: 600;">Generated:</td>
                    <td style="padding: 5px 0;">${new Date().toLocaleString()}</td>
                  </tr>
                </table>
              </div>
              
              <!-- Security Warning -->
              <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 6px; padding: 15px; margin: 20px 0;">
                <p style="color: #856404; font-size: 14px; margin: 0; line-height: 1.5;">
                  <strong>Security Notice:</strong> If you did not request this login verification, please ignore this email and consider changing your account password.
                </p>
              </div>
            </div>
            
            <!-- Footer -->
            <div style="background: #f8f9fa; padding: 20px 30px; text-align: center; border-top: 1px solid #e9ecef;">
              <p style="color: #6c757d; font-size: 12px; margin: 0; line-height: 1.5;">
                This is an automated message from the IT No-Dues Clearance System.<br>
                Please do not reply to this email.
              </p>
            </div>
          </div>
        </body>
        </html>
      `,
            text: `
        IT No-Dues System - Login Verification
        
        Your verification code is: ${otp}
        
        Employee ID: ${employeeId}
        Valid for: ${CONFIG.OTP.EXPIRY_MINUTES} minutes
        Generated: ${new Date().toLocaleString()}
        
        If you did not request this login, please ignore this email.
        
        This is an automated message from IT No-Dues Clearance System.
      `
        };

        const result = await this.transporter.sendMail(mailOptions);

        logger.info('OTP email sent successfully', {
            messageId: result.messageId,
            email: email.replace(/(.{2}).*@/, '$1***@'), // Partially mask email
            employeeId
        });

        return result;
    }

    /**
     * Enhanced OTP verification with security features
     */
    async verifyOTP(sessionToken, inputOTP, clientInfo = {}) {
        try {
            // Sanitize inputs
            if (!sessionToken || !inputOTP) {
                return {
                    success: false,
                    message: 'Session token and OTP are required'
                };
            }

            const sanitizedOTP = inputOTP.replace(/\D/g, '').substring(0, CONFIG.OTP.LENGTH);
            if (sanitizedOTP.length !== CONFIG.OTP.LENGTH) {
                return {
                    success: false,
                    message: 'Invalid OTP format'
                };
            }

            await this.cleanExpired();

            // Get session
            const sessions = await FileManager.loadJSON(CONFIG.FILES.SESSIONS);
            const session = sessions[sessionToken];

            if (!session || session.status !== 'pending_otp') {
                await this.auditLog('OTP_VERIFY_INVALID_SESSION', 'unknown', {
                    ...clientInfo,
                    success: false,
                    details: { sessionToken: sessionToken.substring(0, 8) + '...' }
                });

                return {
                    success: false,
                    message: 'Invalid or expired session'
                };
            }

            // Get OTP data
            const otps = await FileManager.loadJSON(CONFIG.FILES.OTP_DATA);
            const otpData = otps[session.employeeId];

            if (!otpData) {
                await this.auditLog('OTP_VERIFY_NOT_FOUND', session.employeeId, {
                    ...clientInfo,
                    success: false
                });

                return {
                    success: false,
                    message: 'OTP not found or expired'
                };
            }

            if (otpData.used) {
                await this.auditLog('OTP_VERIFY_ALREADY_USED', session.employeeId, {
                    ...clientInfo,
                    success: false
                });

                return {
                    success: false,
                    message: 'OTP already used'
                };
            }

            if (new Date() > new Date(otpData.expiresAt)) {
                delete otps[session.employeeId];
                await FileManager.saveJSON(CONFIG.FILES.OTP_DATA, otps);

                await this.auditLog('OTP_VERIFY_EXPIRED', session.employeeId, {
                    ...clientInfo,
                    success: false
                });

                return {
                    success: false,
                    message: 'OTP expired. Please request a new one.'
                };
            }

            if (otpData.attempts >= otpData.maxAttempts) {
                await this.auditLog('OTP_VERIFY_MAX_ATTEMPTS', session.employeeId, {
                    ...clientInfo,
                    success: false,
                    details: { attempts: otpData.attempts }
                });

                return {
                    success: false,
                    message: 'Too many failed attempts. Please request a new OTP.'
                };
            }

            // Verify OTP hash
            const inputOTPHash = SecurityManager.hashOTP(sanitizedOTP);
            if (otpData.otpHash !== inputOTPHash) {
                otps[session.employeeId].attempts++;
                await FileManager.saveJSON(CONFIG.FILES.OTP_DATA, otps);

                const remainingAttempts = otpData.maxAttempts - otps[session.employeeId].attempts;

                await this.auditLog('OTP_VERIFY_FAILED', session.employeeId, {
                    ...clientInfo,
                    success: false,
                    details: {
                        attempts: otps[session.employeeId].attempts,
                        remaining: remainingAttempts
                    }
                });

                return {
                    success: false,
                    message: `Invalid OTP. ${remainingAttempts} attempts remaining.`
                };
            }

            // Success - mark OTP as used and activate session
            otps[session.employeeId].used = true;
            sessions[sessionToken].status = 'verified';
            sessions[sessionToken].otpVerifiedAt = new Date().toISOString();

            // Update user data
            const userData = await FileManager.loadJSON(CONFIG.FILES.USERS);
            if (userData && userData.employeeId === session.employeeId) {
                userData.lastLogin = new Date().toISOString();
                userData.emailVerified = true;
                userData.failedOtpAttempts = 0;
                await FileManager.saveJSON(CONFIG.FILES.USERS, userData);
            }

            await FileManager.saveJSON(CONFIG.FILES.OTP_DATA, otps);
            await FileManager.saveJSON(CONFIG.FILES.SESSIONS, sessions);

            await this.auditLog('OTP_VERIFY_SUCCESS', session.employeeId, {
                ...clientInfo,
                success: true,
                details: { sessionToken: sessionToken.substring(0, 8) + '...' }
            });

            logger.info('OTP verification successful', {
                employeeId: session.employeeId,
                sessionToken: sessionToken.substring(0, 8) + '...'
            });

            return {
                success: true,
                message: 'Login successful',
                employeeId: session.employeeId,
                sessionToken
            };

        } catch (error) {
            logger.error('OTP verification failed', error);

            await this.auditLog('OTP_VERIFY_ERROR', 'unknown', {
                ...clientInfo,
                success: false,
                details: { error: error.message }
            });

            return {
                success: false,
                message: 'Verification failed. Please try again.'
            };
        }
    }

    /**
     * Enhanced OTP resend with improved rate limiting
     */
    async resendOTP(sessionToken, clientInfo = {}) {
        try {
            if (!sessionToken) {
                return {
                    success: false,
                    message: 'Session token is required'
                };
            }

            const sessions = await FileManager.loadJSON(CONFIG.FILES.SESSIONS);
            const session = sessions[sessionToken];

            if (!session || session.status !== 'pending_otp') {
                return {
                    success: false,
                    message: 'Invalid session'
                };
            }

            // Check rate limiting for resends
            const rateLimitKey = `resend:${session.employeeId}:${clientInfo.ip || 'unknown'}`;
            if (!this.checkRateLimit(rateLimitKey)) {
                await this.auditLog('OTP_RESEND_RATE_LIMITED', session.employeeId, {
                    ...clientInfo,
                    success: false
                });

                return {
                    success: false,
                    message: 'Too many resend requests. Please wait before trying again.'
                };
            }

            const otps = await FileManager.loadJSON(CONFIG.FILES.OTP_DATA);
            const otpData = otps[session.employeeId];

            if (otpData && otpData.attempts >= CONFIG.OTP.RESEND_LIMIT) {
                await this.auditLog('OTP_RESEND_LIMIT_EXCEEDED', session.employeeId, {
                    ...clientInfo,
                    success: false
                });

                return {
                    success: false,
                    message: 'Too many OTP requests. Please try logging in again.'
                };
            }

            // Generate new OTP
            const newOTP = this.generateOTP();
            const otpHash = SecurityManager.hashOTP(newOTP);
            const now = new Date();
            const otpExpiry = new Date(now.getTime() + CONFIG.OTP.EXPIRY_MINUTES * 60 * 1000);

            // Get user email
            const userData = await FileManager.loadJSON(CONFIG.FILES.USERS);
            const userEmail = userData.email;

            if (!userEmail) {
                return {
                    success: false,
                    message: 'User email not found'
                };
            }

            // Update OTP
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

            await FileManager.saveJSON(CONFIG.FILES.OTP_DATA, otps);

            // Send new OTP
            await this.sendEmailOTPWithRetry(userEmail, newOTP, session.employeeId);

            await this.auditLog('OTP_RESEND_SUCCESS', session.employeeId, {
                ...clientInfo,
                success: true,
                details: { resendCount: otps[session.employeeId].resendCount }
            });

            logger.info('OTP resent successfully', {
                employeeId: session.employeeId,
                resendCount: otps[session.employeeId].resendCount
            });

            return {
                success: true,
                message: 'New OTP sent to your email',
                expiresIn: CONFIG.OTP.EXPIRY_MINUTES
            };

        } catch (error) {
            logger.error('OTP resend failed', error);
            return {
                success: false,
                message: 'Failed to resend OTP'
            };
        }
    }

    /**
     * Enhanced session validation
     */
    async isValidSession(sessionToken) {
        try {
            await this.cleanExpired();

            const sessions = await FileManager.loadJSON(CONFIG.FILES.SESSIONS);
            const session = sessions[sessionToken];

            return session &&
                session.status === 'verified' &&
                new Date() < new Date(session.expiresAt);
        } catch (error) {
            logger.error('Session validation failed', error);
            return false;
        }
    }

    /**
     * Get enhanced session data
     */
    async getSessionData(sessionToken) {
        try {
            const sessions = await FileManager.loadJSON(CONFIG.FILES.SESSIONS);
            const session = sessions[sessionToken];

            if (!session) return null;

            // Return sanitized session data
            return {
                employeeId: session.employeeId,
                status: session.status,
                createdAt: session.createdAt,
                expiresAt: session.expiresAt,
                otpVerifiedAt: session.otpVerifiedAt,
                isExpired: new Date() > new Date(session.expiresAt)
            };
        } catch (error) {
            logger.error('Failed to get session data', error);
            return null;
        }
    }

    /**
     * Revoke session (logout)
     */
    async revokeSession(sessionToken, clientInfo = {}) {
        try {
            const sessions = await FileManager.loadJSON(CONFIG.FILES.SESSIONS);
            const session = sessions[sessionToken];

            if (session) {
                await this.auditLog('SESSION_REVOKED', session.employeeId, {
                    ...clientInfo,
                    success: true,
                    details: { sessionToken: sessionToken.substring(0, 8) + '...' }
                });

                delete sessions[sessionToken];
                await FileManager.saveJSON(CONFIG.FILES.SESSIONS, sessions);

                logger.info('Session revoked successfully', {
                    employeeId: session.employeeId,
                    sessionToken: sessionToken.substring(0, 8) + '...'
                });
            }

            return true;
        } catch (error) {
            logger.error('Failed to revoke session', error);
            return false;
        }
    }

    /**
     * Get system statistics
     */
    async getSystemStats() {
        try {
            const sessions = await FileManager.loadJSON(CONFIG.FILES.SESSIONS);
            const otps = await FileManager.loadJSON(CONFIG.FILES.OTP_DATA);
            const auditData = await FileManager.loadJSON(CONFIG.FILES.AUDIT_LOG, []);

            const now = new Date();
            const activeSessions = Object.values(sessions).filter(s =>
                s.status === 'verified' && new Date(s.expiresAt) > now
            );

            const pendingSessions = Object.values(sessions).filter(s =>
                s.status === 'pending_otp' && new Date(s.expiresAt) > now
            );

            const activeOTPs = Object.values(otps).filter(o =>
                !o.used && new Date(o.expiresAt) > now
            );

            // Recent activity (last 24 hours)
            const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
            const recentActivity = auditData.filter(a => new Date(a.timestamp) > yesterday);

            return {
                sessions: {
                    active: activeSessions.length,
                    pending: pendingSessions.length,
                    total: Object.keys(sessions).length
                },
                otps: {
                    active: activeOTPs.length,
                    total: Object.keys(otps).length
                },
                recentActivity: {
                    total: recentActivity.length,
                    successful: recentActivity.filter(a => a.success).length,
                    failed: recentActivity.filter(a => !a.success).length
                },
                rateLimiter: {
                    activeEntries: this.rateLimiter.size
                },
                system: {
                    uptime: process.uptime(),
                    memoryUsage: process.memoryUsage(),
                    isInitialized: this.isInitialized
                }
            };
        } catch (error) {
            logger.error('Failed to get system stats', error);
            return null;
        }
    }

    /**
     * Health check
     */
    async healthCheck() {
        try {
            const health = {
                status: 'healthy',
                timestamp: new Date().toISOString(),
                services: {
                    email: 'unknown',
                    storage: 'unknown',
                    encryption: 'unknown'
                }
            };

            // Test email service
            try {
                await this.transporter.verify();
                health.services.email = 'operational';
            } catch (error) {
                health.services.email = 'error';
                health.status = 'degraded';
            }

            // Test file storage
            try {
                await FileManager.loadJSON(CONFIG.FILES.SESSIONS);
                health.services.storage = 'operational';
            } catch (error) {
                health.services.storage = 'error';
                health.status = 'degraded';
            }

            // Test encryption
            try {
                const testData = { test: 'data' };
                const encrypted = SecurityManager.encryptData(testData);
                const decrypted = SecurityManager.decryptData(encrypted);
                health.services.encryption = decrypted.test === 'data' ? 'operational' : 'error';
            } catch (error) {
                health.services.encryption = 'error';
                health.status = 'degraded';
            }

            return health;
        } catch (error) {
            return {
                status: 'unhealthy',
                timestamp: new Date().toISOString(),
                error: error.message
            };
        }
    }

    /**
     * Graceful shutdown
     */
    async shutdown() {
        try {
            if (this.cleanupInterval) {
                clearInterval(this.cleanupInterval);
            }

            await this.cleanExpired();

            if (this.transporter) {
                this.transporter.close();
            }

            logger.info('OTP Manager shutdown completed');
        } catch (error) {
            logger.error('Error during shutdown', error);
        }
    }
}

module.exports = OTPManager;
