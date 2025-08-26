const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { promisify } = require('util');
const rateLimit = require('express-rate-limit');

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

// -----------------------------------------
// SECURITY UTILITIES
// -----------------------------------------

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

// -----------------------------------------
// FILE OPERATIONS
// -----------------------------------------

class FileManager {
    static async ensureDirectory(filePath) {
        const dir = path.dirname(filePath);
        try {
            await fs.promises.access(dir);
        } catch (error) {
            if (error.code === 'ENOENT') {
                await fs.promises.mkdir(dir, { recursive: true, mode: 0o755 });
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
            return false;
        }
    }
}

// -----------------------------------------
// OTP MANAGER CLASS
// -----------------------------------------

class OTPManager {
    constructor() {
        this.transporter = null;
        this.isInitialized = false;
        this.rateLimiter = new Map(); // IP -> { count, resetTime }
        this.cleanupInterval = null;
        this.initialize();
    }

    async initialize() {
        try {
            if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
                throw new Error('EMAIL_USER and EMAIL_PASS environment variables are required');
            }
            await this.createTransporter();
            this.startCleanupInterval();
            await this.verifyConnection();
            this.isInitialized = true;
        } catch (error) {
            throw error;
        }
    }

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
        if (process.env.OAUTH_CLIENT_ID && process.env.OAUTH_CLIENT_SECRET && process.env.OAUTH_REFRESH_TOKEN) {
            transporterConfig.auth = {
                type: 'OAuth2',
                user: process.env.EMAIL_USER,
                clientId: process.env.OAUTH_CLIENT_ID,
                clientSecret: process.env.OAUTH_CLIENT_SECRET,
                refreshToken: process.env.OAUTH_REFRESH_TOKEN
            };
        }
        this.transporter = nodemailer.createTransport(transporterConfig);
    }

    async verifyConnection() {
        try {
            await this.transporter.verify();
        } catch (error) {
            throw new Error('Email service connection failed');
        }
    }

    startCleanupInterval() {
        this.cleanupInterval = setInterval(() => {
            this.cleanExpired();
            this.cleanupRateLimiter();
        }, CONFIG.OTP.CLEANUP_INTERVAL);
    }

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

    cleanupRateLimiter() {
        const now = Date.now();
        for (const [identifier, data] of this.rateLimiter.entries()) {
            if (now > data.resetTime) {
                this.rateLimiter.delete(identifier);
            }
        }
    }

    generateOTP() {
        return crypto.randomInt(100000, 999999).toString();
    }

    generateSessionToken() {
        return crypto.randomBytes(CONFIG.SESSION.TOKEN_LENGTH).toString('hex');
    }

    async cleanExpired() {
        try {
            const now = new Date();
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
        } catch (error) { }
    }

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
            if (auditData.length > 10000) {
                auditData.splice(0, auditData.length - 10000);
            }
            await FileManager.saveJSON(CONFIG.FILES.AUDIT_LOG, auditData);
        } catch (error) { }
    }

    async createLoginSession(employeeId, email, clientInfo = {}) {
        try {
            const sanitizedEmployeeId = SecurityManager.sanitizeEmployeeId(employeeId);
            const sanitizedEmail = SecurityManager.sanitizeEmail(email);
            if (!sanitizedEmployeeId || !sanitizedEmail) {
                throw new Error('Invalid employee ID or email format');
            }
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
                    retryAfter: Math.ceil(CONFIG.EMAIL.RATE_LIMIT_WINDOW / 1000 / 60)
                };
            }
            await this.cleanExpired();
            const sessions = await FileManager.loadJSON(CONFIG.FILES.SESSIONS);
            const userSessions = Object.values(sessions).filter(s => s.employeeId === sanitizedEmployeeId);
            if (userSessions.length >= CONFIG.SESSION.MAX_SESSIONS_PER_USER) {
                const oldestSession = userSessions.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))[0];
                delete sessions[oldestSession.sessionToken];
            }
            const sessionToken = this.generateSessionToken();
            const otp = this.generateOTP();
            const otpHash = SecurityManager.hashOTP(otp);
            const now = new Date();
            const sessionExpiry = new Date(now.getTime() + CONFIG.SESSION.EXPIRY_MINUTES * 60 * 1000);
            const otpExpiry = new Date(now.getTime() + CONFIG.OTP.EXPIRY_MINUTES * 60 * 1000);
            sessions[sessionToken] = {
                employeeId: sanitizedEmployeeId,
                sessionToken,
                status: 'pending_otp',
                expiresAt: sessionExpiry.toISOString(),
                createdAt: now.toISOString(),
                otpVerifiedAt: null,
                clientInfo: {
                    ip: clientInfo.ip,
                    userAgent: clientInfo.userAgent?.substring(0, 200)
                }
            };
            await FileManager.saveJSON(CONFIG.FILES.SESSIONS, sessions);
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
            await this.sendEmailOTPWithRetry(sanitizedEmail, otp, sanitizedEmployeeId);
            await this.auditLog('OTP_GENERATED', sanitizedEmployeeId, {
                ...clientInfo,
                success: true,
                details: { email: sanitizedEmail }
            });
            return {
                success: true,
                sessionToken,
                message: 'OTP sent to your email address',
                expiresIn: CONFIG.OTP.EXPIRY_MINUTES
            };
        } catch (error) {
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

    async sendEmailOTPWithRetry(email, otp, employeeId, attempt = 1) {
        try {
            await this.sendEmailOTP(email, otp, employeeId);
        } catch (error) {
            if (attempt < CONFIG.EMAIL.RETRY_ATTEMPTS) {
                await new Promise(resolve => setTimeout(resolve, CONFIG.EMAIL.RETRY_DELAY * attempt));
                return this.sendEmailOTPWithRetry(email, otp, employeeId, attempt + 1);
            }
            throw error;
        }
    }

    async sendEmailOTP(email, otp, employeeId) {
        const mailOptions = {
            from: {
                name: 'IT No-Dues System',
                address: process.env.EMAIL_FROM || process.env.EMAIL_USER
            },
            to: email,
            subject: 'IT No-Dues System - Login Verification Code',
            html: `
                ...snip email HTML...
            `,
            text: `
                ...snip text body...
            `
        };
        return await this.transporter.sendMail(mailOptions);
    }

    async verifyOTP(sessionToken, inputOTP, clientInfo = {}) {
        try {
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
            otps[session.employeeId].used = true;
            sessions[sessionToken].status = 'verified';
            sessions[sessionToken].otpVerifiedAt = new Date().toISOString();
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
            return {
                success: true,
                message: 'Login successful',
                employeeId: session.employeeId,
                sessionToken
            };
        } catch (error) {
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
            const newOTP = this.generateOTP();
            const otpHash = SecurityManager.hashOTP(newOTP);
            const now = new Date();
            const otpExpiry = new Date(now.getTime() + CONFIG.OTP.EXPIRY_MINUTES * 60 * 1000);
            const userData = await FileManager.loadJSON(CONFIG.FILES.USERS);
            const userEmail = userData.email;
            if (!userEmail) {
                return {
                    success: false,
                    message: 'User email not found'
                };
            }
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
            await this.sendEmailOTPWithRetry(userEmail, newOTP, session.employeeId);
            await this.auditLog('OTP_RESEND_SUCCESS', session.employeeId, {
                ...clientInfo,
                success: true,
                details: { resendCount: otps[session.employeeId].resendCount }
            });
            return {
                success: true,
                message: 'New OTP sent to your email',
                expiresIn: CONFIG.OTP.EXPIRY_MINUTES
            };
        } catch (error) {
            return {
                success: false,
                message: 'Failed to resend OTP'
            };
        }
    }

    async isValidSession(sessionToken) {
        try {
            await this.cleanExpired();
            const sessions = await FileManager.loadJSON(CONFIG.FILES.SESSIONS);
            const session = sessions[sessionToken];
            return session &&
                session.status === 'verified' &&
                new Date() < new Date(session.expiresAt);
        } catch (error) {
            return false;
        }
    }

    async getSessionData(sessionToken) {
        try {
            const sessions = await FileManager.loadJSON(CONFIG.FILES.SESSIONS);
            const session = sessions[sessionToken];
            if (!session) return null;
            return {
                employeeId: session.employeeId,
                status: session.status,
                createdAt: session.createdAt,
                expiresAt: session.expiresAt,
                otpVerifiedAt: session.otpVerifiedAt,
                isExpired: new Date() > new Date(session.expiresAt)
            };
        } catch (error) {
            return null;
        }
    }

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
            }
            return true;
        } catch (error) {
            return false;
        }
    }

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
            return null;
        }
    }

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
            try {
                await this.transporter.verify();
                health.services.email = 'operational';
            } catch (error) {
                health.services.email = 'error';
                health.status = 'degraded';
            }
            try {
                await FileManager.loadJSON(CONFIG.FILES.SESSIONS);
                health.services.storage = 'operational';
            } catch (error) {
                health.services.storage = 'error';
                health.status = 'degraded';
            }
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

    async shutdown() {
        try {
            if (this.cleanupInterval) {
                clearInterval(this.cleanupInterval);
            }
            await this.cleanExpired();
            if (this.transporter) {
                this.transporter.close();
            }
        } catch (error) { }
    }
}

module.exports = OTPManager;
