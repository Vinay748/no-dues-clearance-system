const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { loadJSON, saveJSON } = require('./fileUtils');

// =========================================
// PRODUCTION CONFIGURATION
// =========================================

const CONFIG = {
  // WebSocket server settings
  WS: {
    PORT: process.env.WS_PORT || 8081,
    MAX_CONNECTIONS: 1000,
    HEARTBEAT_INTERVAL: 30000, // 30 seconds
    CONNECTION_TIMEOUT: 60000, // 60 seconds
    MESSAGE_SIZE_LIMIT: 10 * 1024, // 10KB per message
    RATE_LIMIT_WINDOW: 60 * 1000, // 1 minute
    RATE_LIMIT_MAX_MESSAGES: 60 // 60 messages per minute per client
  },

  // Security settings
  SECURITY: {
    JWT_SECRET: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
    JWT_EXPIRY: '24h',
    ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS ?
      process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'],
    ENABLE_ORIGIN_CHECK: process.env.NODE_ENV === 'production',
    ENABLE_TLS: process.env.NODE_ENV === 'production',
    TLS_CERT_PATH: process.env.TLS_CERT_PATH || './certs/cert.pem',
    TLS_KEY_PATH: process.env.TLS_KEY_PATH || './certs/key.pem'
  },

  // File paths
  FILES: {
    NOTIFICATIONS_LOG: './data/notifications.json',
    EMPLOYEE_SESSIONS: './data/employee_sessions.json',
    CONNECTION_LOG: './data/ws_connections.json'
  },

  // Performance settings
  PERFORMANCE: {
    CLEANUP_INTERVAL: 60 * 60 * 1000, // 1 hour
    MAX_QUEUE_SIZE: 10000,
    MAX_NOTIFICATION_HISTORY: 1000,
    COMPRESSION_THRESHOLD: 1024 // Compress messages > 1KB
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
  static validateOrigin(origin) {
    if (!CONFIG.SECURITY.ENABLE_ORIGIN_CHECK) return true;

    return CONFIG.SECURITY.ALLOWED_ORIGINS.includes(origin);
  }

  static generateJWT(payload) {
    return jwt.sign(payload, CONFIG.SECURITY.JWT_SECRET, {
      expiresIn: CONFIG.SECURITY.JWT_EXPIRY,
      issuer: 'notification-system',
      audience: 'employees'
    });
  }

  static verifyJWT(token) {
    try {
      return jwt.verify(token, CONFIG.SECURITY.JWT_SECRET);
    } catch (error) {
      logger.warn('JWT verification failed', { error: error.message });
      return null;
    }
  }

  static sanitizeMessage(message) {
    if (typeof message !== 'object') return message;

    const sanitized = JSON.parse(JSON.stringify(message));

    // Remove potentially dangerous properties
    delete sanitized.__proto__;
    delete sanitized.constructor;

    // Limit string lengths
    Object.keys(sanitized).forEach(key => {
      if (typeof sanitized[key] === 'string' && sanitized[key].length > 1000) {
        sanitized[key] = sanitized[key].substring(0, 1000) + '...';
      }
    });

    return sanitized;
  }

  static generateSecureId() {
    return crypto.randomBytes(16).toString('hex');
  }
}

// =========================================
// PRODUCTION RATE LIMITING
// =========================================

class RateLimiter {
  constructor() {
    this.clients = new Map(); // clientId -> { count, resetTime }
  }

  checkLimit(clientId) {
    const now = Date.now();
    const client = this.clients.get(clientId);

    if (!client || now > client.resetTime) {
      // Reset or initialize
      this.clients.set(clientId, {
        count: 1,
        resetTime: now + CONFIG.WS.RATE_LIMIT_WINDOW
      });
      return true;
    }

    if (client.count >= CONFIG.WS.RATE_LIMIT_MAX_MESSAGES) {
      return false;
    }

    client.count++;
    return true;
  }

  cleanup() {
    const now = Date.now();
    for (const [clientId, client] of this.clients.entries()) {
      if (now > client.resetTime) {
        this.clients.delete(clientId);
      }
    }
  }
}

// =========================================
// ENHANCED NOTIFICATION MANAGER
// =========================================

/**
 * Production-ready Real-time Notification Manager
 * Enhanced with security, performance, and reliability features
 */
class NotificationManager {
  constructor() {
    this.wsServer = null;
    this.connectedClients = new Map(); // employeeId -> { ws, metadata }
    this.notificationQueue = [];
    this.isInitialized = false;
    this.rateLimiter = new RateLimiter();
    this.connectionCount = 0;
    this.messageCount = 0;
    this.errorCount = 0;
  }

  /**
   * Initialize WebSocket server with production security
   * @param {object} options - Configuration options
   */
  initializeWebSocket(options = {}) {
    try {
      const wsOptions = {
        port: options.port || CONFIG.WS.PORT,
        maxPayload: CONFIG.WS.MESSAGE_SIZE_LIMIT,
        perMessageDeflate: {
          threshold: CONFIG.PERFORMANCE.COMPRESSION_THRESHOLD
        }
      };

      // Add TLS support for production
      if (CONFIG.SECURITY.ENABLE_TLS) {
        try {
          const https = require('https');
          const server = https.createServer({
            cert: fs.readFileSync(CONFIG.SECURITY.TLS_CERT_PATH),
            key: fs.readFileSync(CONFIG.SECURITY.TLS_KEY_PATH)
          });
          wsOptions.server = server;
          server.listen(wsOptions.port);
          delete wsOptions.port;
        } catch (tlsError) {
          logger.warn('TLS setup failed, falling back to non-secure WebSocket', {
            error: tlsError.message
          });
        }
      }

      this.wsServer = new WebSocket.Server(wsOptions);

      this.wsServer.on('connection', (ws, req) => {
        this.handleConnection(ws, req);
      });

      this.wsServer.on('error', (error) => {
        logger.error('WebSocket server error', error);
        this.errorCount++;
      });

      // Start maintenance tasks
      this.startMaintenanceTasks();

      const protocol = CONFIG.SECURITY.ENABLE_TLS ? 'wss' : 'ws';
      logger.info(`WebSocket notification server started`, {
        protocol,
        port: options.port || CONFIG.WS.PORT,
        maxConnections: CONFIG.WS.MAX_CONNECTIONS
      });

      this.isInitialized = true;

    } catch (error) {
      logger.error('Failed to initialize WebSocket server', error);
      throw error;
    }
  }

  /**
   * Handle new WebSocket connection with security checks
   * @param {WebSocket} ws - WebSocket connection
   * @param {object} req - HTTP request object
   */
  handleConnection(ws, req) {
    try {
      // Check connection limit
      if (this.connectionCount >= CONFIG.WS.MAX_CONNECTIONS) {
        logger.warn('Connection rejected: Max connections reached');
        ws.close(1008, 'Server at capacity');
        return;
      }

      // Validate origin
      const origin = req.headers.origin;
      if (!SecurityManager.validateOrigin(origin)) {
        logger.warn('Connection rejected: Invalid origin', { origin });
        ws.close(1008, 'Invalid origin');
        return;
      }

      const connectionId = SecurityManager.generateSecureId();
      const clientInfo = {
        connectionId,
        ip: req.socket.remoteAddress,
        userAgent: req.headers['user-agent'],
        origin,
        connectedAt: new Date().toISOString(),
        authenticated: false,
        employeeId: null,
        messageCount: 0,
        lastActivity: Date.now()
      };

      // Set connection timeout
      const timeout = setTimeout(() => {
        if (!clientInfo.authenticated) {
          logger.warn('Connection closed: Authentication timeout', { connectionId });
          ws.close(1000, 'Authentication timeout');
        }
      }, CONFIG.WS.CONNECTION_TIMEOUT);

      ws.connectionId = connectionId;
      ws.clientInfo = clientInfo;

      // Handle messages
      ws.on('message', (data) => {
        clearTimeout(timeout);
        this.handleMessage(ws, data);
      });

      // Handle connection close
      ws.on('close', (code, reason) => {
        this.handleDisconnection(ws, code, reason);
      });

      // Handle errors
      ws.on('error', (error) => {
        logger.error('WebSocket connection error', error, {
          connectionId,
          employeeId: clientInfo.employeeId
        });
        this.errorCount++;
      });

      // Start heartbeat
      this.setupHeartbeat(ws);

      this.connectionCount++;
      logger.info('New WebSocket connection established', {
        connectionId,
        origin,
        totalConnections: this.connectionCount
      });

    } catch (error) {
      logger.error('Error handling WebSocket connection', error);
      ws.close(1011, 'Internal server error');
    }
  }

  /**
   * Handle incoming WebSocket messages with security validation
   * @param {WebSocket} ws - WebSocket connection
   * @param {Buffer} data - Message data
   */
  handleMessage(ws, data) {
    try {
      // Rate limiting
      if (!this.rateLimiter.checkLimit(ws.connectionId)) {
        logger.warn('Message rejected: Rate limit exceeded', {
          connectionId: ws.connectionId
        });
        ws.send(JSON.stringify({
          type: 'error',
          message: 'Rate limit exceeded'
        }));
        return;
      }

      // Parse and validate message
      let message;
      try {
        message = JSON.parse(data.toString());
      } catch (parseError) {
        logger.warn('Invalid JSON message received', {
          connectionId: ws.connectionId,
          error: parseError.message
        });
        return;
      }

      // Sanitize message
      message = SecurityManager.sanitizeMessage(message);

      // Update activity
      ws.clientInfo.lastActivity = Date.now();
      ws.clientInfo.messageCount++;
      this.messageCount++;

      // Handle different message types
      switch (message.type) {
        case 'identify':
          this.handleIdentification(ws, message);
          break;

        case 'ping':
          this.handlePing(ws, message);
          break;

        case 'subscribe':
          this.handleSubscription(ws, message);
          break;

        default:
          logger.warn('Unknown message type received', {
            type: message.type,
            connectionId: ws.connectionId
          });
      }

    } catch (error) {
      logger.error('Error handling WebSocket message', error, {
        connectionId: ws.connectionId
      });
    }
  }

  /**
   * Handle client identification with JWT authentication
   * @param {WebSocket} ws - WebSocket connection
   * @param {object} message - Identification message
   */
  handleIdentification(ws, message) {
    try {
      const { employeeId, token } = message;

      if (!employeeId || !token) {
        ws.send(JSON.stringify({
          type: 'error',
          message: 'Employee ID and token required'
        }));
        return;
      }

      // Verify JWT token
      const payload = SecurityManager.verifyJWT(token);
      if (!payload || payload.employeeId !== employeeId) {
        logger.warn('Authentication failed', {
          employeeId,
          connectionId: ws.connectionId
        });
        ws.close(1008, 'Invalid authentication');
        return;
      }

      // Check if employee is already connected
      if (this.connectedClients.has(employeeId)) {
        const existingClient = this.connectedClients.get(employeeId);
        logger.info('Employee reconnecting, closing previous connection', {
          employeeId
        });
        existingClient.ws.close(1000, 'New connection established');
      }

      // Register authenticated connection
      ws.clientInfo.authenticated = true;
      ws.clientInfo.employeeId = employeeId;

      this.connectedClients.set(employeeId, {
        ws,
        metadata: ws.clientInfo
      });

      logger.audit('EMPLOYEE_CONNECTED', employeeId, {
        connectionId: ws.connectionId,
        ip: ws.clientInfo.ip
      });

      // Send confirmation
      ws.send(JSON.stringify({
        type: 'authenticated',
        employeeId,
        timestamp: new Date().toISOString()
      }));

      // Send queued notifications
      this.sendQueuedNotifications(employeeId);

    } catch (error) {
      logger.error('Error handling identification', error, {
        connectionId: ws.connectionId
      });
    }
  }

  /**
   * Handle ping messages for heartbeat
   * @param {WebSocket} ws - WebSocket connection
   * @param {object} message - Ping message
   */
  handlePing(ws, message) {
    ws.send(JSON.stringify({
      type: 'pong',
      timestamp: new Date().toISOString()
    }));
  }

  /**
   * Handle subscription to notification types
   * @param {WebSocket} ws - WebSocket connection
   * @param {object} message - Subscription message
   */
  handleSubscription(ws, message) {
    if (!ws.clientInfo.authenticated) {
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Authentication required'
      }));
      return;
    }

    const { notificationTypes } = message;
    if (Array.isArray(notificationTypes)) {
      ws.clientInfo.subscriptions = notificationTypes;

      ws.send(JSON.stringify({
        type: 'subscription_confirmed',
        subscriptions: notificationTypes
      }));
    }
  }

  /**
   * Handle client disconnection
   * @param {WebSocket} ws - WebSocket connection
   * @param {number} code - Close code
   * @param {string} reason - Close reason
   */
  handleDisconnection(ws, code, reason) {
    const { employeeId, connectionId } = ws.clientInfo || {};

    if (employeeId) {
      this.connectedClients.delete(employeeId);
      logger.audit('EMPLOYEE_DISCONNECTED', employeeId, {
        connectionId,
        code,
        reason: reason.toString()
      });
    }

    this.connectionCount--;
    logger.info('WebSocket connection closed', {
      connectionId,
      employeeId,
      code,
      reason: reason.toString(),
      remainingConnections: this.connectionCount
    });
  }

  /**
   * Setup heartbeat mechanism
   * @param {WebSocket} ws - WebSocket connection
   */
  setupHeartbeat(ws) {
    ws.isAlive = true;

    ws.on('pong', () => {
      ws.isAlive = true;
    });

    const heartbeat = setInterval(() => {
      if (!ws.isAlive) {
        logger.info('Heartbeat failed, terminating connection', {
          connectionId: ws.connectionId
        });
        ws.terminate();
        clearInterval(heartbeat);
        return;
      }

      ws.isAlive = false;
      ws.ping();
    }, CONFIG.WS.HEARTBEAT_INTERVAL);

    ws.on('close', () => {
      clearInterval(heartbeat);
    });
  }

  /**
   * Start maintenance tasks
   */
  startMaintenanceTasks() {
    // Cleanup expired notifications and rate limits
    setInterval(() => {
      this.cleanupExpiredNotifications();
      this.rateLimiter.cleanup();
    }, CONFIG.PERFORMANCE.CLEANUP_INTERVAL);

    // Log statistics
    setInterval(() => {
      this.logStatistics();
    }, 5 * 60 * 1000); // Every 5 minutes
  }

  /**
   * Log system statistics
   */
  logStatistics() {
    const stats = {
      connectedClients: this.connectionCount,
      queuedNotifications: this.notificationQueue.length,
      totalMessages: this.messageCount,
      totalErrors: this.errorCount,
      memoryUsage: process.memoryUsage()
    };

    logger.info('WebSocket server statistics', stats);
  }

  /**
   * Send queued notifications to newly connected employee
   * @param {string} employeeId 
   */
  sendQueuedNotifications(employeeId) {
    const queuedNotifications = this.notificationQueue.filter(n => n.employeeId === employeeId);

    queuedNotifications.forEach(notification => {
      this.sendRealTimeNotification(employeeId, notification);
    });

    // Remove sent notifications from queue
    this.notificationQueue = this.notificationQueue.filter(n => n.employeeId !== employeeId);

    if (queuedNotifications.length > 0) {
      logger.info('Queued notifications sent', {
        employeeId,
        count: queuedNotifications.length
      });
    }
  }

  /**
   * Enhanced notification methods with security and validation
   */

  static notifyFormRejection(employeeId, formId, reason, options = {}) {
    const instance = NotificationManager.getInstance();

    const notificationData = {
      id: SecurityManager.generateSecureId(),
      type: 'form_rejection',
      employeeId,
      formId,
      reason: reason.substring(0, 500), // Limit reason length
      timestamp: new Date().toISOString(),
      priority: 'high',
      title: 'Application Rejected',
      message: `Your application ${formId} has been rejected.`,
      details: {
        rejectionReason: reason.substring(0, 500),
        actionRequired: 'Submit new application',
        redirectUrl: '/employee.html'
      },
      ...options
    };

    logger.audit('NOTIFICATION_FORM_REJECTION', employeeId, {
      formId,
      reason: reason.substring(0, 100)
    });

    instance.sendMultiChannelNotification(notificationData);
    instance.logNotification(notificationData);

    return notificationData;
  }

  static notifyFormApproval(employeeId, formId, approvedBy, options = {}) {
    const instance = NotificationManager.getInstance();

    const notificationData = {
      id: SecurityManager.generateSecureId(),
      type: 'form_approval',
      employeeId,
      formId,
      approvedBy,
      timestamp: new Date().toISOString(),
      priority: 'medium',
      title: 'Application Approved',
      message: `Your application ${formId} has been approved by ${approvedBy}.`,
      details: {
        nextStep: 'Forwarded to IT department',
        estimatedCompletion: '2-3 business days'
      },
      ...options
    };

    logger.audit('NOTIFICATION_FORM_APPROVAL', employeeId, {
      formId,
      approvedBy
    });

    instance.sendMultiChannelNotification(notificationData);
    instance.logNotification(notificationData);

    return notificationData;
  }

  static notifyCertificatesReady(employeeId, formId, certificates, options = {}) {
    const instance = NotificationManager.getInstance();

    const notificationData = {
      id: SecurityManager.generateSecureId(),
      type: 'certificates_ready',
      employeeId,
      formId,
      certificates: certificates.map(cert => ({
        formType: cert.formType,
        filename: cert.filename,
        generatedAt: cert.generatedAt
      })),
      timestamp: new Date().toISOString(),
      priority: 'high',
      title: 'Certificates Ready',
      message: 'Your IT clearance certificates are ready for download!',
      details: {
        certificateCount: certificates.length,
        downloadUrl: '/certificates.html',
        validUntil: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
      },
      ...options
    };

    logger.audit('NOTIFICATION_CERTIFICATES_READY', employeeId, {
      formId,
      certificateCount: certificates.length
    });

    instance.sendMultiChannelNotification(notificationData);
    instance.logNotification(notificationData);

    return notificationData;
  }

  /**
   * Send notification via multiple channels with error handling
   * @param {object} notificationData 
   */
  sendMultiChannelNotification(notificationData) {
    try {
      // Validate notification data
      if (!notificationData.employeeId || !notificationData.type) {
        throw new Error('Invalid notification data: missing required fields');
      }

      // 1. Real-time WebSocket notification
      this.sendRealTimeNotification(notificationData.employeeId, notificationData);

      // 2. Browser notification (if client supports)
      this.sendBrowserNotification(notificationData.employeeId, notificationData);

      // 3. Future: Email notification
      // this.sendEmailNotification(notificationData);

      // 4. Future: SMS notification
      // this.sendSMSNotification(notificationData);

    } catch (error) {
      logger.error('Error sending multi-channel notification', error, {
        employeeId: notificationData.employeeId,
        type: notificationData.type
      });
    }
  }

  /**
   * Send real-time WebSocket notification with enhanced error handling
   * @param {string} employeeId 
   * @param {object} notificationData 
   */
  sendRealTimeNotification(employeeId, notificationData) {
    const clientInfo = this.connectedClients.get(employeeId);

    if (clientInfo && clientInfo.ws.readyState === WebSocket.OPEN) {
      try {
        // Check subscription filters
        if (clientInfo.metadata.subscriptions) {
          if (!clientInfo.metadata.subscriptions.includes(notificationData.type)) {
            return false; // Client not subscribed to this notification type
          }
        }

        const message = JSON.stringify({
          type: 'notification',
          ...SecurityManager.sanitizeMessage(notificationData)
        });

        clientInfo.ws.send(message);

        logger.info('Real-time notification sent', {
          employeeId,
          notificationType: notificationData.type,
          notificationId: notificationData.id
        });

        return true;
      } catch (error) {
        logger.error('Failed to send real-time notification', error, {
          employeeId,
          notificationType: notificationData.type
        });

        this.queueNotification(notificationData);
        return false;
      }
    } else {
      logger.info('Employee not connected, queuing notification', {
        employeeId,
        notificationType: notificationData.type
      });

      this.queueNotification(notificationData);
      return false;
    }
  }

  /**
   * Send browser notification with enhanced security
   * @param {string} employeeId 
   * @param {object} notificationData 
   */
  sendBrowserNotification(employeeId, notificationData) {
    const clientInfo = this.connectedClients.get(employeeId);

    if (clientInfo && clientInfo.ws.readyState === WebSocket.OPEN) {
      try {
        const browserNotification = {
          type: 'browser_notification',
          title: notificationData.title.substring(0, 100), // Limit title length
          body: notificationData.message.substring(0, 300), // Limit body length
          icon: this.getNotificationIcon(notificationData.type),
          badge: '/images/notification-badge.png',
          tag: notificationData.type,
          requireInteraction: notificationData.priority === 'high',
          actions: this.getNotificationActions(notificationData.type),
          data: {
            formId: notificationData.formId,
            redirectUrl: notificationData.details?.redirectUrl,
            notificationId: notificationData.id
          }
        };

        clientInfo.ws.send(JSON.stringify(browserNotification));

        logger.info('Browser notification sent', {
          employeeId,
          notificationType: notificationData.type
        });

        return true;
      } catch (error) {
        logger.error('Failed to send browser notification', error, {
          employeeId,
          notificationType: notificationData.type
        });
        return false;
      }
    }

    return false;
  }

  /**
   * Queue notification with size limits
   * @param {object} notificationData 
   */
  queueNotification(notificationData) {
    // Check queue size limit
    if (this.notificationQueue.length >= CONFIG.PERFORMANCE.MAX_QUEUE_SIZE) {
      // Remove oldest notifications
      const removeCount = Math.floor(CONFIG.PERFORMANCE.MAX_QUEUE_SIZE * 0.1); // Remove 10%
      this.notificationQueue.splice(0, removeCount);

      logger.warn('Notification queue overflow, removed old notifications', {
        removedCount: removeCount
      });
    }

    // Add expiry time (24 hours)
    notificationData.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    this.notificationQueue.push(notificationData);

    logger.info('Notification queued', {
      employeeId: notificationData.employeeId,
      notificationType: notificationData.type,
      queueSize: this.notificationQueue.length
    });
  }

  /**
   * Get notification icon with validation
   * @param {string} type 
   */
  getNotificationIcon(type) {
    const icons = {
      'form_rejection': '/images/rejection-icon.png',
      'form_approval': '/images/approval-icon.png',
      'certificates_ready': '/images/certificate-icon.png',
      'form_assigned': '/images/form-icon.png',
      'it_announcement': '/images/announcement-icon.png'
    };

    return icons[type] || '/images/default-notification-icon.png';
  }

  /**
   * Get notification actions with validation
   * @param {string} type 
   */
  getNotificationActions(type) {
    const actions = {
      'form_rejection': [
        { action: 'submit_new', title: 'Submit New Application' },
        { action: 'view_details', title: 'View Details' }
      ],
      'form_approval': [
        { action: 'track_progress', title: 'Track Progress' },
        { action: 'view_details', title: 'View Details' }
      ],
      'certificates_ready': [
        { action: 'download_certificates', title: 'Download Now' },
        { action: 'view_certificates', title: 'View All' }
      ],
      'it_announcement': [
        { action: 'view_announcement', title: 'View' }
      ]
    };

    return actions[type] || [{ action: 'view', title: 'View' }];
  }

  /**
   * Enhanced notification logging with security
   * @param {object} notificationData 
   */
  logNotification(notificationData) {
    try {
      let notifications = [];

      try {
        notifications = loadJSON(CONFIG.FILES.NOTIFICATIONS_LOG);
        if (!Array.isArray(notifications)) notifications = [];
      } catch (error) {
        notifications = [];
      }

      const logEntry = {
        id: notificationData.id,
        employeeId: notificationData.employeeId,
        type: notificationData.type,
        title: notificationData.title,
        message: notificationData.message,
        priority: notificationData.priority,
        timestamp: notificationData.timestamp,
        loggedAt: new Date().toISOString(),
        formId: notificationData.formId,
        // Don't log sensitive details
        metadata: {
          ip: this.connectedClients.get(notificationData.employeeId)?.metadata?.ip,
          userAgent: this.connectedClients.get(notificationData.employeeId)?.metadata?.userAgent?.substring(0, 100)
        }
      };

      notifications.push(logEntry);

      // Keep only recent notifications
      if (notifications.length > CONFIG.PERFORMANCE.MAX_NOTIFICATION_HISTORY) {
        notifications = notifications.slice(-CONFIG.PERFORMANCE.MAX_NOTIFICATION_HISTORY);
      }

      saveJSON(CONFIG.FILES.NOTIFICATIONS_LOG, notifications);

      logger.info('Notification logged', {
        employeeId: notificationData.employeeId,
        notificationId: notificationData.id
      });

    } catch (error) {
      logger.error('Failed to log notification', error, {
        employeeId: notificationData.employeeId,
        notificationType: notificationData.type
      });
    }
  }

  /**
   * Generate unique notification ID with timestamp
   */
  generateNotificationId() {
    return 'NOTIF_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');
  }

  /**
   * Get notification history with security filtering
   * @param {string} employeeId 
   * @param {number} limit 
   */
  getNotificationHistory(employeeId, limit = 50) {
    try {
      const notifications = loadJSON(CONFIG.FILES.NOTIFICATIONS_LOG) || [];

      return notifications
        .filter(n => n.employeeId === employeeId)
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, Math.min(limit, 100)) // Max 100 notifications
        .map(n => ({
          // Return only safe fields
          id: n.id,
          type: n.type,
          title: n.title,
          message: n.message,
          priority: n.priority,
          timestamp: n.timestamp,
          formId: n.formId
        }));

    } catch (error) {
      logger.error('Failed to get notification history', error, { employeeId });
      return [];
    }
  }

  /**
   * Clean up expired notifications with performance optimization
   */
  cleanupExpiredNotifications() {
    const now = new Date();
    const initialLength = this.notificationQueue.length;

    this.notificationQueue = this.notificationQueue.filter(notification => {
      if (notification.expiresAt) {
        return new Date(notification.expiresAt) > now;
      }
      return true;
    });

    const removedCount = initialLength - this.notificationQueue.length;
    if (removedCount > 0) {
      logger.info('Expired notifications cleaned up', {
        removedCount,
        remainingCount: this.notificationQueue.length
      });
    }
  }

  /**
   * Get system statistics
   */
  getSystemStats() {
    return {
      connectedClients: this.connectionCount,
      authenticatedClients: this.connectedClients.size,
      queuedNotifications: this.notificationQueue.length,
      totalMessages: this.messageCount,
      totalErrors: this.errorCount,
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage()
    };
  }

  /**
   * Enhanced utility methods
   */

  getConnectedClientsCount() {
    return this.connectedClients.size;
  }

  isEmployeeOnline(employeeId) {
    const clientInfo = this.connectedClients.get(employeeId);
    return clientInfo && clientInfo.ws.readyState === WebSocket.OPEN;
  }

  /**
   * Broadcast notification with improved security
   * @param {object} notificationData 
   */
  broadcastNotification(notificationData) {
    let sentCount = 0;
    const sanitizedData = SecurityManager.sanitizeMessage(notificationData);

    for (const [employeeId, clientInfo] of this.connectedClients.entries()) {
      if (clientInfo.ws.readyState === WebSocket.OPEN) {
        try {
          clientInfo.ws.send(JSON.stringify({
            type: 'broadcast',
            ...sanitizedData
          }));
          sentCount++;
        } catch (error) {
          logger.error('Failed to broadcast to employee', error, { employeeId });
        }
      }
    }

    logger.info('Broadcast notification sent', {
      sentCount,
      totalConnected: this.connectedClients.size
    });

    return sentCount;
  }

  /**
   * Graceful shutdown
   */
  shutdown() {
    logger.info('Shutting down NotificationManager...');

    // Close all client connections
    for (const [employeeId, clientInfo] of this.connectedClients.entries()) {
      try {
        clientInfo.ws.close(1001, 'Server shutting down');
      } catch (error) {
        logger.error('Error closing client connection', error, { employeeId });
      }
    }

    // Close server
    if (this.wsServer) {
      this.wsServer.close(() => {
        logger.info('WebSocket server closed');
      });
    }

    this.isInitialized = false;
  }

  /**
   * Health check
   */
  healthCheck() {
    return {
      status: this.isInitialized ? 'healthy' : 'unhealthy',
      uptime: process.uptime(),
      connectedClients: this.connectionCount,
      authenticatedClients: this.connectedClients.size,
      queueSize: this.notificationQueue.length,
      errorRate: this.errorCount / Math.max(this.messageCount, 1),
      memoryUsage: process.memoryUsage(),
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Singleton pattern - get instance
   */
  static getInstance() {
    if (!NotificationManager.instance) {
      NotificationManager.instance = new NotificationManager();
    }
    return NotificationManager.instance;
  }

  /**
   * Initialize the notification system with enhanced options
   * @param {object} options 
   */
  static initialize(options = {}) {
    const instance = NotificationManager.getInstance();

    if (!instance.isInitialized) {
      instance.initializeWebSocket(options);

      logger.info('NotificationManager initialized successfully', {
        wsPort: options.wsPort || CONFIG.WS.PORT,
        tlsEnabled: CONFIG.SECURITY.ENABLE_TLS,
        maxConnections: CONFIG.WS.MAX_CONNECTIONS
      });
    }

    return instance;
  }

  /**
   * Enhanced shutdown with cleanup
   */
  static shutdown() {
    const instance = NotificationManager.getInstance();
    instance.shutdown();
    NotificationManager.instance = null;
  }
}

// Static instance
NotificationManager.instance = null;

module.exports = NotificationManager;
