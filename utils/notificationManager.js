const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');
const { loadJSON, saveJSON } = require('./fileUtils');


// File paths
const NOTIFICATIONS_LOG = './data/notifications.json';
const EMPLOYEE_SESSIONS = './data/employee_sessions.json';


/**
 * Enhanced Real-time Notification Manager
 * Supports multiple notification channels: WebSocket, Email, SMS, Push Notifications
 */
class NotificationManager {
  constructor() {
    this.wsServer = null;
    this.connectedClients = new Map(); // employeeId -> WebSocket connection
    this.notificationQueue = [];
    this.isInitialized = false;
  }


  /**
   * Initialize WebSocket server for real-time notifications
   * @param {number} port - WebSocket server port
   */
  initializeWebSocket(port = 8081) {
    try {
      this.wsServer = new WebSocket.Server({ port });

      this.wsServer.on('connection', (ws, req) => {
        console.log('📡 New WebSocket connection established');

        // Handle client identification
        ws.on('message', (message) => {
          try {
            const data = JSON.parse(message);

            if (data.type === 'identify' && data.employeeId) {
              this.connectedClients.set(data.employeeId, ws);
              console.log(`👤 Employee ${data.employeeId} connected to WebSocket`);

              // Send queued notifications for this employee
              this.sendQueuedNotifications(data.employeeId);
            }
          } catch (error) {
            console.error('Error processing WebSocket message:', error);
          }
        });


        ws.on('close', () => {
          // Remove client from connected clients
          for (const [employeeId, client] of this.connectedClients.entries()) {
            if (client === ws) {
              this.connectedClients.delete(employeeId);
              console.log(`📴 Employee ${employeeId} disconnected from WebSocket`);
              break;
            }
          }
        });


        ws.on('error', (error) => {
          console.error('WebSocket error:', error);
        });
      });


      console.log(`✅ WebSocket notification server started on port ${port}`);
      this.isInitialized = true;

    } catch (error) {
      console.error('❌ Failed to initialize WebSocket server:', error);
    }
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
  }


  /**
   * ENHANCED: Notify employee about form rejection with multiple channels
   * @param {string} employeeId - Employee ID
   * @param {string} formId - Form ID that was rejected
   * @param {string} reason - Rejection reason
   * @param {Object} options - Additional notification options
   */
  static notifyFormRejection(employeeId, formId, reason, options = {}) {
    const instance = NotificationManager.getInstance();

    const notificationData = {
      type: 'form_rejection',
      employeeId,
      formId,
      reason,
      timestamp: new Date().toISOString(),
      priority: 'high',
      title: '❌ Application Rejected',
      message: `Your application ${formId} has been rejected by HOD.`,
      details: {
        rejectionReason: reason,
        actionRequired: 'Submit new application',
        redirectUrl: '/employee.html'
      },
      ...options
    };


    // Log the notification
    console.log(`📢 Form rejection notification for employee ${employeeId}: Form ${formId} rejected - ${reason}`);

    // Send via multiple channels
    instance.sendMultiChannelNotification(notificationData);

    // Save to log
    instance.logNotification(notificationData);

    return notificationData;
  }


  /**
   * ENHANCED: Notify about form approval
   * @param {string} employeeId 
   * @param {string} formId 
   * @param {string} approvedBy 
   * @param {Object} options 
   */
  static notifyFormApproval(employeeId, formId, approvedBy, options = {}) {
    const instance = NotificationManager.getInstance();

    const notificationData = {
      type: 'form_approval',
      employeeId,
      formId,
      approvedBy,
      timestamp: new Date().toISOString(),
      priority: 'medium',
      title: '✅ Application Approved',
      message: `Your application ${formId} has been approved by ${approvedBy}.`,
      details: {
        nextStep: 'Forwarded to IT department',
        estimatedCompletion: '2-3 business days'
      },
      ...options
    };


    console.log(`📢 Form approval notification for employee ${employeeId}: Form ${formId} approved by ${approvedBy}`);

    instance.sendMultiChannelNotification(notificationData);
    instance.logNotification(notificationData);

    return notificationData;
  }


  /**
   * ENHANCED: Notify about certificate generation
   * @param {string} employeeId 
   * @param {string} formId 
   * @param {Array} certificates 
   * @param {Object} options 
   */
  static notifyCertificatesReady(employeeId, formId, certificates, options = {}) {
    const instance = NotificationManager.getInstance();

    const notificationData = {
      type: 'certificates_ready',
      employeeId,
      formId,
      certificates,
      timestamp: new Date().toISOString(),
      priority: 'high',
      title: '🏆 Certificates Ready',
      message: `Your IT clearance certificates are ready for download!`,
      details: {
        certificateCount: certificates.length,
        downloadUrl: '/certificates.html',
        validUntil: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() // 30 days
      },
      ...options
    };


    console.log(`📢 Certificates ready notification for employee ${employeeId}: ${certificates.length} certificates available`);

    instance.sendMultiChannelNotification(notificationData);
    instance.logNotification(notificationData);

    return notificationData;
  }


  /**
   * Send notification via multiple channels
   * @param {Object} notificationData 
   */
  sendMultiChannelNotification(notificationData) {
    // 1. Real-time WebSocket notification
    this.sendRealTimeNotification(notificationData.employeeId, notificationData);

    // 2. Browser notification (if client supports)
    this.sendBrowserNotification(notificationData.employeeId, notificationData);

    // 3. Email notification (future implementation)
    // this.sendEmailNotification(notificationData);

    // 4. SMS notification (future implementation)
    // this.sendSMSNotification(notificationData);
  }


  /**
   * Send real-time WebSocket notification
   * @param {string} employeeId 
   * @param {Object} notificationData 
   */
  sendRealTimeNotification(employeeId, notificationData) {
    const client = this.connectedClients.get(employeeId);

    if (client && client.readyState === WebSocket.OPEN) {
      try {
        client.send(JSON.stringify({
          type: 'notification',
          ...notificationData
        }));

        console.log(`📡 Real-time notification sent to employee ${employeeId}`);
        return true;
      } catch (error) {
        console.error(`Failed to send real-time notification to ${employeeId}:`, error);
        this.queueNotification(notificationData);
        return false;
      }
    } else {
      console.log(`📤 Employee ${employeeId} not connected, queuing notification`);
      this.queueNotification(notificationData);
      return false;
    }
  }


  /**
   * Send browser notification (for web clients)
   * @param {string} employeeId 
   * @param {Object} notificationData 
   */
  sendBrowserNotification(employeeId, notificationData) {
    const client = this.connectedClients.get(employeeId);

    if (client && client.readyState === WebSocket.OPEN) {
      try {
        client.send(JSON.stringify({
          type: 'browser_notification',
          title: notificationData.title,
          body: notificationData.message,
          icon: this.getNotificationIcon(notificationData.type),
          badge: '/images/notification-badge.png',
          tag: notificationData.type,
          requireInteraction: notificationData.priority === 'high',
          actions: this.getNotificationActions(notificationData.type),
          data: {
            formId: notificationData.formId,
            redirectUrl: notificationData.details?.redirectUrl
          }
        }));

        console.log(`🔔 Browser notification sent to employee ${employeeId}`);
        return true;
      } catch (error) {
        console.error(`Failed to send browser notification to ${employeeId}:`, error);
        return false;
      }
    }

    return false;
  }


  /**
   * Queue notification for later delivery
   * @param {Object} notificationData 
   */
  queueNotification(notificationData) {
    // Add expiry time (24 hours)
    notificationData.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    this.notificationQueue.push(notificationData);
    console.log(`📥 Notification queued for employee ${notificationData.employeeId}`);
  }


  /**
   * Get notification icon based on type
   * @param {string} type 
   */
  getNotificationIcon(type) {
    const icons = {
      'form_rejection': '/images/rejection-icon.png',
      'form_approval': '/images/approval-icon.png',
      'certificates_ready': '/images/certificate-icon.png',
      'form_assigned': '/images/form-icon.png'
    };

    return icons[type] || '/images/default-notification-icon.png';
  }


  /**
   * Get notification actions based on type
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
      ]
    };

    return actions[type] || [{ action: 'view', title: 'View' }];
  }


  /**
   * Log notification to file
   * @param {Object} notificationData 
   */
  logNotification(notificationData) {
    try {
      let notifications = [];

      try {
        notifications = loadJSON(NOTIFICATIONS_LOG);
        if (!Array.isArray(notifications)) notifications = [];
      } catch (error) {
        notifications = [];
      }

      notifications.push({
        id: this.generateNotificationId(),
        ...notificationData,
        loggedAt: new Date().toISOString()
      });

      // Keep only last 1000 notifications
      if (notifications.length > 1000) {
        notifications = notifications.slice(-1000);
      }

      saveJSON(NOTIFICATIONS_LOG, notifications);
      console.log(`📝 Notification logged for employee ${notificationData.employeeId}`);

    } catch (error) {
      console.error('Failed to log notification:', error);
    }
  }


  /**
   * Generate unique notification ID
   */
  generateNotificationId() {
    return 'NOTIF_' + Date.now() + '_' + Math.random().toString(36).substring(2, 9);
  }


  /**
   * Get notification history for employee
   * @param {string} employeeId 
   * @param {number} limit 
   */
  getNotificationHistory(employeeId, limit = 50) {
    try {
      const notifications = loadJSON(NOTIFICATIONS_LOG) || [];

      return notifications
        .filter(n => n.employeeId === employeeId)
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, limit);

    } catch (error) {
      console.error('Failed to get notification history:', error);
      return [];
    }
  }


  /**
   * Clean up expired notifications from queue
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
      console.log(`🧹 Cleaned up ${removedCount} expired notifications`);
    }
  }


  /**
   * Get connected clients count
   */
  getConnectedClientsCount() {
    return this.connectedClients.size;
  }


  /**
   * Check if employee is online
   * @param {string} employeeId 
   */
  isEmployeeOnline(employeeId) {
    const client = this.connectedClients.get(employeeId);
    return client && client.readyState === WebSocket.OPEN;
  }


  /**
   * Broadcast notification to all connected clients
   * @param {Object} notificationData 
   */
  broadcastNotification(notificationData) {
    let sentCount = 0;

    for (const [employeeId, client] of this.connectedClients.entries()) {
      if (client.readyState === WebSocket.OPEN) {
        try {
          client.send(JSON.stringify({
            type: 'broadcast',
            ...notificationData
          }));
          sentCount++;
        } catch (error) {
          console.error(`Failed to broadcast to ${employeeId}:`, error);
        }
      }
    }

    console.log(`📡 Broadcast notification sent to ${sentCount} connected clients`);
    return sentCount;
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
   * Initialize the notification system
   * @param {Object} options 
   */
  static initialize(options = {}) {
    const instance = NotificationManager.getInstance();

    if (!instance.isInitialized) {
      instance.initializeWebSocket(options.wsPort || 8081);

      // Start cleanup interval (every hour)
      setInterval(() => {
        instance.cleanupExpiredNotifications();
      }, 60 * 60 * 1000);

      console.log('✅ NotificationManager initialized successfully');
    }

    return instance;
  }


  /**
   * Shutdown notification system
   */
  static shutdown() {
    const instance = NotificationManager.getInstance();

    if (instance.wsServer) {
      instance.wsServer.close();
      console.log('📴 NotificationManager shut down');
    }
  }
}


// Static instance
NotificationManager.instance = null;


module.exports = NotificationManager;