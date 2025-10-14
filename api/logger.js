import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Create secure logs directory with restricted permissions
const logsDir = path.join(__dirname, 'logs');

try {
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { mode: 0o750 }); // Owner: rwx, Group: r-x, Others: none
  }
  
  // Set restrictive permissions on logs directory
  fs.chmodSync(logsDir, 0o750);
} catch (error) {
  console.error('Failed to create secure logs directory:', error.message);
}

// Failed login tracking
const failedLoginAttempts = new Map(); // username -> { count, lastAttempt, locked }
const FAILED_LOGIN_THRESHOLD = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes in milliseconds

// Custom format with sanitization
const sanitizeLogData = winston.format((info) => {
  // Remove sensitive data from logs
  const sensitiveFields = ['password', 'token', 'jwt', 'secret', 'key', 'auth', 'cookie'];
  
  if (typeof info.message === 'object') {
    const sanitized = { ...info.message };
    sensitiveFields.forEach(field => {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    });
    info.message = sanitized;
  } else if (typeof info.message === 'string') {
    // Basic sanitization for string messages
    sensitiveFields.forEach(field => {
      const regex = new RegExp(`${field}['"\\s]*[:=]['"\\s]*[^\\s,}]+`, 'gi');
      info.message = info.message.replace(regex, `${field}: [REDACTED]`);
    });
  }
  
  return info;
});

// Create Winston logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({
      format: 'YYYY-MM-DD HH:mm:ss.SSS'
    }),
    sanitizeLogData(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { 
    service: 'social-media-api',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  },
  transports: [
    // Console transport for development
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple(),
        winston.format.printf(({ timestamp, level, message, service, ...meta }) => {
          const metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
          return `${timestamp} [${service}] ${level}: ${typeof message === 'object' ? JSON.stringify(message) : message} ${metaStr}`;
        })
      )
    }),
    
    // Application logs with daily rotation
    new DailyRotateFile({
      filename: path.join(logsDir, 'application-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: '10m',
      maxFiles: '30d',
      zippedArchive: true,
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    }),
    
    // Security-specific logs
    new DailyRotateFile({
      filename: path.join(logsDir, 'security-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: '10m',
      maxFiles: '90d', // Keep security logs longer
      zippedArchive: true,
      level: 'warn',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    }),
    
    // Error logs
    new DailyRotateFile({
      filename: path.join(logsDir, 'error-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: '10m',
      maxFiles: '60d',
      zippedArchive: true,
      level: 'error',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    })
  ],
  
  // Handle exceptions and rejections
  exceptionHandlers: [
    new DailyRotateFile({
      filename: path.join(logsDir, 'exceptions-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: '10m',
      maxFiles: '30d',
      zippedArchive: true
    })
  ],
  
  rejectionHandlers: [
    new DailyRotateFile({
      filename: path.join(logsDir, 'rejections-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: '10m',
      maxFiles: '30d',
      zippedArchive: true
    })
  ]
});

/**
 * Enhanced logging function with context and metadata
 * @param {string} level - Log level (info, warn, error)
 * @param {string|object} message - Log message or object
 * @param {object} metadata - Additional metadata
 */
export function logEvent(level, message, metadata = {}) {
  // Validate log level
  const validLevels = ['error', 'warn', 'info', 'debug'];
  if (!validLevels.includes(level)) {
    level = 'info';
  }
  
  // Add request context if available
  const logData = {
    ...metadata,
    timestamp: new Date().toISOString(),
    pid: process.pid,
    hostname: os.hostname()
  };
  
  logger.log(level, message, logData);
}

/**
 * Track failed login attempts and implement account lockout
 * @param {string} username - Username attempting login
 * @param {string} ip - IP address of the attempt
 * @param {string} userAgent - User agent string
 * @returns {boolean} - Whether account is locked
 */
export function trackFailedLogin(username, ip = 'unknown', userAgent = 'unknown') {
  if (!username) {
    logEvent('warn', 'Failed login tracking called without username');
    return false;
  }
  
  const now = Date.now();
  const userAttempts = failedLoginAttempts.get(username) || { count: 0, lastAttempt: 0, locked: false };
  
  // Check if lockout period has expired
  if (userAttempts.locked && (now - userAttempts.lastAttempt) > LOCKOUT_DURATION) {
    userAttempts.locked = false;
    userAttempts.count = 0;
    logEvent('info', `Account lockout expired for user: ${username}`, { 
      security_event: 'lockout_expired',
      username,
      ip,
      userAgent 
    });
  }
  
  // If account is still locked, deny attempt
  if (userAttempts.locked) {
    logEvent('warn', `Login attempt on locked account: ${username}`, {
      security_event: 'locked_account_attempt',
      username,
      ip,
      userAgent,
      attempts_count: userAttempts.count,
      locked_since: new Date(userAttempts.lastAttempt).toISOString()
    });
    return true;
  }
  
  // Increment failed attempts
  userAttempts.count++;
  userAttempts.lastAttempt = now;
  
  // Log the failed attempt
  logEvent('warn', `Failed login attempt #${userAttempts.count} for user: ${username}`, {
    security_event: 'failed_login',
    username,
    ip,
    userAgent,
    attempts_count: userAttempts.count,
    threshold: FAILED_LOGIN_THRESHOLD
  });
  
  // Check if threshold reached
  if (userAttempts.count >= FAILED_LOGIN_THRESHOLD) {
    userAttempts.locked = true;
    
    // Log security alert
    logEvent('error', `SECURITY ALERT: Account locked due to multiple failed login attempts`, {
      security_event: 'account_locked',
      username,
      ip,
      userAgent,
      attempts_count: userAttempts.count,
      locked_at: new Date(now).toISOString()
    });
    
    // Send security alert
    sendSecurityAlert(username, ip, userAttempts.count);
  }
  
  failedLoginAttempts.set(username, userAttempts);
  return userAttempts.locked;
}

/**
 * Log successful login and reset failed attempts
 * @param {string} username - Username that logged in successfully
 * @param {string} ip - IP address
 * @param {string} userAgent - User agent string
 */
export function logSuccessfulLogin(username, ip = 'unknown', userAgent = 'unknown') {
  // Reset failed login attempts on successful login
  if (failedLoginAttempts.has(username)) {
    failedLoginAttempts.delete(username);
  }
  
  logEvent('info', `Successful login for user: ${username}`, {
    security_event: 'successful_login',
    username,
    ip,
    userAgent
  });
}

/**
 * Send security alert for critical events
 * @param {string} username - Username involved in the security event
 * @param {string} ip - IP address
 * @param {number} attemptCount - Number of failed attempts
 */
export function sendSecurityAlert(username, ip = 'unknown', attemptCount = 0) {
  const alertMessage = `🚨 SECURITY ALERT: Account "${username}" locked due to ${attemptCount} failed login attempts from IP: ${ip}`;
  
  // Log the alert
  logEvent('error', alertMessage, {
    alert_type: 'account_lockout',
    username,
    ip,
    attempt_count: attemptCount,
    timestamp: new Date().toISOString()
  });
  
  // Console alert for immediate visibility
  console.error(`\n${'='.repeat(80)}`);
  console.error(`🚨 SECURITY ALERT - ${new Date().toISOString()}`);
  console.error(`Account: ${username}`);
  console.error(`IP Address: ${ip}`);
  console.error(`Failed Attempts: ${attemptCount}`);
  console.error(`Action: Account temporarily locked`);
  console.error(`${'='.repeat(80)}\n`);
  
  // In production, you would send this to:
  // - Security team via email/Slack/webhook
  // - SIEM system
  // - Security monitoring dashboard
  
  // Example webhook implementation (commented out for safety):
  /*
  if (process.env.SECURITY_WEBHOOK_URL) {
    try {
      await fetch(process.env.SECURITY_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert_type: 'account_lockout',
          username,
          ip,
          attempt_count: attemptCount,
          timestamp: new Date().toISOString(),
          message: alertMessage
        })
      });
    } catch (error) {
      logEvent('error', 'Failed to send security webhook', { error: error.message });
    }
  }
  */
}

/**
 * Log security events with enhanced context
 * @param {string} eventType - Type of security event
 * @param {string} message - Event message
 * @param {object} context - Additional context
 */
export function logSecurityEvent(eventType, message, context = {}) {
  logEvent('warn', message, {
    security_event: eventType,
    ...context,
    timestamp: new Date().toISOString()
  });
}

/**
 * Log user data access/modification events (for GDPR compliance)
 * @param {string} action - Action performed (read, update, delete)
 * @param {string} userId - ID of the user whose data was accessed
 * @param {string} actorId - ID of the user performing the action
 * @param {object} context - Additional context
 */
export function logUserDataAccess(action, userId, actorId, context = {}) {
  logEvent('info', `User data ${action}`, {
    audit_event: 'user_data_access',
    action,
    target_user_id: userId,
    actor_user_id: actorId,
    ...context,
    timestamp: new Date().toISOString()
  });
}

/**
 * Clean up old failed login attempts (call periodically)
 */
export function cleanupFailedLogins() {
  const now = Date.now();
  const expiredEntries = [];
  
  for (const [username, attempts] of failedLoginAttempts.entries()) {
    if ((now - attempts.lastAttempt) > LOCKOUT_DURATION * 2) {
      expiredEntries.push(username);
    }
  }
  
  expiredEntries.forEach(username => {
    failedLoginAttempts.delete(username);
  });
  
  if (expiredEntries.length > 0) {
    logEvent('info', `Cleaned up ${expiredEntries.length} expired failed login records`);
  }
}

// Cleanup failed logins every 30 minutes
setInterval(cleanupFailedLogins, 30 * 60 * 1000);

// Graceful shutdown handling
process.on('SIGINT', () => {
  logEvent('info', 'Application shutting down gracefully');
  logger.end();
});

process.on('SIGTERM', () => {
  logEvent('info', 'Application terminated');
  logger.end();
});

// Export logger instance for direct use if needed
export { logger };

// Export default logEvent for backwards compatibility
export default logEvent;