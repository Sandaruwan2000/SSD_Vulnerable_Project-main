# 🔒 Security Logging & Monitoring System Documentation

## 📋 Table of Contents
1. [Overview](#overview)
2. [OWASP A09 Compliance](#owasp-a09-compliance)
3. [Architecture](#architecture)
4. [Features](#features)
5. [Installation & Setup](#installation--setup)
6. [Usage Guide](#usage-guide)
7. [Log Files Structure](#log-files-structure)
8. [Security Features](#security-features)
9. [Monitoring & Alerting](#monitoring--alerting)
10. [Best Practices](#best-practices)
11. [Troubleshooting](#troubleshooting)

---

## 📖 Overview

This security logging system implements **OWASP A09: Security Logging & Monitoring Failures** compliance using Winston logger. It provides comprehensive, production-ready logging with automated threat detection, secure storage, and real-time alerting capabilities.

### 🎯 Purpose
- **Detect security incidents** in real-time
- **Track user activities** for audit compliance
- **Monitor failed login attempts** and prevent brute force attacks
- **Log security events** with proper context and metadata
- **Maintain audit trails** for compliance requirements
- **Alert security teams** of critical events

---

## 🛡️ OWASP A09 Compliance

### What is OWASP A09?
OWASP A09 addresses "Security Logging and Monitoring Failures" - insufficient logging, detection, monitoring, and active response to security breaches.

### Our Implementation Covers:
✅ **Comprehensive Event Logging**
- All authentication attempts (success/failure)
- Administrative actions (user deletion, data modification)
- File access attempts
- External API calls
- Security policy violations

✅ **Real-time Threat Detection**
- Failed login attempt tracking
- Account lockout mechanisms  
- Suspicious activity pattern detection
- Automated security alerts

✅ **Secure Log Storage**
- Restricted file permissions (750)
- Log rotation and archival
- Tamper-evident logging
- Sensitive data sanitization

✅ **Audit Trail Maintenance**
- Timestamped entries
- User context tracking
- IP address logging
- Request metadata capture

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                 Application Layer                    │
├─────────────────────────────────────────────────────┤
│  Express Routes & Middleware                        │
│  ├── Authentication Events                          │
│  ├── File Operations                                │
│  ├── Admin Actions                                  │
│  └── Security Events                                │
└─────────────────┬───────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────┐
│            Security Logger (logger.js)              │
├─────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │
│  │   Winston   │  │ Failed Login │  │   Alert     │  │
│  │   Logger    │  │  Tracking    │  │  System     │  │
│  └─────────────┘  └─────────────┘  └─────────────┘  │
└─────────────────┬───────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────┐
│              Log Storage Layer                      │
├─────────────────────────────────────────────────────┤
│  /logs/ (Secure Directory - 750 permissions)       │
│  ├── application-YYYY-MM-DD.log                    │
│  ├── security-YYYY-MM-DD.log                       │
│  ├── error-YYYY-MM-DD.log                          │
│  ├── exceptions-YYYY-MM-DD.log                     │
│  └── rejections-YYYY-MM-DD.log                     │
└─────────────────────────────────────────────────────┘
```

---

## 🚀 Features

### 🔧 Core Logging Features
- **Multi-level Logging**: Info, Warn, Error, Debug
- **Structured JSON Logging**: Machine-readable format
- **Daily Log Rotation**: 10MB max file size, 30-90 day retention
- **Multiple Output Streams**: Console + File outputs
- **Automatic Compression**: Gzip archived old logs

### 🔒 Security Features
- **Sensitive Data Sanitization**: Passwords, tokens automatically redacted
- **Failed Login Tracking**: 5-attempt threshold with 15-minute lockout
- **Real-time Alerting**: Console and webhook notifications
- **IP Address Logging**: Track request origins
- **User Agent Logging**: Device/browser identification

### 📊 Monitoring Features
- **Security Event Classification**: Categorized threat detection
- **Audit Trail Generation**: GDPR/compliance ready
- **Performance Metrics**: Request timing and system stats
- **Health Monitoring**: Exception and rejection tracking

---

## ⚙️ Installation & Setup

### 1. Install Dependencies
```bash
npm install winston winston-daily-rotate-file
```

### 2. Import Logger in Your Application
```javascript
import { 
  logEvent, 
  logSecurityEvent, 
  logUserDataAccess, 
  trackFailedLogin, 
  logSuccessfulLogin 
} from "./logger.js";
```

### 3. Directory Structure Created Automatically
```
api/
├── logger.js
├── logs/ (Created automatically with 750 permissions)
│   ├── application-2024-10-15.log
│   ├── security-2024-10-15.log
│   ├── error-2024-10-15.log
│   ├── exceptions-2024-10-15.log
│   └── rejections-2024-10-15.log
└── index.js (Your main application)
```

---

## 📘 Usage Guide

### Basic Event Logging
```javascript
// General application events
logEvent('info', 'User profile updated', {
  user_id: 123,
  fields_changed: ['email', 'name'],
  requester_ip: req.ip
});

// Error logging
logEvent('error', 'Database connection failed', {
  error: error.message,
  retry_count: 3
});
```

### Security Event Logging
```javascript
// Track security violations
logSecurityEvent('unauthorized_access', 'Admin panel access denied', {
  user_id: 456,
  requested_resource: '/admin/users',
  requester_ip: req.ip,
  user_agent: req.headers['user-agent']
});
```

### Authentication Tracking
```javascript
// Track failed login
const isLocked = trackFailedLogin(username, req.ip, req.headers['user-agent']);
if (isLocked) {
  return res.status(429).json({ error: "Account temporarily locked" });
}

// Log successful login
logSuccessfulLogin(username, req.ip, req.headers['user-agent']);
```

### User Data Access Logging (GDPR Compliance)
```javascript
// Log when user data is accessed/modified
logUserDataAccess('update', userId, adminId, {
  fields_modified: ['email', 'phone'],
  admin_ip: req.ip,
  justification: 'User support request #12345'
});
```

---

## 📁 Log Files Structure

### Application Logs (`application-YYYY-MM-DD.log`)
```json
{
  "level": "info",
  "message": "User profile updated",
  "timestamp": "2024-10-15T14:30:25.123Z",
  "service": "social-media-api",
  "version": "1.0.0",
  "environment": "production",
  "user_id": 123,
  "fields_changed": ["email", "name"],
  "requester_ip": "192.168.1.100"
}
```

### Security Logs (`security-YYYY-MM-DD.log`)
```json
{
  "level": "warn",
  "message": "Failed login attempt #3 for user: john_doe",
  "timestamp": "2024-10-15T14:35:12.456Z",
  "security_event": "failed_login",
  "username": "john_doe",
  "ip": "192.168.1.200",
  "userAgent": "Mozilla/5.0...",
  "attempts_count": 3,
  "threshold": 5
}
```

### Error Logs (`error-YYYY-MM-DD.log`)
```json
{
  "level": "error",
  "message": "Database connection timeout",
  "timestamp": "2024-10-15T14:40:33.789Z",
  "error": "Connection timeout after 5000ms",
  "database": "mysql",
  "retry_attempts": 3
}
```

---

## 🔐 Security Features

### 1. Sensitive Data Sanitization
Automatically removes sensitive information from logs:
```javascript
// Input
{ username: "john", password: "secret123", token: "jwt_token_here" }

// Logged as
{ username: "john", password: "[REDACTED]", token: "[REDACTED]" }
```

### 2. Failed Login Protection
```javascript
const FAILED_LOGIN_THRESHOLD = 5;      // Max failed attempts
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes lockout
```

**Process Flow:**
1. Track failed attempts per username
2. Log each attempt with context
3. Lock account after 5 failures
4. Auto-unlock after 15 minutes
5. Send security alert on lockout

### 3. Secure Log Directory
```javascript
// Directory created with restricted permissions
fs.mkdirSync(logsDir, { mode: 0o750 }); // Owner: rwx, Group: r-x, Others: none
```

### 4. Log Rotation & Retention
```javascript
new DailyRotateFile({
  filename: 'application-%DATE%.log',
  datePattern: 'YYYY-MM-DD',
  maxSize: '10m',        // 10MB max file size
  maxFiles: '30d',       // Keep for 30 days
  zippedArchive: true    // Compress old files
})
```

---

## 🚨 Monitoring & Alerting

### Automatic Security Alerts
When critical events occur, the system:
1. **Logs the event** to security log file
2. **Displays console alert** for immediate visibility
3. **Can send webhooks** (configure `SECURITY_WEBHOOK_URL`)

### Alert Example
```
================================================================================
🚨 SECURITY ALERT - 2024-10-15T14:45:00.000Z
Account: john_doe
IP Address: 192.168.1.200
Failed Attempts: 5
Action: Account temporarily locked
================================================================================
```

### Webhook Integration (Production)
```javascript
// Set environment variable
process.env.SECURITY_WEBHOOK_URL = "https://your-webhook-endpoint.com/alerts"

// Automatic webhook calls for critical events
// Payload includes: alert_type, username, ip, timestamp, message
```

---

## 📋 Best Practices

### 1. Log Levels Usage
- **INFO**: Normal operations, successful actions
- **WARN**: Security events, policy violations  
- **ERROR**: System errors, failed operations
- **DEBUG**: Development/troubleshooting info

### 2. What to Log
✅ **DO Log:**
- Authentication attempts (success/failure)
- Administrative actions
- Data access/modification
- Security policy violations
- System errors and exceptions
- API calls to external services

❌ **DON'T Log:**
- Passwords or tokens
- Full credit card numbers
- Personal sensitive data
- Large binary data

### 3. Production Configuration
```javascript
// Environment variables for production
NODE_ENV=production
SECURITY_WEBHOOK_URL=https://your-siem-system.com/webhooks
LOG_RETENTION_DAYS=90
MAX_LOG_FILE_SIZE=50m
```

### 4. Regular Maintenance
- **Monitor disk space** for log directory
- **Review security alerts** daily
- **Archive old logs** to cold storage
- **Update log retention** policies as needed

---

## 🔍 Monitoring Queries

### Find Failed Login Attempts
```bash
grep "failed_login" logs/security-*.log | jq '.username, .ip, .timestamp'
```

### Check Account Lockouts
```bash
grep "account_locked" logs/security-*.log | jq '.username, .locked_at, .attempts_count'
```

### Monitor File Access Violations
```bash
grep "file_access_denied" logs/security-*.log | jq '.requested_path, .requester_ip'
```

### Track Admin Actions
```bash
grep "user_data_access" logs/application-*.log | jq '.action, .target_user_id, .actor_user_id'
```

---

## 🛠️ Troubleshooting

### Common Issues

#### 1. Logs Directory Not Created
**Problem:** Permission denied or directory missing
**Solution:**
```javascript
// Check directory permissions
ls -la logs/
chmod 750 logs/
chown app:app logs/
```

#### 2. Log Files Not Rotating
**Problem:** Files growing too large
**Solution:**
```javascript
// Check Winston configuration
maxSize: '10m',     // Ensure size limit is set
maxFiles: '30d',    // Ensure file limit is set
```

#### 3. Missing Log Entries
**Problem:** Events not being logged
**Solution:**
```javascript
// Verify logger import and usage
import { logEvent } from './logger.js';

// Check log level configuration
logger.level = 'info'; // Ensure appropriate level
```

#### 4. High Disk Usage
**Problem:** Log files consuming too much space
**Solution:**
```bash
# Manual cleanup of old logs
find logs/ -name "*.log.gz" -mtime +90 -delete

# Adjust retention policy
maxFiles: '14d'  // Reduce retention period
```

---

## 📊 Performance Considerations

### Log Volume Management
- **Average log entry**: ~500 bytes
- **Expected daily volume**: 10MB-100MB depending on traffic
- **Recommended monitoring**: Set up disk space alerts at 80% capacity

### Memory Usage
- **Winston memory footprint**: ~10-50MB depending on configuration
- **Log buffer size**: Configurable, default 16KB
- **Background processing**: Log writes are asynchronous

---

## 🔮 Future Enhancements

### Planned Features
1. **SIEM Integration**: Direct integration with Splunk, ELK Stack
2. **Machine Learning**: Anomaly detection for unusual patterns
3. **Dashboard**: Web-based log viewing and analysis
4. **Mobile Alerts**: SMS/push notifications for critical events
5. **Compliance Reporting**: Automated GDPR/SOX compliance reports

### Integration Options
- **Elasticsearch**: For advanced log searching
- **Grafana**: For log visualization and dashboards  
- **PagerDuty**: For incident escalation
- **Slack/Teams**: For team notifications

---

## 📞 Support & Contact

For questions or issues with the logging system:
1. Check this documentation first
2. Review the log files in `/logs/` directory
3. Check console output for immediate errors
4. Verify Winston and dependencies are properly installed

---

## 🏷️ Version History

- **v1.0.0** - Initial Winston-based implementation
- **Features**: Basic logging, rotation, failed login tracking
- **Security**: Sensitive data sanitization, secure storage
- **Compliance**: OWASP A09 coverage

---

*This documentation covers the complete security logging system implementation. The system is production-ready and provides comprehensive security monitoring capabilities in compliance with OWASP A09 guidelines.*