# 🚀 Winston Security Logger - Quick Reference

## 📦 Installation
```bash
npm install winston winston-daily-rotate-file
```

## 🔧 Import & Setup
```javascript
import { 
  logEvent, 
  logSecurityEvent, 
  logUserDataAccess, 
  trackFailedLogin, 
  logSuccessfulLogin 
} from "./logger.js";
```

## 🎯 Quick Usage Examples

### Basic Logging
```javascript
// Info level - general events
logEvent('info', 'User profile updated', {
  user_id: 123,
  fields: ['email', 'name']
});

// Warning level - potential issues  
logEvent('warn', 'Invalid API key used', {
  api_key: 'abc123...',
  endpoint: '/api/users'
});

// Error level - system errors
logEvent('error', 'Database connection failed', {
  error: error.message,
  retry_count: 3
});
```

### Security Events
```javascript
// Track security violations
logSecurityEvent('unauthorized_access', 'Admin panel breach attempt', {
  user_id: 456,
  resource: '/admin/users',
  ip: req.ip
});

// File access violations
logSecurityEvent('path_traversal_attempt', 'Blocked file access', {
  requested_path: '../../../etc/passwd',
  real_path: '/safe/files/',
  ip: req.ip
});
```

### Authentication Tracking
```javascript
// Login endpoint integration
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  if (isValidLogin(username, password)) {
    logSuccessfulLogin(username, req.ip, req.headers['user-agent']);
    res.json({ success: true });
  } else {
    const isLocked = trackFailedLogin(username, req.ip, req.headers['user-agent']);
    
    if (isLocked) {
      return res.status(429).json({ 
        error: "Account locked - too many failed attempts" 
      });
    }
    
    res.status(401).json({ error: "Invalid credentials" });
  }
});
```

### User Data Access (GDPR)
```javascript
// Log when sensitive data is accessed/modified
app.put('/api/admin/user/:id', (req, res) => {
  const userId = req.params.id;
  const adminId = req.user.id;
  
  // Update user data...
  
  logUserDataAccess('update', userId, adminId, {
    fields_modified: Object.keys(req.body),
    justification: 'Admin panel update',
    ip: req.ip
  });
});
```

## 🔒 Security Features

### Automatic Protection
- ✅ **Sensitive data sanitization** (passwords, tokens automatically redacted)
- ✅ **Failed login tracking** (5 attempts = 15min lockout)  
- ✅ **Real-time alerts** (console + webhook ready)
- ✅ **Secure file storage** (750 permissions on logs directory)

### Log Types Created
```
logs/
├── application-2024-10-15.log  # General app events (30 days)
├── security-2024-10-15.log     # Security events only (90 days) 
├── error-2024-10-15.log        # Errors only (60 days)
├── exceptions-2024-10-15.log   # Unhandled exceptions
└── rejections-2024-10-15.log   # Promise rejections
```

## 📊 Common Log Patterns

### Request Logging Middleware
```javascript
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    
    logEvent('info', 'HTTP Request', {
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      duration_ms: duration,
      ip: req.ip,
      user_agent: req.headers['user-agent']
    });
  });
  
  next();
});
```

### Error Handler Integration
```javascript
app.use((err, req, res, next) => {
  logEvent('error', 'Unhandled application error', {
    error: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip
  });
  
  res.status(500).json({ error: 'Internal server error' });
});
```

### File Upload Logging
```javascript
app.post('/api/upload', upload.single('file'), (req, res) => {
  logEvent('info', 'File uploaded', {
    filename: req.file.filename,
    size: req.file.size,
    mimetype: req.file.mimetype,
    uploader_ip: req.ip
  });
  
  res.json({ filename: req.file.filename });
});
```

## 🚨 Alert Configuration

### Console Alerts (Development)
Automatically shown for:
- Account lockouts
- Security violations  
- Critical errors

### Webhook Alerts (Production)
```javascript
// Set environment variable
process.env.SECURITY_WEBHOOK_URL = "https://your-webhook.com/alerts"

// Automatic webhook calls for critical events
```

## 📋 Log Analysis Commands

### View Recent Security Events
```bash
tail -f logs/security-$(date +%Y-%m-%d).log | jq '.'
```

### Find Failed Logins by IP
```bash
grep "failed_login" logs/security-*.log | jq 'select(.ip=="192.168.1.100")'
```

### Monitor Account Lockouts
```bash
grep "account_locked" logs/security-*.log | jq '{username, ip, timestamp}'
```

### Count Events by Type
```bash
cat logs/security-*.log | jq '.security_event' | sort | uniq -c
```

## ⚙️ Configuration Options

### Environment Variables
```bash
# .env file
NODE_ENV=production
LOG_LEVEL=info                    # info, warn, error, debug
FAILED_LOGIN_THRESHOLD=5          # Max failed attempts
LOCKOUT_DURATION_MINUTES=15       # Account lockout time
SECURITY_WEBHOOK_URL=https://...  # Alert webhook endpoint
```

### Log Retention
```javascript
// Modify in logger.js
new DailyRotateFile({
  maxSize: '10m',    # Max file size before rotation
  maxFiles: '30d',   # Keep logs for 30 days
  zippedArchive: true # Compress old files
})
```

## 🛠️ Troubleshooting

### Common Issues
```javascript
// Issue: Logs not appearing
// Solution: Check log level
logger.level = 'info'; // Make sure level allows your events

// Issue: Permission denied
// Solution: Check directory permissions
chmod 750 logs/
chown app:app logs/

// Issue: Files not rotating  
// Solution: Check disk space and permissions
df -h logs/
ls -la logs/
```

### Debug Mode
```javascript
// Enable debug logging temporarily
import { logger } from './logger.js';
logger.level = 'debug';

logEvent('debug', 'Debug information', { debug_data: '...' });
```

## 🎯 Best Practices

### ✅ DO
- Log all authentication events
- Include IP addresses and user agents
- Use structured JSON format
- Sanitize sensitive data automatically  
- Set up log rotation and retention
- Monitor disk space usage

### ❌ DON'T
- Log passwords or API tokens
- Log large binary data
- Use synchronous logging calls
- Ignore log file permissions
- Skip error context information

## 🔗 Integration Examples

### Express Rate Limiting
```javascript
import rateLimit from 'express-rate-limit';

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  handler: (req, res) => {
    logSecurityEvent('rate_limit_exceeded', 'Too many requests', {
      ip: req.ip,
      user_agent: req.headers['user-agent']
    });
    res.status(429).json({ error: 'Too many requests' });
  }
});
```

### Database Query Logging
```javascript
// Log database errors and slow queries
db.query(sql, params, (err, result) => {
  if (err) {
    logEvent('error', 'Database query failed', {
      sql: sql.substring(0, 100) + '...',
      error: err.message,
      duration_ms: Date.now() - queryStart
    });
  }
});
```

---

**🎉 You're all set!** This logging system provides enterprise-grade security monitoring with minimal configuration. Check the logs directory for your security events and set up alerts for production use.