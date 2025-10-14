import express from "express";
import authRoutes from "./routes/auth.js";
import userRoutes from "./routes/users.js";
import postRoutes from "./routes/posts.js";
import commentRoutes from "./routes/comments.js";
import likeRoutes from "./routes/likes.js";
import relationshipRoutes from "./routes/relationships.js";
import cors from "cors";
import multer from "multer";
import cookieParser from "cookie-parser";
import fs from "fs";
import path from "path";
import axios from "axios";
import dotenv from "dotenv";
import { db } from "./connect.js";

// Import Winston-based security logging system
import { 
  logEvent, 
  logSecurityEvent, 
  logUserDataAccess, 
  trackFailedLogin, 
  logSuccessfulLogin 
} from "./logger.js";

// Load environment variables
dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());

// -------------------
// Security Logging & Monitoring Setup
// -------------------
logEvent('info', 'API server starting up', {
  startup: true,
  node_version: process.version,
  environment: process.env.NODE_ENV || 'development'
});

// -------------------
// CORS & Security Headers
// -------------------
app.use(cors({ origin: true, credentials: true }));
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Credentials", true);
  res.header("X-Content-Type-Options", "nosniff");
  res.header("X-Frame-Options", "DENY");
  res.header("Content-Security-Policy", "default-src 'self'");
  next();
});


// Legacy login tracking - replaced by Winston logger
const loginAttempts = [];


app.post("/api/log-login", (req, res) => {
  const { username, success, ip } = req.body;
  const userAgent = req.headers['user-agent'] || 'unknown';

  const attempt = {
    username,
    success,
    ip,
    timestamp: new Date().toISOString(),
    userAgent
  };

  // Add to legacy array for backwards compatibility
  loginAttempts.push(attempt);

  if (success) {
    // Log successful login and reset failed attempts
    logSuccessfulLogin(username, ip, userAgent);
  } else {
    // Track failed login and check for account lockout
    const isLocked = trackFailedLogin(username, ip, userAgent);
    
    if (isLocked) {
      return res.status(429).json({
        error: "Account temporarily locked due to multiple failed login attempts",
        message: "Please try again later"
      });
    }
  }

  res.json({
    message: "Login attempt logged",
    recentAttempts: loginAttempts.slice(-5).map(a => ({
      username: a.username,
      success: a.success,
      timestamp: a.timestamp,
      ip: a.ip // Only show to authorized users in production
    }))
  });
});

// -------------------
// Audit Logs (safe) - Enhanced with Winston logging
// -------------------
app.get("/api/audit-logs", (req, res) => {
  // Log audit access
  logSecurityEvent('audit_access', 'Audit logs accessed', {
    requester_ip: req.ip,
    user_agent: req.headers['user-agent']
  });

  res.json({
    loginAttempts: loginAttempts.map(a => ({
      username: a.username,
      success: a.success,
      ip: a.ip,
      timestamp: a.timestamp
    })),
    serverInfo: {
      uptime: process.uptime(),
      environment: process.env.NODE_ENV,
      version: process.version,
      platform: process.platform,
      logging_status: "Winston-based security logging active"
    }
  });
});

// -------------------
// Safe Debug Endpoint
// -------------------
app.get("/api/debug", (req, res) => {
  res.json({ message: "Debug endpoint safe; secrets not exposed" });
});

// -------------------
// Safe File Download
// -------------------
app.get("/api/download", (req, res) => {
  const baseDir = path.join(__dirname, "public/files");
  const safePath = path.join(baseDir, path.basename(req.query.path || ""));

  fs.readFile(safePath, (err, data) => {
    if (err) {
      logSecurityEvent('file_access_denied', 'Failed file download attempt', {
        requested_path: req.query.path,
        safe_path: safePath,
        error: err.message,
        requester_ip: req.ip
      });
      return res.status(404).json({ error: "File not found" });
    }
    logEvent('info', 'File downloaded successfully', {
      file_path: safePath,
      requester_ip: req.ip,
      user_agent: req.headers['user-agent']
    });
    res.send(data);
  });
});

// -------------------
// Safe External Fetch (SSRF prevention)
// -------------------
app.get("/api/fetch", async (req, res) => {
  const { endpoint } = req.query;
  
  // Input validation
  if (!endpoint) {
    return res.status(400).json({ error: "Endpoint parameter is required" });
  }
  
  // Define predefined, safe endpoints instead of allowing arbitrary URLs
  const allowedEndpoints = {
    'weather': 'https://api.openweathermap.org/data/2.5/weather',
    'news': 'https://newsapi.org/v2/top-headlines',
    'quotes': 'https://api.quotable.io/random',
    'time': 'https://worldtimeapi.org/api/timezone/UTC'
  };
  
  // Only allow predefined endpoints
  if (!allowedEndpoints[endpoint]) {
    logSecurityEvent('unauthorized_endpoint_access', 'Blocked fetch to unauthorized endpoint', {
      requested_endpoint: endpoint,
      requester_ip: req.ip,
      user_agent: req.headers['user-agent'],
      allowed_endpoints: Object.keys(allowedEndpoints)
    });
    return res.status(400).json({ 
      error: "Invalid endpoint",
      allowedEndpoints: Object.keys(allowedEndpoints)
    });
  }
  
  const targetUrl = allowedEndpoints[endpoint];
  
  try {
    // Configure axios with security settings
    const axiosConfig = {
      timeout: 5000, // 5 second timeout
      maxRedirects: 0, // No redirects allowed
      validateStatus: (status) => status < 400,
      headers: {
        'User-Agent': 'SecureApp-Fetcher/1.0'
      }
    };
    
    const response = await axios.get(targetUrl, axiosConfig);
    logEvent('info', 'External fetch successful', {
      endpoint: endpoint,
      target_url: targetUrl,
      status_code: response.status,
      requester_ip: req.ip
    });
    
    res.status(200).json({
      success: true,
      endpoint: endpoint,
      data: response.data
    });
  } catch (err) {
    logEvent('error', 'External fetch failed', {
      endpoint: endpoint,
      target_url: targetUrl,
      error: err.message,
      requester_ip: req.ip
    });
    res.status(500).json({ error: "Request failed" });
  }
});

// -------------------
// Safe HTML Echo
// -------------------
app.get("/api/echo", (req, res) => {
  const safeInput = req.query.input ? req.query.input.replace(/</g, "&lt;").replace(/>/g, "&gt;") : "";
  res.send(`<html><body>${safeInput}</body></html>`);
});

// -------------------
// Admin Delete User (auth placeholder + parameterized query)
// -------------------
app.post("/api/admin/deleteUser", (req, res) => {
  const userId = parseInt(req.body.userId);
  if (!userId) return res.status(400).json({ error: "Invalid user ID" });

  // TODO: implement proper authentication & authorization
  db.query("DELETE FROM users WHERE id = ?", [userId], (err, data) => {
    if (err) {
      logEvent('error', 'User deletion failed', {
        user_id: userId,
        error: err.message,
        admin_ip: req.ip,
        user_agent: req.headers['user-agent']
      });
      return res.status(500).json({ error: "Server error" });
    }
    
    // Log critical user data modification
    logUserDataAccess('delete', userId, 'admin', {
      admin_ip: req.ip,
      user_agent: req.headers['user-agent']
    });
    
    res.json({ message: "User deleted safely" });
  });
});

// -------------------
// File Upload (with type validation)
// -------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "../client/public/upload"),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname)
});

const upload = multer({ 
  storage: storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ["image/png", "image/jpeg", "application/pdf"];
    if (!allowedTypes.includes(file.mimetype)) return cb(new Error("File type not allowed"));
    cb(null, true);
  }
});

app.post("/api/upload", upload.single("file"), (req, res) => {
  logEvent('info', 'File uploaded successfully', {
    filename: req.file.filename,
    original_name: req.file.originalname,
    size: req.file.size,
    mimetype: req.file.mimetype,
    uploader_ip: req.ip,
    user_agent: req.headers['user-agent']
  });
  res.status(200).json({ filename: req.file.filename });
});

// -------------------
// Safe Redirect (whitelist)
// -------------------
const allowedRedirects = ["/dashboard", "/profile"];
app.get("/api/redirect", (req, res) => {
  const path = req.query.url;
  if (!allowedRedirects.includes(path)) {
    logSecurityEvent('unsafe_redirect_blocked', 'Blocked unsafe redirect attempt', {
      requested_path: path,
      requester_ip: req.ip,
      user_agent: req.headers['user-agent'],
      allowed_paths: allowedRedirects
    });
    return res.status(400).json({ error: "Invalid redirect path" });
  }
  
  logEvent('info', 'Safe redirect executed', {
    redirect_path: path,
    requester_ip: req.ip,
    user_agent: req.headers['user-agent']
  });
  res.redirect(path);
});

// -------------------
// Routes
// -------------------
app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/posts", postRoutes);
app.use("/api/comments", commentRoutes);
app.use("/api/likes", likeRoutes);
app.use("/api/relationships", relationshipRoutes);

// -------------------
// Error Handling Middleware
// -------------------
app.use((err, req, res, next) => {
  logEvent('error', 'Unhandled server error', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    user_agent: req.headers['user-agent'],
    ip: req.ip
  });
  res.status(500).json({ error: "Internal server error" });
});

// -------------------
// VULNERABLE: Open Redirect (Broken Access Control)
// -------------------
// // NONCOMPLIANT CODE - DO NOT USE IN PRODUCTION
// app.get("/api/unsafe-redirect", (req, res) => {
//   // No security headers set
//   const url = req.query.url;
//   res.redirect(url); // Vulnerable to open redirect attacks
// });

// -------------------
// SECURE: Fixed Open Redirect with URL Validation
// -------------------
app.get("/api/safe-redirect", (req, res) => {
  const url = req.query.url;
  
  // Validate URL to prevent open redirect attacks
  if (!url) {
    return res.status(400).json({ error: "URL parameter is required" });
  }
  
  try {
    const parsedUrl = new URL(url);
    
    // Whitelist allowed domains for external redirects
    const allowedDomains = [
      'www.example.com',
      'app.example.com',
      'secure.example.com'
    ];
    
    // Allow internal redirects (relative paths)
    if (url.startsWith('/')) {
      // Ensure it's a valid internal path
      const allowedPaths = ['/dashboard', '/profile', '/home', '/settings'];
      if (allowedPaths.includes(url)) {
        logEvent('info', 'Safe internal redirect executed', {
          redirect_url: url,
          requester_ip: req.ip
        });
        return res.redirect(url);
      } else {
        logSecurityEvent('unsafe_internal_redirect_blocked', 'Blocked internal redirect attempt', {
          requested_url: url,
          requester_ip: req.ip,
          allowed_paths: allowedPaths
        });
        return res.status(400).json({ error: "Invalid internal redirect path" });
      }
    }
    
    // For external URLs, check against whitelist
    if (allowedDomains.includes(parsedUrl.hostname) && parsedUrl.protocol === 'https:') {
      logEvent('info', 'Safe external redirect executed', {
        redirect_url: url,
        domain: parsedUrl.hostname,
        requester_ip: req.ip
      });
      res.redirect(url);
    } else {
      logSecurityEvent('unsafe_external_redirect_blocked', 'Blocked unsafe external redirect', {
        requested_url: url,
        domain: parsedUrl.hostname,
        protocol: parsedUrl.protocol,
        requester_ip: req.ip,
        allowed_domains: allowedDomains
      });
      res.status(400).json({ error: "Redirect to external domain not allowed" });
    }
    
  } catch (error) {
    logSecurityEvent('invalid_redirect_url', 'Invalid URL format for redirect', {
      requested_url: url,
      error: error.message,
      requester_ip: req.ip
    });
    res.status(400).json({ error: "Invalid URL format" });
  }
});

// -------------------
// VULNERABLE: Path Traversal in File Serving
// -------------------
// // NONCOMPLIANT CODE - DO NOT USE IN PRODUCTION
// app.get("/api/unsafe-file", (req, res) => {
//   const targetDirectory = "/data/app/resources/";
//   const userFilename = path.join(targetDirectory, req.query.filename);
//   res.sendFile(userFilename); // Vulnerable to path traversal
// });

// -------------------
// SECURE: Fixed File Serving with Path Validation
// -------------------
app.get("/api/safe-file", (req, res) => {
  const targetDirectory = path.join(__dirname, "public", "files");
  const userFilename = req.query.filename;
  
  // Validate input
  if (!userFilename) {
    return res.status(400).json({ error: "Filename parameter is required" });
  }
  
  // Prevent path traversal by using path.basename and root option
  const safeFilename = path.basename(userFilename);
  
  // Additional security: validate file extension
  const allowedExtensions = ['.txt', '.pdf', '.jpg', '.png', '.json'];
  const fileExtension = path.extname(safeFilename).toLowerCase();
  
  if (!allowedExtensions.includes(fileExtension)) {
    logSecurityEvent('invalid_file_extension_blocked', 'Blocked file access with invalid extension', {
      requested_filename: userFilename,
      safe_filename: safeFilename,
      extension: fileExtension,
      allowed_extensions: allowedExtensions,
      requester_ip: req.ip
    });
    return res.status(400).json({ error: "File type not allowed" });
  }
  
  // Use sendFile with root option for security
  res.sendFile(safeFilename, { 
    root: targetDirectory,
    dotfiles: 'deny' // Prevent access to hidden files
  }, (err) => {
    if (err) {
      logEvent('error', 'File access error', {
        filename: safeFilename,
        error: err.message,
        status: err.status,
        requester_ip: req.ip
      });
      if (err.status === 404) {
        res.status(404).json({ error: "File not found" });
      } else {
        res.status(500).json({ error: "File access error" });
      }
    } else {
      logEvent('info', 'Safe file access successful', {
        filename: safeFilename,
        requester_ip: req.ip,
        user_agent: req.headers['user-agent']
      });
    }
  });
});

// -------------------
// VULNERABLE: Server-Side Request Forgery (SSRF)
// -------------------
// // NONCOMPLIANT CODE - DO NOT USE IN PRODUCTION
// app.get("/api/unsafe-fetch", async (req, res) => {
//   const url = req.query.url; // No validation - vulnerable to SSRF
//   try {
//     const response = await axios.get(url); // Attacker can access internal services
//     res.send(response.data);
//   } catch (err) {
//     res.status(500).send(err.stack); // Information disclosure
//   }
// });

// -------------------
// SECURE: SSRF Prevention with URL Validation
// -------------------
app.get("/api/secure-fetch", async (req, res) => {
  const url = req.query.url;
  
  // Input validation
  if (!url) {
    return res.status(400).json({ error: "URL parameter is required" });
  }
  
  try {
    // Parse and validate URL
    const parsedUrl = new URL(url);
    
    // Define allowed schemes and domains
    const allowedSchemes = ["http:", "https:"];
    const allowedDomains = [
      "api.example.com",
      "data.example.com", 
      "secure-api.example.org",
      "public-data.trusted.com"
    ];
    
    // Validate scheme
    if (!allowedSchemes.includes(parsedUrl.protocol)) {
      logSecurityEvent('ssrf_invalid_scheme_blocked', 'SSRF attempt blocked - Invalid scheme', {
        url: url,
        scheme: parsedUrl.protocol,
        allowed_schemes: allowedSchemes,
        requester_ip: req.ip
      });
      return res.status(400).json({ 
        error: "Invalid URL scheme. Only HTTP and HTTPS are allowed." 
      });
    }
    
    // Validate domain
    if (!allowedDomains.includes(parsedUrl.hostname)) {
      logSecurityEvent('ssrf_untrusted_domain_blocked', 'SSRF attempt blocked - Untrusted domain', {
        url: url,
        domain: parsedUrl.hostname,
        allowed_domains: allowedDomains,
        requester_ip: req.ip
      });
      return res.status(400).json({ 
        error: "Domain not in allowed list" 
      });
    }
    
    // Additional security checks
    // Prevent access to private IP ranges
    const privateIpRanges = [
      /^127\./, // 127.0.0.0/8 (localhost)
      /^10\./, // 10.0.0.0/8
      /^172\.(1[6-9]|2\d|3[0-1])\./, // 172.16.0.0/12
      /^192\.168\./, // 192.168.0.0/16
      /^169\.254\./, // 169.254.0.0/16 (link-local)
      /^::1$/, // IPv6 localhost
      /^fc00:/, // IPv6 private
      /^fe80:/ // IPv6 link-local
    ];
    
    const isPrivateIp = privateIpRanges.some(range => range.test(parsedUrl.hostname));
    if (isPrivateIp) {
      logSecurityEvent('ssrf_private_ip_blocked', 'SSRF attempt blocked - Private IP access', {
        url: url,
        hostname: parsedUrl.hostname,
        requester_ip: req.ip
      });
      return res.status(400).json({ 
        error: "Access to private IP ranges is not allowed" 
      });
    }
    
    // Prevent access to common internal ports
    const blockedPorts = [22, 23, 25, 53, 110, 143, 993, 995, 1433, 3306, 5432, 6379, 27017];
    if (parsedUrl.port && blockedPorts.includes(Number.parseInt(parsedUrl.port, 10))) {
      logSecurityEvent('ssrf_blocked_port', 'SSRF attempt blocked - Blocked port access', {
        url: url,
        port: parsedUrl.port,
        blocked_ports: blockedPorts,
        requester_ip: req.ip
      });
      return res.status(400).json({ 
        error: "Access to this port is not allowed" 
      });
    }
    
    // Configure axios with security settings
    const axiosConfig = {
      timeout: 5000, // 5 second timeout
      maxRedirects: 3, // Limit redirects
      validateStatus: (status) => status < 400, // Only allow 2xx and 3xx responses
      headers: {
        'User-Agent': 'SecureApp-Fetcher/1.0'
      }
    };
    
    // Make the secure request
    const response = await axios.get(url, axiosConfig);
    
    logEvent('info', 'Secure external fetch successful', {
      url: url,
      status: response.status,
      requester_ip: req.ip
    });
    
    // Return safe response (consider filtering sensitive headers)
    res.status(200).json({
      success: true,
      url: url,
      status: response.status,
      data: response.data,
      // Don't expose internal response headers
      contentType: response.headers['content-type']
    });
    
  } catch (error) {
    if (error.code === 'ENOTFOUND') {
      logEvent('warn', 'SSRF fetch failed - DNS resolution', {
        url: url,
        error_code: error.code,
        requester_ip: req.ip
      });
      return res.status(400).json({ error: "Unable to resolve hostname" });
    } else if (error.code === 'ECONNREFUSED') {
      logEvent('warn', 'SSRF fetch failed - Connection refused', {
        url: url,
        error_code: error.code,
        requester_ip: req.ip
      });
      return res.status(400).json({ error: "Connection refused" });
    } else if (error.code === 'ETIMEDOUT') {
      logEvent('warn', 'SSRF fetch failed - Timeout', {
        url: url,
        error_code: error.code,
        requester_ip: req.ip
      });
      return res.status(400).json({ error: "Request timeout" });
    } else {
      logEvent('error', 'SSRF fetch error', {
        url: url,
        error: error.message,
        error_code: error.code,
        requester_ip: req.ip
      });
      return res.status(500).json({ error: "Request failed" });
    }
  }
});

// -------------------
// Start Server
// -------------------
const PORT = process.env.PORT || 8800;
app.listen(PORT, () => {
  const startupMessage = `API server started securely on port ${PORT}`;
  console.log(startupMessage);
  
  logEvent('info', 'Server started successfully', {
    port: PORT,
    environment: process.env.NODE_ENV || 'development',
    node_version: process.version,
    security_features: [
      'Winston logging enabled',
      'Failed login tracking active',
      'SSRF protection enabled',
      'Path traversal protection enabled',
      'Open redirect protection enabled'
    ]
  });
});
