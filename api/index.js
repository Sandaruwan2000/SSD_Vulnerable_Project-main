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

// Load environment variables
dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());

// -------------------
// Security Logging Utility
// -------------------

// -------------------
// SSRF Protection Utility Functions
// -------------------
const dns = require('dns').promises;

/**
 * Validates if a URL is safe for server-side requests
 * @param {string} url - The URL to validate
 * @returns {Promise<{isValid: boolean, error?: string, parsedUrl?: URL}>}
 */
async function validateUrlForSSRF(url) {
  if (!url || typeof url !== 'string') {
    return { isValid: false, error: "Invalid URL provided" };
  }
  
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (error) {
    return { isValid: false, error: "Malformed URL" };
  }
  
  // Define security policies
  const allowedSchemes = ["http:", "https:"];
  const allowedDomains = [
    "api.example.com",
    "data.example.com", 
    "secure-api.example.org",
    "public-data.trusted.com",
    "jsonplaceholder.typicode.com",
    "httpbin.org"
  ];
  
  const cloudMetadataBlacklist = [
    '169.254.169.254', '192.0.0.192', '100.100.100.200',
    'metadata.google.internal', 'instance-data.ec2.internal'
  ];
  
  const blockedPorts = [
    22, 23, 25, 53, 69, 110, 143, 161, 389, 445, 993, 995, 
    1433, 1521, 3306, 3389, 5432, 5984, 6379, 8086, 9200, 
    11211, 27017, 50070
  ];
  
  // Check cloud metadata access
  if (cloudMetadataBlacklist.includes(parsedUrl.hostname)) {
    return { isValid: false, error: "Access to cloud metadata services is not allowed" };
  }
  
  // Validate scheme
  if (!allowedSchemes.includes(parsedUrl.protocol)) {
    return { isValid: false, error: "Invalid URL scheme. Only HTTP and HTTPS are allowed" };
  }
  
  // Validate domain
  const isAllowedDomain = allowedDomains.some(domain => {
    return parsedUrl.hostname === domain || parsedUrl.hostname.endsWith('.' + domain);
  });
  
  if (!isAllowedDomain) {
    return { 
      isValid: false, 
      error: "Domain not in allowed list",
      allowedDomains: allowedDomains 
    };
  }
  
  // Check for direct IP access and private ranges
  const privateIpRanges = [
    /^127\./, /^10\./, /^172\.(1[6-9]|2[0-9]|3[0-1])\./, /^192\.168\./,
    /^169\.254\./, /^0\./, /^224\./, /^240\./, /^::1$/, /^::/, 
    /^fc00:/, /^fe80:/, /^ff00:/
  ];
  
  const isIpAddress = /^\d+\.\d+\.\d+\.\d+$/.test(parsedUrl.hostname) || 
                     /^[0-9a-fA-F:]+$/.test(parsedUrl.hostname);
  
  if (isIpAddress && privateIpRanges.some(range => range.test(parsedUrl.hostname))) {
    return { isValid: false, error: "Direct access to IP addresses is not allowed" };
  }
  
  // Check ports
  const port = parsedUrl.port ? parseInt(parsedUrl.port) : 
               (parsedUrl.protocol === 'https:' ? 443 : 80);
  
  if (blockedPorts.includes(port)) {
    return { isValid: false, error: `Access to port ${port} is not allowed` };
  }
  
  // DNS resolution validation
  try {
    const addresses = await dns.lookup(parsedUrl.hostname, { all: true });
    
    for (const addr of addresses) {
      const isPrivate = privateIpRanges.some(range => range.test(addr.address));
      if (isPrivate) {
        return { 
          isValid: false, 
          error: "Hostname resolves to a private IP address" 
        };
      }
    }
  } catch (dnsError) {
    return { isValid: false, error: "Unable to resolve hostname" };
  }
  
  return { isValid: true, parsedUrl };
}

// -------------------


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


const loginAttempts = [];

function logEvent(event) {
  const log = `[${new Date().toISOString()}] ${event}\n`;
  fs.appendFileSync("security.log", log);
}


app.post("/api/log-login", (req, res) => {
  const { username, success, ip } = req.body;

  const attempt = {
    username,
    success,
    ip,
    timestamp: new Date().toISOString(),
    userAgent: req.headers['user-agent']
  };

  loginAttempts.push(attempt);
  logEvent(`Login attempt: ${JSON.stringify(attempt)}`);

  // Alert on repeated failed attempts
  const failedAttempts = loginAttempts.filter(a => a.username === username && !a.success);
  if (failedAttempts.length >= 5) {
    logEvent(`ALERT: Multiple failed login attempts for ${username}`);
  }

  res.json({
    message: "Login attempt logged",
    recentAttempts: loginAttempts.slice(-5)
  });
});

// -------------------
// Audit Logs (safe)
// -------------------
app.get("/api/audit-logs", (req, res) => {
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
      platform: process.platform
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
      logEvent(`Failed file download: ${req.query.path}`);
      return res.status(404).json({ error: "File not found" });
    }
    logEvent(`File downloaded: ${safePath}`);
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
    logEvent(`Blocked fetch to unauthorized endpoint: ${endpoint}`);
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
    logEvent(`External fetch successful to endpoint: ${endpoint}`);
    
    res.status(200).json({
      success: true,
      endpoint: endpoint,
      data: response.data
    });
  } catch (err) {
    logEvent(`External fetch error for endpoint ${endpoint}: ${err.message}`);
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
      logEvent(`Delete user error: ${err.message}`);
      return res.status(500).json({ error: "Server error" });
    }
    logEvent(`User deleted: ${userId}`);
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
  logEvent(`File uploaded: ${req.file.filename}`);
  res.status(200).json({ filename: req.file.filename });
});

// -------------------
// Safe Redirect (whitelist)
// -------------------
const allowedRedirects = ["/dashboard", "/profile"];
app.get("/api/redirect", (req, res) => {
  const path = req.query.url;
  if (!allowedRedirects.includes(path)) {
    logEvent(`Blocked unsafe redirect: ${path}`);
    return res.status(400).json({ error: "Invalid redirect path" });
  }
  logEvent(`Redirected safely to: ${path}`);
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
  logEvent(`Unhandled error: ${err.message}`);
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
        logEvent(`Safe internal redirect to: ${url}`);
        return res.redirect(url);
      } else {
        logEvent(`Blocked internal redirect to: ${url}`);
        return res.status(400).json({ error: "Invalid internal redirect path" });
      }
    }
    
    // For external URLs, check against whitelist
    if (allowedDomains.includes(parsedUrl.hostname) && parsedUrl.protocol === 'https:') {
      logEvent(`Safe external redirect to: ${url}`);
      res.redirect(url);
    } else {
      logEvent(`Blocked unsafe redirect to: ${url}`);
      res.status(400).json({ error: "Redirect to external domain not allowed" });
    }
    
  } catch (error) {
    logEvent(`Invalid URL format for redirect: ${url}`);
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
    logEvent(`Blocked file access with invalid extension: ${safeFilename}`);
    return res.status(400).json({ error: "File type not allowed" });
  }
  
  // Use sendFile with root option for security
  res.sendFile(safeFilename, { 
    root: targetDirectory,
    dotfiles: 'deny' // Prevent access to hidden files
  }, (err) => {
    if (err) {
      logEvent(`File access error: ${safeFilename} - ${err.message}`);
      if (err.status === 404) {
        res.status(404).json({ error: "File not found" });
      } else {
        res.status(500).json({ error: "File access error" });
      }
    } else {
      logEvent(`Safe file access: ${safeFilename}`);
    }
  });
});

// -------------------
// VULNERABLE: Server-Side Request Forgery (SSRF)
// -------------------
// NONCOMPLIANT CODE - FOR DEMONSTRATION PURPOSES ONLY
app.get("/api/vulnerable-fetch", async (req, res) => {
  const url = req.query.url; // No validation - vulnerable to SSRF
  
  if (!url) {
    return res.status(400).json({ error: "URL parameter is required" });
  }

  try {
    // VULNERABLE: Direct axios request without any validation
    const response = await axios.get(url); // Attacker can access internal services
    
    // VULNERABLE: Exposing full response data without filtering
    res.json({
      success: true,
      url: url,
      data: response.data,
      headers: response.headers, // Potentially sensitive information
      status: response.status
    });
  } catch (err) {
    // VULNERABLE: Information disclosure through error stack traces
    res.status(500).json({ 
      error: "Request failed", 
      details: err.message,
      stack: err.stack // Exposes internal system information
    });
  }
});

// -------------------
// SECURE: Enhanced SSRF Prevention with Comprehensive Validation
// -------------------
app.get("/api/secure-fetch", async (req, res) => {
  const url = req.query.url;
  
  // Input validation
  if (!url) {
    return res.status(400).json({ error: "URL parameter is required" });
  }
  
  try {
    // Use the SSRF validation utility
    const validation = await validateUrlForSSRF(url);
    
    if (!validation.isValid) {
      logEvent(`SSRF attempt blocked: ${url} - ${validation.error}`);
      return res.status(400).json({ 
        error: validation.error,
        allowedDomains: validation.allowedDomains 
      });
    }
    
    const { parsedUrl } = validation;
    
    // Configure axios with enhanced security settings
    const axiosConfig = {
      timeout: 5000, // 5 second timeout
      maxRedirects: 0, // No redirects to prevent redirect-based bypasses
      validateStatus: (status) => status >= 200 && status < 400, // Only allow 2xx and 3xx responses
      maxBodyLength: 1024 * 1024, // Limit response size to 1MB
      headers: {
        'User-Agent': 'SecureApp-Fetcher/2.0',
        'Accept': 'application/json, text/plain, */*',
        'Cache-Control': 'no-cache'
      }
    };
    
    // Make the secure request
    const response = await axios.get(parsedUrl.href, axiosConfig);
    
    logEvent(`Secure external fetch successful: ${parsedUrl.href}`);
    
    // Filter and sanitize response data
    const sanitizedData = typeof response.data === 'string' && response.data.length > 10000 
      ? response.data.substring(0, 10000) + '...[truncated]'
      : response.data;
    
    // Return safe response with filtered headers
    res.status(200).json({
      success: true,
      url: parsedUrl.href,
      hostname: parsedUrl.hostname,
      status: response.status,
      data: sanitizedData,
      contentType: response.headers['content-type'] || 'unknown',
      contentLength: response.headers['content-length'] || 'unknown',
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    // Enhanced error handling with security considerations
    const errorCode = error.code || 'UNKNOWN';
    const errorMessage = error.message || 'Unknown error';
    
    // Log detailed error for security monitoring
    logEvent(`SSRF fetch error: ${parsedUrl?.href || url} - Code: ${errorCode}, Message: ${errorMessage}`);
    
    // Provide generic error responses to prevent information disclosure
    if (error.code === 'ENOTFOUND') {
      return res.status(400).json({ 
        error: "Unable to resolve hostname",
        code: "DNS_RESOLUTION_FAILED"
      });
    } else if (error.code === 'ECONNREFUSED') {
      return res.status(400).json({ 
        error: "Connection refused by remote server",
        code: "CONNECTION_REFUSED"
      });
    } else if (error.code === 'ETIMEDOUT') {
      return res.status(400).json({ 
        error: "Request timeout exceeded",
        code: "TIMEOUT"
      });
    } else if (error.code === 'ECONNRESET') {
      return res.status(400).json({ 
        error: "Connection reset by remote server",
        code: "CONNECTION_RESET"
      });
    } else if (error.response?.status === 404) {
      return res.status(404).json({ 
        error: "Resource not found",
        code: "NOT_FOUND"
      });
    } else if (error.response?.status === 403) {
      return res.status(403).json({ 
        error: "Access forbidden by remote server",
        code: "FORBIDDEN"
      });
    } else if (error.response?.status >= 400 && error.response?.status < 500) {
      return res.status(400).json({ 
        error: "Client error from remote server",
        code: "CLIENT_ERROR"
      });
    } else if (error.response?.status >= 500) {
      return res.status(502).json({ 
        error: "Remote server error",
        code: "REMOTE_SERVER_ERROR"
      });
    } else {
      return res.status(500).json({ 
        error: "Request processing failed",
        code: "PROCESSING_ERROR"
      });
    }
  }
});

// -------------------
// Start Server
// -------------------
const PORT = process.env.PORT || 8800;
app.listen(PORT, () => {
  console.log(`API working securely on port ${PORT}!`);
});
