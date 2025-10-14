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
// VULNERABLE: Server-Side Request Forgery (SSRF) - DO NOT USE IN PRODUCTION
// -------------------
app.get("/api/vulnerable-fetch", async (req, res) => {
  const url = req.query.url; // User-controlled input - DANGEROUS!
  
  // ❌ NO INPUT VALIDATION - VULNERABLE TO SSRF
  if (!url) {
    return res.status(400).json({ error: "URL parameter is required" });
  }
  
  try {
    // ❌ DIRECT REQUEST TO USER-PROVIDED URL - MAJOR SECURITY RISK
    const response = await axios.get(url); // Attacker can access internal services!
    
    logEvent(`Vulnerable fetch executed: ${url}`); // This logs the attack
    res.json({
      success: true,
      url: url,
      data: response.data,
      headers: response.headers // ❌ Exposing internal response headers
    });
  } catch (err) {
    // ❌ INFORMATION DISCLOSURE - Exposing internal error details
    res.status(500).json({ 
      error: "Request failed",
      details: err.message, // ❌ Leaking internal error information
      stack: err.stack      // ❌ Exposing stack trace
    });
  }
});

// -------------------
// SECURE: SSRF Prevention with Comprehensive Validation
// -------------------
app.get("/api/fetch", async (req, res) => {
  const url = req.query.url;
  
  // 1. Input validation
  if (!url) {
    return res.status(400).json({ error: "URL parameter is required" });
  }
  
  try {
    // 2. Parse and validate URL structure
    const parsedUrl = new URL(url);
    
    // 3. Scheme validation - only allow HTTP/HTTPS
    const allowedSchemes = ["http:", "https:"];
    if (!allowedSchemes.includes(parsedUrl.protocol)) {
      logEvent(`SSRF attempt blocked - Invalid scheme: ${parsedUrl.protocol} for URL: ${url}`);
      return res.status(400).json({ 
        error: "Invalid URL scheme. Only HTTP and HTTPS are allowed." 
      });
    }
    
    // 4. Domain allowlist - only trusted domains
    const allowedDomains = [
      "api.example.com",
      "data.example.com", 
      "secure-api.example.org",
      "public-data.trusted.com"
    ];
    
    if (!allowedDomains.includes(parsedUrl.hostname)) {
      logEvent(`SSRF attempt blocked - Untrusted domain: ${parsedUrl.hostname} for URL: ${url}`);
      return res.status(400).json({ 
        error: "Domain not in allowed list",
        allowedDomains: allowedDomains
      });
    }
    
    // 5. Prevent access to private IP ranges
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
      logEvent(`SSRF attempt blocked - Private IP access: ${parsedUrl.hostname}`);
      return res.status(400).json({ 
        error: "Access to private IP ranges is not allowed" 
      });
    }
    
    // 6. Block dangerous ports
    const blockedPorts = [22, 23, 25, 53, 110, 143, 993, 995, 1433, 3306, 5432, 6379, 27017];
    if (parsedUrl.port && blockedPorts.includes(Number.parseInt(parsedUrl.port))) {
      logEvent(`SSRF attempt blocked - Blocked port: ${parsedUrl.port}`);
      return res.status(400).json({ 
        error: "Access to this port is not allowed" 
      });
    }
    
    // 7. Configure secure axios settings
    const axiosConfig = {
      timeout: 5000, // 5 second timeout
      maxRedirects: 3, // Limit redirects
      maxContentLength: 1024 * 1024, // 1MB limit
      validateStatus: (status) => status < 400, // Only 2xx and 3xx
      headers: {
        'User-Agent': 'SecureApp-Fetcher/1.0'
      }
    };
    
    // 8. Make the secure request
    const response = await axios.get(url, axiosConfig);
    
    logEvent(`Secure external fetch successful: ${url}`);
    
    // 9. Return sanitized response (don't expose internal headers)
    res.status(200).json({
      success: true,
      url: url,
      status: response.status,
      data: response.data,
      contentType: response.headers['content-type']
    });
    
  } catch (error) {
    // 10. Proper error handling without information disclosure
    if (error.code === 'ENOTFOUND') {
      logEvent(`SSRF fetch failed - DNS resolution: ${url}`);
      return res.status(400).json({ error: "Unable to resolve hostname" });
    } else if (error.code === 'ECONNREFUSED') {
      logEvent(`SSRF fetch failed - Connection refused: ${url}`);
      return res.status(400).json({ error: "Connection refused" });
    } else if (error.code === 'ETIMEDOUT') {
      logEvent(`SSRF fetch failed - Timeout: ${url}`);
      return res.status(400).json({ error: "Request timeout" });
    } else {
      logEvent(`SSRF fetch failed - General error: ${error.message} for URL: ${url}`);
      return res.status(500).json({ error: "Request failed" });
    }
  }
});

// -------------------
// ALTERNATIVE SECURE APPROACH: Predefined Endpoints Only
// -------------------
app.get("/api/fetch-preset", async (req, res) => {
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
      logEvent(`SSRF attempt blocked - Invalid scheme: ${parsedUrl.protocol} for URL: ${url}`);
      return res.status(400).json({ 
        error: "Invalid URL scheme. Only HTTP and HTTPS are allowed." 
      });
    }
    
    // Validate domain
    if (!allowedDomains.includes(parsedUrl.hostname)) {
      logEvent(`SSRF attempt blocked - Untrusted domain: ${parsedUrl.hostname} for URL: ${url}`);
      return res.status(400).json({ 
        error: "Domain not in allowed list" 
      });
    }
    
    // Additional security checks
    // Prevent access to private IP ranges
    const privateIpRanges = [
      /^127\./, // 127.0.0.0/8 (localhost)
      /^10\./, // 10.0.0.0/8
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12
      /^192\.168\./, // 192.168.0.0/16
      /^169\.254\./, // 169.254.0.0/16 (link-local)
      /^::1$/, // IPv6 localhost
      /^fc00:/, // IPv6 private
      /^fe80:/ // IPv6 link-local
    ];
    
    const isPrivateIp = privateIpRanges.some(range => range.test(parsedUrl.hostname));
    if (isPrivateIp) {
      logEvent(`SSRF attempt blocked - Private IP access: ${parsedUrl.hostname}`);
      return res.status(400).json({ 
        error: "Access to private IP ranges is not allowed" 
      });
    }
    
    // Prevent access to common internal ports
    const blockedPorts = [22, 23, 25, 53, 110, 143, 993, 995, 1433, 3306, 5432, 6379, 27017];
    if (parsedUrl.port && blockedPorts.includes(parseInt(parsedUrl.port))) {
      logEvent(`SSRF attempt blocked - Blocked port: ${parsedUrl.port}`);
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
    
    logEvent(`Secure external fetch successful: ${url}`);
    
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
      logEvent(`SSRF fetch failed - DNS resolution: ${url}`);
      return res.status(400).json({ error: "Unable to resolve hostname" });
    } else if (error.code === 'ECONNREFUSED') {
      logEvent(`SSRF fetch failed - Connection refused: ${url}`);
      return res.status(400).json({ error: "Connection refused" });
    } else if (error.code === 'ETIMEDOUT') {
      logEvent(`SSRF fetch failed - Timeout: ${url}`);
      return res.status(400).json({ error: "Request timeout" });
    } else {
      logEvent(`SSRF fetch error: ${url} - ${error.message}`);
      return res.status(500).json({ error: "Request failed" });
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
