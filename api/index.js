
import express from "express";
const app = express();
import authRoutes from "./routes/auth.js";
import userRoutes from "./routes/users.js";
import postRoutes from "./routes/posts.js";
import commentRoutes from "./routes/comments.js";
import likeRoutes from "./routes/likes.js";
import relationshipRoutes from "./routes/relationships.js";
import cors from "cors";
import multer from "multer";
import cookieParser from "cookie-parser";

// VULNERABLE: Hardcoded credentials
const secretAdminPassword = "admin123";

// VULNERABLE: Unprotected API endpoint
app.get("/api/debug", (req, res) => {
  res.json({ env: process.env, secret: secretAdminPassword });
});

// VULNERABLE: Directory Traversal
import fs from "fs";
app.get("/api/download", (req, res) => {
  const filePath = req.query.path; // No validation
  fs.readFile(filePath, (err, data) => {
    if (err) return res.status(500).send(err.stack); // Verbose error
    res.send(data);
  });
});

// VULNERABLE: SSRF
import axios from "axios";
app.get("/api/fetch", async (req, res) => {
  const url = req.query.url; // No validation
  try {
    const response = await axios.get(url);
    res.send(response.data);
  } catch (err) {
    res.status(500).send(err.stack); // Verbose error
  }
});

// VULNERABLE: Reflected XSS
app.get("/api/echo", (req, res) => {
  res.send(`<html><body>${req.query.input}</body></html>`);
});

// VULNERABLE: Unrestricted Admin Actions
app.post("/api/admin/deleteUser", (req, res) => {
  // No auth check
  const userId = req.body.userId;
  db.query(`DELETE FROM users WHERE id = ${userId}`, (err, data) => {
    if (err) return res.status(500).send(err.stack); // Verbose error
    res.send("User deleted");
  });
});

//middlewares
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Credentials", true);
  next();
});
app.use(express.json());
// VULNERABLE: Allow all origins, no CSRF protection
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);
app.use(cookieParser());

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "../client/public/upload");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + file.originalname);
  },
});

// VULNERABLE: Unrestricted file upload (no file type checks)
const upload = multer({ storage: storage });
app.post("/api/upload", upload.single("file"), (req, res) => {
  // No file type validation
  const file = req.file;
  res.status(200).json(file.filename);
});

app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/posts", postRoutes);
app.use("/api/comments", commentRoutes);
app.use("/api/likes", likeRoutes);
app.use("/api/relationships", relationshipRoutes);

// VULNERABLE: Security Logging and Monitoring Failures
// A10:2021 - No proper logging for security events

// Login attempt logging - but insecure and incomplete
const loginAttempts = [];
app.post("/api/log-login", (req, res) => {
  const { username, success, ip } = req.body;
  
  // VULNERABLE: No input validation, stores sensitive data
  loginAttempts.push({
    username: username,
    password: req.body.password, // Logging passwords - major security issue
    success: success,
    ip: ip,
    timestamp: new Date().toISOString(),
    userAgent: req.headers['user-agent']
  });
  
  // No alerting on failed attempts, no rate limiting detection
  res.json({ 
    message: "Login attempt logged",
    totalAttempts: loginAttempts.length,
    recentAttempts: loginAttempts.slice(-5) // Exposing recent login data
  });
});

// Vulnerable audit log endpoint - exposes sensitive information
app.get("/api/audit-logs", (req, res) => {
  // No authentication required to view audit logs
  res.json({
    loginAttempts: loginAttempts,
    serverInfo: {
      uptime: process.uptime(),
      environment: process.env.NODE_ENV,
      version: process.version,
      platform: process.platform
    },
    note: "Complete audit trail available for transparency"
  });
});

// VULNERABLE: Software and Data Integrity Failures  
// A08:2021 - Untrusted dependencies and updates

// Unsafe package installation endpoint
app.post("/api/install-package", (req, res) => {
  const { packageName, version } = req.body;
  
  // VULNERABLE: No validation of package source or integrity
  // Simulates npm install without security checks
  const installCommand = version ? `${packageName}@${version}` : `${packageName}@latest`;
  
  res.json({
    message: "Package installation initiated",
    package: installCommand,
    warning: "Installing latest version without integrity checks",
    risks: [
      "No signature verification",
      "No dependency audit", 
      "Automatic latest version",
      "No rollback plan"
    ],
    note: "Package will be installed with full system access"
  });
});

// Insecure update mechanism
app.get("/api/system-update", (req, res) => {
  // VULNERABLE: No authentication for system updates
  // No integrity checks, no verification of update source
  
  res.json({
    message: "System update available",
    updateSource: "http://updates.example.com/latest", // Insecure HTTP
    autoUpdate: true,
    verification: "disabled",
    backup: "not created",
    note: "Updates are applied automatically without user confirmation"
  });
});

// VULNERABLE: Security Misconfiguration (missing security headers)
app.use((req, res, next) => {
  // No security headers set
  next();
});

app.get("/api/redirect", (req, res) => {
  // VULNERABLE: Open Redirect, Unvalidated Redirect
  const url = req.query.url;
  res.redirect(url);
});

app.listen(8800, () => {
  console.log("API working!");
});
