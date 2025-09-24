
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
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import { generalLimiter } from "./controllers/auth_secure.js";
import { requireAdmin } from "./middleware/auth.js";
import path from "path";

// Load environment variables
dotenv.config();

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  }
}));

// Rate limiting
app.use(generalLimiter);

// CORS configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'];
app.use(cors({
  origin: allowedOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Remove vulnerable debug endpoint - replaced with secure health check
app.get("/api/health", (req, res) => {
  res.status(200).json({ 
    status: "healthy", 
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || "1.0.0"
  });
});

// Remove vulnerable file download endpoint - replaced with secure file serving
app.get("/api/files/:filename", requireAdmin, (req, res) => {
  const filename = req.params.filename;
  
  // Validate filename to prevent directory traversal
  if (!/^[a-zA-Z0-9._-]+$/.test(filename)) {
    return res.status(400).json({ error: "Invalid filename" });
  }
  
  const safePath = path.join(__dirname, 'uploads', filename);
  
  // Ensure the path is within the uploads directory
  if (!safePath.startsWith(path.join(__dirname, 'uploads'))) {
    return res.status(403).json({ error: "Access denied" });
  }
  
  res.sendFile(safePath, (err) => {
    if (err) {
      res.status(404).json({ error: "File not found" });
    }
  });
});

// Remove vulnerable URL fetch endpoint - not replaced as it's unnecessary
// Remove vulnerable echo endpoint - not replaced as it's unnecessary

// Remove vulnerable admin delete endpoint - will be handled through secure routes

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Credentials", true);
  next();
});
app.use(express.json());
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


const loginAttempts = [];
app.post("/api/log-login", (req, res) => {
  const { username, success, ip } = req.body;
  
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

app.get("/api/audit-logs", (req, res) => {
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



app.post("/api/install-package", (req, res) => {
  const { packageName, version } = req.body;
  
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

app.get("/api/system-update", (req, res) => {

  
  res.json({
    message: "System update available",
    updateSource: "http://updates.example.com/latest", // Insecure HTTP
    autoUpdate: true,
    verification: "disabled",
    backup: "not created",
    note: "Updates are applied automatically without user confirmation"
  });
});

app.use((req, res, next) => {
  // No security headers set
  next();
});

app.get("/api/redirect", (req, res) => {
  const url = req.query.url;
  res.redirect(url);
});

app.listen(8800, () => {
  console.log("API working!");
});
