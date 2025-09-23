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
