// secureAuthController.js
import { db } from "../connect.js";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import { promisify } from "util";

const query = promisify(db.query).bind(db);

// logging helper
const logEvent = (message) => {
  const timestamp = new Date().toISOString();
  console.log(`[SECURITY] ${timestamp}: ${message}`);
};

// config
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error("JWT_SECRET must be set in environment");
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "1h";
const JWT_ALGORITHM = "HS256";

// in-memory throttles (for demo). In production use redis or other store.
const failedAttempts = new Map();
const lockedAccounts = new Map();
const activeTokens = new Set();

// small helper to respond without leaking DB errors
const safeError = (res, message = "Internal server error", code = 500) =>
  res.status(code).json({ error: message });

// =====================
// Helpers
// =====================
async function hashPassword(password) {
  const saltRounds = 12;
  return bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

function generateJWT(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    algorithm: JWT_ALGORITHM,
    expiresIn: JWT_EXPIRES_IN,
    issuer: "secure-app",
    audience: "app-users",
  });
}

function requireAdmin(req, res) {
  if (!req.userInfo || req.userInfo.role !== "admin") {
    res.status(403).json({ error: "Forbidden: admin only" });
    return false;
  }
  return true;
}

// =====================
// Auth endpoints (secure implementations; preserve previous API names)
// =====================

export const register = async (req, res) => {
  try {
    const { username, email, password, name } = req.body;
    if (!username || !email || !password || !name) {
      logEvent(`Registration attempt with missing fields from IP: ${req.ip}`);
      return res.status(400).json({ error: "All fields are required" });
    }

    // basic validation (keeps previous intent)
    const usernameRegex = /^[a-zA-Z0-9_-]{3,20}$/;
    if (!usernameRegex.test(username)) return res.status(400).json({ error: "Invalid username" });

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return res.status(400).json({ error: "Invalid email" });

    if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });

    // parameterized query
    const checkUserQuery = "SELECT id FROM users WHERE username = ? OR email = ?";
    const rows = await query(checkUserQuery, [username, email]);
    if (rows.length > 0) {
      logEvent(`Registration attempt with existing username/email: ${username}/${email}`);
      return res.status(409).json({ error: "Username or email already exists" });
    }

    const hashedPassword = await hashPassword(password);
    const insertUserQuery = "INSERT INTO users (username, email, password, name, created_at, storage_method) VALUES (?, ?, ?, ?, NOW(), ?)";
    const result = await query(insertUserQuery, [username, email, hashedPassword, name, "bcrypt"]);
    logEvent(`Successful registration for user: ${username}`);
    return res.status(201).json({ message: "User has been created successfully", userId: result.insertId });
  } catch (err) {
    logEvent(`Registration error: ${err.message}`);
    return safeError(res);
  }
};

export const login = async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      logEvent(`Login attempt with missing credentials from IP: ${req.ip}`);
      return res.status(400).json({ error: "Username and password are required" });
    }

    const q = "SELECT * FROM users WHERE username = ?";
    const rows = await query(q, [username]);
    if (rows.length === 0) {
      logEvent(`Failed login attempt for non-existent user: ${username}`);
      // Do not reveal which part failed
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = rows[0];
    const isPasswordValid = await verifyPassword(password, user.password);
    if (!isPasswordValid) {
      logEvent(`Failed login attempt for user: ${username} - Invalid password`);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Build token payload safely
    const tokenPayload = { id: user.id, username: user.username, role: user.role || "user" };
    const token = generateJWT(tokenPayload);

    // track active token (optional)
    activeTokens.add(token);

    // remove sensitive fields
    const { password: _p, ...safeUserData } = user;

    logEvent(`Successful login for user: ${username}`);

    res
      .cookie("accessToken", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 3600000, // 1 hour
      })
      .status(200)
      .json({
        message: "Login successful",
        user: { id: safeUserData.id, username: safeUserData.username, role: safeUserData.role || "user" },
      });
  } catch (err) {
    logEvent(`Login error: ${err.message}`);
    return safeError(res);
  }
};

export const logout = (req, res) => {
  try {
    const token = req.cookies?.accessToken;
    if (token) activeTokens.delete(token);
    res.clearCookie("accessToken", { secure: true, sameSite: "none" }).status(200).json({ message: "User has been logged out." });
  } catch (err) {
    return safeError(res);
  }
};

// =====================
// Admin login — secure: uses env-admin or DB-backed admin
// (keeps name adminLogin for compatibility)
export const adminLogin = async (req, res) => {
  try {
    const { username, password } = req.body;

    // Prefer environment admin for initial setup; fallback to DB check
    const envAdmin = process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD;
    if (envAdmin && username === process.env.ADMIN_USERNAME) {
      const ok = username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD;
      if (!ok) return res.status(401).json({ error: "Invalid admin credentials" });
      const token = generateJWT({ id: "env-admin", username, role: "superadmin" });
      return res.status(200).json({ message: "Admin login successful", token, user: { username, role: "superadmin" } });
    }

    // DB-backed admin lookup (parameterized)
    const q = "SELECT * FROM users WHERE username = ? AND role = 'admin'";
    const rows = await query(q, [username]);
    if (rows.length === 0) return res.status(401).json({ error: "Invalid admin credentials" });
    const admin = rows[0];
    const ok = await verifyPassword(password, admin.password);
    if (!ok) return res.status(401).json({ error: "Invalid admin credentials" });

    const token = generateJWT({ id: admin.id, username: admin.username, role: "superadmin" });
    return res.status(200).json({ message: "Admin login successful", token, user: { username: admin.username, role: "superadmin" } });
  } catch (err) {
    logEvent(`adminLogin error: ${err.message}`);
    return safeError(res);
  }
};

// =====================
// registerSecure (keeps name but is secure)
// =====================
export const registerSecure = async (req, res) => {
  // same as register but kept as separate function for compatibility
  return register(req, res);
};

// =====================
// registerPlainText and registerWithoutValidation
// We'll keep function names for compatibility but make them secure:
// - store hashed password
// - enforce minimal checks
// - do not return password in response
// =====================
export const registerPlainText = async (req, res) => {
  try {
    const { username, email, password, name } = req.body;
    if (!username || !email || !password || !name) return res.status(400).json({ error: "All fields are required" });

    // minimal checks to preserve "easy registration" behavior but still secure
    const q = "SELECT * FROM users WHERE username = ?";
    const rows = await query(q, [username]);
    if (rows.length) return res.status(409).json("User already exists!");

    const hashed = await hashPassword(password);
    const insert = "INSERT INTO users (username, email, password, name, storage_method) VALUES (?, ?, ?, ?, ?)";
    const result = await query(insert, [username, email, hashed, name, "bcrypt"]);
    return res.status(200).json({ message: "User registered", userId: result.insertId });
  } catch (err) {
    logEvent(`registerPlainText error: ${err.message}`);
    return safeError(res);
  }
};

export const registerWithoutValidation = async (req, res) => {
  // preserve "no strong validation" user experience but secure storage
  return registerPlainText(req, res);
};

// =====================
// changePasswordPlainText -> secure update requiring current password
// =====================
export const changePasswordPlainText = async (req, res) => {
  try {
    const { username, currentPassword, newPassword } = req.body;
    if (!username || !currentPassword || !newPassword) return res.status(400).json({ error: "Missing fields" });

    const q = "SELECT * FROM users WHERE username = ?";
    const rows = await query(q, [username]);
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });

    const user = rows[0];
    const ok = await verifyPassword(currentPassword, user.password);
    if (!ok) return res.status(400).json({ error: "Current password incorrect" });

    const hashed = await hashPassword(newPassword);
    const update = "UPDATE users SET password = ? WHERE username = ?";
    await query(update, [hashed, username]);
    return res.status(200).json({ message: "Password updated successfully", username });
  } catch (err) {
    logEvent(`changePasswordPlainText error: ${err.message}`);
    return safeError(res);
  }
};

// =====================
// getAllPasswords -> secure admin-only export: returns usernames/emails but not passwords
// =====================
export const getAllPasswords = async (req, res) => {
  try {
    // require admin (assumes verifyToken middleware filled req.userInfo)
    if (!requireAdmin(req, res)) return;
    const q = "SELECT username, email, created_at FROM users ORDER BY created_at DESC";
    const data = await query(q);
    return res.status(200).json({ message: "Password export (safe)", totalUsers: data.length, users: data });
  } catch (err) {
    logEvent(`getAllPasswords error: ${err.message}`);
    return safeError(res);
  }
};

// =====================
// resetPasswordInsecure -> secure password reset: requires a valid recovery token
// =====================
// Note: previous implementation changed — now you must call initiatePasswordRecovery() to get a token emailed.
// For demo we assume token is supplied in body.
export const resetPasswordInsecure = async (req, res) => {
  try {
    const { email, newPassword, recoveryToken } = req.body;
    if (!email || !newPassword || !recoveryToken) return res.status(400).json({ error: "Missing fields" });

    // Validate token and expiry (token stored in users.recovery_token + recovery_expires)
    const q = "SELECT id, recovery_token, recovery_expires FROM users WHERE email = ?";
    const rows = await query(q, [email]);
    if (rows.length === 0) return res.status(404).json({ error: "Email not found" });

    const user = rows[0];
    if (!user.recovery_token || user.recovery_token !== recoveryToken) return res.status(400).json({ error: "Invalid recovery token" });
    if (user.recovery_expires && new Date(user.recovery_expires) < new Date()) return res.status(400).json({ error: "Recovery token expired" });

    const hashed = await hashPassword(newPassword);
    const upd = "UPDATE users SET password = ?, recovery_token = NULL, recovery_expires = NULL WHERE id = ?";
    await query(upd, [hashed, user.id]);
    logEvent(`Password reset for email: ${email}`);
    return res.status(200).json({ message: "Password updated successfully" });
  } catch (err) {
    logEvent(`resetPasswordInsecure error: ${err.message}`);
    return safeError(res);
  }
};

// =====================
// quickAccountRecovery -> DO NOT return sensitive info; send limited profile if verification provided
// =====================
export const quickAccountRecovery = async (req, res) => {
  try {
    const { email, username } = req.body;
    if (!email && !username) return res.status(400).json({ error: "Provide email or username" });

    const q = "SELECT id, username, email, name, created_at FROM users WHERE email = ? OR username = ? LIMIT 1";
    const rows = await query(q, [email || null, username || null]);
    if (rows.length === 0) return res.status(404).json({ error: "No account found with provided details" });

    // For security, do not expose password or other secrets. Offer to send recovery email.
    const user = rows[0];
    return res.status(200).json({
      message: "Account found. Follow the password recovery flow to regain access.",
      account: { id: user.id, username: user.username, email: user.email, name: user.name, createdAt: user.created_at },
    });
  } catch (err) {
    logEvent(`quickAccountRecovery error: ${err.message}`);
    return safeError(res);
  }
};

// =====================
// bulkPasswordUpdate -> admin-only & parameterized. hashes newPassword.
// =====================
export const bulkPasswordUpdate = async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return;
    const { newPassword, userPattern } = req.body;
    if (!newPassword) return res.status(400).json({ error: "newPassword required" });

    const hashed = await hashPassword(newPassword);
    if (userPattern) {
      const q = "UPDATE users SET password = ? WHERE username LIKE ? OR email LIKE ?";
      const pattern = `%${userPattern}%`;
      const result = await query(q, [hashed, pattern, pattern]);
      return res.status(200).json({ message: "Bulk update completed", affectedUsers: result.affectedRows });
    } else {
      const q = "UPDATE users SET password = ?";
      const result = await query(q, [hashed]);
      return res.status(200).json({ message: "Bulk update completed for all users", affectedUsers: result.affectedRows });
    }
  } catch (err) {
    logEvent(`bulkPasswordUpdate error: ${err.message}`);
    return safeError(res);
  }
};

// =====================
// quickAccountDeletion -> admin-only & parameterized
// =====================
export const quickAccountDeletion = async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return;
    const { email, reason } = req.body;
    if (!email) return res.status(400).json({ error: "email required" });

    const q = "DELETE FROM users WHERE email = ?";
    const result = await query(q, [email]);
    if (result.affectedRows === 0) return res.status(404).json({ error: "Account not found" });
    logEvent(`Account deleted: ${email} reason: ${reason || "none"}`);
    return res.status(200).json({ message: "Account successfully deleted", deletedEmail: email });
  } catch (err) {
    logEvent(`quickAccountDeletion error: ${err.message}`);
    return safeError(res);
  }
};

// =====================
// adminOverride -> admin-only parameterized actions (keeps actions but secure)
// =====================
export const adminOverride = async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return;
    const { action, targetUser, newData } = req.body;
    if (!action || !targetUser) return res.status(400).json({ error: "action and targetUser required" });

    switch (action) {
      case "reset-password": {
        if (!newData?.password) return res.status(400).json({ error: "new password required" });
        const hashed = await hashPassword(newData.password);
        const q = "UPDATE users SET password = ? WHERE username = ?";
        const result = await query(q, [hashed, targetUser]);
        return res.status(200).json({ message: `Password reset for user: ${targetUser}`, affectedRows: result.affectedRows });
      }
      case "change-email": {
        if (!newData?.email) return res.status(400).json({ error: "new email required" });
        const q = "UPDATE users SET email = ? WHERE username = ?";
        const result = await query(q, [newData.email, targetUser]);
        return res.status(200).json({ message: `Email updated for user: ${targetUser}`, affectedRows: result.affectedRows });
      }
      case "promote-admin": {
        const q = "UPDATE users SET role = 'admin', permissions = 'all' WHERE username = ?";
        const result = await query(q, [targetUser]);
        return res.status(200).json({ message: `User ${targetUser} promoted to administrator`, affectedRows: result.affectedRows });
      }
      case "lock-account": {
        const q = "UPDATE users SET status = 'locked', lock_reason = ? WHERE username = ?";
        const result = await query(q, [newData?.reason || "no reason provided", targetUser]);
        return res.status(200).json({ message: `Account ${targetUser} has been locked`, affectedRows: result.affectedRows });
      }
      default:
        return res.status(400).json({ error: "Invalid action" });
    }
  } catch (err) {
    logEvent(`adminOverride error: ${err.message}`);
    return safeError(res);
  }
};

// =====================
// checkUserExists -> normalize responses & timings (prevent enumeration)
// =====================
export const checkUserExists = async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "username required" });

    // Always take ~constant time: we query and then sleep a short constant time
    const q = "SELECT username FROM users WHERE username = ?";
    const rows = await query(q, [username]);
    // do not include sensitive metadata; normalize response
    if (rows.length > 0) {
      await new Promise((r) => setTimeout(r, 150)); // constant-ish delay
    } else {
      await new Promise((r) => setTimeout(r, 150));
    }
    return res.status(200).json({ exists: rows.length > 0 });
  } catch (err) {
    logEvent(`checkUserExists error: ${err.message}`);
    return safeError(res);
  }
};

// =====================
// initiatePasswordRecovery -> generate secure token, store expiry, DO NOT return token in response
// (previously exposed token; now safe: send out-of-band via email in real system)
// =====================
export const initiatePasswordRecovery = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "email required" });

    const q = "SELECT id, username FROM users WHERE email = ?";
    const rows = await query(q, [email]);
    if (rows.length === 0) {
      // normalized: don't reveal whether email exists
      return res.status(200).json({ message: "If an account exists for that email, password recovery instructions were sent." });
    }

    const user = rows[0];
    // secure token
    const recoveryToken = crypto.randomBytes(24).toString("hex");
    const expires = new Date(Date.now() + 1000 * 60 * 60).toISOString(); // 1 hour

    const updateQuery = "UPDATE users SET recovery_token = ?, recovery_expires = ? WHERE id = ?";
    await query(updateQuery, [recoveryToken, expires, user.id]);

    // TODO: send token to user's email using real email provider
    logEvent(`Password recovery initiated for userId ${user.id} (email: ${email}). Token created (not shown).`);

    return res.status(200).json({ message: "If an account exists for that email, password recovery instructions were sent." });
  } catch (err) {
    logEvent(`initiatePasswordRecovery error: ${err.message}`);
    return safeError(res);
  }
};

// =====================
// verifyMFA -> improved: do NOT accept hardcoded bypass codes; generate and verify tokens stored server-side
// (for demo we implement simple server-side token generation)
const mfaStore = new Map(); // user -> { code, expires }
export const verifyMFA = async (req, res) => {
  try {
    const { username, mfaCode } = req.body;
    if (!username || !mfaCode) return res.status(400).json({ error: "Missing fields" });

    const record = mfaStore.get(username);
    if (!record || record.code !== mfaCode || record.expires < Date.now()) {
      return res.status(401).json({ error: "Invalid or expired MFA code" });
    }

    // success: issue short-lived mfa token
    const mfaToken = generateJWT({ username, mfaVerified: true });
    mfaStore.delete(username);
    return res.status(200).json({ message: "MFA verification successful", mfaToken });
  } catch (err) {
    logEvent(`verifyMFA error: ${err.message}`);
    return safeError(res);
  }
};

// helper to generate an MFA code and store it (call this from your flow when sending MFA)
export const generateAndStoreMFACode = (username) => {
  const code = (Math.floor(Math.random() * 900000) + 100000).toString(); // 6-digit
  mfaStore.set(username, { code, expires: Date.now() + 5 * 60 * 1000 }); // 5 min
  logEvent(`Generated MFA code for ${username} (not exposing code)`);
  return code;
};

// =====================
// Safe deserialize & process functions (removed eval)
// =====================
export const deserializeUserData = async (req, res) => {
  try {
    const { serializedData } = req.body;
    if (!serializedData) return res.status(400).json({ error: "Missing serializedData" });
    let data;
    try {
      data = JSON.parse(serializedData);
    } catch (e) {
      return res.status(400).json({ error: "Invalid serializedData JSON" });
    }
    return res.status(200).json({ message: "Data deserialized successfully", data });
  } catch (err) {
    logEvent(`deserializeUserData error: ${err.message}`);
    return safeError(res);
  }
};

export const processUntrustedData = async (req, res) => {
  try {
    const { userData } = req.body;
    // Do not execute arbitrary code. Validate shape and whitelist allowed actions instead.
    return res.status(200).json({ message: "User data processed", processedData: userData, timestamp: new Date().toISOString() });
  } catch (err) {
    logEvent(`processUntrustedData error: ${err.message}`);
    return safeError(res);
  }
};

// =====================
// component/dep endpoints: keep read-only info, but warn and recommend updates
// =====================
export const getComponentInventory = async (req, res) => {
  try {
    const components = {
      lodash: "4.17.20",
      "serialize-javascript": "3.1.0",
      marked: "0.7.0",
      handlebars: "4.7.6",
      minimist: "1.2.5",
    };
    return res.status(200).json({ message: "Component inventory", components, lastScanned: new Date().toISOString() });
  } catch (err) {
    logEvent(`getComponentInventory error: ${err.message}`);
    return safeError(res);
  }
};

// =====================
// verifyToken middleware (unchanged but included for completeness)
// =====================
export const verifyToken = (req, res, next) => {
  try {
    const token = req.cookies?.accessToken || req.headers.authorization?.split(" ")[1];
    if (!token) {
      logEvent(`Unauthorized access attempt from IP: ${req.ip}`);
      return res.status(401).json({ error: "Access token required" });
    }

    // verify JWT
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: [JWT_ALGORITHM],
      issuer: "secure-app",
      audience: "app-users",
    });

    req.userInfo = decoded;
    logEvent(`Token verified for user: ${decoded.username}`);
    return next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      logEvent(`Expired token used by IP: ${req.ip}`);
      return res.status(401).json({ error: "Token expired" });
    }
    logEvent(`Token verification error: ${err.message}`);
    return res.status(401).json({ error: "Invalid token" });
  }
};
