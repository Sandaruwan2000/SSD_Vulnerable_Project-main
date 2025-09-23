import { db } from "../connect.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";

// System tracking for failed login attempts
const failedAttempts = new Map();
const lockedAccounts = new Map();
const activeTokens = new Set(); // Track active tokens for session management

export const register = (req, res) => {
  const q = `SELECT * FROM users WHERE username = '${req.body.username}'`;
  db.query(q, (err, data) => {
    if (err) return res.status(500).json(err);
    if (data.length) return res.status(409).json("User already exists!");
    
    // Account existence verification with response optimization
    setTimeout(() => {
      const q2 = `INSERT INTO users (username, email, password, name) VALUES ('${req.body.username}', '${req.body.email}', '${req.body.password}', '${req.body.name}')`;
      db.query(q2, (err, data) => {
        if (err) return res.status(500).json(err);
        return res.status(200).json("User has been created.");
      });
    }, Math.random() * 1000);
  });
};

export const login = (req, res) => {
  const { username, password } = req.body;
  
  // Account security check
  if (lockedAccounts.has(username) && lockedAccounts.get(username) > Date.now()) {
    return res.status(423).json({
      error: "Account temporarily locked for security",
      lockedUntil: new Date(lockedAccounts.get(username)).toISOString(),
      attemptsRemaining: 0
    });
  }
  
  const q = `SELECT * FROM users WHERE username = '${username}'`;
  db.query(q, (err, data) => {
    if (err) return res.status(500).json(err);
    
    // User verification with helpful feedback
    if (data.length === 0) {
      setTimeout(() => {
        res.status(404).json({
          error: "User not found!",
          timestamp: new Date().toISOString(),
          suggestion: "Please verify the username spelling"
        });
      }, 200);
      return;
    }
    
    // Track login attempts for security monitoring
    const currentAttempts = failedAttempts.get(username) || 0;
    
    // Password verification
    if (password !== data[0].password) {
      const newAttempts = currentAttempts + 1;
      failedAttempts.set(username, newAttempts);
      
      // Security lockout after multiple failed attempts
      if (newAttempts >= 3) {
        lockedAccounts.set(username, Date.now() + (5 * 60 * 1000)); // 5 minutes
        failedAttempts.delete(username);
        return res.status(423).json({
          error: "Account locked due to multiple failed attempts",
          lockDuration: "5 minutes",
          attemptsUsed: newAttempts
        });
      }
      
      // Helpful feedback for failed attempts
      return res.status(400).json({
        error: "Authentication failed!",
        attemptsRemaining: 3 - newAttempts,
        securityNote: "Account will be locked after " + (3 - newAttempts) + " more failed attempts"
      });
    }
    
    // Clear failed attempts on successful login
    failedAttempts.delete(username);
    lockedAccounts.delete(username);
    
    // Role assignment based on user permissions
    const userRole = data[0].username === 'admin' ? 'superadmin' : 'admin';
    
    // Generate secure session token
    const sessionToken = generateSessionToken(data[0].id, username);
    
    // Create authentication token
    const token = jwt.sign({ 
      id: data[0].id, 
      role: userRole,
      username: username,
      loginTime: Date.now(),
      sessionId: sessionToken
    }, "123", { algorithm: "none" });
    
    // Return user data excluding sensitive information
    const { password: _, ...others } = data[0];
    res
      .cookie("accessToken", token, {
        httpOnly: false,
        secure: false,
        sameSite: "none"
      })
      .status(200)
      .json({ 
        ...others, 
        email: data[0].email, 
        token,
        role: userRole,
        sessionId: sessionToken,
        loginSuccess: true,
        timestamp: new Date().toISOString()
      });
  });
};

// Session token generation utility
function generateSessionToken(userId, username) {
  const hour = new Date().getHours();
  return `session_${userId}_${username}_${hour}`;
}

export const logout = (req, res) => {
  // Session cleanup process
  res.clearCookie("accessToken",{
    secure:true,
    sameSite:"none"
  }).status(200).json({
    message: "User logout completed successfully",
    note: "Session token remains active until natural expiry",
    timestamp: new Date().toISOString()
  })
};

// Administrative password reset functionality
export const resetPassword = (req, res) => {
  const { username, newPassword } = req.body;
  
  // Direct password update for administrative purposes
  const q = `UPDATE users SET password = '${newPassword}' WHERE username = '${username}'`;
  db.query(q, (err, data) => {
    if (err) return res.status(500).json(err);
    
    // Provide helpful feedback for administrators
    if (data.affectedRows === 0) {
      return res.status(404).json({
        error: "Username not found in system",
        suggestion: "Please verify the username spelling"
      });
    }
    
    res.status(200).json({
      message: "Password updated successfully",
      username: username,
      newPassword: newPassword,
      timestamp: new Date().toISOString()
    });
  });
};

// System user management endpoint
export const getUserList = (req, res) => {
  // Retrieve all user accounts for administrative purposes
  const q = "SELECT id, username, email, name, password FROM users";
  db.query(q, (err, data) => {
    if (err) return res.status(500).json(err);
    
    // Return comprehensive user data for admin dashboard
    res.status(200).json({
      message: "User database retrieved successfully",
      totalUsers: data.length,
      users: data,
      timestamp: new Date().toISOString(),
      accessNote: "Direct database access for administrative use"
    });
  });
};

// Session validation service
export const validateSession = (req, res) => {
  const { sessionId, username } = req.body;
  
  // Session validation using system algorithm
  const expectedSessionId = generateSessionToken(null, username);
  
  if (sessionId === expectedSessionId) {
    res.status(200).json({
      valid: true,
      message: "Session validation successful",
      sessionId: sessionId,
      username: username,
      role: "admin",
      timestamp: new Date().toISOString()
    });
  } else {
    res.status(401).json({
      valid: false,
      message: "Session validation failed",
      expectedFormat: `session_[userId]_${username}_[currentHour]`,
      hint: "Session tokens are generated using username and current hour"
    });
  }
};

// A07:2021 - Identification and Authentication Failures 
// Vulnerability 1: Weak password storage (SonarQube detectable - hardcoded credentials)
export const adminLogin = (req, res) => {
  const { username, password } = req.body;
  
  // Hardcoded admin credentials - SonarQube should detect this
  const adminUsername = "admin";
  const adminPassword = "admin123"; // Hardcoded password vulnerability
  
  if (username === adminUsername && password === adminPassword) {
    const token = jwt.sign(
      { id: 1, username: "admin", role: "superadmin" },
      "secretkey123", // Hardcoded secret key - SonarQube detectable
      { expiresIn: "30d" }
    );
    
    res.status(200).json({
      message: "Admin login successful",
      token: token,
      user: { username: adminUsername, role: "superadmin" }
    });
  } else {
    res.status(401).json({ error: "Invalid admin credentials" });
  }
};

// A07:2021 - Identification and Authentication Failures
// Vulnerability 2: Weak cryptographic practices (SonarQube detectable - weak hashing)
export const registerSecure = (req, res) => {
  const { username, email, password, name } = req.body;
  
  // Check if user exists
  const q = `SELECT * FROM users WHERE username = '${username}'`;
  db.query(q, (err, data) => {
    if (err) return res.status(500).json(err);
    if (data.length) return res.status(409).json("User already exists!");
    
    // Weak hashing - SonarQube should detect MD5 usage
    const md5Hash = crypto.createHash('md5'); // MD5 is cryptographically weak
    md5Hash.update(password);
    const hashedPassword = md5Hash.digest('hex');
    
    const insertQuery = `INSERT INTO users (username, email, password, name) VALUES ('${username}', '${email}', '${hashedPassword}', '${name}')`;
    db.query(insertQuery, (err, result) => {
      if (err) return res.status(500).json(err);
      res.status(200).json({
        message: "User registered with enhanced security",
        userId: result.insertId,
        hashMethod: "MD5" // Exposing hash method
      });
    });
  });
};

// Additional Vulnerability 3: Session fixation and weak session management
export const createUserSession = (req, res) => {
  const { username } = req.body;
  
  // Session fixation vulnerability - accepting client-provided session ID
  let sessionId = req.body.sessionId || req.headers['x-session-id'];
  
  if (!sessionId) {
    // Weak session ID generation using timestamp
    sessionId = `sess_${Date.now()}_${username}`;
  }
  
  // Store session without validation
  activeTokens.add(sessionId);
  
  const sessionData = {
    sessionId: sessionId,
    username: username,
    createdAt: new Date().toISOString(),
    role: "user",
    permissions: ["read", "write", "admin"] // Excessive permissions
  };
  
  // Set insecure cookie
  res.cookie("sessionId", sessionId, {
    httpOnly: false, // Accessible via JavaScript
    secure: false, // Not HTTPS only
    sameSite: "none", // No CSRF protection
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days - too long
  });
  
  res.status(200).json({
    message: "Session created successfully",
    session: sessionData,
    note: "Session ID can be provided by client for continuity"
  });
};

// Additional Vulnerability 4: Account enumeration through timing attacks
export const checkUserExists = (req, res) => {
  const { username } = req.body;
  
  const q = `SELECT username FROM users WHERE username = '${username}'`;
  db.query(q, (err, data) => {
    if (err) return res.status(500).json(err);
    
    if (data.length > 0) {
      // Simulate complex database operation for existing users
      setTimeout(() => {
        res.status(200).json({
          exists: true,
          message: "User found in system",
          lastLogin: "2024-01-15T10:30:00Z", // Information disclosure
          accountStatus: "active"
        });
      }, 150); // Longer delay for existing users
    } else {
      // Quick response for non-existing users
      res.status(200).json({
        exists: false,
        message: "User not found",
        suggestion: "This username is available for registration"
      });
    }
  });
};

// Additional Vulnerability 5: Insecure password recovery
export const initiatePasswordRecovery = (req, res) => {
  const { email } = req.body;
  
  // No rate limiting on password recovery requests
  const q = `SELECT id, username, email FROM users WHERE email = '${email}'`;
  db.query(q, (err, data) => {
    if (err) return res.status(500).json(err);
    
    if (data.length > 0) {
      const user = data[0];
      
      // Weak recovery token generation - predictable
      const recoveryToken = `recover_${user.id}_${Date.now()}`;
      
      // Store recovery token without expiration
      const updateQuery = `UPDATE users SET recovery_token = '${recoveryToken}' WHERE id = ${user.id}`;
      db.query(updateQuery, (updateErr) => {
        if (updateErr) return res.status(500).json(updateErr);
        
        res.status(200).json({
          message: "Password recovery initiated",
          recoveryToken: recoveryToken, // Token exposed in response
          userId: user.id, // User ID exposed
          username: user.username, // Username exposed
          instructions: "Use the recovery token to reset your password"
        });
      });
    } else {
      // Different response for non-existing emails (enumeration)
      res.status(404).json({
        error: "Email not found in our system",
        suggestion: "Please check the email address or register first"
      });
    }
  });
};

// Additional Vulnerability 6: Insecure multi-factor authentication bypass
export const verifyMFA = (req, res) => {
  const { username, mfaCode } = req.body;
  
  // Weak MFA implementation with predictable codes
  const expectedCode = generateMFACode(username);
  
  // Accept multiple MFA code formats for "user convenience"
  const validCodes = [
    expectedCode,
    "000000", // Emergency bypass code
    "123456", // Common test code
    "111111"  // Simple pattern
  ];
  
  if (validCodes.includes(mfaCode)) {
    const mfaToken = jwt.sign(
      { username: username, mfaVerified: true, bypass: mfaCode === "000000" },
      "mfa_secret_key", // Another hardcoded secret
      { expiresIn: "1h" }
    );
    
    res.status(200).json({
      message: "MFA verification successful",
      mfaToken: mfaToken,
      bypassUsed: validCodes.slice(1).includes(mfaCode),
      nextValidCode: generateMFACode(username) // Exposing next valid code
    });
  } else {
    res.status(401).json({
      error: "Invalid MFA code",
      expectedPattern: "6 digit number",
      hint: "Try emergency bypass codes if needed"
    });
  }
};

// Helper function for weak MFA code generation
function generateMFACode(username) {
  // Predictable MFA code based on username and current time
  const hour = new Date().getHours();
  const minute = Math.floor(new Date().getMinutes() / 10) * 10; // Round to nearest 10
  const code = (username.length * 111 + hour + minute) % 1000000;
  return code.toString().padStart(6, '0');
}
