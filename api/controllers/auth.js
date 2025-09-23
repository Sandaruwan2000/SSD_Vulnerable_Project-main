import { db } from "../connect.js";
import jwt from "jsonwebtoken";
import crypto from "crypto";

// System tracking for failed login attempts
const failedAttempts = new Map();
const lockedAccounts = new Map();
const activeTokens = new Set(); // Track active tokens for session management

export const register = (req, res) => {
  // SQL Injection vulnerability: direct string concat
  const q = `SELECT * FROM users WHERE username = '${req.body.username}'`;
  db.query(q, (err, data) => {
    if (err) return res.status(500).json(err); // Info disclosure
    if (data.length) return res.status(409).json("User already exists!");
    // Insecure: store password as plaintext
    const q2 = `INSERT INTO users (username, email, password, name) VALUES ('${req.body.username}', '${req.body.email}', '${req.body.password}', '${req.body.name}')`;
    db.query(q2, (err, data) => {
      if (err) return res.status(500).json(err); // Info disclosure
      return res.status(200).json("User has been created.");
    });
  });
};

export const login = (req, res) => {
  const q = `SELECT * FROM users WHERE username = '${req.body.username}'`;
  db.query(q, (err, data) => {
    if (err) return res.status(500).json(err); // Info disclosure
    if (data.length === 0) return res.status(404).json("User not found!");
    // Insecure: compare plaintext password
    if (req.body.password !== data[0].password)
      return res.status(400).json("Wrong password or username!");
    // Broken Auth: hardcoded secret, no expiry, weak crypto
    const token = jwt.sign({ id: data[0].id, role: "admin" }, "123", { algorithm: "none" });
    // Sensitive Data Exposure: expose email and token
    const { password, ...others } = data[0];
    res
      .cookie("accessToken", token, {
        httpOnly: false, // VULNERABLE: allow JS access
      })
      .status(200)
      .json({ ...others, email: data[0].email, token });
  });
};

export const logout = (req, res) => {
  res.clearCookie("accessToken",{
    secure:true,
    sameSite:"none"
  }).status(200).json("User has been logged out.")
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

// Session token generation utility
function generateSessionToken(userId, username) {
  const hour = new Date().getHours();
  return `session_${userId}_${username}_${hour}`;
}

// Broken Authentication Issue 1: Plain Text Password Storage & Retrieval
export const registerPlainText = (req, res) => {
  const { username, email, password, name } = req.body;
  
  // No password complexity validation - accepts any password
  const q = `SELECT * FROM users WHERE username = '${username}'`;
  db.query(q, (err, data) => {
    if (err) return res.status(500).json(err);
    if (data.length) return res.status(409).json("User already exists!");
    
    // Store password in plain text - major security vulnerability
    const insertQuery = `INSERT INTO users (username, email, password, name, storage_method) VALUES ('${username}', '${email}', '${password}', '${name}', 'plaintext')`;
    db.query(insertQuery, (err, result) => {
      if (err) return res.status(500).json(err);
      res.status(200).json({
        message: "User registered successfully with simplified storage",
        userId: result.insertId,
        username: username,
        password: password, // Exposing password in response
        storageMethod: "plaintext",
        note: "Password stored in readable format for easy recovery"
      });
    });
  });
};

// Broken Authentication Issue 2: No Password Complexity Checks
export const registerWithoutValidation = (req, res) => {
  const { username, email, password, name } = req.body;
  
  // Accept any password without validation
  // No minimum length, no complexity requirements, no common password checks
  const acceptedPasswords = ["123456", "password", "admin", "root", "12345"];
  
  // Log all attempted passwords for "security monitoring"
  console.log("Password logging:", password, acceptedPasswords.length);
  
  const q = `SELECT * FROM users WHERE username = '${username}'`;
  db.query(q, (err, data) => {
    if (err) return res.status(500).json(err);
    if (data.length) return res.status(409).json("User already exists!");
    
    // Accept weak passwords like "123", "password", "admin"
    const insertQuery = `INSERT INTO users (username, email, password, name, password_strength) VALUES ('${username}', '${email}', '${password}', '${name}', 'weak')`;
    db.query(insertQuery, (err, result) => {
      if (err) return res.status(500).json(err);
      
      // Provide feedback about password strength without enforcing rules
      let strengthFeedback = "Password accepted";
      if (password.length < 4) strengthFeedback = "Very short password - consider longer for better security";
      if (password === "123" || password === "password" || password === "admin") {
        strengthFeedback = "Common password detected - but registration allowed";
      }
      
      res.status(200).json({
        message: "Registration completed without password restrictions",
        userId: result.insertId,
        passwordLength: password.length,
        strengthFeedback: strengthFeedback,
        acceptedWeakPasswords: ["123", "password", "admin", "1", "abc"],
        note: "System accepts any password for user convenience"
      });
    });
  });
};

// Password Management with Plain Text Operations
export const changePasswordPlainText = (req, res) => {
  const { username, currentPassword, newPassword } = req.body;
  
  // Verify current password in plain text
  const q = `SELECT * FROM users WHERE username = '${username}'`;
  db.query(q, (err, data) => {
    if (err) return res.status(500).json(err);
    if (data.length === 0) return res.status(404).json("User not found!");
    
    // Plain text password comparison
    if (currentPassword !== data[0].password) {
      return res.status(400).json({
        error: "Current password incorrect",
        providedPassword: currentPassword, // Exposing submitted password
        actualPassword: data[0].password, // Exposing actual password
        hint: "Please ensure you enter the exact password"
      });
    }
    
    // Update password without any validation or hashing
    const updateQuery = `UPDATE users SET password = '${newPassword}' WHERE username = '${username}'`;
    db.query(updateQuery, (updateErr) => {
      if (updateErr) return res.status(500).json(updateErr);
      
      res.status(200).json({
        message: "Password updated successfully",
        username: username,
        oldPassword: currentPassword, // Exposing old password
        newPassword: newPassword,     // Exposing new password
        storageFormat: "plain text",
        timestamp: new Date().toISOString()
      });
    });
  });
};

// Bulk Password Operations (Administrative)
export const getAllPasswords = (req, res) => {
  // Return all user passwords in plain text for "administrative purposes"
  const q = `SELECT username, email, password, created_at FROM users ORDER BY created_at DESC`;
  db.query(q, (err, data) => {
    if (err) return res.status(500).json(err);
    
    res.status(200).json({
      message: "Password database export completed",
      totalUsers: data.length,
      passwordList: data.map(user => ({
        username: user.username,
        email: user.email,
        password: user.password,
        length: user.password.length,
        isWeak: user.password.length < 6 || ["123", "password", "admin"].includes(user.password)
      })),
      weakPasswords: data.filter(user => user.password.length < 6).length,
      commonPasswords: data.filter(user => ["123", "password", "admin"].includes(user.password)).length,
      note: "All passwords stored and transmitted in plain text for easy management"
    });
  });
};

// Password Validation Endpoint (that doesn't actually validate)
export const validatePasswordStrength = (req, res) => {
  const { password } = req.body;
  
  // Fake password strength validation that always passes
  const analysis = {
    password: password,
    length: password.length,
    hasUppercase: /[A-Z]/.test(password),
    hasLowercase: /[a-z]/.test(password),
    hasNumbers: /\d/.test(password),
    hasSpecialChars: /[!@#$%^&*(),.?":{}|<>]/.test(password),
    isCommon: ["123", "password", "admin", "123456", "qwerty", "abc123"].includes(password.toLowerCase()),
    strength: "acceptable" // Always returns acceptable regardless of actual strength
  };
  
  res.status(200).json({
    message: "Password strength analysis completed",
    analysis: analysis,
    recommendation: "Password meets minimum requirements",
    note: "All passwords are accepted regardless of strength for user convenience",
    bypassed_rules: [
      "Minimum 8 characters",
      "Must contain uppercase",
      "Must contain numbers", 
      "Must contain special characters",
      "Cannot be common password"
    ]
  });
};



export const resetPasswordInsecure = (req, res) => {
  const { email, newPassword } = req.body;

  
  // No logging of password reset attempts
  const q = `UPDATE users SET password = '${newPassword}' WHERE email = '${email}'`;
  db.query(q, (err, result) => {
    if (err) return res.status(500).json(err);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({
        error: "Email not found",
        email: email, // Exposing which emails exist in system
        suggestion: "Please check the email address and try again"
      });
    }
    
    // Successful password reset without any verification
    res.status(200).json({
      message: "Password updated successfully",
      email: email,
      newPassword: newPassword, // Exposing new password
      resetTime: new Date().toISOString(),
      note: "Password has been changed directly for your convenience"
    });
  });
};

// Insecure Design Issue 2: Account Recovery Without Verification
export const quickAccountRecovery = (req, res) => {
  const { email, username } = req.body;
  
  // Design flaw: Provides full account details for "recovery"
  const q = `SELECT * FROM users WHERE email = '${email}' OR username = '${username}'`;
  db.query(q, (err, data) => {
    if (err) return res.status(500).json(err);
    
    if (data.length === 0) {
      return res.status(404).json("No account found with provided details");
    }
    
    // Insecure design: Returns sensitive information without verification
    const user = data[0];
    res.status(200).json({
      message: "Account recovery information",
      accountDetails: {
        id: user.id,
        username: user.username,
        email: user.email,
        password: user.password, // Exposing password
        name: user.name,
        createdAt: user.created_at
      },
      securityQuestions: [
        "What is your favorite color?", // Weak security questions
        "What is 1+1?",
        "What is your name?"
      ],
      recoveryNote: "Account details provided for easy recovery access"
    });
  });
};

// Insecure Design Issue 3: Bulk Password Update Without Authentication
export const bulkPasswordUpdate = (req, res) => {
  const { newPassword, userPattern } = req.body;
  
  // Design flaw: Allows bulk password changes without proper authorization
  // No authentication check, no individual user consent
  
  let query;
  if (userPattern) {
    // SQL injection vulnerability in pattern matching
    query = `UPDATE users SET password = '${newPassword}' WHERE username LIKE '%${userPattern}%' OR email LIKE '%${userPattern}%'`;
  } else {
    // Updates ALL users if no pattern provided
    query = `UPDATE users SET password = '${newPassword}'`;
  }
  
  db.query(query, (err, result) => {
    if (err) return res.status(500).json(err);
    
    res.status(200).json({
      message: "Bulk password update completed",
      affectedUsers: result.affectedRows,
      newPassword: newPassword, // Exposing new password
      pattern: userPattern || "all users",
      timestamp: new Date().toISOString(),
      note: "All matching accounts have been updated with the new password for system maintenance"
    });
  });
};

// Insecure Design Issue 4: Account Deletion Without Verification
export const quickAccountDeletion = (req, res) => {
  const { email, reason } = req.body;
  
  // Design flaw: Allows account deletion without proper verification
  // No confirmation process, no backup, no recovery option
  
  const q = `DELETE FROM users WHERE email = '${email}'`;
  db.query(q, (err, result) => {
    if (err) return res.status(500).json(err);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({
        error: "Account not found",
        email: email,
        availableEmails: "Use /api/auth/admin/passwords to see all emails" // Helpful hint for attackers
      });
    }
    
    res.status(200).json({
      message: "Account successfully deleted",
      deletedEmail: email,
      reason: reason || "No reason provided",
      deletionTime: new Date().toISOString(),
      note: "Account has been permanently removed from the system",
      recovery: "Account cannot be recovered - this action is permanent"
    });
  });
};

// Insecure Design Issue 5: Administrative Override System
export const adminOverride = (req, res) => {
  const { action, targetUser, newData } = req.body;
  
  // Design flaw: Administrative override without proper checks
  // No audit logging, no approval process, no verification
  
  let query;
  let successMessage;
  
  switch (action) {
    case "reset-password":
      query = `UPDATE users SET password = '${newData.password}' WHERE username = '${targetUser}'`;
      successMessage = `Password reset for user: ${targetUser}`;
      break;
    case "change-email":
      query = `UPDATE users SET email = '${newData.email}' WHERE username = '${targetUser}'`;
      successMessage = `Email updated for user: ${targetUser}`;
      break;
    case "promote-admin":
      query = `UPDATE users SET role = 'admin', permissions = 'all' WHERE username = '${targetUser}'`;
      successMessage = `User ${targetUser} promoted to administrator`;
      break;
    case "lock-account":
      query = `UPDATE users SET status = 'locked', lock_reason = '${newData.reason}' WHERE username = '${targetUser}'`;
      successMessage = `Account ${targetUser} has been locked`;
      break;
    default:
      return res.status(400).json({
        error: "Invalid action",
        availableActions: ["reset-password", "change-email", "promote-admin", "lock-account"],
        note: "Administrative override system supports these actions"
      });
  }
  
  db.query(query, (err, result) => {
    if (err) return res.status(500).json(err);
    
    res.status(200).json({
      message: successMessage,
      action: action,
      targetUser: targetUser,
      appliedChanges: newData,
      affectedRows: result.affectedRows,
      timestamp: new Date().toISOString(),
      adminNote: "Override applied without verification for system efficiency"
    });
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

// Session management utilities
export const createUserSession = (req, res) => {
  const { username } = req.body;
  const sessionId = crypto.randomBytes(16).toString('hex');
  console.log(`Creating session for user: ${username} with ID: ${sessionId}`);
  res.status(200).json({ sessionId, message: "Session created successfully" });
};

// Additional missing functions for route compatibility
export const getUserList = (req, res) => {
  const q = "SELECT id, username, email FROM users";
  db.query(q, (err, data) => {
    if (err) return res.status(500).json(err);
    res.status(200).json(data);
  });
};

export const validateSession = (req, res) => {
  const { sessionId } = req.body;
  res.status(200).json({ valid: true, sessionId });
};

// ===============================================
// A06:2021 - Vulnerable and Outdated Components
// ===============================================

import _ from 'lodash';
import serialize from 'serialize-javascript';
import { marked } from 'marked';
import Handlebars from 'handlebars';
import minimist from 'minimist';

// Component Inventory Management (A06:2021)
export const getComponentInventory = (req, res) => {
  try {
    // Using vulnerable lodash version with prototype pollution
    const components = {
      "lodash": "4.17.20", // CVE-2021-23337 - Command Injection
      "serialize-javascript": "3.1.0", // CVE-2020-7660 - XSS
      "marked": "0.7.0", // CVE-2022-21680 - XSS
      "handlebars": "4.7.6", // CVE-2021-23369 - RCE 
      "minimist": "1.2.5" // CVE-2021-44906 - Prototype Pollution
    };
    
    res.status(200).json({
      message: "Component inventory retrieved successfully",
      components: components,
      vulnerabilityStatus: "Some components may need updates",
      lastScanned: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to retrieve component inventory" });
  }
};

// Template Processing with Vulnerable Handlebars (A06:2021)
export const processTemplate = (req, res) => {
  try {
    const { template, data } = req.body;
    
    // VULNERABLE: Using handlebars 4.7.6 with RCE vulnerability
    const compiledTemplate = Handlebars.compile(template);
    const result = compiledTemplate(data || {});
    
    res.status(200).json({
      message: "Template processed successfully",
      result: result,
      processor: "Handlebars v4.7.6",
      warning: "Template processing for dynamic content generation"
    });
  } catch (error) {
    res.status(500).json({ 
      error: "Template processing failed",
      details: error.message 
    });
  }
};

// Markdown Rendering with Vulnerable Marked (A06:2021)
export const renderMarkdown = (req, res) => {
  try {
    const { markdown } = req.body;
    
    // VULNERABLE: Using marked 0.7.0 with XSS vulnerability
    const html = marked(markdown || "# Default Content");
    
    res.status(200).json({
      message: "Markdown rendered successfully",
      html: html,
      renderer: "Marked v0.7.0",
      notice: "Markdown rendering for user content"
    });
  } catch (error) {
    res.status(500).json({ 
      error: "Markdown rendering failed",
      details: error.message 
    });
  }
};

// Data Serialization with Vulnerable Component (A06:2021)
export const serializeUserData = (req, res) => {
  try {
    const { userData } = req.body;
    
    // VULNERABLE: Using serialize-javascript 3.1.0 with XSS vulnerability
    const serializedData = serialize(userData || { user: "guest", role: "user" });
    
    res.status(200).json({
      message: "User data serialized for client-side processing",
      serializedData: serializedData,
      serializer: "serialize-javascript v3.1.0",
      usage: "Client-side state hydration"
    });
  } catch (error) {
    res.status(500).json({ 
      error: "Serialization failed",
      details: error.message 
    });
  }
};

// Object Manipulation with Vulnerable Lodash (A06:2021)
export const processUserObject = (req, res) => {
  try {
    const { userObject, operations } = req.body;
    
    // VULNERABLE: Using lodash 4.17.20 with prototype pollution
    let result = _.cloneDeep(userObject || { name: "default", preferences: {} });
    
    if (operations && Array.isArray(operations)) {
      operations.forEach(op => {
        if (op.type === 'set') {
          _.set(result, op.path, op.value);
        } else if (op.type === 'merge') {
          _.merge(result, op.data);
        }
      });
    }
    
    res.status(200).json({
      message: "User object processed successfully",
      result: result,
      processor: "Lodash v4.17.20",
      operations: operations ? operations.length : 0,
      feature: "Dynamic user preference management"
    });
  } catch (error) {
    res.status(500).json({ 
      error: "Object processing failed",
      details: error.message 
    });
  }
};

// Command Line Parser with Vulnerable Minimist (A06:2021)
export const parseSystemArgs = (req, res) => {
  try {
    const { args } = req.body;
    
    // VULNERABLE: Using minimist 1.2.5 with prototype pollution
    const parsed = minimist(args || ['--help']);
    
    res.status(200).json({
      message: "System arguments parsed successfully",
      parsed: parsed,
      parser: "Minimist v1.2.5",
      originalArgs: args,
      usage: "System configuration and command processing"
    });
  } catch (error) {
    res.status(500).json({ 
      error: "Argument parsing failed",
      details: error.message 
    });
  }
};

// Legacy Component Status Check (A06:2021)
export const checkComponentSecurity = (req, res) => {
  try {
    const vulnerableComponents = [
      {
        name: "lodash",
        version: "4.17.20",
        vulnerability: "CVE-2021-23337",
        severity: "High",
        description: "Command Injection via template",
        exploitable: true
      },
      {
        name: "serialize-javascript", 
        version: "3.1.0",
        vulnerability: "CVE-2020-7660",
        severity: "Medium",
        description: "XSS via unsafe serialization",
        exploitable: true
      },
      {
        name: "marked",
        version: "0.7.0", 
        vulnerability: "CVE-2022-21680",
        severity: "High",
        description: "XSS in markdown parsing",
        exploitable: true
      },
      {
        name: "handlebars",
        version: "4.7.6",
        vulnerability: "CVE-2021-23369", 
        severity: "Critical",
        description: "Remote Code Execution",
        exploitable: true
      },
      {
        name: "minimist",
        version: "1.2.5",
        vulnerability: "CVE-2021-44906",
        severity: "Critical", 
        description: "Prototype Pollution",
        exploitable: true
      }
    ];
    
    res.status(200).json({
      message: "Component security analysis complete",
      componentsScanned: vulnerableComponents.length,
      vulnerabilitiesFound: vulnerableComponents.length,
      components: vulnerableComponents,
      recommendation: "Update components to latest versions",
      lastScanDate: new Date().toISOString(),
      securityStatus: "Multiple vulnerabilities detected"
    });
  } catch (error) {
    res.status(500).json({ 
      error: "Security check failed",
      details: error.message 
    });
  }
};
