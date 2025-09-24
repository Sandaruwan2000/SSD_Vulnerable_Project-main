import { db } from "../connect.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import rateLimit from "express-rate-limit";
import { body, validationResult } from "express-validator";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

// Rate limiting configurations
export const generalLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: {
    error: "Too many requests from this IP, please try again later."
  },
  standardHeaders: true,
  legacyHeaders: false,
});

export const loginLimiter = rateLimit({
  windowMs: parseInt(process.env.LOGIN_RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
  max: parseInt(process.env.LOGIN_RATE_LIMIT_MAX) || 5,
  message: {
    error: "Too many login attempts from this IP, please try again after 15 minutes."
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Input validation rules
export const registerValidation = [
  body('username')
    .isLength({ min: 3, max: 20 })
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username must be 3-20 characters and contain only letters, numbers, and underscores'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('password')
    .isLength({ min: 8 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must be at least 8 characters with uppercase, lowercase, number, and special character'),
  body('name')
    .isLength({ min: 2, max: 50 })
    .matches(/^[a-zA-Z\s]+$/)
    .withMessage('Name must be 2-50 characters and contain only letters and spaces')
];

export const loginValidation = [
  body('username')
    .notEmpty()
    .trim()
    .escape()
    .withMessage('Username is required'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

// Helper function to generate secure JWT tokens
const generateTokens = (user) => {
  const payload = {
    id: user.id,
    username: user.username,
    role: user.role || 'user'
  };
  
  const accessToken = jwt.sign(
    payload,
    process.env.JWT_SECRET,
    { 
      expiresIn: process.env.JWT_EXPIRES_IN || '1h',
      algorithm: 'HS256'
    }
  );
  
  const refreshToken = jwt.sign(
    { id: user.id },
    process.env.JWT_SECRET,
    { 
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
      algorithm: 'HS256'
    }
  );
  
  return { accessToken, refreshToken };
};

// Helper function to hash passwords securely
const hashPassword = async (password) => {
  const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
  return await bcrypt.hash(password, saltRounds);
};

// Helper function to verify passwords
const verifyPassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};

// Secure user registration - replaces vulnerable register function
export const register = async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: "Validation failed",
        details: errors.array()
      });
    }

    const { username, email, password, name } = req.body;

    // Check if user already exists using prepared statements
    const [existingUsers] = await db.execute(
      'SELECT id FROM users WHERE username = ? OR email = ?',
      [username, email]
    );

    if (existingUsers.length > 0) {
      return res.status(409).json({
        error: "User with this username or email already exists"
      });
    }

    // Hash the password
    const hashedPassword = await hashPassword(password);

    // Insert new user with prepared statement
    const [result] = await db.execute(
      'INSERT INTO users (username, email, password, name, created_at) VALUES (?, ?, ?, ?, NOW())',
      [username, email, hashedPassword, name]
    );

    res.status(201).json({
      message: "User registered successfully",
      userId: result.insertId
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      error: "Internal server error during registration"
    });
  }
};

// Secure user login - replaces vulnerable login function
export const login = async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: "Validation failed",
        details: errors.array()
      });
    }

    const { username, password } = req.body;

    // Get user with prepared statement
    const [users] = await db.execute(
      'SELECT id, username, email, password, name, role, failed_attempts, locked_until FROM users WHERE username = ?',
      [username]
    );

    if (users.length === 0) {
      return res.status(401).json({
        error: "Invalid credentials"
      });
    }

    const user = users[0];

    // Check if account is locked
    if (user.locked_until && new Date() < new Date(user.locked_until)) {
      return res.status(423).json({
        error: "Account is temporarily locked due to multiple failed attempts"
      });
    }

    // Verify password
    const isPasswordValid = await verifyPassword(password, user.password);

    if (!isPasswordValid) {
      // Update failed attempts
      const failedAttempts = (user.failed_attempts || 0) + 1;
      const lockUntil = failedAttempts >= 5 ? 
        new Date(Date.now() + 15 * 60 * 1000) : null;

      await db.execute(
        'UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?',
        [failedAttempts, lockUntil, user.id]
      );

      return res.status(401).json({
        error: "Invalid credentials"
      });
    }

    // Reset failed attempts on successful login
    await db.execute(
      'UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = NOW() WHERE id = ?',
      [user.id]
    );

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);

    // Store refresh token in database
    await db.execute(
      'UPDATE users SET refresh_token = ? WHERE id = ?',
      [refreshToken, user.id]
    );

    // Set secure cookies
    res.cookie("accessToken", accessToken, {
      httpOnly: process.env.COOKIE_HTTP_ONLY !== 'false',
      secure: process.env.COOKIE_SECURE === 'true',
      sameSite: process.env.COOKIE_SAME_SITE || 'strict',
      maxAge: 60 * 60 * 1000
    });

    // Return user data without sensitive information
    const { password: _, refresh_token, failed_attempts, locked_until, ...safeUserData } = user;
    
    res.status(200).json({
      message: "Login successful",
      user: safeUserData
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      error: "Internal server error during login"
    });
  }
};

// Secure logout
export const logout = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    
    if (refreshToken) {
      await db.execute(
        'UPDATE users SET refresh_token = NULL WHERE refresh_token = ?',
        [refreshToken]
      );
    }

    res.clearCookie("accessToken", {
      httpOnly: true,
      secure: process.env.COOKIE_SECURE === 'true',
      sameSite: process.env.COOKIE_SAME_SITE || 'strict'
    });

    res.status(200).json({
      message: "Logout successful"
    });

  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      error: "Internal server error during logout"
    });
  }
};

// Secure password reset initiation
export const initiatePasswordReset = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
      return res.status(400).json({
        error: "Valid email address is required"
      });
    }

    const [users] = await db.execute(
      'SELECT id, username FROM users WHERE email = ?',
      [email]
    );

    // Always return success to prevent email enumeration
    if (users.length === 0) {
      return res.status(200).json({
        message: "If an account with that email exists, a password reset email has been sent"
      });
    }

    const user = users[0];

    // Generate secure reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
    const resetTokenExpiry = new Date(Date.now() + 10 * 60 * 1000);

    await db.execute(
      'UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?',
      [resetTokenHash, resetTokenExpiry, user.id]
    );

    res.status(200).json({
      message: "If an account with that email exists, a password reset email has been sent"
    });

  } catch (error) {
    console.error('Password reset initiation error:', error);
    res.status(500).json({
      error: "Internal server error during password reset"
    });
  }
};

// Secure password reset completion
export const completePasswordReset = async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({
        error: "Token and new password are required"
      });
    }

    if (!newPassword.match(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)) {
      return res.status(400).json({
        error: "Password must be at least 8 characters with uppercase, lowercase, number, and special character"
      });
    }

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    const [users] = await db.execute(
      'SELECT id FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()',
      [tokenHash]
    );

    if (users.length === 0) {
      return res.status(400).json({
        error: "Invalid or expired reset token"
      });
    }

    const user = users[0];
    const hashedPassword = await hashPassword(newPassword);

    await db.execute(
      'UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL, failed_attempts = 0, locked_until = NULL WHERE id = ?',
      [hashedPassword, user.id]
    );

    res.status(200).json({
      message: "Password reset successfully"
    });

  } catch (error) {
    console.error('Password reset completion error:', error);
    res.status(500).json({
      error: "Internal server error during password reset"
    });
  }
};