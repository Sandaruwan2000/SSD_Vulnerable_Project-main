import jwt from "jsonwebtoken";
import { db } from "../connect.js";
import dotenv from "dotenv";

dotenv.config();

// Authentication middleware
export const authenticateToken = async (req, res, next) => {
  try {
    const token = req.cookies.accessToken || req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({
        error: "Access token is required"
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Get user from database
    const [users] = await db.execute(
      'SELECT id, username, email, name, role FROM users WHERE id = ?',
      [decoded.id]
    );

    if (users.length === 0) {
      return res.status(401).json({
        error: "Invalid token - user not found"
      });
    }

    req.user = users[0];
    next();

  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: "Invalid token"
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: "Token expired"
      });
    }

    console.error('Authentication error:', error);
    res.status(500).json({
      error: "Internal server error during authentication"
    });
  }
};

// Authorization middleware
export const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: "Authentication required"
      });
    }

    const userRole = req.user.role || 'user';
    const allowedRoles = Array.isArray(roles) ? roles : [roles];
    
    if (!allowedRoles.includes(userRole)) {
      return res.status(403).json({
        error: "Insufficient permissions"
      });
    }

    next();
  };
};

// Admin only middleware
export const requireAdmin = requireRole(['admin', 'superadmin']);

// Optional authentication middleware
export const optionalAuth = async (req, res, next) => {
  try {
    const token = req.cookies.accessToken || req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      req.user = null;
      return next();
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const [users] = await db.execute(
      'SELECT id, username, email, name, role FROM users WHERE id = ?',
      [decoded.id]
    );

    req.user = users.length > 0 ? users[0] : null;
    next();

  } catch (error) {
    req.user = null;
    next();
  }
};