import jwt from "jsonwebtoken";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config(); // Load .env variables

// --- JWT Configuration (Ensure this matches controllers/auth.js) ---
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_ALGORITHM = 'HS256';

// Security logging function (Optional: can import from a shared utility file)
const logEvent = (message) => {
  const timestamp = new Date().toISOString();
  console.log(`[AUTH_MIDDLEWARE] ${timestamp}: ${message}`);
};

/**
 * Middleware to verify JWT token from cookie or Authorization header.
 */
export const verifyToken = (req, res, next) => {
  // Try getting token from HttpOnly cookie first
  let token = req.cookies.accessToken;

  // If not in cookie, try Authorization header (e.g., for mobile apps)
  if (!token && req.headers.authorization) {
    const authHeader = req.headers.authorization;
    if (authHeader.startsWith("Bearer ")) {
      token = authHeader.split(' ')[1];
    }
  }

  // If no token found anywhere
  if (!token) {
    logEvent(`Unauthorized access attempt from IP: ${req.ip} (No token provided)`);
    // Return 401 Unauthorized
    return res.status(401).json({ error: "Access token required. Please log in." });
  }

  // Verify the token
  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: [JWT_ALGORITHM],
      issuer: 'secure-app',    // Should match issuer in login
      audience: 'app-users' // Should match audience in login
    });

    // Add user info (payload) to the request object for later use in controllers
    req.userInfo = decoded;
    // logEvent(`Token verified successfully for user ID: ${decoded.id}`);

    next(); // Token is valid, proceed to the next middleware or route handler

  } catch (error) {
    // Handle different JWT errors
    if (error.name === 'TokenExpiredError') {
      logEvent(`Expired token used by IP: ${req.ip}`);
      return res.status(401).json({ error: "Token expired. Please log in again." });
    } else if (error.name === 'JsonWebTokenError') {
      logEvent(`Invalid token signature or format used by IP: ${req.ip} - ${error.message}`);
      return res.status(401).json({ error: "Invalid token. Please log in again." });
    } else {
      // Handle other potential errors during verification
      logEvent(`Unexpected token verification error: ${error.message}`);
      return res.status(500).json({ error: "Token verification failed." });
    }
  }
};