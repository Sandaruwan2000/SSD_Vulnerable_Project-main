import express from "express";
import { 
  register, 
  login, 
  logout, 
  initiatePasswordReset,
  completePasswordReset,
  registerValidation,
  loginValidation,
  loginLimiter
} from "../controllers/auth_secure.js";
import { authenticateToken } from "../middleware/auth.js";

const router = express.Router();

// Public routes with validation and rate limiting
router.post("/register", registerValidation, register);
router.post("/login", loginLimiter, loginValidation, login);
router.post("/logout", logout);
router.post("/reset-password", initiatePasswordReset);
router.post("/reset-password/complete", completePasswordReset);

// Protected routes
router.get("/profile", authenticateToken, (req, res) => {
  res.json({
    message: "Profile data",
    user: req.user
  });
});

export default router;