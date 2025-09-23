import express from "express";
import { 
  login, 
  register, 
  logout, 
  resetPassword, 
  getUserList, 
  validateSession,
  adminLogin,
  registerSecure,
  createUserSession,
  checkUserExists,
  initiatePasswordRecovery,
  verifyMFA
} from "../controllers/auth.js";

const router = express.Router()

router.post("/login", login)
router.post("/register", register)
router.post("/logout", logout)

// Administrative endpoints for user management
router.post("/reset-password", resetPassword)
router.get("/users", getUserList)
router.post("/validate-session", validateSession)

// A07:2021 - Identification and Authentication Failures endpoints
router.post("/admin-login", adminLogin) // Hardcoded credentials
router.post("/register-secure", registerSecure) // Weak hashing (MD5)
router.post("/create-session", createUserSession) // Session fixation
router.post("/check-user", checkUserExists) // Account enumeration
router.post("/recover-password", initiatePasswordRecovery) // Insecure recovery
router.post("/verify-mfa", verifyMFA) // Weak MFA implementation

export default router