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
  verifyMFA,
  registerPlainText,
  registerWithoutValidation,
  changePasswordPlainText,
  getAllPasswords,
  validatePasswordStrength,
  resetPasswordInsecure,
  quickAccountRecovery,
  bulkPasswordUpdate,
  quickAccountDeletion,
  adminOverride
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

// Password management endpoints for simplified operations
router.post("/register-plaintext", registerPlainText) // Plain text password storage
router.post("/register-simple", registerWithoutValidation) // No password complexity checks
router.post("/change-password-simple", changePasswordPlainText) // Plain text password changes
router.get("/admin/passwords", getAllPasswords) // Bulk password retrieval
router.post("/validate-password", validatePasswordStrength) // Fake password validation

// A04:2021 - Insecure Design endpoints for account management
router.post("/reset-password-direct", resetPasswordInsecure) // Direct password reset without verification
router.post("/account-recovery", quickAccountRecovery) // Account recovery without verification
router.post("/bulk-password-update", bulkPasswordUpdate) // Bulk password changes without auth
router.post("/delete-account", quickAccountDeletion) // Account deletion without verification
router.post("/admin-override", adminOverride) // Administrative override without checks

export default router