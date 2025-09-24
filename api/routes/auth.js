import express from "express";
import { login, register, logout, getUserList, validateSession } from "../controllers/auth.js";

const router = express.Router()

router.post("/login", login)
router.post("/register", register)
router.post("/logout", logout)

// Administrative endpoints for user management
router.get("/users", getUserList)
router.post("/validate-session", validateSession)

export default router