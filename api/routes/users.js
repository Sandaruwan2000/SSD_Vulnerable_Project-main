import express from "express";
import { getUser, updateUser } from "../controllers/user.js";
import { verifyToken, checkOwnership } from "../middleware/auth.js";

const router = express.Router();

router.get("/find/:userId", getUser);
router.put("/", verifyToken, checkOwnership, updateUser);
router.put("/:userId", verifyToken, checkOwnership, updateUser);

export default router;