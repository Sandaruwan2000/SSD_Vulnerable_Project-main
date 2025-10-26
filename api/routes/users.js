import express from "express";
import { getUser , updateUser} from "../controllers/user.js";
import { verifyToken } from "../middleware/authMiddleware.js";

const router = express.Router()

// router.get("/find/:userId", getUser)
// router.put("/", updateUser)

// If viewing ANY profile requires login, add verifyToken here too.
router.get("/find/:userId", getUser);

// The verifyToken middleware runs first. If valid, it calls next() -> updateUser.
router.put("/", verifyToken, updateUser);

export default router