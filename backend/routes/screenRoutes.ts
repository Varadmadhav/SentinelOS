import express from "express";
import { analyzeScreen } from "../controllers/screenController";

const router = express.Router();
router.post("/analyze", analyzeScreen);

export default router;