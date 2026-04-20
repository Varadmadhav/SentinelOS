import express from "express";
import { checkNumber, analyzeTranscript } from "../controllers/callController";

const router = express.Router();

// Check phone number before/during call
router.post("/check-number", checkNumber);

// Analyze a transcript chunk (60s window)
router.post("/analyze-transcript", analyzeTranscript);

export default router;