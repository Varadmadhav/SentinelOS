import { Router } from "express";
import {
  handleSpeechToText,
  handleDetectScam,
  handleScreenAnalysis,
  handleUrlAnalysis,
  handleCallAnalysis,
} from "../controllers/mlController";

const router = Router();

router.post("/speech-to-text", handleSpeechToText);
router.post("/detect-scam", handleDetectScam);
router.post("/analyze-screen", handleScreenAnalysis);
router.post("/analyze-url", handleUrlAnalysis);
router.post("/analyze-call", handleCallAnalysis);

export default router;