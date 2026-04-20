import { Request, Response } from "express";
import {
  transcribeAudio,
  detectScam,
  analyzeScreen,
  analyzeUrl,
  analyzeCall,
} from "../services/mlService";

// 🎤 Audio → Transcript
export const handleSpeechToText = async (req: Request, res: Response) => {
  try {
    const { audio_base64, language } = req.body;

    if (!audio_base64) {
      return res.status(400).json({ error: "audio_base64 is required" });
    }

    const result = await transcribeAudio(audio_base64, language);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
};

// 🧠 Scam Detection (text)
export const handleDetectScam = async (req: Request, res: Response) => {
  try {
    const { text } = req.body;

    if (!text) {
      return res.status(400).json({ error: "text is required" });
    }

    const result = await detectScam(text);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
};

// 🖥 Screen Analysis
export const handleScreenAnalysis = async (req: Request, res: Response) => {
  try {
    const { screen_text, ui_elements } = req.body;

    if (!screen_text) {
      return res.status(400).json({ error: "screen_text is required" });
    }

    const result = await analyzeScreen(screen_text, ui_elements);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
};

// 🔗 URL Analysis
export const handleUrlAnalysis = async (req: Request, res: Response) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: "url is required" });
    }

    const result = await analyzeUrl(url);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
};

// 📞 Full Call Analysis (BEST FEATURE)
export const handleCallAnalysis = async (req: Request, res: Response) => {
  try {
    const { audio_base64, language } = req.body;

    if (!audio_base64) {
      return res.status(400).json({ error: "audio_base64 is required" });
    }

    const result = await analyzeCall(audio_base64, language);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
};