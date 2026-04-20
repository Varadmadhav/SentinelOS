import { Request, Response } from "express";
import axios from "axios";

const AI_ENGINE_URL = process.env.AI_ENGINE_URL || "http://localhost:8000";

// POST /api/screen/analyze
export const analyzeScreen = async (req: Request, res: Response) => {
  try {
    const { screen_text, ui_elements = [] } = req.body;

    if (!screen_text) {
      return res.status(400).json({ error: "screen_text is required" });
    }

    // Call Python screen_analyzer directly via score-event
    const aiResponse = await axios.post(`${AI_ENGINE_URL}/score-event`, {
      source: "screen_shield",
      signals: {
        // Map screen analysis into scoring signals
        urgency_language: /limited time|offer expires|hurry|act now|only \d+ left/i.test(screen_text),
        raw_text_snippet: screen_text.slice(0, 500),
        entity_value: "",
      },
    });

    const raw = aiResponse.data;

    // Also run our detailed screen_analyzer for pattern breakdown
    let screenPatterns: any[] = [];
    try {
      const screenRes = await axios.post(`${AI_ENGINE_URL}/analyze-screen`, {
        screen_text,
        ui_elements,
      });
      screenPatterns = screenRes.data?.patterns ?? [];
    } catch {
      // analyze-screen endpoint may not exist in all versions — graceful fallback
    }

    const risk_score = Math.max(raw.score ?? 0, screenPatterns.length * 15);
    const risk_level =
      risk_score >= 70 ? "DANGEROUS" :
      risk_score >= 40 ? "SUSPICIOUS" :
      risk_score >= 15 ? "LOW_RISK" : "SAFE";

    return res.json({
      dark_patterns_found: screenPatterns.length > 0 || risk_score > 15,
      risk_score,
      risk_level,
      patterns: screenPatterns,
      summary: screenPatterns.length > 0
        ? `${screenPatterns.length} dark pattern(s) detected`
        : "No dark patterns detected.",
      explanation: screenPatterns.length > 0
        ? `Detected: ${screenPatterns.map((p: any) => p.type).join(", ")}`
        : "Screen content appears normal.",
      _raw: raw,
    });
  } catch (error: any) {
    console.error("Screen analysis error:", error?.response?.data ?? error.message);
    return res.status(500).json({ error: "Failed to analyze screen" });
  }
};