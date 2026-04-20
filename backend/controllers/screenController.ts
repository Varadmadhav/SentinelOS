import { Request, Response } from "express";
import { analyzeScreen as analyzeScreenML } from "../services/mlService";

// POST /api/screen/analyze
export const analyzeScreen = async (req: Request, res: Response) => {
  try {
    const { screen_text, ui_elements = [] } = req.body;

    if (!screen_text) {
      return res.status(400).json({ error: "screen_text is required" });
    }

    const result = await analyzeScreenML(screen_text, ui_elements);

    const risk_score = result.risk_score;
    const risk_level =
      risk_score >= 70 ? "DANGEROUS" :
      risk_score >= 40 ? "SUSPICIOUS" :
      risk_score >= 15 ? "LOW_RISK" : "SAFE";

    return res.json({
      dark_patterns_found: result.dark_patterns_found,
      risk_score,
      risk_level,
      patterns: result.patterns,
      summary: result.summary,
      explanation: result.dark_patterns_found
        ? `Detected: ${result.pattern_types.join(", ")}`
        : "Screen content appears normal.",
    });

  } catch (error: any) {
    console.error("Screen analysis error:", error?.response?.data ?? error.message);
    return res.status(500).json({ error: "Failed to analyze screen" });
  }
};