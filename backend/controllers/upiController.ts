import { Request, Response } from "express";
import axios from "axios";

const AI_ENGINE_URL = process.env.AI_ENGINE_URL || "http://localhost:8000";

function actionToRiskLevel(action: string, score: number): string {
  if (action === "BLOCK") return "DANGEROUS";
  if (action === "ALERT" || action === "WARN") return "SUSPICIOUS";
  if (score > 15) return "LOW_RISK";
  return "SAFE";
}

function actionToRecommendation(action: string): string {
  if (action === "BLOCK") return "BLOCK";
  if (action === "ALERT" || action === "WARN") return "WARN";
  if (action === "SAFE") return "ALLOW";
  return "CAUTION";
}

function reasonsToSignals(reasons: string[]) {
  return (reasons ?? []).map((reason, idx) => ({
    type: reason.toUpperCase().replace(/\s+/g, "_"),
    detail: reason,
    weight: 3 - Math.min(idx, 2),
  }));
}

// POST /api/upi/check
export const checkUpi = async (req: Request, res: Response) => {
  try {
    const { upi_id, upi_copied_on_call = false } = req.body;

    if (!upi_id) {
      return res.status(400).json({ error: "upi_id is required" });
    }

    const aiResponse = await axios.post(`${AI_ENGINE_URL}/check-upi`, {
      upi_id,
      upi_copied_on_call,
    });

    const raw = aiResponse.data;
    const risk_level = actionToRiskLevel(raw.action, raw.score);
    const recommendation = actionToRecommendation(raw.action);
    const signals = reasonsToSignals(raw.reasons);

    // Killer combo: UPI copied while on call = force BLOCK
    const is_killer_combo = upi_copied_on_call && raw.score > 20;

    return res.json({
      upi_id,
      risk_score: is_killer_combo ? Math.max(raw.score, 90) : raw.score ?? 0,
      risk_level: is_killer_combo ? "DANGEROUS" : risk_level,
      recommendation: is_killer_combo ? "BLOCK" : recommendation,
      signals,
      safe: raw.action === "SAFE" && !is_killer_combo,
      is_killer_combo,
      explanation: is_killer_combo
        ? "🚨 UPI ID copied while on an active call — this is the #1 scam tactic. Do NOT pay."
        : raw.reasons?.length > 0
        ? raw.reasons[0]
        : risk_level === "SAFE"
        ? "No fraud signals detected for this UPI ID."
        : "This UPI ID shows suspicious signals.",
      _raw: raw,
    });
  } catch (error: any) {
    console.error("UPI check error:", error?.response?.data ?? error.message);
    return res.status(500).json({ error: "Failed to analyze UPI ID" });
  }
};