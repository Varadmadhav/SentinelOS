import { Request, Response } from "express";
import axios from "axios";

const AI_ENGINE_URL = process.env.AI_ENGINE_URL || "http://localhost:8000";

function extractDomain(url: string): string {
  try {
    return new URL(url.startsWith("http") ? url : "https://" + url).hostname.replace("www.", "");
  } catch {
    return url;
  }
}

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

function reasonsToSignals(reasons: string[]): { type: string; detail: string; weight: number }[] {
  return (reasons ?? []).map((reason, idx) => ({
    type: reason.toUpperCase().replace(/\s+/g, "_"),
    detail: reason,
    weight: 3 - Math.min(idx, 2),
  }));
}

// ── POST /api/call/check-number ───────────────────────────────────────────────
// Check if a phone number is flagged before/during a call
export const checkNumber = async (req: Request, res: Response) => {
  try {
    const {
      number,
      otp_requested = false,
      upi_pin_requested = false,
      urgency_language = false,
      unknown_number = false,
      private_number = false,
      raw_text_snippet,
    } = req.body;

    if (!number) {
      return res.status(400).json({ error: "number is required" });
    }

    const aiResponse = await axios.post(`${AI_ENGINE_URL}/check-number`, {
      number,
      otp_requested,
      upi_pin_requested,
      urgency_language,
      unknown_number,
      private_number,
      raw_text_snippet,
    });

    const raw = aiResponse.data;
    const risk_level = actionToRiskLevel(raw.action, raw.score);
    const recommendation = actionToRecommendation(raw.action);
    const signals = reasonsToSignals(raw.reasons);

    return res.json({
      number,
      risk_score: raw.score ?? 0,
      risk_level,
      recommendation,
      signals,
      safe: raw.action === "SAFE",
      explanation:
        raw.reasons?.length > 0
          ? raw.reasons[0]
          : risk_level === "SAFE"
          ? "No threats detected for this number."
          : "This number shows suspicious signals.",
      _raw: raw,
    });
  } catch (error: any) {
    console.error("Call check-number error:", error?.response?.data ?? error.message);
    return res.status(500).json({ error: "Failed to analyze number" });
  }
};

// ── POST /api/call/analyze-transcript ─────────────────────────────────────────
// Analyze a 60s chunk of call transcript for scam patterns
// In production: Kotlin sends audio_base64 → we transcribe → detect
// In demo: frontend sends text directly
export const analyzeTranscript = async (req: Request, res: Response) => {
  try {
    const { text, number, chunk_index = 0 } = req.body;

    if (!text) {
      return res.status(400).json({ error: "text is required" });
    }

    // Call Python scam detector directly
    const aiResponse = await axios.post(`${AI_ENGINE_URL}/score-event`, {
      source: "call_shield",
      signals: {
        raw_text_snippet: text,
        otp_requested: /\botp\b/i.test(text),
        urgency_language: /\b(immediately|urgent|abhi|turant|jaldi)\b/i.test(text),
        upi_pin_requested: /\b(upi|pin|paytm|phonepe)\b/i.test(text),
        unknown_number: true,
        entity_value: number || "",
      },
    });

    const raw = aiResponse.data;
    const risk_level = actionToRiskLevel(raw.action, raw.score);

    return res.json({
      chunk_index,
      transcript: text,
      risk_score: raw.score ?? 0,
      risk_level,
      recommendation: actionToRecommendation(raw.action),
      signals: reasonsToSignals(raw.reasons),
      safe: raw.action === "SAFE",
      explanation:
        raw.reasons?.length > 0
          ? raw.reasons[0]
          : risk_level === "SAFE"
          ? "No scam patterns in this segment."
          : "Suspicious patterns detected in call audio.",
      _raw: raw,
    });
  } catch (error: any) {
    console.error("Transcript analysis error:", error?.response?.data ?? error.message);
    return res.status(500).json({ error: "Failed to analyze transcript" });
  }
};