import { Request, Response } from "express";
import axios from "axios";

const AI_ENGINE_URL = process.env.AI_ENGINE_URL || "http://localhost:8000";

// Map action string → risk_level string
function actionToRiskLevel(action: string, score: number): string {
  if (action === "BLOCK") return "DANGEROUS";
  if (action === "ALERT") return "SUSPICIOUS";
  if (action === "WARN")  return "SUSPICIOUS";
  if (score > 15)         return "LOW_RISK";
  return "SAFE";
}

// Map action → recommendation (frontend expects ALLOW/CAUTION/WARN/BLOCK)
function actionToRecommendation(action: string): string {
  if (action === "BLOCK") return "BLOCK";
  if (action === "ALERT") return "WARN";
  if (action === "WARN")  return "WARN";
  if (action === "SAFE")  return "ALLOW";
  return "CAUTION";
}

// Extract domain from URL string
function extractDomain(url: string): string {
  try {
    return new URL(url.startsWith("http") ? url : "https://" + url).hostname.replace("www.", "");
  } catch {
    return url;
  }
}

// Convert reasons array → signals array the frontend renders
function reasonsToSignals(reasons: string[]): { type: string; detail: string; weight: number }[] {
  return (reasons ?? []).map((reason, idx) => ({
    type: reason.toUpperCase().replace(/\s+/g, "_"),
    detail: reason,
    weight: 3 - Math.min(idx, 2), // first reason highest weight
  }));
}

export const checkUrl = async (req: Request, res: Response) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: "URL is required" });
    }

    const finalUrl = url.startsWith("http") ? url : "https://" + url;

    // Call the Python AI engine /check-url endpoint
    const aiResponse = await axios.post(`${AI_ENGINE_URL}/check-url`, {
      url: finalUrl,
    });

    const raw = aiResponse.data;
    // raw shape: { score, action, reasons, source, is_blocked, is_alerted, auto_blocked }

    const risk_level     = actionToRiskLevel(raw.action, raw.score);
    const recommendation = actionToRecommendation(raw.action);
    const signals        = reasonsToSignals(raw.reasons);

    // Transform to the shape LinkShield.tsx expects
    const transformed = {
      url:            finalUrl,
      domain:         extractDomain(finalUrl),
      safe:           raw.action === "SAFE",
      risk_score:     raw.score ?? 0,
      risk_level,
      recommendation,
      signals,
      explanation:    raw.reasons?.length > 0
                        ? raw.reasons[0]
                        : risk_level === "SAFE"
                          ? "No threats detected. This URL appears safe."
                          : "This URL shows suspicious signals.",
      // Keep raw fields too in case needed
      _raw: raw,
    };

    return res.json(transformed);
  } catch (error: any) {
    console.error("Link check error:", error?.response?.data ?? error.message);
    return res.status(500).json({ error: "Failed to analyze URL" });
  }
};