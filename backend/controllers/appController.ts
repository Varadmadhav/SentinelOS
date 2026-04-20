/**
 * appController.ts
 * ----------------
 * App Shield — AI-powered malicious app detection.
 *
 * Architecture:
 *   1. Whitelist fast-path                         (instant)
 *   2. Rule-based signal extraction                (instant)
 *   3. Claude AI deep contextual analysis          (real intelligence)
 *   4. Merge both → final verdict
 *
 * The Python scorer is NOT called here — it's built for call/UPI signals,
 * not Android app analysis. Claude handles this directly.
 */

import Anthropic from "@anthropic-ai/sdk";
import { Request, Response } from "express";

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY,
});

// ─── Whitelist ────────────────────────────────────────────────────────────────

const TRUSTED_APPS = new Set([
  "com.whatsapp", "com.google.android.apps.maps", "com.google.android.gm",
  "com.phonepe.app", "net.one97.paytm", "com.google.android.apps.nbu.paisa.user",
  "com.instagram.android", "com.facebook.katana", "com.amazon.mShop.android.shopping",
  "com.flipkart.android", "com.swiggy.android", "com.zomato.restaurants",
  "in.amazon.mShop.android.shopping", "com.myntra.android",
  "com.google.android.youtube", "com.google.android.apps.photos",
  "com.microsoft.teams", "com.zoom.videomeetings",
]);

// ─── Types ────────────────────────────────────────────────────────────────────

interface Signal {
  type: string;
  detail: string;
  weight: number;
}

interface AIVerdict {
  risk_score: number;
  risk_level: "SAFE" | "LOW_RISK" | "SUSPICIOUS" | "DANGEROUS";
  recommendation: "ALLOW" | "WARN" | "UNINSTALL";
  explanation: string;
  ai_signals: Signal[];
}

// ─── Rule-based signal extraction ────────────────────────────────────────────

function extractRuleSignals(
  appName: string,
  packageName: string,
  permissions: string[],
  installedFrom: string
): { signals: Signal[]; ruleScore: number } {
  const signals: Signal[] = [];
  let ruleScore = 0;
 const text = `${appName} ${packageName}`.toLowerCase();

// 🔥 ADD THIS BLOCK HERE
if (/sbi|bank|upi|pay|kyc/.test(text) && /fake|update|verify|kyc/.test(text)) {
  signals.push({
    type: "BANKING_IMPERSONATION",
    detail: "Likely fake banking/KYC scam app targeting users",
    weight: 4
  });
  ruleScore += 50;
}

  const namePatterns = [
    { re: /fake|spoof|clone|copy/,                detail: "App name suggests impersonation",              weight: 3 },
    { re: /remote.*support|anydesk|teamview/,     detail: "Remote access tool — high risk",               weight: 3 },
    { re: /bank.*update|kyc.*update|verify.*kyc/, detail: "Fake banking/KYC update pattern",              weight: 3 },
    { re: /prize|lottery|winner|reward|cashback/,  detail: "Lottery / prize scam pattern",                weight: 2 },
    { re: /\.apk$/,                               detail: "Filename ends in .apk — likely sideloaded",    weight: 2 },
  ];
  for (const { re, detail, weight } of namePatterns) {
    if (re.test(text)) {
      signals.push({ type: "SUSPICIOUS_NAME", detail, weight });
      ruleScore += weight * 10;
    }
  }

  if (packageName) {
    if (packageName.split(".").length < 3) {
      signals.push({ type: "WEAK_PACKAGE", detail: "Package name has too few segments (non-standard)", weight: 2 });
      ruleScore += 15;
    }
    if (/fake|test|clone|spoof|hack/.test(packageName)) {
      signals.push({ type: "SUSPICIOUS_PACKAGE", detail: "Package name contains suspicious keyword", weight: 3 });
      ruleScore += 25;
    }
  }

  if (installedFrom === "sideload") {
    signals.push({ type: "SIDELOADED", detail: "APK sideloaded — not installed from Google Play Store", weight: 3 });
    ruleScore += 25;
  } else if (installedFrom === "unknown") {
    signals.push({ type: "UNKNOWN_SOURCE", detail: "Install source unknown — treat with caution", weight: 2 });
    ruleScore += 15;
  }

  const permLower = permissions.map((p) => p.toLowerCase());
  const dangerousCombos = [
    { perms: ["sms", "contacts", "camera"],       detail: "SMS + Contacts + Camera — can steal OTPs and personal data",        weight: 3 },
    { perms: ["screen overlay", "accessibility"], detail: "Screen Overlay + Accessibility — can intercept taps and fake UI",   weight: 3 },
    { perms: ["call logs", "microphone", "location"], detail: "Call Logs + Mic + Location — full surveillance capability",     weight: 3 },
    { perms: ["accessibility"],                   detail: "Accessibility permission — can read and control all screen content", weight: 2 },
    { perms: ["screen overlay"],                  detail: "Screen overlay — can display fake UI over banking apps",            weight: 2 },
  ];
  for (const { perms, detail, weight } of dangerousCombos) {
    if (perms.every((p) => permLower.some((up) => up.includes(p)))) {
      signals.push({ type: "DANGEROUS_PERMISSIONS", detail, weight });
      ruleScore += weight * 10;
    }
  }

  return { signals, ruleScore };
}

// ─── Claude AI analysis ───────────────────────────────────────────────────────

async function analyzeWithClaude(
  appName: string,
  packageName: string,
  permissions: string[],
  installedFrom: string,
  ruleSignals: Signal[],
  ruleScore: number
): Promise<AIVerdict> {
  const prompt = `You are SentinelOS, an Android security expert protecting Indian users from mobile fraud.

Analyze this app and return a JSON verdict. Be strict — Indian users are frequently targeted by fake banking, KYC, and remote-access scams.

APP DETAILS:
- Name: "${appName || "(not provided)"}"
- Package: "${packageName || "(not provided)"}"  
- Permissions requested: ${permissions.length > 0 ? permissions.join(", ") : "none"}
- Installed from: ${installedFrom}
- Rule-based pre-score: ${ruleScore}/60
- Rule signals already detected: ${ruleSignals.map((s) => s.detail).join("; ") || "none"}

SCORING GUIDE (be precise, not conservative):
- Screen Overlay + Accessibility from unknown/sideload source → 80–95 (DANGEROUS, UNINSTALL)
- Fake bank/KYC name + sideloaded → 75–90 (DANGEROUS, UNINSTALL)
- Remote access tool from unknown source → 70–85 (DANGEROUS, UNINSTALL)
- Sideloaded app with sensitive permissions → 50–70 (SUSPICIOUS, WARN)
- Play Store app with standard permissions → 0–20 (SAFE, ALLOW)
- Known safe app (WhatsApp, PhonePe, etc.) → 0–10 (SAFE, ALLOW)

Consider the COMBINATION of factors. One suspicious signal = WARN. Multiple = DANGEROUS.

Return ONLY valid JSON, no markdown fences, no text outside the JSON:
{
  "risk_score": <integer 0-100>,
  "risk_level": "<SAFE|LOW_RISK|SUSPICIOUS|DANGEROUS>",
  "recommendation": "<ALLOW|WARN|UNINSTALL>",
  "explanation": "<2-3 sentences in plain English explaining the verdict to a non-technical Indian user>",
  "ai_signals": [
    { "type": "<SIGNAL_TYPE>", "detail": "<specific finding>", "weight": <1-3> }
  ]
}`;

  const message = await anthropic.messages.create({
    model: "claude-sonnet-4-20250514",
    max_tokens: 700,
    messages: [{ role: "user", content: prompt }],
  });

  const raw = (message.content[0] as { type: string; text: string }).text.trim();
  const clean = raw.replace(/^```json\s*/i, "").replace(/^```\s*/i, "").replace(/```\s*$/i, "").trim();
  const parsed = JSON.parse(clean);

  return {
    risk_score:     Math.min(100, Math.max(0, Number(parsed.risk_score) || 0)),
    risk_level:     parsed.risk_level     || "SAFE",
    recommendation: parsed.recommendation || "ALLOW",
    explanation:    parsed.explanation    || "Analysis complete.",
    ai_signals:     Array.isArray(parsed.ai_signals) ? parsed.ai_signals : [],
  };
}

// ─── POST /api/app/check ──────────────────────────────────────────────────────

export const checkApp = async (req: Request, res: Response) => {
  try {
    const {
      app_name       = "",
      package_name   = "",
      permissions    = [],
      installed_from = "unknown",
    } = req.body;

    if (!app_name && !package_name) {
      return res.status(400).json({ error: "app_name or package_name is required" });
    }

    // 1. Whitelist fast-path
    if (package_name && TRUSTED_APPS.has(package_name)) {
      return res.json({
        app_name, package_name,
        safe: true, risk_score: 0,
        risk_level: "SAFE", recommendation: "ALLOW",
        signals: [], explanation: "This app is verified and trusted.",
        analysis_method: "whitelist",
      });
    }

    // 2. Rule-based signals
    const { signals: ruleSignals, ruleScore } = extractRuleSignals(
      app_name, package_name, permissions, installed_from
    );

    // 3. Claude AI analysis
    let aiVerdict: AIVerdict;

try {
  aiVerdict = await analyzeWithClaude(
    app_name,
    package_name,
    permissions,
    installed_from,
    ruleSignals,
    ruleScore
  );
} catch (aiErr) {
  console.warn("[AppShield] Claude unavailable, using rule-only fallback:", aiErr);

  const fallbackScore = Math.min(100, ruleScore + ruleSignals.length * 10);

  const fallbackLevel =
    fallbackScore >= 70 ? "DANGEROUS" :
    fallbackScore >= 40 ? "SUSPICIOUS" :
    fallbackScore >= 15 ? "LOW_RISK" :
    "SAFE";

  aiVerdict = {
    risk_score: fallbackScore,
    risk_level: fallbackLevel as AIVerdict["risk_level"],
    recommendation:
      fallbackScore >= 70 ? "UNINSTALL" :
      fallbackScore >= 40 ? "WARN" :
      "ALLOW",
    explanation:
      ruleSignals.length > 0
        ? ruleSignals.map((s) => s.detail).join(". ")
        : "No suspicious signals detected.",
    ai_signals: [],
  };
}

// 🔥🔥 FIX 4 — FORCE CRITICAL OVERRIDE (ADD THIS PART)
// 🔥🔥 FINAL STRONG OVERRIDE (REPLACE OLD FIX 4 WITH THIS)

// Detect key high-risk signals by TYPE (more reliable than text)
const hasFakeApp =
  ruleSignals.some(s => s.type === "SUSPICIOUS_NAME") ||
  ruleSignals.some(s => s.type === "SUSPICIOUS_PACKAGE") ||
  ruleSignals.some(s => s.type === "BANKING_IMPERSONATION");

const hasBadSource =
  ruleSignals.some(s => s.type === "SIDELOADED") ||
  ruleSignals.some(s => s.type === "UNKNOWN_SOURCE");

const hasDangerousPerms =
  ruleSignals.some(s => s.type === "DANGEROUS_PERMISSIONS");

// 🚨 FINAL DECISION LOGIC
if ((hasFakeApp && hasBadSource && hasDangerousPerms) || ruleScore >= 70) {
  aiVerdict = {
    risk_score: 95,
    risk_level: "DANGEROUS",
    recommendation: "UNINSTALL",
    explanation:
      "This app is very likely a fake or malicious application. It requests dangerous permissions and is not from a trusted source. It can steal sensitive data like OTPs and banking details.",
    ai_signals: [],
  };
}

// 🛠 Safety fallback (prevents SAFE with signals)
if (aiVerdict.risk_score === 0 && ruleSignals.length > 0) {
  aiVerdict.risk_score = Math.min(80, ruleScore + 20);
  aiVerdict.risk_level = "SUSPICIOUS";
  aiVerdict.recommendation = "WARN";
}

    // 4. Merge rule + AI signals (deduplicate by detail text)
    const seen = new Set<string>();
    const allSignals = [...ruleSignals, ...aiVerdict.ai_signals].filter((s) => {
      if (seen.has(s.detail)) return false;
      seen.add(s.detail);
      return true;
    });

    return res.json({
      app_name,
      package_name,
      safe:            aiVerdict.risk_level === "SAFE",
      risk_score:      aiVerdict.risk_score,
      risk_level:      aiVerdict.risk_level,
      recommendation:  aiVerdict.recommendation,
      signals:         allSignals,
      explanation:     aiVerdict.explanation,
      analysis_method: "ai+rules",
    });

  } catch (err: any) {
    console.error("[AppShield] checkApp error:", err?.message ?? err);
    return res.status(500).json({ error: "Failed to analyze app. Please try again." });
  }
};

// ─── Threat store (wire to MongoDB Threat model for persistence) ──────────────

const activeThreats: any[] = [];

export const getThreats = (_req: Request, res: Response) =>
  res.json({ threats: activeThreats });

export const dismissThreat = (req: Request, res: Response) => {
  const { package_name } = req.params;
  const idx = activeThreats.findIndex((t) => t.package_name === package_name);
  if (idx !== -1) activeThreats.splice(idx, 1);
  return res.json({ success: true });
};