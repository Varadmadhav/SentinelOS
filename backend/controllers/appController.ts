import { Request, Response } from "express";
import axios from "axios";

const AI_ENGINE_URL = process.env.AI_ENGINE_URL || "http://localhost:8000";
const VIRUSTOTAL_KEY = process.env.VIRUSTOTAL_API_KEY || "";

// Known legitimate apps whitelist
const TRUSTED_APPS = new Set([
  "com.whatsapp", "com.google.android.apps.maps", "com.google.android.gm",
  "com.phonepe.app", "net.one97.paytm", "com.google.android.apps.nbu.paisa.user",
  "com.instagram.android", "com.facebook.katana", "com.amazon.mShop.android.shopping",
  "com.flipkart.android", "com.swiggy.android", "com.zomato.restaurants",
  "in.amazon.mShop.android.shopping", "com.myntra.android",
]);

// Known malicious app patterns
const SUSPICIOUS_PATTERNS = [
  { pattern: /fake|spoof|clone|copy/i,         reason: "App name suggests impersonation",      weight: 3 },
  { pattern: /remote.*support|anydesk|teamview/i, reason: "Remote access tool detected",        weight: 3 },
  { pattern: /bank.*update|kyc.*app|verify.*app/i, reason: "Fake banking/KYC app pattern",      weight: 3 },
  { pattern: /prize|lottery|winner|reward/i,    reason: "Lottery/prize scam app pattern",       weight: 2 },
  { pattern: /\.apk$/i,                         reason: "Sideloaded APK (not from Play Store)",  weight: 2 },
];

// Dangerous permission combinations
const DANGEROUS_PERMISSIONS = [
  { perms: ["SMS", "Contacts", "Camera"],          reason: "Can steal OTPs and contacts",    weight: 3 },
  { perms: ["Screen overlay", "Accessibility"],    reason: "Can overlay fake UI on your apps", weight: 3 },
  { perms: ["Call logs", "Microphone", "Location"],reason: "Surveillance capability",         weight: 2 },
];

// POST /api/app/check
export const checkApp = async (req: Request, res: Response) => {
  try {
    const {
      app_name = "",
      package_name = "",
      permissions = [],
      apk_hash = "",       // SHA256 of APK — for VirusTotal
      installed_from = "", // "play_store" | "sideload" | "unknown"
    } = req.body;

    if (!app_name && !package_name) {
      return res.status(400).json({ error: "app_name or package_name is required" });
    }

    const signals: { type: string; detail: string; weight: number }[] = [];
    let risk_score = 0;


    // ── 1. Whitelist check ──────────────────────────────────────────────────
    if (package_name && TRUSTED_APPS.has(package_name)) {
      return res.json({
        app_name, package_name,
        safe: true, risk_score: 0,
        risk_level: "SAFE", recommendation: "ALLOW",
        signals: [], explanation: "App is on trusted whitelist.",
      });
    }

    // ── 2. Name pattern matching ────────────────────────────────────────────
    const checkText = `${app_name} ${package_name}`;
    for (const { pattern, reason, weight } of SUSPICIOUS_PATTERNS) {
      if (pattern.test(checkText)) {
        signals.push({ type: "SUSPICIOUS_NAME", detail: reason, weight });
        risk_score += weight * 10;
      }
    }

    // ── 2.5 Advanced behavior checks ───────────────────────

// Fake or weak package name
const isFakePackage =
  package_name.split(".").length < 3 ||
  package_name.includes("fake") ||
  package_name.includes("test");

if (isFakePackage) {
  signals.push({
    type: "SUSPICIOUS_PACKAGE",
    detail: "Package name looks fake or non-standard",
    weight: 2,
  });
  risk_score += 20;
}

// Generic app name
if (app_name && app_name.length < 5) {
  signals.push({
    type: "GENERIC_APP_NAME",
    detail: "Very generic or short app name",
    weight: 1,
  });
  risk_score += 10;
}

// Invalid package format
if (
  package_name &&
  !package_name.startsWith("com.") &&
  !package_name.startsWith("in.")
) {
  signals.push({
    type: "INVALID_PACKAGE",
    detail: "Non-standard package naming",
    weight: 2,
  });
  risk_score += 20;
}


    // ── 3. Sideload check ──────────────────────────────────────────────────
    if (installed_from === "sideload" || installed_from === "unknown") {
      signals.push({
        type: "SIDELOADED",
        detail: "App not installed from Google Play Store",
        weight: 2,
      });
      risk_score += 20;
    }

    // ── 4. Dangerous permissions ────────────────────────────────────────────
    for (const { perms, reason, weight } of DANGEROUS_PERMISSIONS) {
      const hasAll = perms.every((p) =>
        permissions.some((up: string) => up.toLowerCase().includes(p.toLowerCase()))
      );
      if (hasAll) {
        signals.push({ type: "DANGEROUS_PERMISSIONS", detail: reason, weight });
        risk_score += weight * 10;
      }
    }

    // ── 5. VirusTotal check (free — 500 req/day) ───────────────────────────
    if (apk_hash && VIRUSTOTAL_KEY) {
      try {
        const vtRes = await axios.get(
          `https://www.virustotal.com/api/v3/files/${apk_hash}`,
          { headers: { "x-apikey": VIRUSTOTAL_KEY } }
        );
        const stats = vtRes.data?.data?.attributes?.last_analysis_stats;
        if (stats?.malicious > 0) {
          signals.push({
            type: "VIRUSTOTAL_FLAGGED",
            detail: `Flagged by ${stats.malicious} antivirus engines on VirusTotal`,
            weight: 3,
          });
          risk_score += 50;
        }
      } catch {
        // VT unavailable — skip silently
      }
    }

    risk_score = Math.min(100, risk_score);
    const risk_level =
      risk_score >= 70 ? "DANGEROUS" :
      risk_score >= 40 ? "SUSPICIOUS" :
      risk_score >= 15 ? "LOW_RISK" : "SAFE";

    const recommendation =
      risk_score >= 70 ? "UNINSTALL" :
      risk_score >= 40 ? "WARN" : "ALLOW";

    const scoringRes = await axios.post(`${AI_ENGINE_URL}/score-event`, {
  source: "app_shield",
  signals: {
    fraud_db_hit: false,

    // 🔥 map your signals properly
    url_flagged_external: signals.some(s => s.type === "VIRUSTOTAL_FLAGGED"),

    urgency_language: signals.some(s => s.type === "SUSPICIOUS_NAME"),

    unknown_number: installed_from !== "play_store",

    upi_pin_requested: signals.some(s => s.type === "DANGEROUS_PERMISSIONS"),
  }
});

return res.json({
  ...scoringRes.data,

  app_name,
  package_name,
  signals,

  explanation:
    signals.length > 0
      ? signals[0].detail
      : "No suspicious signals detected for this app.",
});
} catch (error: any) {
  console.error("App check error:", error?.response?.data ?? error.message);
  return res.status(500).json({ error: "Failed to analyze app" });
}
};
  