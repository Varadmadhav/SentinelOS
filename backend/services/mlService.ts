/**
 * SentinelOS — mlService.ts
 * Bridge between Node.js backend and Python AI engine (FastAPI on port 8000).
 * All controllers call this service instead of hitting Python directly.
 * 
 * PASTE THIS FILE INTO: backend/services/mlService.ts
 */

import axios, { AxiosInstance } from "axios";

const AI_ENGINE_URL = process.env.AI_ENGINE_URL || "http://localhost:8000";

const aiClient: AxiosInstance = axios.create({
  baseURL: AI_ENGINE_URL,
  timeout: 30000, // 30s — Whisper can take a few seconds on first run
  headers: { "Content-Type": "application/json" },
});

// ─── Types ────────────────────────────────────────────────────────────────────

export interface TranscriptResult {
  transcript: string;
  language: string;
  confidence: number;
  segments: { start: number; end: number; text: string }[];
}

export interface ScamDetectionResult {
  scam: boolean;
  type: string | null;
  confidence: number;
  risk_score: number;
  signals: string[];
  all_types: Record<string, number>;
  explanation: string;
}

export interface ScreenAnalysisResult {
  dark_patterns_found: boolean;
  risk_score: number;
  patterns: {
    type: string;
    description: string;
    matched_text: string;
    severity: "HIGH" | "MEDIUM" | "LOW";
  }[];
  pattern_types: string[];
  highlight_elements: object[];
  summary: string;
}

export interface UrlAnalysisResult {
  url: string;
  domain: string;
  safe: boolean;
  risk_score: number;
  risk_level: "SAFE" | "LOW_RISK" | "SUSPICIOUS" | "DANGEROUS";
  recommendation: "ALLOW" | "CAUTION" | "WARN" | "BLOCK";
  signals: { type: string; detail: string; weight: number }[];
  explanation: string;
}

export interface CallAnalysisResult {
  transcript: string;
  language: string;
  scam_analysis: ScamDetectionResult;
}

// ─── Health Check ─────────────────────────────────────────────────────────────

export async function checkAIEngineHealth(): Promise<boolean> {
  try {
    const res = await aiClient.get("/health");
    return res.data?.status === "ok";
  } catch {
    return false;
  }
}

// ─── Module 1: Speech → Text ──────────────────────────────────────────────────

/**
 * Transcribe audio from base64 string.
 * Called by callController after receiving audio from Kotlin.
 */
export async function transcribeAudio(
  audioBase64: string,
  language = "en"
): Promise<TranscriptResult> {
  const res = await aiClient.post<TranscriptResult>("/speech-to-text", {
    audio_base64: audioBase64,
    language,
  });
  return res.data;
}

// ─── Module 2: Scam Detection ─────────────────────────────────────────────────

/**
 * Detect scam patterns in any text.
 * Used by callController (on transcript) and screenController.
 */
export async function detectScam(text: string): Promise<ScamDetectionResult> {
  const res = await aiClient.post<ScamDetectionResult>("/detect-scam", { text });
  return res.data;
}

// ─── Module 3: Screen Analysis ────────────────────────────────────────────────

/**
 * Analyze screen content for dark patterns.
 * Called by screenController with text from Android AccessibilityService.
 */
export async function analyzeScreen(
  screenText: string,
  uiElements: object[] = []
): Promise<ScreenAnalysisResult> {
  const res = await aiClient.post<ScreenAnalysisResult>("/analyze-screen", {
    screen_text: screenText,
    ui_elements: uiElements,
  });
  return res.data;
}

// ─── Module 4: URL Analysis ───────────────────────────────────────────────────

/**
 * Analyze a URL for phishing/scam signals.
 * Called by linkController when a link is intercepted.
 */
export async function analyzeUrl(url: string): Promise<UrlAnalysisResult> {
  const res = await aiClient.post<UrlAnalysisResult>("/analyze-url", { url });
  return res.data;
}

// ─── Combined: Full Call Pipeline ─────────────────────────────────────────────

/**
 * Single call: audio → transcript → scam detection.
 * Most convenient endpoint for callController.
 */
export async function analyzeCall(
  audioBase64: string,
  language = "en"
): Promise<CallAnalysisResult> {
  const res = await aiClient.post<CallAnalysisResult>("/analyze-call", {
    audio_base64: audioBase64,
    language,
  });
  return res.data;
}