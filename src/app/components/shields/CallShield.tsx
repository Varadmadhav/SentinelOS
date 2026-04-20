import { useNavigate } from "react-router";
import {
  ArrowLeft, Phone, Shield, ShieldOff, AlertTriangle,
  Mic, MicOff, PhoneCall, PhoneOff, ChevronRight
} from "lucide-react";
import { useState, useEffect, useRef } from "react";
import axios from "axios";

const API = "http://localhost:3000/api/call";

// Scam call transcript chunks — simulates what Whisper would produce every 60s
const DEMO_SCAM_CHUNKS = [
  "Hello, I am calling from SBI Bank customer care. Your account has been flagged for suspicious activity.",
  "Sir your KYC verification is pending. If you don't complete it in the next 30 minutes your account will be blocked permanently.",
  "Please don't worry, I just need you to share the OTP that was sent to your registered mobile number to verify your identity.",
  "Sir please hurry, my supervisor is waiting. Just share the OTP and we will unblock your account immediately. This is very urgent.",
];

const DEMO_SAFE_CHUNKS = [
  "Hi, this is Rahul calling from Swiggy delivery. Your order number 4521 is out for delivery.",
  "I will be reaching your location in about 15 minutes. Please keep your phone nearby.",
  "The delivery address shows Sector 12, Noida. Is that correct? I will ring the bell when I arrive.",
];

interface NumberResult {
  number: string;
  risk_score: number;
  risk_level: string;
  recommendation: string;
  signals: { type: string; detail: string; weight: number }[];
  safe: boolean;
  explanation: string;
}

interface TranscriptChunk {
  chunk_index: number;
  transcript: string;
  risk_score: number;
  risk_level: string;
  recommendation: string;
  signals: { type: string; detail: string; weight: number }[];
  safe: boolean;
  explanation: string;
}

const riskColors: Record<string, { bg: string; border: string; text: string; bar: string }> = {
  SAFE:       { bg: "bg-green-50",  border: "border-green-200",  text: "text-green-700",  bar: "bg-green-500" },
  LOW_RISK:   { bg: "bg-blue-50",   border: "border-blue-200",   text: "text-blue-700",   bar: "bg-blue-500" },
  SUSPICIOUS: { bg: "bg-yellow-50", border: "border-yellow-200", text: "text-yellow-700", bar: "bg-yellow-500" },
  DANGEROUS:  { bg: "bg-red-50",    border: "border-red-200",    text: "text-red-700",    bar: "bg-red-500" },
};

const riskIcons: Record<string, any> = {
  SAFE: Shield, LOW_RISK: Shield, SUSPICIOUS: AlertTriangle, DANGEROUS: ShieldOff,
};

export function CallShield() {
  const navigate = useNavigate();

  // Number check state
  const [number, setNumber] = useState("");
  const [numberResult, setNumberResult] = useState<NumberResult | null>(null);
  const [numberLoading, setNumberLoading] = useState(false);
  const [numberError, setNumberError] = useState("");

  // Live call simulation state
  const [callActive, setCallActive] = useState(false);
  const [callEnded, setCallEnded] = useState(false);
  const [demoType, setDemoType] = useState<"scam" | "safe">("scam");
  const [chunks, setChunks] = useState<TranscriptChunk[]>([]);
  const [currentChunkIdx, setCurrentChunkIdx] = useState(0);
  const [callTimer, setCallTimer] = useState(0);
  const [analyzing, setAnalyzing] = useState(false);
  const [overallRisk, setOverallRisk] = useState(0);

  const timerRef = useRef<any>(null);
  const chunkRef = useRef<any>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  // ── Number Check ────────────────────────────────────────────────────────────
  const handleNumberCheck = async () => {
    if (!number.trim()) return;
    setNumberLoading(true);
    setNumberResult(null);
    setNumberError("");
    try {
      const res = await axios.post(`${API}/check-number`, { number: number.trim() });
      setNumberResult(res.data);
    } catch {
      setNumberError("Failed to check number. Make sure backend is running.");
    }
    setNumberLoading(false);
  };

  // ── Live Call Simulation ─────────────────────────────────────────────────────
  const startCall = () => {
    setCallActive(true);
    setCallEnded(false);
    setChunks([]);
    setCurrentChunkIdx(0);
    setCallTimer(0);
    setOverallRisk(0);

    // Timer counting up
    timerRef.current = setInterval(() => {
      setCallTimer((t) => t + 1);
    }, 1000);

    // Analyze first chunk immediately, then every 8s (represents 60s in demo)
    analyzeChunk(0);
    chunkRef.current = setInterval(() => {
      setCurrentChunkIdx((idx) => {
        const next = idx + 1;
        const demoChunks = demoType === "scam" ? DEMO_SCAM_CHUNKS : DEMO_SAFE_CHUNKS;
        if (next >= demoChunks.length) {
          endCall();
          return idx;
        }
        analyzeChunk(next);
        return next;
      });
    }, 8000);
  };

  const endCall = () => {
    clearInterval(timerRef.current);
    clearInterval(chunkRef.current);
    setCallActive(false);
    setCallEnded(true);
  };

  const analyzeChunk = async (idx: number) => {
    const demoChunks = demoType === "scam" ? DEMO_SCAM_CHUNKS : DEMO_SAFE_CHUNKS;
    const text = demoChunks[idx];
    if (!text) return;

    setAnalyzing(true);
    try {
      const res = await axios.post(`${API}/analyze-transcript`, {
        text,
        number: number || "unknown",
        chunk_index: idx,
      });
      const chunk: TranscriptChunk = res.data;
      setChunks((prev) => [...prev, chunk]);
      setOverallRisk((prev) => Math.max(prev, chunk.risk_score));
      setTimeout(() => scrollRef.current?.scrollIntoView({ behavior: "smooth" }), 100);
    } catch {
      // Add mock result if backend fails
      setChunks((prev) => [...prev, {
        chunk_index: idx, transcript: text,
        risk_score: 0, risk_level: "SAFE",
        recommendation: "ALLOW", signals: [], safe: true,
        explanation: "Backend unavailable — showing demo only",
      }]);
    }
    setAnalyzing(false);
  };

  useEffect(() => () => { clearInterval(timerRef.current); clearInterval(chunkRef.current); }, []);

  const formatTime = (s: number) => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
  const overallLevel = overallRisk >= 70 ? "DANGEROUS" : overallRisk >= 40 ? "SUSPICIOUS" : overallRisk >= 15 ? "LOW_RISK" : "SAFE";
  const risk = riskColors[overallLevel] ?? riskColors.SAFE;
  const RiskIcon = riskIcons[overallLevel] ?? Shield;

  // Static stats (would come from DB in production)
  const dailyStats = [
    { label: "Safe", count: 234, color: "bg-green-500" },
    { label: "Warned", count: 12, color: "bg-yellow-500" },
    { label: "Blocked", count: 8, color: "bg-red-500" },
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-screen-sm mx-auto">

        {/* ── Header ── */}
        <div className="bg-white border-b border-gray-200 px-4 py-4">
          <div className="flex items-center gap-3">
            <button onClick={() => navigate("/shield")} className="w-8 h-8 flex items-center justify-center">
              <ArrowLeft className="w-5 h-5 text-gray-700" />
            </button>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-blue-50 flex items-center justify-center">
                <Phone className="w-5 h-5 text-blue-600" />
              </div>
              <div>
                <h1 className="text-lg text-gray-900">Call Shield</h1>
                <p className="text-xs text-gray-600">Real-time call analysis</p>
              </div>
            </div>
          </div>
        </div>

        <div className="px-4 py-6 space-y-4">

          {/* ── Section 1: Number Check ── */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Check a Phone Number</p>
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="+91XXXXXXXXXX"
                value={number}
                onChange={(e) => setNumber(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleNumberCheck()}
                className="flex-1 border border-gray-200 p-3 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-300"
              />
              <button
                onClick={handleNumberCheck}
                disabled={numberLoading || !number.trim()}
                className="bg-blue-600 text-white px-4 rounded-lg text-sm font-medium disabled:opacity-50"
              >
                {numberLoading ? "..." : "Check"}
              </button>
            </div>

            {numberError && (
              <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-lg">
                <p className="text-xs text-red-700">{numberError}</p>
              </div>
            )}

            {numberResult && (() => {
              const nr = riskColors[numberResult.risk_level] ?? riskColors.SAFE;
              const NIcon = riskIcons[numberResult.risk_level] ?? Shield;
              return (
                <div className={`mt-3 p-3 ${nr.bg} border ${nr.border} rounded-lg`}>
                  <div className="flex items-center gap-2 mb-1">
                    <NIcon className={`w-4 h-4 ${nr.text}`} />
                    <span className={`text-sm font-semibold ${nr.text}`}>
                      {numberResult.risk_level.replace("_", " ")}
                    </span>
                    <span className={`ml-auto text-xs font-bold px-2 py-0.5 rounded-full ${
                      numberResult.recommendation === "BLOCK" ? "bg-red-100 text-red-700" :
                      numberResult.recommendation === "WARN"  ? "bg-yellow-100 text-yellow-700" :
                      "bg-green-100 text-green-700"
                    }`}>
                      {numberResult.recommendation}
                    </span>
                  </div>
                  <p className="text-xs text-gray-600">{numberResult.explanation}</p>
                  {(numberResult.signals ?? []).length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {numberResult.signals.map((s, i) => (
                        <span key={i} className="text-xs px-2 py-0.5 bg-white rounded-full border border-gray-200 text-gray-600">
                          {s.detail}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              );
            })()}
          </div>

          {/* ── Section 2: Live Call Simulator ── */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Live Call Analysis Demo</p>

            {/* Demo type selector */}
            {!callActive && !callEnded && (
              <div className="flex gap-2 mb-4">
                <button
                  onClick={() => setDemoType("scam")}
                  className={`flex-1 py-2 rounded-lg text-sm font-medium border transition-colors ${
                    demoType === "scam"
                      ? "bg-red-50 border-red-300 text-red-700"
                      : "border-gray-200 text-gray-600"
                  }`}
                >
                  🚨 Scam Call
                </button>
                <button
                  onClick={() => setDemoType("safe")}
                  className={`flex-1 py-2 rounded-lg text-sm font-medium border transition-colors ${
                    demoType === "safe"
                      ? "bg-green-50 border-green-300 text-green-700"
                      : "border-gray-200 text-gray-600"
                  }`}
                >
                  ✅ Safe Call
                </button>
              </div>
            )}

            {/* Call controls */}
            {!callActive && !callEnded && (
              <button
                onClick={startCall}
                className="w-full bg-blue-600 text-white py-3 rounded-lg text-sm font-medium flex items-center justify-center gap-2"
              >
                <PhoneCall className="w-4 h-4" />
                Simulate Incoming Call
              </button>
            )}

            {/* Active call UI */}
            {callActive && (
              <div className="space-y-3">
                {/* Call header */}
                <div className={`p-3 rounded-lg border ${risk.bg} ${risk.border} flex items-center justify-between`}>
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                    <span className="text-sm font-medium text-gray-900">Live — {formatTime(callTimer)}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs font-bold ${risk.text}`}>Risk: {overallRisk}</span>
                    {analyzing && <Mic className="w-3 h-3 text-blue-500 animate-pulse" />}
                  </div>
                </div>

                {/* Risk bar */}
                <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${risk.bar} rounded-full transition-all duration-1000`}
                    style={{ width: `${overallRisk}%` }}
                  />
                </div>

                {/* Transcript feed */}
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {chunks.map((chunk, i) => {
                    const cr = riskColors[chunk.risk_level] ?? riskColors.SAFE;
                    return (
                      <div key={i} className={`p-3 rounded-lg border ${cr.bg} ${cr.border}`}>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs text-gray-500">Segment {i + 1}</span>
                          <span className={`text-xs font-bold ${cr.text}`}>
                            {chunk.risk_level.replace("_", " ")} · {chunk.risk_score}
                          </span>
                        </div>
                        <p className="text-xs text-gray-800 italic">"{chunk.transcript}"</p>
                        {(chunk.signals ?? []).length > 0 && (
                          <div className="mt-1 flex flex-wrap gap-1">
                            {chunk.signals.slice(0, 2).map((s, si) => (
                              <span key={si} className="text-xs px-1.5 py-0.5 bg-white rounded border border-gray-200 text-gray-600">
                                ⚠ {s.detail.slice(0, 30)}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                  {analyzing && (
                    <div className="p-3 bg-gray-50 border border-gray-200 rounded-lg">
                      <p className="text-xs text-gray-400 animate-pulse">Analyzing audio segment...</p>
                    </div>
                  )}
                  <div ref={scrollRef} />
                </div>

                {/* End call button */}
                <button
                  onClick={endCall}
                  className="w-full bg-red-600 text-white py-3 rounded-lg text-sm font-medium flex items-center justify-center gap-2"
                >
                  <PhoneOff className="w-4 h-4" />
                  End Call
                </button>
              </div>
            )}

            {/* Call ended summary */}
            {callEnded && (
              <div className="space-y-3">
                <div className={`p-4 rounded-lg border ${risk.bg} ${risk.border}`}>
                  <div className="flex items-center gap-2 mb-2">
                    <RiskIcon className={`w-5 h-5 ${risk.text}`} />
                    <span className={`text-sm font-bold ${risk.text}`}>
                      Call Ended — {overallLevel.replace("_", " ")}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-xs text-gray-600">
                    <span>Duration: {formatTime(callTimer)}</span>
                    <span>Peak risk score: <strong className={risk.text}>{overallRisk}</strong></span>
                    <span>Segments: {chunks.length}</span>
                  </div>
                </div>

                {/* All segments summary */}
                {chunks.map((chunk, i) => {
                  const cr = riskColors[chunk.risk_level] ?? riskColors.SAFE;
                  return (
                    <div key={i} className="p-3 bg-gray-50 border border-gray-200 rounded-lg">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs text-gray-500">Segment {i + 1}</span>
                        <span className={`text-xs font-bold ${cr.text}`}>{chunk.risk_score}</span>
                      </div>
                      <p className="text-xs text-gray-700 italic mb-1">"{chunk.transcript.slice(0, 80)}..."</p>
                      {(chunk.signals ?? []).length > 0 && (
                        <p className="text-xs text-red-600">⚠ {chunk.signals[0]?.detail}</p>
                      )}
                    </div>
                  );
                })}

                <button
                  onClick={() => { setCallEnded(false); setChunks([]); setOverallRisk(0); setCallTimer(0); }}
                  className="w-full border border-blue-300 text-blue-600 py-3 rounded-lg text-sm font-medium"
                >
                  Try Another Call
                </button>
              </div>
            )}
          </div>

          {/* ── Section 3: Analysis Timeline (original) ── */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">How Analysis Works</p>
            <div className="space-y-3">
              {[
                { step: "Call incoming", description: "Number identified instantly" },
                { step: "Voice analysis", description: "Real-time transcription via Whisper" },
                { step: "Pattern detection", description: "Scam signals checked every 60s" },
                { step: "Alert triggered", description: "Overlay warning shown to user" },
              ].map((item, idx, arr) => (
                <div key={idx} className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <div className="w-6 h-6 rounded-full bg-blue-500 flex items-center justify-center">
                      <div className="w-2 h-2 rounded-full bg-white" />
                    </div>
                    {idx < arr.length - 1 && <div className="w-0.5 h-8 bg-blue-200" />}
                  </div>
                  <div className="flex-1 pb-2">
                    <p className="text-sm text-gray-900">{item.step}</p>
                    <p className="text-xs text-gray-500">{item.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* ── Section 4: Today's Stats (original) ── */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Today's Activity</p>
            <div className="space-y-3">
              {dailyStats.map((stat, idx) => (
                <div key={idx}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm text-gray-700">{stat.label}</span>
                    <span className="text-sm text-gray-900">{stat.count}</span>
                  </div>
                  <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                    <div className={`h-full ${stat.color} rounded-full`}
                      style={{ width: `${(stat.count / 254) * 100}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* ── Section 5: Scam Patterns (original) ── */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Detected Scam Patterns</p>
            <div className="space-y-3">
              {[
                { pattern: "Isolation tactics", description: "Asking to move away from others", detections: 12 },
                { pattern: "Urgency language", description: "Creating false time pressure", detections: 18 },
                { pattern: "Authority impersonation", description: "Claiming to be police/bank", detections: 8 },
                { pattern: "Money requests", description: "Asking for payment/transfer", detections: 15 },
              ].map((item, idx) => (
                <div key={idx} className="p-3 bg-gray-50 rounded-lg border border-gray-200">
                  <div className="flex items-center justify-between mb-1">
                    <p className="text-sm text-gray-900">{item.pattern}</p>
                    <span className="text-xs px-2 py-0.5 rounded-full bg-red-100 text-red-700">
                      {item.detections}
                    </span>
                  </div>
                  <p className="text-xs text-gray-600">{item.description}</p>
                </div>
              ))}
            </div>
          </div>

          {/* ── Info card (original) ── */}
          <div className="bg-blue-50 rounded-xl p-4 border border-blue-200">
            <p className="text-xs text-blue-600 mb-1">How it works</p>
            <p className="text-sm text-blue-900">
              Call Shield analyzes incoming calls in real-time using Whisper AI to detect
              scam patterns, urgency tactics, and authority impersonation every 60 seconds.
              You'll receive alerts during suspicious calls.
            </p>
          </div>

        </div>
      </div>
    </div>
  );
}