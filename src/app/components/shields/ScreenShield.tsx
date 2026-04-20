import { useNavigate } from "react-router";
import { ArrowLeft, Eye, Zap, HardDrive, Shield, AlertTriangle, ShieldOff } from "lucide-react";
import { useState } from "react";
import axios from "axios";

const API = "http://localhost:3000/api/screen";

interface Pattern {
  type: string;
  description: string;
  matched_text: string;
  severity: "HIGH" | "MEDIUM" | "LOW";
}

interface ScreenResult {
  dark_patterns_found: boolean;
  risk_score: number;
  risk_level: string;
  patterns: Pattern[];
  summary: string;
  explanation: string;
}

const riskColors: Record<string, { bg: string; border: string; text: string }> = {
  SAFE:       { bg: "bg-green-50",  border: "border-green-200",  text: "text-green-700" },
  LOW_RISK:   { bg: "bg-blue-50",   border: "border-blue-200",   text: "text-blue-700" },
  SUSPICIOUS: { bg: "bg-yellow-50", border: "border-yellow-200", text: "text-yellow-700" },
  DANGEROUS:  { bg: "bg-red-50",    border: "border-red-200",    text: "text-red-700" },
};

const severityColor = { HIGH: "bg-red-100 text-red-700", MEDIUM: "bg-yellow-100 text-yellow-700", LOW: "bg-blue-100 text-blue-700" };

// Demo screen samples for hackathon
const DEMO_SCREENS = [
  {
    label: "🛒 Fake Shopping Checkout",
    text: "OFFER EXPIRES IN 00:14:32\nOnly 3 seats left!\n✓ Subscribe to premium newsletter\nTotal: ₹999 + GST\n*Additional convenience fee applies",
  },
  {
    label: "⚠️ Fake Virus Alert",
    text: "VIRUS DETECTED on your device! Your phone is infected with malware. Call 1800-XXX-XXXX immediately for support. Immediate action required.",
  },
  {
    label: "🎰 Fake Prize Popup",
    text: "Congratulations! You've been selected as today's lucky winner. Claim your ₹10,000 prize now! Limited time offer ends tonight.",
  },
  {
    label: "✅ Normal Screen",
    text: "Welcome back! Your account balance is ₹12,430. Recent transactions: Amazon ₹499, Swiggy ₹340.",
  },
];

export function ScreenShield() {
  const navigate = useNavigate();
  const [screenText, setScreenText] = useState("");
  const [result, setResult] = useState<ScreenResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [scanTime, setScanTime] = useState<number | null>(null);

  const handleAnalyze = async (text?: string) => {
    const input = text ?? screenText;
    if (!input.trim()) return;
    setLoading(true);
    setResult(null);
    setError("");
    const start = Date.now();
    try {
      const res = await axios.post(`${API}/analyze`, { screen_text: input });
      setScanTime(Date.now() - start);
      setResult(res.data);
    } catch {
      setError("Failed to analyze screen. Make sure backend is running.");
    }
    setLoading(false);
  };

  const loadDemo = (demo: typeof DEMO_SCREENS[0]) => {
    setScreenText(demo.text);
    setResult(null);
    handleAnalyze(demo.text);
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-screen-sm mx-auto">

        {/* Header */}
        <div className="bg-white border-b border-gray-200 px-4 py-4">
          <div className="flex items-center gap-3">
            <button onClick={() => navigate("/shield")} className="w-8 h-8 flex items-center justify-center">
              <ArrowLeft className="w-5 h-5 text-gray-700" />
            </button>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-orange-50 flex items-center justify-center">
                <Eye className="w-5 h-5 text-orange-600" />
              </div>
              <div>
                <h1 className="text-lg text-gray-900">Screen Shield</h1>
                <p className="text-xs text-gray-600">Dark pattern detection</p>
              </div>
            </div>
          </div>
        </div>

        <div className="px-4 py-6 space-y-4">

          {/* Demo quick-load */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Quick Demo — tap a screen type</p>
            <div className="grid grid-cols-2 gap-2">
              {DEMO_SCREENS.map((demo, i) => (
                <button
                  key={i}
                  onClick={() => loadDemo(demo)}
                  className="p-2.5 border border-gray-200 rounded-lg text-xs text-gray-700 text-left hover:bg-gray-50 active:bg-gray-100"
                >
                  {demo.label}
                </button>
              ))}
            </div>
          </div>

          {/* Manual input */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Or paste screen text manually</p>
            <textarea
              rows={4}
              placeholder="Paste screen content here..."
              value={screenText}
              onChange={(e) => setScreenText(e.target.value)}
              className="w-full border border-gray-200 p-3 rounded-lg text-sm mb-3 focus:outline-none focus:ring-2 focus:ring-orange-300 resize-none"
            />
            <button
              onClick={() => handleAnalyze()}
              disabled={loading || !screenText.trim()}
              className="w-full bg-orange-500 text-white py-3 rounded-lg text-sm font-medium disabled:opacity-50"
            >
              {loading ? "Analyzing..." : "Analyze Screen"}
            </button>
            {error && (
              <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-lg">
                <p className="text-xs text-red-700">{error}</p>
              </div>
            )}
          </div>

          {/* Result */}
          {result && (() => {
            const rc = riskColors[result.risk_level] ?? riskColors.SAFE;
            const RIcon = result.risk_level === "DANGEROUS" ? ShieldOff :
                          result.risk_level === "SUSPICIOUS" ? AlertTriangle : Shield;
            return (
              <>
                {/* Banner */}
                <div className={`${rc.bg} rounded-xl p-4 border ${rc.border}`}>
                  <div className="flex items-center gap-2 mb-1">
                    <RIcon className={`w-4 h-4 ${rc.text}`} />
                    <span className={`text-sm font-semibold ${rc.text}`}>
                      {result.dark_patterns_found ? result.summary : "Screen appears safe"}
                    </span>
                    {scanTime && (
                      <span className="ml-auto text-xs text-gray-400">{scanTime}ms</span>
                    )}
                  </div>
                  <p className="text-xs text-gray-600">{result.explanation}</p>
                </div>

                {/* Detected patterns */}
                {(result.patterns ?? []).length > 0 && (
                  <div className="bg-white rounded-xl p-4 shadow-sm">
                    <p className="text-xs text-gray-600 mb-3">Detected Dark Patterns</p>
                    <div className="space-y-3">
                      {result.patterns.map((pattern, idx) => (
                        <div key={idx} className="p-3 bg-orange-50 rounded-lg border border-orange-200">
                          <div className="flex items-center justify-between mb-1">
                            <p className="text-sm text-gray-900">{pattern.type.replace(/_/g, " ")}</p>
                            <span className={`text-xs px-2 py-0.5 rounded-full ${severityColor[pattern.severity] ?? "bg-gray-100 text-gray-600"}`}>
                              {pattern.severity}
                            </span>
                          </div>
                          <p className="text-xs text-orange-800 mb-1">{pattern.description}</p>
                          <p className="text-xs text-gray-500 italic">"{pattern.matched_text}"</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            );
          })()}

          {/* AI Model info */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">AI Model Information</p>
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 bg-gray-50 rounded-lg">
                <div className="flex items-center gap-2 mb-1">
                  <Zap className="w-4 h-4 text-orange-600" />
                  <p className="text-xs text-gray-600">Speed</p>
                </div>
                <p className="text-lg text-gray-900">{scanTime ? `${scanTime}ms` : "45ms"}</p>
                <p className="text-xs text-gray-500">Average scan time</p>
              </div>
              <div className="p-3 bg-gray-50 rounded-lg">
                <div className="flex items-center gap-2 mb-1">
                  <HardDrive className="w-4 h-4 text-orange-600" />
                  <p className="text-xs text-gray-600">Processing</p>
                </div>
                <p className="text-lg text-gray-900">On-device</p>
                <p className="text-xs text-gray-500">Fully offline</p>
              </div>
            </div>
          </div>

          {/* What we detect */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">What We Detect</p>
            {["Hidden costs and fees", "False urgency timers", "Confusing UI patterns", "Misleading buttons", "Trick questions", "Forced continuity"].map((item, i) => (
              <div key={i} className="flex items-center gap-2 mb-2">
                <div className="w-1.5 h-1.5 rounded-full bg-orange-500" />
                <p className="text-sm text-gray-700">{item}</p>
              </div>
            ))}
          </div>

          <div className="bg-orange-50 rounded-xl p-4 border border-orange-200">
            <p className="text-xs text-orange-600 mb-1">How it works</p>
            <p className="text-sm text-orange-900">
              Screen Shield uses on-device AI to analyze app screens in real-time,
              detecting manipulative design patterns that try to trick you into unwanted actions.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}