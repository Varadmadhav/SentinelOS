import { useNavigate } from "react-router";
import { ArrowLeft, CreditCard, AlertTriangle, Shield, ShieldOff } from "lucide-react";
import { useState, useCallback } from "react";
import axios from "axios";

const API = "http://localhost:3000/api/upi";

interface UpiResult {
  upi_id: string;
  risk_score: number;
  risk_level: string;
  recommendation: string;
  signals: { type: string; detail: string; weight: number }[];
  safe: boolean;
  is_killer_combo: boolean;
  explanation: string;
}

const riskColors: Record<string, { bg: string; border: string; text: string }> = {
  SAFE:       { bg: "bg-green-50",  border: "border-green-200",  text: "text-green-700" },
  LOW_RISK:   { bg: "bg-blue-50",   border: "border-blue-200",   text: "text-blue-700" },
  SUSPICIOUS: { bg: "bg-yellow-50", border: "border-yellow-200", text: "text-yellow-700" },
  DANGEROUS:  { bg: "bg-red-50",    border: "border-red-200",    text: "text-red-700" },
};

const riskIcons: Record<string, any> = {
  SAFE: Shield, LOW_RISK: Shield, SUSPICIOUS: AlertTriangle, DANGEROUS: ShieldOff,
};

// Matches fraud_data.json exactly — these will now score DANGEROUS when checked
const flaggedIds = [
  { id: "scammer@paytm",     reports: 142, lastSeen: "2 hours ago" },
  { id: "fake.merchant@upi", reports: 89,  lastSeen: "5 hours ago" },
  { id: "urgent-verify@ok",  reports: 67,  lastSeen: "1 day ago"   },
  { id: "prize.winner@ybl",  reports: 54,  lastSeen: "2 days ago"  },
];

export function UpiShield() {
  const navigate = useNavigate();
  const [upiId, setUpiId]     = useState("");
  const [onCall, setOnCall]   = useState(false);
  const [result, setResult]   = useState<UpiResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState("");

  const handleCheck = useCallback(async (idToCheck?: string) => {
    const input = (idToCheck ?? upiId).trim();
    if (!input) return;

    setLoading(true);
    setResult(null);
    setError("");

    try {
      const res = await axios.post<UpiResult>(`${API}/check`, {
        upi_id: input,
        upi_copied_on_call: onCall,
      });
      console.log("UPI result:", res.data); // debug
      setResult(res.data);
    } catch (err) {
      console.error("UPI check error:", err);
      setError("Failed to check UPI ID. Make sure backend is running.");
    } finally {
      setLoading(false);
    }
  }, [upiId, onCall]);

  // Tap a flagged ID to auto-fill and check it
  const handleFlaggedTap = (id: string) => {
    setUpiId(id);
    setResult(null);
    handleCheck(id);
  };

  const rc    = result ? (riskColors[result.risk_level] ?? riskColors.SAFE) : null;
  const RIcon = result ? (riskIcons[result.risk_level]  ?? Shield)          : Shield;

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
              <div className="w-10 h-10 rounded-lg bg-green-50 flex items-center justify-center">
                <CreditCard className="w-5 h-5 text-green-600" />
              </div>
              <div>
                <h1 className="text-lg text-gray-900">UPI Shield</h1>
                <p className="text-xs text-gray-600">Payment fraud detection</p>
              </div>
            </div>
          </div>
        </div>

        <div className="px-4 py-6 space-y-4">

          {/* Input */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Check a UPI ID</p>
            <input
              type="text"
              placeholder="e.g. someone@ybl or scammer@paytm"
              value={upiId}
              onChange={(e) => setUpiId(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleCheck()}
              className="w-full border border-gray-200 p-3 rounded-lg text-sm mb-3 focus:outline-none focus:ring-2 focus:ring-green-300"
            />

            {/* Killer combo toggle */}
            <button
              onClick={() => setOnCall((v) => !v)}
              className={`w-full mb-3 py-2.5 rounded-lg text-sm font-medium border transition-colors flex items-center justify-center gap-2 ${
                onCall
                  ? "bg-red-50 border-red-300 text-red-700"
                  : "border-gray-200 text-gray-600"
              }`}
            >
              📞 {onCall ? "ON CALL — Killer combo active 🚨" : "Currently on a call? (tap to enable)"}
            </button>

            <button
              onClick={() => handleCheck()}
              disabled={loading || !upiId.trim()}
              className="w-full bg-green-600 text-white py-3 rounded-lg text-sm font-medium disabled:opacity-50 transition-opacity"
            >
              {loading ? "Checking..." : "Check UPI ID"}
            </button>

            {error && (
              <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-lg">
                <p className="text-xs text-red-700">{error}</p>
              </div>
            )}
          </div>

          {/* Result */}
          {result && rc && (
            <>
              {/* Killer combo warning */}
              {result.is_killer_combo && (
                <div className="bg-gradient-to-br from-red-50 to-orange-50 rounded-xl p-4 border border-red-300">
                  <div className="flex gap-3">
                    <AlertTriangle className="w-5 h-5 text-red-700 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm font-bold text-red-900 mb-1">🚨 KILLER COMBO DETECTED</p>
                      <p className="text-xs text-red-800">{result.explanation}</p>
                    </div>
                  </div>
                </div>
              )}

              {/* Risk banner */}
              <div className={`${rc.bg} rounded-xl p-4 border ${rc.border}`}>
                <div className="flex items-center gap-2 mb-1">
                  <RIcon className={`w-4 h-4 ${rc.text}`} />
                  <span className={`text-sm font-semibold ${rc.text}`}>
                    {result.risk_level.replace("_", " ")}
                  </span>
                  <span className={`ml-auto text-xs font-bold px-2 py-0.5 rounded-full ${
                    result.recommendation === "BLOCK"  ? "bg-red-100 text-red-700" :
                    result.recommendation === "WARN"   ? "bg-yellow-100 text-yellow-700" :
                    result.recommendation === "CAUTION"? "bg-blue-100 text-blue-700" :
                    "bg-green-100 text-green-700"
                  }`}>
                    {result.recommendation}
                  </span>
                </div>
                <p className="text-xs text-gray-600 font-mono">{result.upi_id}</p>
                {!result.is_killer_combo && (
                  <p className="text-xs text-gray-600 mt-1">{result.explanation}</p>
                )}

                {/* Risk score bar */}
                <div className="mt-3">
                  <div className="flex justify-between text-xs text-gray-500 mb-1">
                    <span>Risk Score</span>
                    <span className={`font-bold ${
                      result.risk_score >= 70 ? "text-red-600" :
                      result.risk_score >= 40 ? "text-yellow-600" : "text-green-600"
                    }`}>{result.risk_score}/100</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-1.5">
                    <div
                      className={`h-1.5 rounded-full transition-all ${
                        result.risk_score >= 70 ? "bg-red-500" :
                        result.risk_score >= 40 ? "bg-yellow-500" :
                        result.risk_score >= 15 ? "bg-blue-500" : "bg-green-500"
                      }`}
                      style={{ width: `${Math.min(result.risk_score, 100)}%` }}
                    />
                  </div>
                </div>
              </div>

              {/* Signals */}
              {result.signals.length > 0 && (
                <div className="bg-white rounded-xl p-4 shadow-sm">
                  <p className="text-xs text-gray-600 mb-3">Fraud Signals Detected</p>
                  <div className="space-y-3">
                    {result.signals.map((signal, idx) => (
                      <div key={idx} className="flex items-start justify-between">
                        <div className="flex items-start gap-2 flex-1">
                          <div className="w-2 h-2 rounded-full mt-1.5 flex-shrink-0 bg-red-500" />
                          <div className="flex-1">
                            <p className="text-sm text-gray-900">{signal.type.replace(/_/g, " ")}</p>
                            <p className="text-xs text-gray-600">{signal.detail}</p>
                          </div>
                        </div>
                        <span className="text-xs ml-2 text-red-600 font-medium">+{signal.weight * 10}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}

          {/* Flagged UPI IDs — tap to check */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Flagged UPI IDs — tap to check</p>
            <div className="space-y-2">
              {flaggedIds.map((item, idx) => (
                <button
                  key={idx}
                  onClick={() => handleFlaggedTap(item.id)}
                  disabled={loading}
                  className="w-full p-3 bg-red-50 rounded-lg border border-red-200 text-left hover:bg-red-100 active:bg-red-200 disabled:opacity-50 transition-colors"
                >
                  <div className="flex items-center justify-between mb-1">
                    <p className="text-sm text-gray-900 font-mono">{item.id}</p>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-red-700">{item.reports} community reports</span>
                    <span className="text-xs text-gray-500">{item.lastSeen}</span>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Protection tips */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Protection Tips</p>
            {[
              "Never make payments during active calls",
              "Verify recipient identity before sending money",
              "Check UPI IDs against our community database",
            ].map((tip, i) => (
              <div key={i} className="flex gap-2 mb-2">
                <span className="text-gray-400">•</span>
                <p className="text-sm text-gray-700">{tip}</p>
              </div>
            ))}
          </div>

          <div className="bg-green-50 rounded-xl p-4 border border-green-200">
            <p className="text-xs text-green-600 mb-1">How it works</p>
            <p className="text-sm text-green-900">
              UPI Shield monitors payment requests and cross-references them with active calls,
              known scammer IDs, and suspicious patterns to protect you from payment fraud.
            </p>
          </div>

        </div>
      </div>
    </div>
  );
}