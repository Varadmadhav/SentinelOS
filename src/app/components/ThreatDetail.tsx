import { useNavigate, useParams } from "react-router";
import { ArrowLeft, Phone, ThumbsUp, ThumbsDown, Share2 } from "lucide-react";

export function ThreatDetail() {
  const navigate = useNavigate();
  const { id } = useParams();

  const threat = {
    type: "Link",
    entity: "suspicious-link.com/verify",
    score: 95,
    severity: "block",
    time: "2 min ago",
    signals: [
      { name: "Phishing pattern", weight: 35, detected: true },
      { name: "New domain (<30 days)", weight: 25, detected: true },
      { name: "Urgency language", weight: 20, detected: true },
      { name: "Typosquatting", weight: 15, detected: true },
      { name: "HTTPS missing", weight: 5, detected: false },
    ],
    explanation:
      "This link shows multiple indicators of a phishing attack. The domain was registered recently and uses language designed to create urgency. The URL pattern matches known scam campaigns.",
    evidence: [
      "Domain age: 12 days",
      "Similar to legitimate site: authentic-bank.com",
      "Keywords: 'verify', 'urgent', 'account suspended'",
      "No SSL certificate",
    ],
    action: "Blocked automatically - link was not opened",
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-screen-sm mx-auto">
        {/* Header */}
        <div className="bg-white border-b border-gray-200 px-4 py-4">
          <div className="flex items-center gap-3">
            <button
              onClick={() => navigate("/activity")}
              className="w-8 h-8 flex items-center justify-center"
            >
              <ArrowLeft className="w-5 h-5 text-gray-700" />
            </button>
            <div>
              <h1 className="text-lg text-gray-900">Threat Details</h1>
              <p className="text-xs text-gray-600">{threat.time}</p>
            </div>
          </div>
        </div>

        <div className="px-4 py-6 space-y-4">
          {/* Entity */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-1">Entity</p>
            <p className="text-sm text-gray-900 break-all">{threat.entity}</p>
          </div>

          {/* Score */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-2">Threat Score</p>
            <div className="flex items-center gap-4">
              <div className="flex-1">
                <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-red-500 rounded-full"
                    style={{ width: `${threat.score}%` }}
                  />
                </div>
              </div>
              <span className="text-2xl text-gray-900">{threat.score}</span>
            </div>
          </div>

          {/* Explanation */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-2">Why was this detected?</p>
            <p className="text-sm text-gray-700 leading-relaxed">
              {threat.explanation}
            </p>
          </div>

          {/* Signals */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Detection Signals</p>
            <div className="space-y-2">
              {threat.signals.map((signal, idx) => (
                <div key={idx} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div
                      className={`w-2 h-2 rounded-full ${
                        signal.detected ? "bg-red-500" : "bg-gray-300"
                      }`}
                    />
                    <span
                      className={`text-sm ${
                        signal.detected ? "text-gray-900" : "text-gray-400"
                      }`}
                    >
                      {signal.name}
                    </span>
                  </div>
                  <span className="text-xs text-gray-500">+{signal.weight}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Evidence */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Evidence</p>
            <div className="space-y-2">
              {threat.evidence.map((item, idx) => (
                <div key={idx} className="flex gap-2">
                  <span className="text-gray-400">•</span>
                  <p className="text-sm text-gray-700">{item}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Action Taken */}
          <div className="bg-blue-50 rounded-xl p-4 border border-blue-200">
            <p className="text-xs text-blue-600 mb-1">Action Taken</p>
            <p className="text-sm text-blue-900">{threat.action}</p>
          </div>

          {/* Feedback */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Was this helpful?</p>
            <div className="flex gap-2">
              <button className="flex-1 flex items-center justify-center gap-2 py-3 bg-green-50 text-green-700 rounded-lg border border-green-200">
                <ThumbsUp className="w-4 h-4" />
                <span className="text-sm">Real scam</span>
              </button>
              <button className="flex-1 flex items-center justify-center gap-2 py-3 bg-red-50 text-red-700 rounded-lg border border-red-200">
                <ThumbsDown className="w-4 h-4" />
                <span className="text-sm">False alarm</span>
              </button>
            </div>
          </div>

          {/* Share */}
          <button className="w-full flex items-center justify-center gap-2 py-3 bg-white text-gray-700 rounded-xl border border-gray-200 shadow-sm">
            <Share2 className="w-4 h-4" />
            <span className="text-sm">Share with community</span>
          </button>
        </div>
      </div>
    </div>
  );
}
