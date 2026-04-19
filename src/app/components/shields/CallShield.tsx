import { useNavigate } from "react-router";
import { ArrowLeft, Phone } from "lucide-react";

export function CallShield() {
  const navigate = useNavigate();

  const timeline = [
    { step: "Call incoming", description: "Number identified", status: "complete" },
    { step: "Voice analysis", description: "Real-time transcription", status: "complete" },
    { step: "Pattern detection", description: "Scam signals detected", status: "complete" },
    { step: "Alert triggered", description: "User notified", status: "complete" },
  ];

  const dailyStats = [
    { label: "Safe", count: 234, color: "bg-green-500" },
    { label: "Warned", count: 12, color: "bg-yellow-500" },
    { label: "Blocked", count: 8, color: "bg-red-500" },
  ];

  const scamPatterns = [
    {
      pattern: "Isolation tactics",
      description: "Asking to move away from others",
      detections: 12,
    },
    {
      pattern: "Urgency language",
      description: "Creating false time pressure",
      detections: 18,
    },
    {
      pattern: "Authority impersonation",
      description: "Claiming to be police/bank",
      detections: 8,
    },
    {
      pattern: "Money requests",
      description: "Asking for payment/transfer",
      detections: 15,
    },
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-screen-sm mx-auto">
        <div className="bg-white border-b border-gray-200 px-4 py-4">
          <div className="flex items-center gap-3">
            <button
              onClick={() => navigate("/shield")}
              className="w-8 h-8 flex items-center justify-center"
            >
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
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Analysis Timeline</p>
            <div className="space-y-3">
              {timeline.map((item, idx) => (
                <div key={idx} className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <div className="w-6 h-6 rounded-full bg-blue-500 flex items-center justify-center">
                      <div className="w-2 h-2 rounded-full bg-white" />
                    </div>
                    {idx < timeline.length - 1 && (
                      <div className="w-0.5 h-8 bg-blue-200" />
                    )}
                  </div>
                  <div className="flex-1 pb-2">
                    <p className="text-sm text-gray-900">{item.step}</p>
                    <p className="text-xs text-gray-500">{item.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

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
                    <div
                      className={`h-full ${stat.color} rounded-full`}
                      style={{
                        width: `${(stat.count / 254) * 100}%`,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Detected Scam Patterns</p>
            <div className="space-y-3">
              {scamPatterns.map((item, idx) => (
                <div
                  key={idx}
                  className="p-3 bg-gray-50 rounded-lg border border-gray-200"
                >
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

          <div className="bg-blue-50 rounded-xl p-4 border border-blue-200">
            <p className="text-xs text-blue-600 mb-1">How it works</p>
            <p className="text-sm text-blue-900">
              Call Shield analyzes incoming calls in real-time using AI to detect
              scam patterns, urgency tactics, and authority impersonation. You'll
              receive alerts during suspicious calls.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
