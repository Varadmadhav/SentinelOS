import { useNavigate } from "react-router";
import { ArrowLeft, CreditCard, AlertTriangle } from "lucide-react";

export function UpiShield() {
  const navigate = useNavigate();

  const flaggedIds = [
    { id: "scammer@paytm", reports: 142, lastSeen: "2 hours ago" },
    { id: "fake.merchant@upi", reports: 89, lastSeen: "5 hours ago" },
    { id: "urgent-verify@ok", reports: 67, lastSeen: "1 day ago" },
    { id: "prize.winner@ybl", reports: 54, lastSeen: "2 days ago" },
  ];

  const patterns = [
    {
      name: "Call + Payment",
      description: "Suspicious call during payment request",
      weight: 40,
      detected: true,
    },
    {
      name: "Unknown recipient",
      description: "Not in contacts or transaction history",
      weight: 25,
      detected: true,
    },
    {
      name: "Large amount",
      description: "Unusual transaction size",
      weight: 20,
      detected: false,
    },
    {
      name: "New UPI ID",
      description: "Recently created account",
      weight: 15,
      detected: true,
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
          <div className="bg-gradient-to-br from-yellow-50 to-orange-50 rounded-xl p-4 border border-yellow-200">
            <div className="flex gap-3">
              <AlertTriangle className="w-5 h-5 text-yellow-700 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm text-yellow-900 mb-1">
                  Suspicious Pattern Detected
                </p>
                <p className="text-xs text-yellow-800">
                  Active call while UPI payment requested - this is a common scam
                  tactic
                </p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Pattern Evaluation</p>
            <div className="space-y-3">
              {patterns.map((pattern, idx) => (
                <div key={idx} className="flex items-start justify-between">
                  <div className="flex items-start gap-2 flex-1">
                    <div
                      className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${
                        pattern.detected ? "bg-red-500" : "bg-gray-300"
                      }`}
                    />
                    <div className="flex-1">
                      <p
                        className={`text-sm ${
                          pattern.detected ? "text-gray-900" : "text-gray-400"
                        }`}
                      >
                        {pattern.name}
                      </p>
                      <p
                        className={`text-xs ${
                          pattern.detected ? "text-gray-600" : "text-gray-400"
                        }`}
                      >
                        {pattern.description}
                      </p>
                    </div>
                  </div>
                  <span className="text-xs text-gray-500 ml-2">
                    +{pattern.weight}
                  </span>
                </div>
              ))}
              <div className="border-t border-gray-200 pt-2 mt-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-900">Risk Score</span>
                  <span className="text-lg text-orange-600">80</span>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Flagged UPI IDs</p>
            <div className="space-y-2">
              {flaggedIds.map((item, idx) => (
                <div
                  key={idx}
                  className="p-3 bg-red-50 rounded-lg border border-red-200"
                >
                  <div className="flex items-center justify-between mb-1">
                    <p className="text-sm text-gray-900 font-mono break-all">
                      {item.id}
                    </p>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-red-700">
                      {item.reports} community reports
                    </span>
                    <span className="text-xs text-gray-500">{item.lastSeen}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Protection Tips</p>
            <div className="space-y-2">
              <div className="flex gap-2">
                <span className="text-gray-400">•</span>
                <p className="text-sm text-gray-700">
                  Never make payments during active calls
                </p>
              </div>
              <div className="flex gap-2">
                <span className="text-gray-400">•</span>
                <p className="text-sm text-gray-700">
                  Verify recipient identity before sending money
                </p>
              </div>
              <div className="flex gap-2">
                <span className="text-gray-400">•</span>
                <p className="text-sm text-gray-700">
                  Check UPI IDs against our community database
                </p>
              </div>
            </div>
          </div>

          <div className="bg-green-50 rounded-xl p-4 border border-green-200">
            <p className="text-xs text-green-600 mb-1">How it works</p>
            <p className="text-sm text-green-900">
              UPI Shield monitors payment requests and cross-references them with
              active calls, known scammer IDs, and suspicious patterns to protect
              you from payment fraud.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
