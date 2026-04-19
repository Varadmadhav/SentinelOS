import { useNavigate } from "react-router";
import { ArrowLeft, Link2, Check, X, Clock } from "lucide-react";

export function LinkShield() {
  const navigate = useNavigate();

  const scanSteps = [
    { name: "DNS lookup", status: "pass", latency: "12ms" },
    { name: "SSL verification", status: "fail", latency: "8ms" },
    { name: "Domain reputation", status: "fail", latency: "24ms" },
    { name: "Content analysis", status: "fail", latency: "156ms" },
    { name: "Phishing DB", status: "fail", latency: "32ms" },
  ];

  const examples = [
    {
      url: "amaz0n-verify.com",
      score: 92,
      reasons: ["Typosquatting", "New domain", "No SSL"],
    },
    {
      url: "secure-login-bank.xyz",
      score: 88,
      reasons: ["Suspicious TLD", "Phishing pattern", "Urgency keywords"],
    },
    {
      url: "official-support.tk",
      score: 85,
      reasons: ["Free domain", "Generic name", "Short domain age"],
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
              <div className="w-10 h-10 rounded-lg bg-purple-50 flex items-center justify-center">
                <Link2 className="w-5 h-5 text-purple-600" />
              </div>
              <div>
                <h1 className="text-lg text-gray-900">Link Shield</h1>
                <p className="text-xs text-gray-600">URL and phishing detection</p>
              </div>
            </div>
          </div>
        </div>

        <div className="px-4 py-6 space-y-4">
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Scanning Process</p>
            <div className="space-y-2">
              {scanSteps.map((step, idx) => {
                const Icon = step.status === "pass" ? Check : X;
                return (
                  <div
                    key={idx}
                    className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className={`w-6 h-6 rounded-full flex items-center justify-center ${
                          step.status === "pass"
                            ? "bg-green-100"
                            : "bg-red-100"
                        }`}
                      >
                        <Icon
                          className={`w-4 h-4 ${
                            step.status === "pass"
                              ? "text-green-600"
                              : "text-red-600"
                          }`}
                        />
                      </div>
                      <span className="text-sm text-gray-900">{step.name}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <Clock className="w-3 h-3 text-gray-400" />
                      <span className="text-xs text-gray-500">{step.latency}</span>
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="mt-3 p-3 bg-blue-50 rounded-lg border border-blue-200">
              <p className="text-xs text-blue-900">
                Total scan time: <span className="font-medium">232ms</span>
              </p>
            </div>
          </div>

          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Suspicious URL Examples</p>
            <div className="space-y-3">
              {examples.map((example, idx) => (
                <div
                  key={idx}
                  className="p-3 border border-gray-200 rounded-lg"
                >
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-sm text-gray-900 font-mono break-all">
                      {example.url}
                    </p>
                    <span className="text-xs px-2 py-1 rounded-full bg-red-100 text-red-700 flex-shrink-0 ml-2">
                      {example.score}
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {example.reasons.map((reason, ridx) => (
                      <span
                        key={ridx}
                        className="text-xs px-2 py-0.5 rounded-full bg-gray-100 text-gray-600"
                      >
                        {reason}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">How Scoring Works</p>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-700">Base score</span>
                <span className="text-sm text-gray-900">0</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-700">+ SSL missing</span>
                <span className="text-sm text-red-600">+30</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-700">+ Typosquatting</span>
                <span className="text-sm text-red-600">+25</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-700">+ New domain</span>
                <span className="text-sm text-red-600">+20</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-700">+ Phishing pattern</span>
                <span className="text-sm text-red-600">+17</span>
              </div>
              <div className="border-t border-gray-200 pt-2 mt-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-900">Final score</span>
                  <span className="text-lg text-red-600">92</span>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-purple-50 rounded-xl p-4 border border-purple-200">
            <p className="text-xs text-purple-600 mb-1">How it works</p>
            <p className="text-sm text-purple-900">
              Link Shield scans URLs before they open, checking against phishing
              databases, analyzing domain reputation, and detecting suspicious
              patterns in milliseconds.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
