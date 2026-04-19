import { useNavigate } from "react-router";
import { Phone, Link2, CreditCard, Eye, Package, ChevronRight } from "lucide-react";

export function Activity() {
  const navigate = useNavigate();

  const threats = [
    {
      id: 1,
      type: "Link",
      entity: "suspicious-link.com/verify",
      score: 95,
      signals: ["Phishing", "New domain", "Urgency"],
      time: "2 min ago",
      severity: "block",
      icon: Link2,
    },
    {
      id: 2,
      type: "UPI",
      entity: "unknown@paytm",
      score: 72,
      signals: ["Call+Payment", "Unknown"],
      time: "15 min ago",
      severity: "warning",
      icon: CreditCard,
    },
    {
      id: 3,
      type: "Call",
      entity: "+91 98765 43210",
      score: 85,
      signals: ["Urgency", "Isolation"],
      time: "1 hour ago",
      severity: "alert",
      icon: Phone,
    },
    {
      id: 4,
      type: "Screen",
      entity: "Dark pattern detected",
      score: 68,
      signals: ["Hidden fees", "False urgency"],
      time: "2 hours ago",
      severity: "warning",
      icon: Eye,
    },
    {
      id: 5,
      type: "App",
      entity: "FakeBanking.apk",
      score: 92,
      signals: ["Remote access", "Fake banking"],
      time: "Yesterday",
      severity: "block",
      icon: Package,
    },
    {
      id: 6,
      type: "Link",
      entity: "trusted-site.com",
      score: 12,
      signals: [],
      time: "Yesterday",
      severity: "info",
      icon: Link2,
    },
  ];

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "block":
        return "border-l-red-500 bg-red-50";
      case "alert":
        return "border-l-orange-500 bg-orange-50";
      case "warning":
        return "border-l-yellow-500 bg-yellow-50";
      default:
        return "border-l-green-500 bg-green-50";
    }
  };

  const getSeverityLabel = (severity: string) => {
    switch (severity) {
      case "block":
        return "Blocked";
      case "alert":
        return "Alert";
      case "warning":
        return "Warning";
      default:
        return "Safe";
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-screen-sm mx-auto px-4 py-6">
        <div className="mb-6">
          <h1 className="text-2xl text-gray-900 mb-1">Activity</h1>
          <p className="text-sm text-gray-600">Detected threats and events</p>
        </div>

        <div className="space-y-3">
          {threats.map((threat) => {
            const Icon = threat.icon;
            return (
              <button
                key={threat.id}
                onClick={() => navigate(`/activity/${threat.id}`)}
                className={`w-full bg-white rounded-xl p-4 shadow-sm border-l-4 ${getSeverityColor(
                  threat.severity
                )}`}
              >
                <div className="flex items-start gap-3">
                  <div className="w-10 h-10 rounded-lg bg-gray-100 flex items-center justify-center flex-shrink-0">
                    <Icon className="w-5 h-5 text-gray-600" />
                  </div>

                  <div className="flex-1 text-left">
                    <div className="flex items-center justify-between mb-1">
                      <p className="text-sm text-gray-900">{threat.type}</p>
                      <span className="text-xs text-gray-500">{threat.time}</span>
                    </div>

                    <p className="text-xs text-gray-600 mb-2 truncate">
                      {threat.entity}
                    </p>

                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-gray-700">
                          Score: <span className="font-medium">{threat.score}</span>
                        </span>
                        <span className="text-xs px-2 py-0.5 rounded-full bg-gray-200 text-gray-700">
                          {getSeverityLabel(threat.severity)}
                        </span>
                      </div>
                      <ChevronRight className="w-4 h-4 text-gray-400" />
                    </div>

                    {threat.signals.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2">
                        {threat.signals.map((signal, idx) => (
                          <span
                            key={idx}
                            className="text-xs px-2 py-0.5 rounded-full bg-gray-100 text-gray-600"
                          >
                            {signal}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
