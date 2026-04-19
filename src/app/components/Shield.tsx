import { useNavigate } from "react-router";
import {
  Phone,
  Link2,
  CreditCard,
  Eye,
  Package,
  Shield as ShieldIcon,
  ChevronRight,
} from "lucide-react";

export function Shield() {
  const navigate = useNavigate();

  const modules = [
    {
      id: "call",
      name: "Call Shield",
      description: "Real-time call analysis",
      icon: Phone,
      color: "bg-blue-50 text-blue-600",
      stats: { safe: 234, warned: 12, blocked: 8 },
    },
    {
      id: "link",
      name: "Link Shield",
      description: "URL and phishing detection",
      icon: Link2,
      color: "bg-purple-50 text-purple-600",
      stats: { safe: 156, warned: 18, blocked: 24 },
    },
    {
      id: "upi",
      name: "UPI Shield",
      description: "Payment fraud detection",
      icon: CreditCard,
      color: "bg-green-50 text-green-600",
      stats: { safe: 89, warned: 6, blocked: 3 },
    },
    {
      id: "screen",
      name: "Screen Shield",
      description: "Dark pattern detection",
      icon: Eye,
      color: "bg-orange-50 text-orange-600",
      stats: { safe: 412, warned: 28, blocked: 5 },
    },
    {
      id: "app",
      name: "App Shield",
      description: "Malicious app detection",
      icon: Package,
      color: "bg-pink-50 text-pink-600",
      stats: { safe: 67, warned: 4, blocked: 2 },
    },
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-screen-sm mx-auto px-4 py-6">
        <div className="mb-6">
          <h1 className="text-2xl text-gray-900 mb-1">Shield</h1>
          <p className="text-sm text-gray-600">Protection modules</p>
        </div>

        {/* System Status */}
        <div className="bg-gradient-to-br from-green-50 to-blue-50 rounded-2xl p-6 mb-6 shadow-sm border border-green-200">
          <div className="flex items-center gap-4 mb-4">
            <div className="w-12 h-12 bg-white rounded-full flex items-center justify-center shadow-sm">
              <ShieldIcon className="w-6 h-6 text-green-600" />
            </div>
            <div>
              <p className="text-lg text-gray-900">You are protected</p>
              <p className="text-sm text-gray-600">All modules active</p>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-white rounded-lg p-3">
              <p className="text-xs text-gray-600">Today</p>
              <p className="text-xl text-gray-900">42</p>
              <p className="text-xs text-gray-500">Scans</p>
            </div>
            <div className="bg-white rounded-lg p-3">
              <p className="text-xs text-gray-600">Blocked</p>
              <p className="text-xl text-red-600">8</p>
              <p className="text-xs text-gray-500">Threats</p>
            </div>
            <div className="bg-white rounded-lg p-3">
              <p className="text-xs text-gray-600">Success</p>
              <p className="text-xl text-green-600">97%</p>
              <p className="text-xs text-gray-500">Rate</p>
            </div>
          </div>
        </div>

        {/* Modules */}
        <div className="space-y-3">
          {modules.map((module) => {
            const Icon = module.icon;
            return (
              <button
                key={module.id}
                onClick={() => navigate(`/shield/${module.id}`)}
                className="w-full bg-white rounded-xl p-4 shadow-sm"
              >
                <div className="flex items-start gap-3">
                  <div
                    className={`w-12 h-12 rounded-xl ${module.color} flex items-center justify-center flex-shrink-0`}
                  >
                    <Icon className="w-6 h-6" />
                  </div>

                  <div className="flex-1 text-left">
                    <div className="flex items-center justify-between mb-1">
                      <p className="text-sm text-gray-900">{module.name}</p>
                      <ChevronRight className="w-5 h-5 text-gray-400" />
                    </div>
                    <p className="text-xs text-gray-600 mb-3">
                      {module.description}
                    </p>

                    <div className="flex gap-4">
                      <div>
                        <p className="text-xs text-gray-500">Safe</p>
                        <p className="text-sm text-gray-900">{module.stats.safe}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500">Warned</p>
                        <p className="text-sm text-yellow-600">
                          {module.stats.warned}
                        </p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500">Blocked</p>
                        <p className="text-sm text-red-600">{module.stats.blocked}</p>
                      </div>
                    </div>
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
