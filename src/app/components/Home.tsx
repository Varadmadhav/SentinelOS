import { useNavigate } from "react-router";
import {
  Phone,
  Link2,
  CreditCard,
  Eye,
  Package,
  Shield,
  ChevronRight,
  Search,
  AlertTriangle,
} from "lucide-react";

export function Home() {
  const navigate = useNavigate();

  const threatScore = 92;
  const status = "safe";

  const modules = [
    {
      id: "call",
      name: "Call Shield",
      icon: Phone,
      status: "active",
      alerts: 0,
      color: "bg-blue-50 text-blue-600",
    },
    {
      id: "link",
      name: "Link Shield",
      icon: Link2,
      status: "active",
      alerts: 2,
      color: "bg-purple-50 text-purple-600",
    },
    {
      id: "upi",
      name: "UPI Shield",
      icon: CreditCard,
      status: "active",
      alerts: 1,
      color: "bg-green-50 text-green-600",
    },
    {
      id: "screen",
      name: "Screen Shield",
      icon: Eye,
      status: "active",
      alerts: 0,
      color: "bg-orange-50 text-orange-600",
    },
    {
      id: "app",
      name: "App Shield",
      icon: Package,
      status: "active",
      alerts: 0,
      color: "bg-pink-50 text-pink-600",
    },
  ];

  const stats = [
    { label: "Threats Blocked", value: "1,247" },
    { label: "Active Alerts", value: "3" },
    { label: "Calls Analyzed", value: "892" },
    { label: "Community DB", value: "2.4M" },
  ];

  const recentActivity = [
    {
      type: "Link blocked",
      entity: "suspicious-link.com",
      time: "2 min ago",
      severity: "high",
    },
    {
      type: "UPI warning",
      entity: "unknown@paytm",
      time: "15 min ago",
      severity: "medium",
    },
    {
      type: "Call safe",
      entity: "+91 98765 43210",
      time: "1 hour ago",
      severity: "low",
    },
  ];

  const quickActions = [
    { label: "Scan Link", icon: Link2 },
    { label: "Check UPI", icon: CreditCard },
    { label: "Report Scam", icon: AlertTriangle },
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-screen-sm mx-auto px-4 py-6">
        {/* Header */}
        <div className="mb-6">
          <h1 className="text-2xl text-gray-900 mb-1">SentinelOS</h1>
          <p className="text-sm text-gray-600">Real-time fraud protection</p>
        </div>

        {/* Threat Score */}
        <div className="bg-white rounded-2xl p-6 mb-6 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <p className="text-sm text-gray-600 mb-1">Overall Status</p>
              <p className="text-lg text-gray-900">You are protected</p>
            </div>
            <Shield className="w-6 h-6 text-green-600" />
          </div>

          <div className="flex items-center justify-center py-4">
            <div className="relative w-32 h-32">
              <svg className="w-32 h-32 transform -rotate-90">
                <circle
                  cx="64"
                  cy="64"
                  r="56"
                  stroke="#E5E7EB"
                  strokeWidth="8"
                  fill="none"
                />
                <circle
                  cx="64"
                  cy="64"
                  r="56"
                  stroke="#10B981"
                  strokeWidth="8"
                  fill="none"
                  strokeDasharray={`${(threatScore / 100) * 351.86} 351.86`}
                  strokeLinecap="round"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-3xl text-gray-900">{threatScore}</span>
                <span className="text-xs text-gray-600">Trust Score</span>
              </div>
            </div>
          </div>
        </div>

        {/* Protection Modules */}
        <div className="mb-6">
          <h2 className="text-base text-gray-900 mb-3">Protection Modules</h2>
          <div className="space-y-2">
            {modules.map((module) => {
              const Icon = module.icon;
              return (
                <button
                  key={module.id}
                  onClick={() => navigate(`/shield/${module.id}`)}
                  className="w-full bg-white rounded-xl p-4 shadow-sm flex items-center justify-between"
                >
                  <div className="flex items-center gap-3">
                    <div className={`w-10 h-10 rounded-lg ${module.color} flex items-center justify-center`}>
                      <Icon className="w-5 h-5" />
                    </div>
                    <div className="text-left">
                      <p className="text-sm text-gray-900">{module.name}</p>
                      <p className="text-xs text-gray-500">Active</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {module.alerts > 0 && (
                      <span className="bg-red-100 text-red-600 text-xs px-2 py-1 rounded-full">
                        {module.alerts}
                      </span>
                    )}
                    <ChevronRight className="w-5 h-5 text-gray-400" />
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Stats */}
        <div className="mb-6">
          <div className="flex gap-3 overflow-x-auto pb-2 scrollbar-hide">
            {stats.map((stat, idx) => (
              <div
                key={idx}
                className="bg-white rounded-xl p-4 shadow-sm min-w-[140px] flex-shrink-0"
              >
                <p className="text-xs text-gray-600 mb-1">{stat.label}</p>
                <p className="text-xl text-gray-900">{stat.value}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Activity */}
        <div className="mb-6">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-base text-gray-900">Recent Activity</h2>
            <button
              onClick={() => navigate("/activity")}
              className="text-sm text-blue-600"
            >
              View all
            </button>
          </div>
          <div className="space-y-2">
            {recentActivity.map((item, idx) => (
              <div
                key={idx}
                className="bg-white rounded-xl p-3 shadow-sm flex items-center justify-between"
              >
                <div>
                  <p className="text-sm text-gray-900">{item.type}</p>
                  <p className="text-xs text-gray-500">{item.entity}</p>
                </div>
                <div className="text-right">
                  <p className="text-xs text-gray-500">{item.time}</p>
                  <span
                    className={`inline-block w-2 h-2 rounded-full mt-1 ${
                      item.severity === "high"
                        ? "bg-red-500"
                        : item.severity === "medium"
                        ? "bg-yellow-500"
                        : "bg-green-500"
                    }`}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Quick Actions */}
        <div className="mb-6">
          <h2 className="text-base text-gray-900 mb-3">Quick Actions</h2>
          <div className="flex gap-2">
            {quickActions.map((action, idx) => {
              const Icon = action.icon;
              return (
                <button
                  key={idx}
                  className="flex-1 bg-white rounded-xl p-4 shadow-sm flex flex-col items-center gap-2"
                >
                  <Icon className="w-5 h-5 text-gray-600" />
                  <span className="text-xs text-gray-700">{action.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
