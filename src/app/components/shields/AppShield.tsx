import { useNavigate } from "react-router";
import { ArrowLeft, Package, Trash2 } from "lucide-react";

export function AppShield() {
  const navigate = useNavigate();

  const suspiciousApps = [
    {
      name: "FakeBanking.apk",
      type: "Fake banking app",
      risk: "Critical",
      installed: "Today",
      permissions: ["SMS", "Contacts", "Camera"],
    },
    {
      name: "RemoteSupport",
      type: "Remote access tool",
      risk: "High",
      installed: "2 days ago",
      permissions: ["Screen overlay", "Accessibility"],
    },
  ];

  const monitoredApps = [
    {
      name: "WhatsApp",
      category: "Communication",
      status: "Safe",
      lastCheck: "5 min ago",
    },
    {
      name: "Google Pay",
      category: "Finance",
      status: "Safe",
      lastCheck: "12 min ago",
    },
    {
      name: "PhonePe",
      category: "Finance",
      status: "Safe",
      lastCheck: "15 min ago",
    },
    {
      name: "Chrome",
      category: "Browser",
      status: "Safe",
      lastCheck: "20 min ago",
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
              <div className="w-10 h-10 rounded-lg bg-pink-50 flex items-center justify-center">
                <Package className="w-5 h-5 text-pink-600" />
              </div>
              <div>
                <h1 className="text-lg text-gray-900">App Shield</h1>
                <p className="text-xs text-gray-600">Malicious app detection</p>
              </div>
            </div>
          </div>
        </div>

        <div className="px-4 py-6 space-y-4">
          {suspiciousApps.length > 0 && (
            <div className="bg-gradient-to-br from-red-50 to-orange-50 rounded-xl p-4 border border-red-200">
              <div className="flex items-center justify-between mb-3">
                <div>
                  <p className="text-sm text-red-900 mb-1">
                    Suspicious Apps Detected
                  </p>
                  <p className="text-xs text-red-700">
                    {suspiciousApps.length} app(s) require immediate attention
                  </p>
                </div>
              </div>
            </div>
          )}

          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Threats Detected</p>
            <div className="space-y-3">
              {suspiciousApps.map((app, idx) => (
                <div
                  key={idx}
                  className="p-3 bg-red-50 rounded-lg border border-red-200"
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex-1">
                      <p className="text-sm text-gray-900 mb-1">{app.name}</p>
                      <p className="text-xs text-red-700 mb-1">{app.type}</p>
                      <div className="flex flex-wrap gap-1 mb-2">
                        {app.permissions.map((perm, pidx) => (
                          <span
                            key={pidx}
                            className="text-xs px-2 py-0.5 rounded-full bg-red-100 text-red-700"
                          >
                            {perm}
                          </span>
                        ))}
                      </div>
                    </div>
                    <span className="text-xs px-2 py-1 rounded-full bg-red-600 text-white flex-shrink-0 ml-2">
                      {app.risk}
                    </span>
                  </div>
                  <button className="w-full flex items-center justify-center gap-2 py-2 bg-red-600 text-white rounded-lg">
                    <Trash2 className="w-4 h-4" />
                    <span className="text-sm">Uninstall now</span>
                  </button>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Monitored Apps</p>
            <div className="space-y-2">
              {monitoredApps.map((app, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
                >
                  <div className="flex-1">
                    <p className="text-sm text-gray-900">{app.name}</p>
                    <p className="text-xs text-gray-600">{app.category}</p>
                  </div>
                  <div className="text-right">
                    <span className="text-xs px-2 py-1 rounded-full bg-green-100 text-green-700">
                      {app.status}
                    </span>
                    <p className="text-xs text-gray-500 mt-1">{app.lastCheck}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">What We Look For</p>
            <div className="space-y-2">
              <div className="flex gap-2">
                <span className="text-gray-400">•</span>
                <p className="text-sm text-gray-700">
                  Fake banking and payment apps
                </p>
              </div>
              <div className="flex gap-2">
                <span className="text-gray-400">•</span>
                <p className="text-sm text-gray-700">
                  Remote access and control tools
                </p>
              </div>
              <div className="flex gap-2">
                <span className="text-gray-400">•</span>
                <p className="text-sm text-gray-700">
                  Apps with excessive permissions
                </p>
              </div>
              <div className="flex gap-2">
                <span className="text-gray-400">•</span>
                <p className="text-sm text-gray-700">
                  Malware and spyware signatures
                </p>
              </div>
            </div>
          </div>

          <div className="bg-pink-50 rounded-xl p-4 border border-pink-200">
            <p className="text-xs text-pink-600 mb-1">How it works</p>
            <p className="text-sm text-pink-900">
              App Shield monitors all app installations, checking against known
              malware signatures, analyzing permissions, and detecting fake apps
              impersonating legitimate services.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
