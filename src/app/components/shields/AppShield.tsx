import { useNavigate } from "react-router";
import { ArrowLeft, Package, Trash2, Shield, AlertTriangle, ShieldOff } from "lucide-react";
import { useState } from "react";
import axios from "axios";

const API = "http://localhost:3000/api/app";

interface AppResult {
  app_name: string;
  package_name: string;
  safe: boolean;
  risk_score: number;
  risk_level: string;
  recommendation: string;
  signals: { type: string; detail: string; weight: number }[];
  explanation: string;
}

const riskColors: Record<string, { bg: string; border: string; text: string }> = {
  SAFE:       { bg: "bg-green-50",  border: "border-green-200",  text: "text-green-700" },
  LOW_RISK:   { bg: "bg-blue-50",   border: "border-blue-200",   text: "text-blue-700" },
  SUSPICIOUS: { bg: "bg-yellow-50", border: "border-yellow-200", text: "text-yellow-700" },
  DANGEROUS:  { bg: "bg-red-50",    border: "border-red-200",    text: "text-red-700" },
};

// Demo apps for hackathon
const DEMO_APPS = [
  {
    label: "🚨 Fake SBI App",
    data: { app_name: "SBI Bank Update KYC", package_name: "com.fake.sbi.kyc", permissions: ["SMS", "Contacts", "Camera"], installed_from: "sideload" },
  },
  {
    label: "🚨 Remote Access",
    data: { app_name: "RemoteSupport Helper", package_name: "com.remote.support.tool", permissions: ["Screen overlay", "Accessibility"], installed_from: "unknown" },
  },
  {
    label: "✅ WhatsApp",
    data: { app_name: "WhatsApp", package_name: "com.whatsapp", permissions: ["Camera", "Microphone"], installed_from: "play_store" },
  },
  {
    label: "✅ PhonePe",
    data: { app_name: "PhonePe", package_name: "com.phonepe.app", permissions: ["SMS"], installed_from: "play_store" },
  },
];

const suspiciousApps = [
  { name: "FakeBanking.apk", type: "Fake banking app", risk: "Critical", installed: "Today", permissions: ["SMS", "Contacts", "Camera"] },
  { name: "RemoteSupport",   type: "Remote access tool", risk: "High",  installed: "2 days ago", permissions: ["Screen overlay", "Accessibility"] },
];

const monitoredApps = [
  { name: "WhatsApp",   category: "Communication", status: "Safe", lastCheck: "5 min ago" },
  { name: "Google Pay", category: "Finance",       status: "Safe", lastCheck: "12 min ago" },
  { name: "PhonePe",    category: "Finance",       status: "Safe", lastCheck: "15 min ago" },
  { name: "Chrome",     category: "Browser",       status: "Safe", lastCheck: "20 min ago" },
];

export function AppShield() {
  const navigate = useNavigate();
  const [appName, setAppName] = useState("");
  const [packageName, setPackageName] = useState("");
  const [permissions, setPermissions] = useState("");
  const [installedFrom, setInstalledFrom] = useState("unknown");
  const [result, setResult] = useState<AppResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleCheck = async (overrideData?: any) => {
    const payload = overrideData ?? {
      app_name: appName.trim(),
      package_name: packageName.trim(),
      permissions: permissions.split(",").map((p) => p.trim()).filter(Boolean),
      installed_from: installedFrom,
    };

    if (!payload.app_name && !payload.package_name) return;

    setLoading(true);
    setResult(null);
    setError("");
    try {
      const res = await axios.post(`${API}/check`, payload);
      setResult(res.data);
      // prefill form with demo data
      if (overrideData) {
        setAppName(overrideData.app_name);
        setPackageName(overrideData.package_name);
        setPermissions((overrideData.permissions ?? []).join(", "));
        setInstalledFrom(overrideData.installed_from);
      }
    } catch {
      setError("Failed to check app. Make sure backend is running.");
    }
    setLoading(false);
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

          {/* Alert banner */}
          <div className="bg-gradient-to-br from-red-50 to-orange-50 rounded-xl p-4 border border-red-200">
            <p className="text-sm text-red-900 mb-1">Suspicious Apps Detected</p>
            <p className="text-xs text-red-700">{suspiciousApps.length} app(s) require immediate attention</p>
          </div>

          {/* Demo quick-load */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Quick Demo — tap to test</p>
            <div className="grid grid-cols-2 gap-2">
              {DEMO_APPS.map((demo, i) => (
                <button
                  key={i}
                  onClick={() => handleCheck(demo.data)}
                  className="p-2.5 border border-gray-200 rounded-lg text-xs text-gray-700 text-left hover:bg-gray-50"
                >
                  {demo.label}
                </button>
              ))}
            </div>
          </div>

          {/* Manual input */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Or check manually</p>
            <input
              type="text" placeholder="App name"
              value={appName} onChange={(e) => setAppName(e.target.value)}
              className="w-full border border-gray-200 p-3 rounded-lg text-sm mb-2 focus:outline-none focus:ring-2 focus:ring-pink-300"
            />
            <input
              type="text" placeholder="Package name (e.g. com.fake.bank)"
              value={packageName} onChange={(e) => setPackageName(e.target.value)}
              className="w-full border border-gray-200 p-3 rounded-lg text-sm mb-2 focus:outline-none focus:ring-2 focus:ring-pink-300"
            />
            <input
              type="text" placeholder="Permissions (comma separated)"
              value={permissions} onChange={(e) => setPermissions(e.target.value)}
              className="w-full border border-gray-200 p-3 rounded-lg text-sm mb-2 focus:outline-none focus:ring-2 focus:ring-pink-300"
            />
            <select
              value={installedFrom} onChange={(e) => setInstalledFrom(e.target.value)}
              className="w-full border border-gray-200 p-3 rounded-lg text-sm mb-3 focus:outline-none"
            >
              <option value="play_store">Play Store</option>
              <option value="sideload">Sideloaded (APK)</option>
              <option value="unknown">Unknown source</option>
            </select>
            <button
              onClick={() => handleCheck()}
              disabled={loading || (!appName.trim() && !packageName.trim())}
              className="w-full bg-pink-600 text-white py-3 rounded-lg text-sm font-medium disabled:opacity-50"
            >
              {loading ? "Scanning..." : "Scan App"}
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
              <div className="space-y-3">
                <div className={`${rc.bg} rounded-xl p-4 border ${rc.border}`}>
                  <div className="flex items-center gap-2 mb-1">
                    <RIcon className={`w-4 h-4 ${rc.text}`} />
                    <span className={`text-sm font-semibold ${rc.text}`}>
                      {result.risk_level.replace("_", " ")}
                    </span>
                    <span className={`ml-auto text-xs font-bold px-2 py-0.5 rounded-full ${
                      result.recommendation === "UNINSTALL" ? "bg-red-100 text-red-700" :
                      result.recommendation === "WARN"      ? "bg-yellow-100 text-yellow-700" :
                      "bg-green-100 text-green-700"
                    }`}>
                      {result.recommendation}
                    </span>
                  </div>
                  <p className="text-xs text-gray-700 mt-1">{result.explanation}</p>
                  {(result.signals ?? []).length > 0 && (
                    <div className="mt-2 space-y-1">
                      {result.signals.map((s, i) => (
                        <p key={i} className="text-xs text-red-700">⚠ {s.detail}</p>
                      ))}
                    </div>
                  )}
                </div>

                {result.recommendation === "UNINSTALL" && (
                  <button className="w-full flex items-center justify-center gap-2 py-3 bg-red-600 text-white rounded-xl text-sm font-medium">
                    <Trash2 className="w-4 h-4" />
                    Uninstall Now
                  </button>
                )}
              </div>
            );
          })()}

          {/* Threats detected (static) */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Threats Detected</p>
            <div className="space-y-3">
              {suspiciousApps.map((app, idx) => (
                <div key={idx} className="p-3 bg-red-50 rounded-lg border border-red-200">
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex-1">
                      <p className="text-sm text-gray-900 mb-1">{app.name}</p>
                      <p className="text-xs text-red-700 mb-1">{app.type}</p>
                      <div className="flex flex-wrap gap-1 mb-2">
                        {app.permissions.map((perm, pidx) => (
                          <span key={pidx} className="text-xs px-2 py-0.5 rounded-full bg-red-100 text-red-700">
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

          {/* Monitored apps */}
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Monitored Apps</p>
            <div className="space-y-2">
              {monitoredApps.map((app, idx) => (
                <div key={idx} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex-1">
                    <p className="text-sm text-gray-900">{app.name}</p>
                    <p className="text-xs text-gray-600">{app.category}</p>
                  </div>
                  <div className="text-right">
                    <span className="text-xs px-2 py-1 rounded-full bg-green-100 text-green-700">{app.status}</span>
                    <p className="text-xs text-gray-500 mt-1">{app.lastCheck}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-pink-50 rounded-xl p-4 border border-pink-200">
            <p className="text-xs text-pink-600 mb-1">How it works</p>
            <p className="text-sm text-pink-900">
              App Shield monitors all app installations, checking against known malware signatures,
              analyzing permissions, and detecting fake apps impersonating legitimate services.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}