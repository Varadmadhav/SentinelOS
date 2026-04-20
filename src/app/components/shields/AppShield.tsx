import { useNavigate } from "react-router";
import {
  ArrowLeft, Package, Trash2, Shield, AlertTriangle,
  ShieldOff, CheckCircle2, RefreshCw, Sparkles, ChevronDown, ChevronUp,
} from "lucide-react";
import { useState, useEffect, useCallback } from "react";
import axios from "axios";

const API = import.meta.env.VITE_API_URL
  ? `${import.meta.env.VITE_API_URL}/api/app`
  : "http://localhost:8000/api/app";

// ─── Types ────────────────────────────────────────────────────────────────────

interface Signal {
  type: string;
  detail: string;
  weight: number;
}

interface AppResult {
  app_name?: string;
  package_name?: string;
  safe?: boolean;
  risk_score?: number;
  risk_level?: "SAFE" | "LOW_RISK" | "SUSPICIOUS" | "DANGEROUS";
  recommendation?: "ALLOW" | "WARN" | "UNINSTALL";
  signals?: Signal[];
  explanation?: string;
  analysis_method?: string;
}

interface ScannedThreat {
  name: string;
  package_name: string;
  type: string;
  risk: string;
  risk_level: string;
  permissions: string[];
  dismissed: boolean;
}

// ─── Styles ───────────────────────────────────────────────────────────────────

const RISK_STYLES = {
  SAFE:       { bg: "bg-green-50",  border: "border-green-200",  text: "text-green-700",  bar: "bg-green-500",  badge: "bg-green-100 text-green-700"  },
  LOW_RISK:   { bg: "bg-blue-50",   border: "border-blue-200",   text: "text-blue-700",   bar: "bg-blue-400",   badge: "bg-blue-100 text-blue-700"    },
  SUSPICIOUS: { bg: "bg-yellow-50", border: "border-yellow-200", text: "text-yellow-700", bar: "bg-yellow-500", badge: "bg-yellow-100 text-yellow-700" },
  DANGEROUS:  { bg: "bg-red-50",    border: "border-red-200",    text: "text-red-700",    bar: "bg-red-500",    badge: "bg-red-600 text-white"         },
} as const;

const RISK_ICON: Record<string, JSX.Element> = {
  SAFE:       <CheckCircle2 className="w-4 h-4" />,
  LOW_RISK:   <Shield className="w-4 h-4" />,
  SUSPICIOUS: <AlertTriangle className="w-4 h-4" />,
  DANGEROUS:  <ShieldOff className="w-4 h-4" />,
};

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

// ─── Main Component ───────────────────────────────────────────────────────────

export function AppShield() {
  const navigate = useNavigate();

  const [appName, setAppName]             = useState("");
  const [packageName, setPackageName]     = useState("");
  const [permissions, setPermissions]     = useState("");
  const [installedFrom, setInstalledFrom] = useState("unknown");

  const [result, setResult]       = useState<AppResult | null>(null);
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState("");
  const [showSignals, setShowSignals] = useState(false);

  const [threats, setThreats]     = useState<ScannedThreat[]>([]);

  // ── Uninstall ──────────────────────────────────────────────────────────────
  const handleUninstall = useCallback(async (pkg: string, name: string) => {
    // On real Android device with Capacitor, replace window.confirm with:
    //   import { App } from "@capacitor-community/app-launcher";
    //   await App.openUrl({ url: `package:${pkg}` });
    const confirmed = window.confirm(
      `Remove "${name}" from your device?\n\nThis would open the Android uninstall screen for ${pkg}.`
    );
    if (!confirmed) return;
    setThreats((prev) => prev.map((t) => t.package_name === pkg ? { ...t, dismissed: true } : t));
    axios.delete(`${API}/threats/${encodeURIComponent(pkg)}`).catch(() => {});
  }, []);

  // ── Scan ───────────────────────────────────────────────────────────────────
  const handleCheck = useCallback(async (overrideData?: typeof DEMO_APPS[0]["data"]) => {
    const payload = overrideData ?? {
      app_name:       appName.trim(),
      package_name:   packageName.trim(),
      permissions:    permissions.split(",").map((p) => p.trim()).filter(Boolean),
      installed_from: installedFrom,
    };

    if (!payload.app_name && !payload.package_name) return;

    setLoading(true);
    setResult(null);
    setError("");
    setShowSignals(false);

    if (overrideData) {
      setAppName(overrideData.app_name);
      setPackageName(overrideData.package_name);
      setPermissions((overrideData.permissions ?? []).join(", "));
      setInstalledFrom(overrideData.installed_from);
    }

    try {
      const { data } = await axios.post<AppResult>(`${API}/check`, payload);

      if (import.meta.env.DEV) console.log("[AppShield] response:", data);

      // Normalise — never trust field presence
      const normalised: AppResult = {
  app_name:     data.app_name     ?? payload.app_name,
  package_name: data.package_name ?? payload.package_name,

  // 🔥 FIX STARTS HERE
  risk_score: data.risk_score ?? data.score ?? 0,

  risk_level:
    data.risk_level ??
    (data.action === "UNINSTALL" ? "DANGEROUS" :
     data.action === "WARN" ? "SUSPICIOUS" :
     data.action === "SAFE" ? "SAFE" : "SAFE"),

  recommendation:
    data.recommendation ??
    data.action ??
    "ALLOW",
  // 🔥 FIX ENDS HERE

  safe:            data.safe ?? false,
  signals:         data.signals ?? [],
  explanation:     data.explanation ?? "Analysis complete.",
  analysis_method: data.analysis_method ?? "rules",
};

      setResult(normalised);

      if (normalised.risk_level === "DANGEROUS" || normalised.risk_level === "SUSPICIOUS") {
        setThreats((prev) => {
          if (prev.some((t) => t.package_name === normalised.package_name)) return prev;
          return [
            ...prev,
            {
              name:         normalised.app_name || normalised.package_name || "Unknown",
              package_name: normalised.package_name ?? "",
              type:         (normalised.signals ?? [])[0]?.detail ?? "Suspicious app",
              risk:         normalised.risk_level === "DANGEROUS" ? "Critical" : "High",
              risk_level:   normalised.risk_level ?? "SUSPICIOUS",
              permissions:  payload.permissions,
              dismissed:    false,
            },
          ];
        });
      }
    } catch (err: any) {
      const msg = err?.response?.data?.error ?? "Could not reach backend. Is it running on port 3000?";
      setError(msg);
    }

    setLoading(false);
  }, [appName, packageName, permissions, installedFrom]);

  useEffect(() => {
    axios.get<{ threats: ScannedThreat[] }>(`${API}/threats`)
      .then(({ data }) => { if (data.threats?.length) setThreats(data.threats); })
      .catch(() => {});
  }, []);

  const activeThreats = threats.filter((t) => !t.dismissed);

  // ─── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-screen-sm mx-auto">

        {/* Header */}
        <div className="bg-white border-b border-gray-200 px-4 py-4 sticky top-0 z-10">
          <div className="flex items-center gap-3">
            <button onClick={() => navigate("/shield")} className="w-8 h-8 flex items-center justify-center rounded-full hover:bg-gray-100">
              <ArrowLeft className="w-5 h-5 text-gray-700" />
            </button>
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-pink-500 to-rose-600 flex items-center justify-center shadow-sm">
              <Package className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-base font-semibold text-gray-900">App Shield</h1>
              <p className="text-xs text-gray-500">AI-powered malicious app detection</p>
            </div>
          </div>
        </div>

        <div className="px-4 py-5 space-y-4">

          {/* Alert banner — dynamic */}
          {activeThreats.length > 0 ? (
            <div className="rounded-2xl p-4 bg-red-50 border border-red-200">
              <div className="flex items-center gap-2 mb-1">
                <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                <p className="text-sm font-semibold text-red-900">Threats Detected</p>
              </div>
              <p className="text-xs text-red-600 ml-4">
                {activeThreats.length} app{activeThreats.length > 1 ? "s" : ""} require immediate attention
              </p>
            </div>
          ) : (
            <div className="rounded-2xl p-4 bg-emerald-50 border border-emerald-200">
              <div className="flex items-center gap-2 mb-1">
                <div className="w-2 h-2 rounded-full bg-emerald-500" />
                <p className="text-sm font-semibold text-emerald-900">All Clear</p>
              </div>
              <p className="text-xs text-emerald-600 ml-4">No threats detected in this session</p>
            </div>
          )}

          {/* Quick demo */}
          <div className="bg-white rounded-2xl p-4 shadow-sm border border-gray-100">
            <p className="text-xs font-medium text-gray-400 uppercase tracking-wide mb-3">Quick Demo — tap to test</p>
            <div className="grid grid-cols-2 gap-2">
              {DEMO_APPS.map((demo, i) => (
                <button
                  key={i}
                  onClick={() => handleCheck(demo.data)}
                  disabled={loading}
                  className="p-3 border border-gray-200 rounded-xl text-xs text-gray-700 text-left hover:bg-gray-50 hover:border-gray-300 transition-all disabled:opacity-50 font-medium"
                >
                  {demo.label}
                </button>
              ))}
            </div>
          </div>

          {/* Manual input */}
          <div className="bg-white rounded-2xl p-4 shadow-sm border border-gray-100">
            <p className="text-xs font-medium text-gray-400 uppercase tracking-wide mb-3">Check manually</p>
            <div className="space-y-2">
              <input
                type="text" placeholder="App name (e.g. SBI Yono)"
                value={appName} onChange={(e) => setAppName(e.target.value)}
                className="w-full border border-gray-200 px-3 py-2.5 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-pink-300 focus:border-transparent bg-gray-50"
              />
              <input
                type="text" placeholder="Package name (e.g. com.fake.bank)"
                value={packageName} onChange={(e) => setPackageName(e.target.value)}
                className="w-full border border-gray-200 px-3 py-2.5 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-pink-300 focus:border-transparent bg-gray-50"
              />
              <input
                type="text" placeholder="Permissions — comma separated"
                value={permissions} onChange={(e) => setPermissions(e.target.value)}
                className="w-full border border-gray-200 px-3 py-2.5 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-pink-300 focus:border-transparent bg-gray-50"
              />
              <select
                value={installedFrom} onChange={(e) => setInstalledFrom(e.target.value)}
                className="w-full border border-gray-200 px-3 py-2.5 rounded-xl text-sm focus:outline-none bg-gray-50 cursor-pointer"
              >
                <option value="play_store">Google Play Store</option>
                <option value="sideload">Sideloaded (APK file)</option>
                <option value="unknown">Unknown source</option>
              </select>
            </div>

            <button
              onClick={() => handleCheck()}
              disabled={loading || (!appName.trim() && !packageName.trim())}
              className="mt-3 w-full bg-gradient-to-r from-pink-500 to-rose-600 text-white py-3 rounded-xl text-sm font-semibold disabled:opacity-50 flex items-center justify-center gap-2 shadow-sm active:scale-[0.98] transition-transform"
            >
              {loading ? (
                <><RefreshCw className="w-4 h-4 animate-spin" /> Scanning with AI...</>
              ) : (
                <><Sparkles className="w-4 h-4" /> Scan App</>
              )}
            </button>

            {error && (
              <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-xl">
                <p className="text-xs text-red-700">{error}</p>
              </div>
            )}
          </div>

          {/* Scan result */}
          {result && (() => {
            const level = result.risk_level ?? "SAFE";
            const score = result.risk_score ?? 0;
            const rec   = result.recommendation ?? "ALLOW";
            const rc    = RISK_STYLES[level] ?? RISK_STYLES.SAFE;
            const sigs  = result.signals ?? [];

            return (
              <div className="space-y-3">
                <div className={`${rc.bg} rounded-2xl p-4 border ${rc.border}`}>
                  {/* Header row */}
                  <div className="flex items-center gap-2 mb-3">
                    <span className={rc.text}>{RISK_ICON[level] ?? RISK_ICON.SAFE}</span>
                    <span className={`text-sm font-bold ${rc.text}`}>{level.replace(/_/g, " ")}</span>
                    <span className={`ml-auto text-xs font-bold px-2.5 py-1 rounded-full ${rc.badge}`}>{rec}</span>
                  </div>

                  {/* AI method badge */}
                  {result.analysis_method === "ai+rules" && (
                    <div className="flex items-center gap-1 mb-2">
                      <Sparkles className="w-3 h-3 text-purple-500" />
                      <span className="text-xs text-purple-600 font-medium">Analyzed by AI</span>
                    </div>
                  )}

                  {/* Explanation */}
                  <p className="text-xs text-gray-700 leading-relaxed mb-3">{result.explanation}</p>

                  {/* Score bar */}
                  <div>
                    <div className="flex justify-between text-xs text-gray-500 mb-1">
                      <span>Risk score</span>
                      <span className="font-semibold">{score}/100</span>
                    </div>
                    <div className="h-2 bg-white/60 rounded-full overflow-hidden border border-black/5">
                      <div
                        className={`h-full ${rc.bar} rounded-full transition-all duration-700`}
                        style={{ width: `${score}%` }}
                      />
                    </div>
                  </div>

                  {/* Signals toggle */}
                  {sigs.length > 0 && (
                    <div className="mt-3">
                      <button
                        onClick={() => setShowSignals((v) => !v)}
                        className={`flex items-center gap-1 text-xs font-medium ${rc.text}`}
                      >
                        {showSignals ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                        {sigs.length} signal{sigs.length > 1 ? "s" : ""} detected
                      </button>
                      {showSignals && (
                        <div className="mt-2 space-y-1.5">
                          {sigs.map((s, i) => (
                            <div key={i} className="flex items-start gap-2">
                              <span className="text-xs mt-0.5">⚠</span>
                              <p className={`text-xs ${rc.text} leading-relaxed`}>{s.detail}</p>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Action buttons */}
                {rec === "UNINSTALL" && (
                  <button
                    onClick={() => handleUninstall(result.package_name ?? "", result.app_name ?? "")}
                    className="w-full flex items-center justify-center gap-2 py-3 bg-red-600 hover:bg-red-700 text-white rounded-2xl text-sm font-semibold shadow-sm active:scale-[0.98] transition-all"
                  >
                    <Trash2 className="w-4 h-4" />
                    Uninstall Now
                  </button>
                )}
                {rec === "WARN" && (
                  <div className="p-3.5 bg-yellow-50 border border-yellow-200 rounded-2xl">
                    <p className="text-xs text-yellow-800 leading-relaxed">
                      ⚠ Use with caution. Avoid granting sensitive permissions and monitor for unusual behaviour.
                    </p>
                  </div>
                )}
                {rec === "ALLOW" && (
                  <div className="p-3.5 bg-green-50 border border-green-200 rounded-2xl">
                    <p className="text-xs text-green-800">✓ This app appears safe to use.</p>
                  </div>
                )}
              </div>
            );
          })()}

          {/* Live threat list */}
          {activeThreats.length > 0 && (
            <div className="bg-white rounded-2xl p-4 shadow-sm border border-gray-100">
              <p className="text-xs font-medium text-gray-400 uppercase tracking-wide mb-3">Threats Detected</p>
              <div className="space-y-3">
                {activeThreats.map((app, idx) => (
                  <div key={idx} className="p-3 bg-red-50 rounded-xl border border-red-200">
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex-1 mr-2">
                        <p className="text-sm font-semibold text-gray-900 mb-0.5">{app.name}</p>
                        <p className="text-xs text-red-600 mb-2">{app.type}</p>
                        <div className="flex flex-wrap gap-1">
                          {app.permissions.map((perm, pidx) => (
                            <span key={pidx} className="text-xs px-2 py-0.5 rounded-full bg-red-100 text-red-700 font-medium">
                              {perm}
                            </span>
                          ))}
                        </div>
                      </div>
                      <span className="text-xs px-2.5 py-1 rounded-full bg-red-600 text-white font-bold flex-shrink-0">
                        {app.risk}
                      </span>
                    </div>
                    <button
                      onClick={() => handleUninstall(app.package_name, app.name)}
                      className="w-full flex items-center justify-center gap-2 py-2.5 bg-red-600 hover:bg-red-700 text-white rounded-xl text-sm font-semibold active:scale-[0.98] transition-all"
                    >
                      <Trash2 className="w-4 h-4" />
                      Uninstall now
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Footer info */}
          <div className="bg-gradient-to-br from-pink-50 to-rose-50 rounded-2xl p-4 border border-pink-100">
            <div className="flex items-center gap-1.5 mb-1.5">
              <Sparkles className="w-3.5 h-3.5 text-pink-500" />
              <p className="text-xs font-semibold text-pink-700">AI-Powered Detection</p>
            </div>
            <p className="text-xs text-pink-800 leading-relaxed">
              App Shield uses Claude AI combined with rule-based analysis to detect fake banking apps,
              remote access tools, dangerous permission combinations, and sideloaded APKs targeting Indian users.
            </p>
          </div>

        </div>
      </div>
    </div>
  );
}