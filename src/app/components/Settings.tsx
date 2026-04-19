import { useState } from "react";
import {
  Phone,
  Link2,
  CreditCard,
  Eye,
  Package,
  Bell,
  Lock,
  Shield,
  ChevronRight,
  Activity,
} from "lucide-react";

export function Settings() {
  const [modules, setModules] = useState({
    call: true,
    link: true,
    upi: true,
    screen: true,
    app: true,
  });

  const [sensitivity, setSensitivity] = useState("balanced");
  const [onDevice, setOnDevice] = useState(true);

  const moduleList = [
    { id: "call", name: "Call Shield", icon: Phone },
    { id: "link", name: "Link Shield", icon: Link2 },
    { id: "upi", name: "UPI Shield", icon: CreditCard },
    { id: "screen", name: "Screen Shield", icon: Eye },
    { id: "app", name: "App Shield", icon: Package },
  ];

  const toggleModule = (id: string) => {
    setModules((prev) => ({ ...prev, [id]: !prev[id as keyof typeof prev] }));
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-screen-sm mx-auto px-4 py-6">
        <div className="mb-6">
          <h1 className="text-2xl text-gray-900 mb-1">Settings</h1>
          <p className="text-sm text-gray-600">Configure protection</p>
        </div>

        <div className="bg-white rounded-xl p-4 shadow-sm mb-4">
          <p className="text-xs text-gray-600 mb-3">Protection Modules</p>
          <div className="space-y-2">
            {moduleList.map((module) => {
              const Icon = module.icon;
              const isEnabled = modules[module.id as keyof typeof modules];
              return (
                <div
                  key={module.id}
                  className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
                >
                  <div className="flex items-center gap-3">
                    <Icon className="w-5 h-5 text-gray-600" />
                    <span className="text-sm text-gray-900">{module.name}</span>
                  </div>
                  <button
                    onClick={() => toggleModule(module.id)}
                    className={`w-12 h-6 rounded-full transition-colors ${
                      isEnabled ? "bg-blue-600" : "bg-gray-300"
                    }`}
                  >
                    <div
                      className={`w-5 h-5 bg-white rounded-full shadow transition-transform ${
                        isEnabled ? "translate-x-6" : "translate-x-0.5"
                      }`}
                    />
                  </button>
                </div>
              );
            })}
          </div>
        </div>

        <div className="bg-white rounded-xl p-4 shadow-sm mb-4">
          <div className="flex items-center gap-2 mb-3">
            <Bell className="w-4 h-4 text-gray-600" />
            <p className="text-xs text-gray-600">Alert Sensitivity</p>
          </div>
          <div className="space-y-2">
            {["low", "balanced", "high"].map((level) => (
              <button
                key={level}
                onClick={() => setSensitivity(level)}
                className={`w-full p-3 rounded-lg border-2 text-left ${
                  sensitivity === level
                    ? "border-blue-600 bg-blue-50"
                    : "border-gray-200 bg-white"
                }`}
              >
                <p className="text-sm text-gray-900 capitalize mb-1">{level}</p>
                <p className="text-xs text-gray-600">
                  {level === "low" &&
                    "Only critical threats - fewer alerts"}
                  {level === "balanced" &&
                    "Recommended - balanced protection"}
                  {level === "high" &&
                    "Maximum protection - more alerts"}
                </p>
              </button>
            ))}
          </div>
        </div>

        <div className="bg-white rounded-xl p-4 shadow-sm mb-4">
          <div className="flex items-center gap-2 mb-3">
            <Shield className="w-4 h-4 text-gray-600" />
            <p className="text-xs text-gray-600">Whitelist</p>
          </div>
          <div className="space-y-2">
            <button className="w-full p-3 bg-gray-50 rounded-lg flex items-center justify-between">
              <span className="text-sm text-gray-900">Trusted Contacts</span>
              <ChevronRight className="w-4 h-4 text-gray-400" />
            </button>
            <button className="w-full p-3 bg-gray-50 rounded-lg flex items-center justify-between">
              <span className="text-sm text-gray-900">Trusted UPI IDs</span>
              <ChevronRight className="w-4 h-4 text-gray-400" />
            </button>
            <button className="w-full p-3 bg-gray-50 rounded-lg flex items-center justify-between">
              <span className="text-sm text-gray-900">Trusted Websites</span>
              <ChevronRight className="w-4 h-4 text-gray-400" />
            </button>
          </div>
        </div>

        <div className="bg-white rounded-xl p-4 shadow-sm mb-4">
          <div className="flex items-center gap-2 mb-3">
            <Lock className="w-4 h-4 text-gray-600" />
            <p className="text-xs text-gray-600">Privacy</p>
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-900 mb-1">On-device Processing</p>
                <p className="text-xs text-gray-600">
                  All analysis happens locally
                </p>
              </div>
              <button
                onClick={() => setOnDevice(!onDevice)}
                className={`w-12 h-6 rounded-full transition-colors ${
                  onDevice ? "bg-blue-600" : "bg-gray-300"
                }`}
              >
                <div
                  className={`w-5 h-5 bg-white rounded-full shadow transition-transform ${
                    onDevice ? "translate-x-6" : "translate-x-0.5"
                  }`}
                />
              </button>
            </div>
            <button className="w-full p-3 bg-gray-50 rounded-lg flex items-center justify-between">
              <span className="text-sm text-gray-900">Data & Storage</span>
              <ChevronRight className="w-4 h-4 text-gray-400" />
            </button>
          </div>
        </div>

        <div className="bg-white rounded-xl p-4 shadow-sm mb-4">
          <div className="flex items-center gap-2 mb-3">
            <Activity className="w-4 h-4 text-gray-600" />
            <p className="text-xs text-gray-600">Advanced</p>
          </div>
          <div className="space-y-2">
            <button className="w-full p-3 bg-gray-50 rounded-lg flex items-center justify-between">
              <span className="text-sm text-gray-900">API Health</span>
              <ChevronRight className="w-4 h-4 text-gray-400" />
            </button>
            <button className="w-full p-3 bg-gray-50 rounded-lg flex items-center justify-between">
              <span className="text-sm text-gray-900">System Diagnostics</span>
              <ChevronRight className="w-4 h-4 text-gray-400" />
            </button>
            <button className="w-full p-3 bg-gray-50 rounded-lg flex items-center justify-between">
              <span className="text-sm text-gray-900">Export Activity Log</span>
              <ChevronRight className="w-4 h-4 text-gray-400" />
            </button>
          </div>
        </div>

        <div className="bg-white rounded-xl p-4 shadow-sm">
          <div className="space-y-2">
            <button className="w-full p-3 bg-gray-50 rounded-lg text-sm text-gray-900 text-left">
              About SentinelOS
            </button>
            <button className="w-full p-3 bg-gray-50 rounded-lg text-sm text-gray-900 text-left">
              Help & Support
            </button>
            <button className="w-full p-3 bg-gray-50 rounded-lg text-sm text-gray-900 text-left">
              Privacy Policy
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
