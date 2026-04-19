import { Outlet, useLocation, useNavigate } from "react-router";
import { Home, Activity, Shield, FileText, Settings } from "lucide-react";

export function Root() {
  const location = useLocation();
  const navigate = useNavigate();

  const tabs = [
    { path: "/", icon: Home, label: "Home" },
    { path: "/activity", icon: Activity, label: "Activity" },
    { path: "/shield", icon: Shield, label: "Shield" },
    { path: "/reports", icon: FileText, label: "Reports" },
    { path: "/settings", icon: Settings, label: "Settings" },
  ];

  const isActive = (path: string) => {
    if (path === "/") {
      return location.pathname === "/";
    }
    return location.pathname.startsWith(path);
  };

  return (
    <div className="h-screen flex flex-col bg-gray-50">
      <div className="flex-1 overflow-y-auto pb-20">
        <Outlet />
      </div>

      <nav className="fixed bottom-0 left-0 right-0 bg-white border-t border-gray-200 safe-area-inset-bottom">
        <div className="flex justify-around items-center h-16 max-w-screen-sm mx-auto">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const active = isActive(tab.path);
            return (
              <button
                key={tab.path}
                onClick={() => navigate(tab.path)}
                className="flex flex-col items-center justify-center flex-1 h-full"
              >
                <Icon
                  className={`w-6 h-6 ${
                    active ? "text-blue-600" : "text-gray-500"
                  }`}
                />
                <span
                  className={`text-xs mt-1 ${
                    active ? "text-blue-600" : "text-gray-600"
                  }`}
                >
                  {tab.label}
                </span>
              </button>
            );
          })}
        </div>
      </nav>
    </div>
  );
}
