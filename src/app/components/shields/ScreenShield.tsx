import { useNavigate } from "react-router";
import { ArrowLeft, Eye, Zap, HardDrive } from "lucide-react";

export function ScreenShield() {
  const navigate = useNavigate();

  const darkPatterns = [
    {
      type: "Hidden fees",
      app: "Shopping App",
      description: "Additional charges shown only at checkout",
      time: "2 hours ago",
    },
    {
      type: "False urgency",
      app: "Travel Booking",
      description: "'Only 1 seat left' - actually 47 available",
      time: "5 hours ago",
    },
    {
      type: "Trick questions",
      app: "Survey App",
      description: "Confusing consent checkbox wording",
      time: "1 day ago",
    },
    {
      type: "Forced continuity",
      app: "Streaming Service",
      description: "Hard to find cancellation option",
      time: "2 days ago",
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
              <div className="w-10 h-10 rounded-lg bg-orange-50 flex items-center justify-center">
                <Eye className="w-5 h-5 text-orange-600" />
              </div>
              <div>
                <h1 className="text-lg text-gray-900">Screen Shield</h1>
                <p className="text-xs text-gray-600">Dark pattern detection</p>
              </div>
            </div>
          </div>
        </div>

        <div className="px-4 py-6 space-y-4">
          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">Detected Dark Patterns</p>
            <div className="space-y-3">
              {darkPatterns.map((pattern, idx) => (
                <div
                  key={idx}
                  className="p-3 bg-orange-50 rounded-lg border border-orange-200"
                >
                  <div className="flex items-center justify-between mb-1">
                    <p className="text-sm text-gray-900">{pattern.type}</p>
                    <span className="text-xs text-gray-500">{pattern.time}</span>
                  </div>
                  <p className="text-xs text-orange-800 mb-1">{pattern.app}</p>
                  <p className="text-xs text-gray-600">{pattern.description}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">AI Model Information</p>
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 bg-gray-50 rounded-lg">
                <div className="flex items-center gap-2 mb-1">
                  <Zap className="w-4 h-4 text-orange-600" />
                  <p className="text-xs text-gray-600">Speed</p>
                </div>
                <p className="text-lg text-gray-900">45ms</p>
                <p className="text-xs text-gray-500">Average scan time</p>
              </div>
              <div className="p-3 bg-gray-50 rounded-lg">
                <div className="flex items-center gap-2 mb-1">
                  <HardDrive className="w-4 h-4 text-orange-600" />
                  <p className="text-xs text-gray-600">Processing</p>
                </div>
                <p className="text-lg text-gray-900">On-device</p>
                <p className="text-xs text-gray-500">Fully offline</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-xl p-4 shadow-sm">
            <p className="text-xs text-gray-600 mb-3">What We Detect</p>
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-orange-500" />
                <p className="text-sm text-gray-700">Hidden costs and fees</p>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-orange-500" />
                <p className="text-sm text-gray-700">False urgency timers</p>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-orange-500" />
                <p className="text-sm text-gray-700">Confusing UI patterns</p>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-orange-500" />
                <p className="text-sm text-gray-700">Misleading buttons</p>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-orange-500" />
                <p className="text-sm text-gray-700">Trick questions</p>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-orange-500" />
                <p className="text-sm text-gray-700">Forced continuity</p>
              </div>
            </div>
          </div>

          <div className="bg-orange-50 rounded-xl p-4 border border-orange-200">
            <p className="text-xs text-orange-600 mb-1">How it works</p>
            <p className="text-sm text-orange-900">
              Screen Shield uses on-device AI to analyze app screens in real-time,
              detecting manipulative design patterns that try to trick you into
              unwanted actions.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
