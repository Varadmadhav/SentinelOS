import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Cell } from "recharts";

export function Reports() {
  const signalWeights = [
    { name: "Phishing", weight: 35, color: "#EF4444" },
    { name: "New domain", weight: 25, color: "#F97316" },
    { name: "Urgency", weight: 20, color: "#F59E0B" },
    { name: "SSL missing", weight: 15, color: "#EAB308" },
    { name: "Typosquatting", weight: 12, color: "#84CC16" },
    { name: "Other", weight: 8, color: "#10B981" },
  ];

  const actionTiers = [
    {
      range: "0-25",
      action: "Info",
      description: "Safe to proceed, minimal risk detected",
      color: "bg-green-50 border-green-200 text-green-900",
      bgColor: "bg-green-100",
    },
    {
      range: "26-50",
      action: "Warning",
      description: "Proceed with caution, some risks detected",
      color: "bg-yellow-50 border-yellow-200 text-yellow-900",
      bgColor: "bg-yellow-100",
    },
    {
      range: "51-75",
      action: "Alert",
      description: "High risk, strongly recommend avoiding",
      color: "bg-orange-50 border-orange-200 text-orange-900",
      bgColor: "bg-orange-100",
    },
    {
      range: "76-100",
      action: "Block",
      description: "Critical threat, automatically blocked",
      color: "bg-red-50 border-red-200 text-red-900",
      bgColor: "bg-red-100",
    },
  ];

  const exampleScenario = [
    { signal: "Base score", value: 0, cumulative: 0 },
    { signal: "Phishing pattern", value: 35, cumulative: 35 },
    { signal: "New domain", value: 25, cumulative: 60 },
    { signal: "Urgency language", value: 20, cumulative: 80 },
    { signal: "Typosquatting", value: 12, cumulative: 92 },
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-screen-sm mx-auto px-4 py-6">
        <div className="mb-6">
          <h1 className="text-2xl text-gray-900 mb-1">Reports</h1>
          <p className="text-sm text-gray-600">Scoring engine insights</p>
        </div>

        <div className="bg-white rounded-xl p-4 shadow-sm mb-4">
          <p className="text-xs text-gray-600 mb-3">Signal Weights</p>
          <div className="h-48 mb-3">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={signalWeights} layout="vertical">
                <XAxis type="number" domain={[0, 40]} hide />
                <YAxis
                  type="category"
                  dataKey="name"
                  width={100}
                  tick={{ fontSize: 12, fill: "#6B7280" }}
                />
                <Bar dataKey="weight" radius={[0, 4, 4, 0]}>
                  {signalWeights.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="space-y-2">
            {signalWeights.map((signal, idx) => (
              <div key={idx} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div
                    className="w-3 h-3 rounded"
                    style={{ backgroundColor: signal.color }}
                  />
                  <span className="text-sm text-gray-700">{signal.name}</span>
                </div>
                <span className="text-sm text-gray-900">+{signal.weight}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white rounded-xl p-4 shadow-sm mb-4">
          <p className="text-xs text-gray-600 mb-3">Action Tiers</p>
          <div className="space-y-2">
            {actionTiers.map((tier, idx) => (
              <div
                key={idx}
                className={`p-3 rounded-lg border ${tier.color}`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <span className={`w-8 h-8 rounded-lg ${tier.bgColor} flex items-center justify-center text-sm`}>
                      {tier.range.split("-")[0]}
                    </span>
                    <span className="text-sm">{tier.action}</span>
                  </div>
                  <span className="text-xs">{tier.range}</span>
                </div>
                <p className="text-xs opacity-80">{tier.description}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white rounded-xl p-4 shadow-sm mb-4">
          <p className="text-xs text-gray-600 mb-3">Example Calculation</p>
          <div className="space-y-2">
            {exampleScenario.map((step, idx) => (
              <div key={idx} className="flex items-center justify-between">
                <span className="text-sm text-gray-700">{step.signal}</span>
                <div className="flex items-center gap-3">
                  {step.value > 0 && (
                    <span className="text-sm text-red-600">+{step.value}</span>
                  )}
                  <span className={`text-sm ${step.cumulative > 75 ? 'text-red-600' : step.cumulative > 50 ? 'text-orange-600' : step.cumulative > 25 ? 'text-yellow-600' : 'text-green-600'}`}>
                    = {step.cumulative}
                  </span>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-4 p-3 bg-red-50 rounded-lg border border-red-200">
            <p className="text-xs text-red-600 mb-1">Final Score: 92</p>
            <p className="text-xs text-red-900">Action: Block automatically</p>
          </div>
        </div>

        <div className="bg-white rounded-xl p-4 shadow-sm">
          <p className="text-xs text-gray-600 mb-3">How It Works</p>
          <div className="space-y-2">
            <div className="flex gap-2">
              <span className="text-gray-400">1.</span>
              <p className="text-sm text-gray-700">
                Each threat is analyzed for specific risk signals
              </p>
            </div>
            <div className="flex gap-2">
              <span className="text-gray-400">2.</span>
              <p className="text-sm text-gray-700">
                Detected signals contribute weighted points to the score
              </p>
            </div>
            <div className="flex gap-2">
              <span className="text-gray-400">3.</span>
              <p className="text-sm text-gray-700">
                Total score determines the action tier (info/warning/alert/block)
              </p>
            </div>
            <div className="flex gap-2">
              <span className="text-gray-400">4.</span>
              <p className="text-sm text-gray-700">
                You're always informed and can override if needed
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
