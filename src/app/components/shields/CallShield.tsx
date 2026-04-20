import { useNavigate } from "react-router";
import {
  ArrowLeft, Phone, Shield, ShieldOff, AlertTriangle,
  Mic, MicOff, PhoneCall, PhoneOff, Upload, FileAudio,
} from "lucide-react";
import { useState, useEffect, useRef } from "react";
import axios from "axios";

const PYTHON_API = "http://localhost:8000";
const NODE_API   = "http://localhost:3000/api/call";

const DEMO_SCAM_CHUNKS = [
  "Hello, I am calling from SBI Bank customer care. Your account has been flagged for suspicious activity.",
  "Sir your KYC verification is pending. If you don't complete it in the next 30 minutes your account will be blocked permanently.",
  "Please don't worry, I just need you to share the OTP that was sent to your registered mobile number to verify your identity.",
  "Sir please hurry, my supervisor is waiting. Just share the OTP and we will unblock your account immediately. This is very urgent.",
];
const DEMO_SAFE_CHUNKS = [
  "Hi, this is Rahul calling from Swiggy delivery. Your order number 4521 is out for delivery.",
  "I will be reaching your location in about 15 minutes. Please keep your phone nearby.",
  "The delivery address shows Sector 12, Noida. Is that correct? I will ring the bell when I arrive.",
];

interface AudioAnalysisResult {
  transcript: string;
  language: string;
  confidence: number;
  scam: boolean;
  type: string | null;
  risk_score: number;
  signals: string[];
  explanation: string;
  segments: { start: number; end: number; text: string }[];
  filename?: string;
}

interface TranscriptChunk {
  chunk_index: number;
  transcript: string;
  risk_score: number;
  risk_level: string;
  recommendation: string;
  signals: { type: string; detail: string; weight: number }[];
  safe: boolean;
  explanation: string;
}

interface NumberResult {
  number: string;
  risk_score: number;
  risk_level: string;
  recommendation: string;
  signals: { type: string; detail: string; weight: number }[];
  safe: boolean;
  explanation: string;
}

const riskColors: Record<string, { bg: string; border: string; text: string; bar: string }> = {
  SAFE:       { bg: "bg-green-50",  border: "border-green-200",  text: "text-green-700",  bar: "bg-green-500" },
  LOW_RISK:   { bg: "bg-blue-50",   border: "border-blue-200",   text: "text-blue-700",   bar: "bg-blue-500" },
  SUSPICIOUS: { bg: "bg-yellow-50", border: "border-yellow-200", text: "text-yellow-700", bar: "bg-yellow-500" },
  DANGEROUS:  { bg: "bg-red-50",    border: "border-red-200",    text: "text-red-700",    bar: "bg-red-500" },
};

const scoreToLevel = (s: number) =>
  s >= 70 ? "DANGEROUS" : s >= 40 ? "SUSPICIOUS" : s >= 15 ? "LOW_RISK" : "SAFE";

const RiskIcon = ({ level }: { level: string }) => {
  if (level === "DANGEROUS") return <ShieldOff className="w-4 h-4" />;
  if (level === "SUSPICIOUS") return <AlertTriangle className="w-4 h-4" />;
  return <Shield className="w-4 h-4" />;
};

const AudioResultCard = ({ result }: { result: AudioAnalysisResult }) => {
  const level = scoreToLevel(result.risk_score);
  const rc = riskColors[level];
  return (
    <div className="space-y-3 mt-3">
      <div className={`${rc.bg} rounded-xl p-4 border ${rc.border}`}>
        <div className="flex items-center gap-2 mb-2">
          <span className={rc.text}><RiskIcon level={level} /></span>
          <span className={`text-sm font-bold ${rc.text}`}>
            {result.scam ? `SCAM — ${(result.type ?? "").replace(/_/g, " ")}` : "No Scam Detected"}
          </span>
          <span className={`ml-auto text-xs font-bold px-2 py-0.5 rounded-full ${
            result.risk_score >= 70 ? "bg-red-100 text-red-700" :
            result.risk_score >= 40 ? "bg-yellow-100 text-yellow-700" :
            "bg-green-100 text-green-700"
          }`}>Score: {result.risk_score}</span>
        </div>
        <p className="text-xs text-gray-700">{result.explanation}</p>
        {result.confidence > 0 && (
          <p className="text-xs text-gray-500 mt-1">
            Confidence: {Math.round(result.confidence * 100)}% · Lang: {result.language}
          </p>
        )}
      </div>
      <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
        <div className={`h-full ${rc.bar} rounded-full transition-all duration-700`}
          style={{ width: `${result.risk_score}%` }} />
      </div>
      <div className="bg-white rounded-xl p-4 shadow-sm">
        <p className="text-xs text-gray-500 mb-2">Transcript {result.filename ? `— ${result.filename}` : ""}</p>
        <p className="text-sm text-gray-800 leading-relaxed italic">
          "{result.transcript || "No speech detected."}"
        </p>
      </div>
      {result.segments.length > 0 && (
        <div className="bg-white rounded-xl p-4 shadow-sm">
          <p className="text-xs text-gray-500 mb-2">Segments ({result.segments.length})</p>
          <div className="space-y-1 max-h-40 overflow-y-auto">
            {result.segments.map((seg, i) => (
              <div key={i} className="flex gap-2 text-xs">
                <span className="text-gray-400 w-12 flex-shrink-0">{seg.start.toFixed(1)}s</span>
                <span className="text-gray-700">{seg.text}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {(result.signals ?? []).length > 0 && (
        <div className="bg-white rounded-xl p-4 shadow-sm">
          <p className="text-xs text-gray-500 mb-2">Detected Signals</p>
          <div className="flex flex-wrap gap-1">
            {result.signals.map((s, i) => (
              <span key={i} className="text-xs px-2 py-1 bg-red-50 border border-red-200 rounded-full text-red-700">
                ⚠ {s}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export function CallShield() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<"upload" | "record" | "demo" | "number">("upload");

  // Number
  const [number, setNumber]             = useState("");
  const [numberResult, setNumberResult] = useState<NumberResult | null>(null);
  const [numberLoading, setNumberLoading] = useState(false);
  const [numberError, setNumberError]   = useState("");

  // Upload
  const [uploadFile, setUploadFile]         = useState<File | null>(null);
  const [uploadResult, setUploadResult]     = useState<AudioAnalysisResult | null>(null);
  const [uploadLoading, setUploadLoading]   = useState(false);
  const [uploadError, setUploadError]       = useState("");
  const [uploadProgress, setUploadProgress] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Record
  const [recording, setRecording]         = useState(false);
  const [recordResult, setRecordResult]   = useState<AudioAnalysisResult | null>(null);
  const [recordLoading, setRecordLoading] = useState(false);
  const [recordError, setRecordError]     = useState("");
  const [recordTimer, setRecordTimer]     = useState(0);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef   = useRef<Blob[]>([]);
  const recordTimerRef   = useRef<any>(null);

  // Demo
  const [callActive, setCallActive]   = useState(false);
  const [callEnded, setCallEnded]     = useState(false);
  const [demoType, setDemoType]       = useState<"scam" | "safe">("scam");
  const [chunks, setChunks]           = useState<TranscriptChunk[]>([]);
  const [callTimer, setCallTimer]     = useState(0);
  const [analyzing, setAnalyzing]     = useState(false);
  const [overallRisk, setOverallRisk] = useState(0);
  const timerRef  = useRef<any>(null);
  const chunkRef  = useRef<any>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  const formatTime = (s: number) =>
    `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;

  // ── Number check ────────────────────────────────────────────────────────
  const handleNumberCheck = async () => {
    if (!number.trim()) return;
    setNumberLoading(true); setNumberResult(null); setNumberError("");
    try {
      const res = await axios.post(`${NODE_API}/check-number`, { number: number.trim() });
      setNumberResult(res.data);
    } catch { setNumberError("Failed. Make sure Node backend is running."); }
    setNumberLoading(false);
  };

  // ── File upload ──────────────────────────────────────────────────────────
  const handleFileUpload = async () => {
    if (!uploadFile) return;
    setUploadLoading(true); setUploadResult(null); setUploadError("");
    setUploadProgress("Uploading audio...");
    const formData = new FormData();
    formData.append("file", uploadFile);
    formData.append("language", "en");
    try {
      setUploadProgress("Transcribing with Whisper AI... (10-30s)");
      const res = await axios.post(`${PYTHON_API}/analyze-audio`, formData, {
        headers: { "Content-Type": "multipart/form-data" },
        timeout: 120000,
      });
      setUploadResult(res.data);
    } catch (err: any) {
      setUploadError(err?.response?.data?.detail ?? "Failed. Make sure Python server has /analyze-audio endpoint.");
    }
    setUploadLoading(false); setUploadProgress("");
  };

  // ── Mic recording ────────────────────────────────────────────────────────
  const startRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const mr = new MediaRecorder(stream, { mimeType: "audio/webm" });
      mediaRecorderRef.current = mr;
      audioChunksRef.current = [];
      mr.ondataavailable = (e) => { if (e.data.size > 0) audioChunksRef.current.push(e.data); };
      mr.onstop = async () => {
        stream.getTracks().forEach((t) => t.stop());
        const blob = new Blob(audioChunksRef.current, { type: "audio/webm" });
        setRecordLoading(true); setRecordResult(null); setRecordError("");
        try {
          const b64 = await new Promise<string>((res, rej) => {
            const r = new FileReader();
            r.onload = () => res((r.result as string).split(",")[1]);
            r.onerror = rej;
            r.readAsDataURL(blob);
          });
          const response = await axios.post(`${PYTHON_API}/analyze-audio-b64`,
            { audio_base64: b64, language: "en" }, { timeout: 120000 });
          setRecordResult(response.data);
        } catch (err: any) {
          setRecordError(err?.response?.data?.detail ?? "Failed. Make sure Python server is running.");
        }
        setRecordLoading(false);
      };
      mr.start(1000);
      setRecording(true); setRecordTimer(0);
      recordTimerRef.current = setInterval(() => setRecordTimer((t) => t + 1), 1000);
    } catch { setRecordError("Microphone access denied."); }
  };

  const stopRecording = () => {
    mediaRecorderRef.current?.stop();
    clearInterval(recordTimerRef.current);
    setRecording(false);
  };

  // ── Demo simulator ───────────────────────────────────────────────────────
  const startCall = () => {
    setCallActive(true); setCallEnded(false);
    setChunks([]); setCallTimer(0); setOverallRisk(0);
    timerRef.current = setInterval(() => setCallTimer((t) => t + 1), 1000);
    analyzeChunk(0);
    let idx = 0;
    chunkRef.current = setInterval(() => {
      idx += 1;
      const dc = demoType === "scam" ? DEMO_SCAM_CHUNKS : DEMO_SAFE_CHUNKS;
      if (idx >= dc.length) { endCall(); return; }
      analyzeChunk(idx);
    }, 8000);
  };

  const endCall = () => {
    clearInterval(timerRef.current); clearInterval(chunkRef.current);
    setCallActive(false); setCallEnded(true);
  };

  const analyzeChunk = async (idx: number) => {
    const dc = demoType === "scam" ? DEMO_SCAM_CHUNKS : DEMO_SAFE_CHUNKS;
    const text = dc[idx]; if (!text) return;
    setAnalyzing(true);
    try {
      const res = await axios.post(`${NODE_API}/analyze-transcript`,
        { text, number: number || "unknown", chunk_index: idx });
      const chunk: TranscriptChunk = res.data;
      setChunks((p) => [...p, chunk]);
      setOverallRisk((p) => Math.max(p, chunk.risk_score));
      setTimeout(() => scrollRef.current?.scrollIntoView({ behavior: "smooth" }), 100);
    } catch {
      setChunks((p) => [...p, {
        chunk_index: idx, transcript: text, risk_score: 0,
        risk_level: "SAFE", recommendation: "ALLOW", signals: [],
        safe: true, explanation: "Backend unavailable",
      }]);
    }
    setAnalyzing(false);
  };

  useEffect(() => () => {
    clearInterval(timerRef.current); clearInterval(chunkRef.current);
    clearInterval(recordTimerRef.current);
  }, []);

  const overallLevel = scoreToLevel(overallRisk);

  const tabs = [
    { id: "upload" as const, label: "📁 Upload MP3" },
    { id: "record" as const, label: "🎙 Record Mic" },
    { id: "demo"   as const, label: "📞 Demo Call" },
    { id: "number" as const, label: "🔢 Number" },
  ];

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
              <div className="w-10 h-10 rounded-lg bg-blue-50 flex items-center justify-center">
                <Phone className="w-5 h-5 text-blue-600" />
              </div>
              <div>
                <h1 className="text-lg text-gray-900">Call Shield</h1>
                <p className="text-xs text-gray-600">Real-time call analysis</p>
              </div>
            </div>
          </div>
        </div>

        {/* Tab bar */}
        <div className="bg-white border-b border-gray-200 px-4">
          <div className="flex gap-1 overflow-x-auto py-2 no-scrollbar">
            {tabs.map((tab) => (
              <button key={tab.id} onClick={() => setActiveTab(tab.id)}
                className={`flex-shrink-0 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                  activeTab === tab.id ? "bg-blue-600 text-white" : "bg-gray-100 text-gray-600"
                }`}>
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        <div className="px-4 py-6 space-y-4">

          {/* ── UPLOAD TAB ── */}
          {activeTab === "upload" && (
            <>
              <div className="bg-white rounded-xl p-4 shadow-sm">
                <p className="text-xs text-gray-600 mb-3">Upload MP3/WAV — Whisper AI transcribes and scans for scams</p>
                <div
                  onDrop={(e) => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) setUploadFile(f); }}
                  onDragOver={(e) => e.preventDefault()}
                  onClick={() => fileInputRef.current?.click()}
                  className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-colors ${
                    uploadFile ? "border-blue-300 bg-blue-50" : "border-gray-200 hover:border-blue-200"
                  }`}
                >
                  {uploadFile ? (
                    <div className="flex items-center justify-center gap-2">
                      <FileAudio className="w-5 h-5 text-blue-600" />
                      <span className="text-sm text-blue-700 font-medium">{uploadFile.name}</span>
                      <span className="text-xs text-gray-400">({(uploadFile.size / 1024 / 1024).toFixed(1)} MB)</span>
                    </div>
                  ) : (
                    <>
                      <Upload className="w-8 h-8 text-gray-300 mx-auto mb-2" />
                      <p className="text-sm text-gray-500">Drop audio file or tap to browse</p>
                      <p className="text-xs text-gray-400 mt-1">MP3 · WAV · M4A · OGG · FLAC · WebM</p>
                    </>
                  )}
                </div>
                <input ref={fileInputRef} type="file"
                  accept=".mp3,.wav,.m4a,.ogg,.flac,.webm,.mp4" className="hidden"
                  onChange={(e) => e.target.files?.[0] && setUploadFile(e.target.files[0])} />

                {uploadFile && (
                  <button onClick={handleFileUpload} disabled={uploadLoading}
                    className="w-full mt-3 bg-blue-600 text-white py-3 rounded-lg text-sm font-medium disabled:opacity-50">
                    {uploadLoading ? uploadProgress || "Analyzing..." : "🎙 Analyze with Whisper"}
                  </button>
                )}
                {uploadLoading && (
                  <div className="mt-3 p-3 bg-blue-50 border border-blue-200 rounded-lg">
                    <p className="text-xs text-blue-700 animate-pulse">{uploadProgress}</p>
                    <p className="text-xs text-gray-400 mt-1">First run downloads model (~140MB). Hang tight.</p>
                  </div>
                )}
                {uploadError && (
                  <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-lg">
                    <p className="text-xs text-red-700">{uploadError}</p>
                  </div>
                )}
              </div>
              {uploadResult && <AudioResultCard result={uploadResult} />}
              <div className="bg-blue-50 rounded-xl p-4 border border-blue-200">
                <p className="text-xs text-blue-600 mb-1">💡 What to test</p>
                <p className="text-sm text-blue-900">
                  Record yourself saying: <em>"Sir your KYC is pending, please share your OTP or your account will be blocked"</em> — save as MP3 and upload.
                </p>
              </div>
            </>
          )}

          {/* ── RECORD TAB ── */}
          {activeTab === "record" && (
            <>
              <div className="bg-white rounded-xl p-4 shadow-sm">
                <p className="text-xs text-gray-600 mb-3">Record from mic — analyzed by Whisper in real time</p>
                <div className={`rounded-xl p-6 text-center border-2 transition-all ${
                  recording ? "border-red-300 bg-red-50" : "border-gray-200 bg-gray-50"
                }`}>
                  {recording ? (
                    <>
                      <div className="w-16 h-16 rounded-full bg-red-100 flex items-center justify-center mx-auto mb-3 animate-pulse">
                        <Mic className="w-8 h-8 text-red-600" />
                      </div>
                      <p className="text-sm font-medium text-red-700">Recording...</p>
                      <p className="text-2xl font-mono text-red-600 mt-1">{formatTime(recordTimer)}</p>
                    </>
                  ) : (
                    <>
                      <div className="w-16 h-16 rounded-full bg-gray-200 flex items-center justify-center mx-auto mb-3">
                        <MicOff className="w-8 h-8 text-gray-400" />
                      </div>
                      <p className="text-sm text-gray-500">Tap to start recording</p>
                    </>
                  )}
                </div>
                <button onClick={recording ? stopRecording : startRecording} disabled={recordLoading}
                  className={`w-full mt-3 py-3 rounded-lg text-sm font-medium flex items-center justify-center gap-2 ${
                    recording ? "bg-red-600 text-white" : "bg-blue-600 text-white disabled:opacity-50"
                  }`}>
                  {recording ? <><MicOff className="w-4 h-4" /> Stop & Analyze</>
                   : recordLoading ? "Analyzing with Whisper..."
                   : <><Mic className="w-4 h-4" /> Start Recording</>}
                </button>
                {recordLoading && (
                  <div className="mt-3 p-3 bg-blue-50 border border-blue-200 rounded-lg">
                    <p className="text-xs text-blue-700 animate-pulse">Transcribing... 10-30 seconds</p>
                  </div>
                )}
                {recordError && (
                  <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-lg">
                    <p className="text-xs text-red-700">{recordError}</p>
                  </div>
                )}
              </div>
              {recordResult && <AudioResultCard result={recordResult} />}
              <div className="bg-blue-50 rounded-xl p-4 border border-blue-200">
                <p className="text-xs text-blue-600 mb-1">💡 What to say</p>
                <p className="text-sm text-blue-900">
                  <strong>Scam:</strong> <em>"Your KYC is pending. Share OTP immediately or account blocked."</em>
                  <br /><br />
                  <strong>Safe:</strong> <em>"Hi, your Swiggy order is on the way. Be there in 10 minutes."</em>
                </p>
              </div>
            </>
          )}

          {/* ── DEMO TAB ── */}
          {activeTab === "demo" && (
            <div className="bg-white rounded-xl p-4 shadow-sm">
              <p className="text-xs text-gray-600 mb-3">
                Live call simulation — transcript analyzed every 8s (= 60s in real app)
              </p>
              {!callActive && !callEnded && (
                <>
                  <div className="flex gap-2 mb-4">
                    {(["scam", "safe"] as const).map((t) => (
                      <button key={t} onClick={() => setDemoType(t)}
                        className={`flex-1 py-2 rounded-lg text-sm font-medium border ${
                          demoType === t
                            ? t === "scam" ? "bg-red-50 border-red-300 text-red-700"
                                           : "bg-green-50 border-green-300 text-green-700"
                            : "border-gray-200 text-gray-600"
                        }`}>
                        {t === "scam" ? "🚨 Scam Call" : "✅ Safe Call"}
                      </button>
                    ))}
                  </div>
                  <button onClick={startCall}
                    className="w-full bg-blue-600 text-white py-3 rounded-lg text-sm font-medium flex items-center justify-center gap-2">
                    <PhoneCall className="w-4 h-4" /> Simulate Incoming Call
                  </button>
                </>
              )}

              {callActive && (() => {
                const rc = riskColors[overallLevel] ?? riskColors.SAFE;
                return (
                  <div className="space-y-3">
                    <div className={`p-3 rounded-lg border ${rc.bg} ${rc.border} flex items-center justify-between`}>
                      <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                        <span className="text-sm font-medium">Live — {formatTime(callTimer)}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`text-xs font-bold ${rc.text}`}>Risk: {overallRisk}</span>
                        {analyzing && <Mic className="w-3 h-3 text-blue-500 animate-pulse" />}
                      </div>
                    </div>
                    <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                      <div className={`h-full ${rc.bar} rounded-full transition-all duration-1000`}
                        style={{ width: `${overallRisk}%` }} />
                    </div>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {chunks.map((chunk, i) => {
                        const cr = riskColors[chunk.risk_level] ?? riskColors.SAFE;
                        return (
                          <div key={i} className={`p-3 rounded-lg border ${cr.bg} ${cr.border}`}>
                            <div className="flex justify-between mb-1">
                              <span className="text-xs text-gray-500">Segment {i + 1}</span>
                              <span className={`text-xs font-bold ${cr.text}`}>
                                {chunk.risk_level.replace("_", " ")} · {chunk.risk_score}
                              </span>
                            </div>
                            <p className="text-xs text-gray-800 italic">"{chunk.transcript}"</p>
                          </div>
                        );
                      })}
                      {analyzing && (
                        <div className="p-3 bg-gray-50 border border-gray-200 rounded-lg">
                          <p className="text-xs text-gray-400 animate-pulse">Analyzing segment...</p>
                        </div>
                      )}
                      <div ref={scrollRef} />
                    </div>
                    <button onClick={endCall}
                      className="w-full bg-red-600 text-white py-3 rounded-lg text-sm font-medium flex items-center justify-center gap-2">
                      <PhoneOff className="w-4 h-4" /> End Call
                    </button>
                  </div>
                );
              })()}

              {callEnded && (() => {
                const rc = riskColors[overallLevel] ?? riskColors.SAFE;
                return (
                  <div className="space-y-3">
                    <div className={`p-4 rounded-lg border ${rc.bg} ${rc.border}`}>
                      <div className="flex items-center gap-2 mb-2">
                        <span className={rc.text}><RiskIcon level={overallLevel} /></span>
                        <span className={`text-sm font-bold ${rc.text}`}>
                          Call Ended — {overallLevel.replace("_", " ")}
                        </span>
                      </div>
                      <div className="flex gap-4 text-xs text-gray-600">
                        <span>Duration: {formatTime(callTimer)}</span>
                        <span>Peak: <strong className={rc.text}>{overallRisk}</strong></span>
                        <span>Segments: {chunks.length}</span>
                      </div>
                    </div>
                    {chunks.map((chunk, i) => {
                      const cr = riskColors[chunk.risk_level] ?? riskColors.SAFE;
                      return (
                        <div key={i} className="p-3 bg-gray-50 border border-gray-200 rounded-lg">
                          <div className="flex justify-between mb-1">
                            <span className="text-xs text-gray-500">Segment {i + 1}</span>
                            <span className={`text-xs font-bold ${cr.text}`}>{chunk.risk_score}</span>
                          </div>
                          <p className="text-xs text-gray-700 italic">"{chunk.transcript.slice(0, 80)}..."</p>
                        </div>
                      );
                    })}
                    <button onClick={() => { setCallEnded(false); setChunks([]); setOverallRisk(0); setCallTimer(0); }}
                      className="w-full border border-blue-300 text-blue-600 py-3 rounded-lg text-sm font-medium">
                      Try Another
                    </button>
                  </div>
                );
              })()}
            </div>
          )}

          {/* ── NUMBER TAB ── */}
          {activeTab === "number" && (
            <>
              <div className="bg-white rounded-xl p-4 shadow-sm">
                <p className="text-xs text-gray-600 mb-3">Check phone number against fraud database + Truecaller</p>
                <div className="flex gap-2 mb-3">
                  <input type="text" placeholder="+91XXXXXXXXXX" value={number}
                    onChange={(e) => setNumber(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleNumberCheck()}
                    className="flex-1 border border-gray-200 p-3 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-300" />
                  <button onClick={handleNumberCheck} disabled={numberLoading || !number.trim()}
                    className="bg-blue-600 text-white px-4 rounded-lg text-sm font-medium disabled:opacity-50">
                    {numberLoading ? "..." : "Check"}
                  </button>
                </div>
                <div className="p-3 bg-gray-50 rounded-lg border border-gray-200">
                  <p className="text-xs text-gray-500 mb-1">Known fraud numbers to test:</p>
                  {["+919999999999", "+918888888888"].map((n) => (
                    <button key={n} onClick={() => setNumber(n)}
                      className="text-xs text-blue-600 underline mr-3">{n}</button>
                  ))}
                </div>
                {numberError && (
                  <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-lg">
                    <p className="text-xs text-red-700">{numberError}</p>
                  </div>
                )}
                {numberResult && (() => {
                  const nr = riskColors[numberResult.risk_level] ?? riskColors.SAFE;
                  return (
                    <div className={`mt-3 p-3 ${nr.bg} border ${nr.border} rounded-lg`}>
                      <div className="flex items-center gap-2 mb-1">
                        <span className={nr.text}><RiskIcon level={numberResult.risk_level} /></span>
                        <span className={`text-sm font-semibold ${nr.text}`}>
                          {numberResult.risk_level.replace("_", " ")}
                        </span>
                        <span className={`ml-auto text-xs font-bold px-2 py-0.5 rounded-full ${
                          numberResult.recommendation === "BLOCK" ? "bg-red-100 text-red-700" :
                          numberResult.recommendation === "WARN"  ? "bg-yellow-100 text-yellow-700" :
                          "bg-green-100 text-green-700"
                        }`}>{numberResult.recommendation}</span>
                      </div>
                      <p className="text-xs text-gray-600">{numberResult.explanation}</p>
                    </div>
                  );
                })()}
              </div>
              <div className="bg-blue-50 rounded-xl p-4 border border-blue-200">
                <p className="text-xs text-blue-600 mb-1">ℹ️ About number checking</p>
                <p className="text-sm text-blue-900">
                  Numbers are checked against fraud DB + Truecaller mock. Add fraud numbers to{" "}
                  <code className="bg-blue-100 px-1 rounded">fraud_data.json</code> then call{" "}
                  <code className="bg-blue-100 px-1 rounded">POST /admin/reload</code>.
                </p>
              </div>
            </>
          )}

          <div className="bg-blue-50 rounded-xl p-4 border border-blue-200">
            <p className="text-xs text-blue-600 mb-1">How it works</p>
            <p className="text-sm text-blue-900">
              Whisper AI transcribes audio locally (free, no API cost). Scam patterns are checked
              every 60s — OTP requests, KYC fraud, urgency language, authority impersonation.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}