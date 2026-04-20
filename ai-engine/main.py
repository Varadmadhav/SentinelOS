"""
main.py
-------
SentinelOS Threat Engine — FastAPI application entry point.
Unified build: Includes Audio Analysis, Screen Shield, and Fraud DB Lookups.
"""

from __future__ import annotations

import logging
import time
import tempfile
import os
import base64
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from db import FraudDB, get_db, init_db
from backend.integrations import IntegrationClients
from models.fraud import DataSource, FraudPhoneNumber, FraudUPIId, FraudURL, Severity
from models.scoring import Action, ScoringInput, ScoringResult, ShieldSource
from scorer import compute_score
from speech_to_text import transcribe_audio_file, transcribe_audio
from scam_detector import detect_scam
from screen_analyzer import analyze_screen as run_screen_analyzer

# ---------------------------------------------------------------------------
# Logging & Lifecycle
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger("sentinelos")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🛡  SentinelOS Threat Engine starting…")
    await init_db()
    app.state.integrations = IntegrationClients.from_env()
    logger.info("✅  Fraud DB loaded. Integrations ready.")
    yield
    logger.info("👋  Threat Engine shutting down.")

async def get_integrations(request: Request) -> IntegrationClients:
    return request.app.state.integrations

app = FastAPI(
    title="SentinelOS Threat Engine",
    description="Real-time fraud scoring API for call, link, UPI, screen and app shields.",
    version="1.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_timing_header(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    ms = round((time.perf_counter() - start) * 1000, 2)
    response.headers["X-Response-Time-Ms"] = str(ms)
    logger.info("%s %s → %s  (%sms)", request.method, request.url.path,
                response.status_code, ms)
    return response

# ---------------------------------------------------------------------------
# Request Schemas
# ---------------------------------------------------------------------------

class CheckNumberRequest(BaseModel):
    number: str = Field(..., examples=["+919999999999"])
    otp_requested:     bool = False
    upi_pin_requested: bool = False
    urgency_language:  bool = False
    unknown_number:    bool = False
    private_number:    bool = False
    raw_text_snippet:  Optional[str] = None

class CheckURLRequest(BaseModel):
    url: str = Field(..., examples=["http://fake-sbi-kyc.com/login"])

class CheckUPIRequest(BaseModel):
    upi_id: str = Field(..., examples=["scammer@ybl"])
    upi_copied_on_call: bool = False

class ScoreEventRequest(BaseModel):
    source: ShieldSource = ShieldSource.manual
    signals: ScoringInput

class ReportRequest(BaseModel):
    entity_type: str = Field(..., examples=["phone_number", "upi_id", "url"])
    value:       str = Field(...)
    tags:        list[str] = Field(default_factory=list)
    severity:    Severity = Severity.medium
    notes:       Optional[str] = None

class AudioBase64Request(BaseModel):
    audio_base64: str
    language: str = "en"

class AnalyzeScreenRequest(BaseModel):
    screen_text: str
    ui_elements: list = []

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _make_input_from_db(result, extra: dict, source: ShieldSource) -> ScoringInput:
    return ScoringInput(
        source=source,
        fraud_db_hit=result.found,
        db_severity=result.severity.value if result.severity else None,
        db_tags=result.tags,
        entity_value=result.query,
        **extra,
    )

def _build_audio_response(transcript_result: dict, filename: str = "") -> dict:
    transcript = transcript_result.get("transcript", "")
    if not transcript.strip():
        return {"transcript": "", "scam": False, "risk_score": 0, "explanation": "No speech detected."}
    
    scam = detect_scam(transcript)
    return {
        "transcript": transcript,
        "language": transcript_result.get("language", "en"),
        "confidence": transcript_result.get("confidence", 0.0),
        "filename": filename,
        **scam,
    }

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health", tags=["System"])
async def health():
    return {"status": "ok", "version": "1.1.0"}

@app.post("/check-number", response_model=ScoringResult, tags=["Shields"])
async def check_number(req: CheckNumberRequest, db: FraudDB = Depends(get_db), integrations: IntegrationClients = Depends(get_integrations)):
    db_result = await db.lookup_phone(req.number)
    tc_result = await integrations.truecaller.lookup(req.number)
    unknown = req.unknown_number or (not tc_result.name and tc_result.spam_score == 0)

    signals = _make_input_from_db(db_result, source=ShieldSource.call_shield, extra={
        "otp_requested": req.otp_requested,
        "upi_pin_requested": req.upi_pin_requested,
        "urgency_language": req.urgency_language,
        "unknown_number": unknown or tc_result.is_spam,
        "private_number": req.private_number,
        "raw_text_snippet": req.raw_text_snippet,
    })
    return compute_score(signals)

@app.post("/check-url", response_model=ScoringResult, tags=["Shields"])
async def check_url(req: CheckURLRequest, db: FraudDB = Depends(get_db)):
    db_result = await db.lookup_url(req.url)
    from url_analyzer import analyze_url
    ai_result = analyze_url(req.url)
    
    ai_flagged = len(ai_result["signals"]) > 0
    ai_phishing = any("phishing" in s["detail"].lower() for s in ai_result["signals"])

    signals = _make_input_from_db(db_result, source=ShieldSource.link_shield, extra={
        "url_flagged_external": ai_flagged,
        "url_is_phishing": ai_phishing,
    })
    return compute_score(signals)

@app.post("/check-upi", response_model=ScoringResult, tags=["Shields"])
async def check_upi(req: CheckUPIRequest, db: FraudDB = Depends(get_db)):
    db_result = await db.lookup_upi(req.upi_id)
    signals = _make_input_from_db(db_result, source=ShieldSource.upi_shield, extra={
        "upi_copied_on_call": req.upi_copied_on_call,
    })
    return compute_score(signals)

@app.post("/api/screen/analyze")
async def analyze_screen(req: AnalyzeScreenRequest):
    try:
        print("INPUT:", req.screen_text)
        result = run_screen_analyzer(req.screen_text, req.ui_elements)
        print("OUTPUT:", result)
        return result
    except Exception as e:
        print("ERROR:", e)
        raise HTTPException(status_code=500, detail=str(e))
    result = run_screen_analyzer(req.screen_text, req.ui_elements)
    logger.info("analyze-screen → risk=%d", result["risk_score"])
    return result

@app.post("/analyze-audio-b64", tags=["Shields"])
async def analyze_audio_base64(req: AudioBase64Request):
    try:
        transcript_result = transcribe_audio(req.audio_base64, req.language)
        return _build_audio_response(transcript_result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze-audio", tags=["Shields"])
async def analyze_audio_file(file: UploadFile = File(...), language: str = Form(default="en")):
    ext = os.path.splitext(file.filename or "")[1].lower()
    contents = await file.read()
    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
        tmp.write(contents)
        tmp_path = tmp.name
    try:
        transcript_result = transcribe_audio_file(tmp_path)
        return _build_audio_response(transcript_result, filename=file.filename)
    finally:
        if os.path.exists(tmp_path): os.unlink(tmp_path)

@app.post("/admin/report", status_code=status.HTTP_201_CREATED, tags=["Admin"])
async def report_entity(req: ReportRequest, db: FraudDB = Depends(get_db)):
    mapping = {"phone_number": db.add_phone, "upi_id": db.add_upi, "url": db.add_url}
    if req.entity_type not in mapping:
        raise HTTPException(status_code=400, detail="Invalid entity type")
    
    # Logic to map req to model classes would go here
    return {"status": "reported", "value": req.value}

@app.post("/api/app/check")
async def check_app(data: dict):
    app_name = (data.get("app_name") or "").lower()
    package = (data.get("package_name") or "").lower()
    permissions = [p.lower() for p in data.get("permissions", [])]
    source = (data.get("installed_from") or "").lower()

    risk_score = 0
    signals = []

    # 🚨 Rule 1: Remote access tools
    if any(word in app_name for word in ["remote", "support", "access"]) \
       or "remote" in package:
        risk_score += 50
        signals.append({"detail": "Remote access tool detected"})

    # 🚨 Rule 2: Dangerous permissions
    if any(p in permissions for p in ["accessibility", "screen overlay"]):
        risk_score += 30
        signals.append({"detail": "High-risk permissions (overlay/accessibility)"})

    # 🚨 Rule 3: Unknown source
    if source in ["unknown", "sideload"]:
        risk_score += 20
        signals.append({"detail": "Installed from unknown source"})

    # 🎯 FINAL CLASSIFICATION
    if risk_score >= 70:
        return {
            "risk_score": risk_score,
            "risk_level": "DANGEROUS",
            "recommendation": "UNINSTALL",
            "explanation": "This app can take control of your device",
            "signals": signals
        }

    elif risk_score >= 40:
        return {
            "risk_score": risk_score,
            "risk_level": "SUSPICIOUS",
            "recommendation": "WARN",
            "explanation": "This app shows risky behavior",
            "signals": signals
        }

    else:
        return {
            "risk_score": risk_score,
            "risk_level": "SAFE",
            "recommendation": "ALLOW",
            "explanation": "App seems safe",
            "signals": signals
        }

# -------------------------------
# App Threat Storage
# -------------------------------
threat_store = []

@app.get("/api/app/threats")
async def get_threats():
    return {"threats": threat_store}

@app.delete("/api/app/threats/{pkg}")
async def delete_threat(pkg: str):
    global threat_store
    threat_store = [t for t in threat_store if t.get("package_name") != pkg]
    return {"status": "deleted", "package": pkg}