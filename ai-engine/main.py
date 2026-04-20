"""
main.py
-------
SentinelOS Threat Engine — FastAPI application entry point.

Routes
------
  POST /check-number          — phone number fraud check
  POST /check-url             — URL phishing / malware check
  POST /check-upi             — UPI ID fraud check
  POST /score-event           — generic multi-signal scoring (primary route)
  POST /analyze-screen        — dark pattern detection for Screen Shield

  GET  /health                — liveness probe
  GET  /stats                 — DB + engine stats (great for demo dashboard)
  POST /admin/reload          — hot-reload fraud DB without restart
  POST /admin/report          — community report a new fraud entity

Run
---
  uvicorn main:app --reload --port 8000
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from db import FraudDB, get_db, init_db
from backend.integrations import IntegrationClients
from models.fraud import DataSource, FraudPhoneNumber, FraudUPIId, FraudURL, Severity
from models.scoring import Action, ScoringInput, ScoringResult, ShieldSource
from scorer import compute_score
from screen_analyzer import analyze_screen as run_screen_analyzer  # ← NEW

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger("sentinelos")

# ---------------------------------------------------------------------------
# App lifecycle — init DB once at startup
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🛡  SentinelOS Threat Engine starting…")
    await init_db()
    # Integrations auto-select Mock vs Real based on env vars
    app.state.integrations = IntegrationClients.from_env()
    logger.info("✅  Fraud DB loaded. Integrations ready.")
    yield
    logger.info("👋  Threat Engine shutting down.")


async def get_integrations(request: Request) -> IntegrationClients:
    return request.app.state.integrations


# ---------------------------------------------------------------------------
# App + middleware
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SentinelOS Threat Engine",
    description="Real-time fraud scoring API for call, link, UPI, screen and app shields.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten to your Android app origin in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request timing middleware — useful for demo + performance logging
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
# Request / response schemas
# ---------------------------------------------------------------------------

class CheckNumberRequest(BaseModel):
    number: str = Field(..., examples=["+919999999999"],
                        description="Phone number (E.164 or 10-digit Indian)")
    otp_requested:     bool = False
    upi_pin_requested: bool = False
    urgency_language:  bool = False
    unknown_number:    bool = False
    private_number:    bool = False
    raw_text_snippet:  Optional[str] = Field(None, description="Call transcript excerpt")


class CheckURLRequest(BaseModel):
    url: str = Field(..., examples=["http://fake-sbi-kyc.com/login"])
    url_flagged_external: bool = False
    url_is_phishing:      bool = False


class CheckUPIRequest(BaseModel):
    upi_id: str = Field(..., examples=["scammer@ybl"])
    upi_copied_on_call: bool = False


class ScoreEventRequest(BaseModel):
    source: ShieldSource = ShieldSource.manual
    signals: ScoringInput


class ReportRequest(BaseModel):
    entity_type: str = Field(..., examples=["phone_number", "upi_id", "url"])
    value:       str = Field(..., examples=["+919999999999"])
    tags:        list[str] = Field(default_factory=list)
    severity:    Severity = Severity.medium
    notes:       Optional[str] = None


# ← NEW: Screen Shield request schema
class AnalyzeScreenRequest(BaseModel):
    screen_text: str
    ui_elements: list = []


# ---------------------------------------------------------------------------
# Utility: build ScoringInput from DB result + request fields
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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health", tags=["System"])
async def health():
    """Liveness probe — always returns 200 if the server is up."""
    return {"status": "ok", "service": "sentinelos-threat-engine"}


@app.get("/stats", tags=["System"])
async def stats(db: FraudDB = Depends(get_db)):
    return {
        "status": "ok",
        "database": db.stats(),
        "scoring_bands": {
            "SAFE":  "0–30",
            "WARN":  "31–65",
            "ALERT": "66–85",
            "BLOCK": "86–100",
        },
    }


# ------------------------------------------------------------------
# /check-number
# ------------------------------------------------------------------

@app.post("/check-number", response_model=ScoringResult, tags=["Shields"])
async def check_number(
    req: CheckNumberRequest,
    db: FraudDB = Depends(get_db),
    integrations: IntegrationClients = Depends(get_integrations),
):
    db_result      = await db.lookup_phone(req.number)
    tc_result      = await integrations.truecaller.lookup(req.number)

    unknown = req.unknown_number or (not tc_result.name and tc_result.spam_score == 0)

    signals = _make_input_from_db(
        db_result,
        source=ShieldSource.call_shield,
        extra={
            "otp_requested":     req.otp_requested,
            "upi_pin_requested": req.upi_pin_requested,
            "urgency_language":  req.urgency_language,
            "unknown_number":    unknown or tc_result.is_spam,
            "private_number":    req.private_number,
            "raw_text_snippet":  req.raw_text_snippet,
        },
    )
    result = compute_score(signals)
    logger.info("check-number %s → %s (score=%d) [tc_spam=%s]",
                req.number, result.action, result.score, tc_result.is_spam)
    return result


# ------------------------------------------------------------------
# /check-url
# ------------------------------------------------------------------

@app.post("/check-url", response_model=ScoringResult, tags=["Shields"])
async def check_url(
    req: CheckURLRequest,
    db: FraudDB = Depends(get_db),
    integrations: IntegrationClients = Depends(get_integrations),
):
    db_result = await db.lookup_url(req.url)

    from url_analyzer import analyze_url
    ai_result = analyze_url(req.url)

    ai_flagged = len(ai_result["signals"]) > 0
    ai_phishing = any(
        any(keyword in s["detail"].lower() for keyword in ["phishing", "social_engineering", "malware"])
        for s in ai_result["signals"]
    )

    signals = _make_input_from_db(
        db_result,
        source=ShieldSource.link_shield,
        extra={
            "url_flagged_external": ai_flagged,
            "url_is_phishing": ai_phishing,
        },
    )

    result = compute_score(signals)
    logger.info(
        "check-url %s → %s (score=%d) [AI_flagged=%s phishing=%s DB_hit=%s]",
        req.url, result.action, result.score, ai_flagged, ai_phishing, db_result.found
    )
    return result


# ------------------------------------------------------------------
# /check-upi
# ------------------------------------------------------------------

@app.post("/check-upi", response_model=ScoringResult, tags=["Shields"])
async def check_upi(
    req: CheckUPIRequest,
    db: FraudDB = Depends(get_db),
):
    db_result = await db.lookup_upi(req.upi_id)

    upi = req.upi_id.lower()
    suspicious_keywords = ["prize", "winner", "reward", "cashback", "offer", "urgent", "bonus", "loan"]
    is_suspicious = any(k in upi for k in suspicious_keywords)

    high_risk_patterns = ["prize", "winner", "lottery", "reward"]
    is_high_risk = any(k in upi for k in high_risk_patterns)

    has_random_numbers = any(char.isdigit() for char in upi)

    signals = _make_input_from_db(
        db_result,
        source=ShieldSource.upi_shield,
        extra={
            "upi_copied_on_call": req.upi_copied_on_call,
            "urgency_language": is_suspicious,
            "unknown_number": has_random_numbers,
            "otp_requested": is_high_risk,
        },
    )
    result = compute_score(signals)
    logger.info("check-upi %s → %s (score=%d)", req.upi_id, result.action, result.score)
    return result


# ------------------------------------------------------------------
# /score-event  (primary route — all shields can use this)
# ------------------------------------------------------------------

@app.post("/score-event", response_model=ScoringResult, tags=["Shields"])
async def score_event(
    req: ScoreEventRequest,
    db: FraudDB = Depends(get_db),
):
    signals = req.signals
    signals.source = req.source

    if signals.entity_value and not signals.fraud_db_hit:
        if req.source == ShieldSource.call_shield:
            db_result = await db.lookup_phone(signals.entity_value)
        elif req.source == ShieldSource.upi_shield:
            db_result = await db.lookup_upi(signals.entity_value)
        elif req.source == ShieldSource.link_shield:
            db_result = await db.lookup_url(signals.entity_value)
        else:
            db_result = None

        if db_result and db_result.found:
            signals.fraud_db_hit = True
            signals.db_severity  = db_result.severity.value if db_result.severity else None
            signals.db_tags      = db_result.tags

    result = compute_score(signals)
    logger.info("score-event [%s] → %s (score=%d)", req.source, result.action, result.score)
    return result


# ------------------------------------------------------------------
# /analyze-screen  ← NEW
# ------------------------------------------------------------------

@app.post("/analyze-screen", tags=["Shields"])
async def analyze_screen(req: AnalyzeScreenRequest):
    """
    Screen Shield — detect dark patterns in screen text.
    Called by Node.js backend screenController via mlService.
    Uses regex-based screen_analyzer.py for pattern detection.
    """
    result = run_screen_analyzer(req.screen_text, req.ui_elements)
    logger.info(
        "analyze-screen → found=%s score=%d patterns=%s",
        result["dark_patterns_found"],
        result["risk_score"],
        result.get("pattern_types", []),
    )
    return result


# ------------------------------------------------------------------
# /admin/reload
# ------------------------------------------------------------------

@app.post("/admin/reload", tags=["Admin"])
async def reload_db(db: FraudDB = Depends(get_db)):
    await db.reload()
    return {
        "status": "reloaded",
        "database": db.stats(),
    }


# ------------------------------------------------------------------
# /admin/report
# ------------------------------------------------------------------

@app.post("/admin/report", status_code=status.HTTP_201_CREATED, tags=["Admin"])
async def report_entity(
    req: ReportRequest,
    db: FraudDB = Depends(get_db),
):
    try:
        if req.entity_type == "phone_number":
            await db.add_phone(FraudPhoneNumber(
                number=req.value, tags=req.tags,
                severity=req.severity, source=DataSource.reported,
                notes=req.notes,
            ))
        elif req.entity_type == "upi_id":
            await db.add_upi(FraudUPIId(
                upi_id=req.value, tags=req.tags,
                severity=req.severity, source=DataSource.reported,
                notes=req.notes,
            ))
        elif req.entity_type == "url":
            await db.add_url(FraudURL(
                url=req.value, tags=req.tags,
                severity=req.severity, source=DataSource.reported,
                notes=req.notes,
            ))
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown entity_type '{req.entity_type}'. "
                       f"Use: phone_number, upi_id, url",
            )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    logger.info("Community report: %s '%s' added.", req.entity_type, req.value)
    return {
        "status": "reported",
        "entity_type": req.entity_type,
        "value": req.value,
        "message": "Added to live index. Persist by saving to fraud_data.json.",
    }