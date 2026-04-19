"""
models/scoring.py
-----------------
Pydantic models for the scoring engine.

ScoringInput  — everything a shield sends to the scorer
ScoringResult — what the scorer sends back to the route / frontend
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Action enum  (matches the 4-band system in the product spec)
# ---------------------------------------------------------------------------

class Action(str, Enum):
    SAFE  = "SAFE"    # 0-30
    WARN  = "WARN"    # 31-65
    ALERT = "ALERT"   # 66-85
    BLOCK = "BLOCK"   # 86-100


# ---------------------------------------------------------------------------
# Signal source — which shield produced this event
# ---------------------------------------------------------------------------

class ShieldSource(str, Enum):
    call_shield   = "call_shield"
    link_shield   = "link_shield"
    upi_shield    = "upi_shield"
    screen_shield = "screen_shield"
    app_shield    = "app_shield"
    manual        = "manual"


# ---------------------------------------------------------------------------
# Scoring input  (all fields optional — send only what you know)
# ---------------------------------------------------------------------------

class ScoringInput(BaseModel):
    """
    Unified input model consumed by every /score-* route.

    Each shield populates the fields it cares about and leaves the rest None.
    The scorer ignores None fields — no signal = no contribution to score.
    """

    source: ShieldSource = ShieldSource.manual

    # --- DB lookup results (populated after db.lookup_* calls) ---
    fraud_db_hit:       bool = False
    db_severity:        Optional[str] = None   # "low"|"medium"|"high"|"critical"
    db_tags:            List[str] = Field(default_factory=list)

    # --- Call shield signals ---
    otp_requested:      bool = False   # caller asked for OTP
    upi_pin_requested:  bool = False   # caller asked for UPI PIN
    urgency_language:   bool = False   # "act now / limited time / urgent"
    unknown_number:     bool = False   # not in contacts + not verified
    private_number:     bool = False   # number withheld

    # --- UPI shield signals ---
    upi_copied_on_call: bool = False   # clipboard UPI while unknown call active  ← killer feature

    # --- Link shield signals ---
    url_flagged_external: bool = False  # flagged by VirusTotal / SafeBrowsing mock
    url_is_phishing:      bool = False

    # --- App shield signals ---
    app_signature_mismatch: bool = False  # fake app detected

    # --- Screen shield signals ---
    dark_pattern_detected:  bool = False
    fake_countdown_detected: bool = False

    # --- Context (optional metadata, not scored but included in result) ---
    raw_text_snippet: Optional[str] = None   # excerpt from call transcript / screen
    entity_value:     Optional[str] = None   # the number / UPI / URL being checked


# ---------------------------------------------------------------------------
# Scoring result  (returned to every caller)
# ---------------------------------------------------------------------------

class ScoringResult(BaseModel):
    score:   int            = Field(..., ge=0, le=100)
    action:  Action
    reasons: List[str]      = Field(default_factory=list)
    source:  ShieldSource

    # convenience booleans the frontend / Node backend can branch on
    is_blocked:  bool = False
    is_alerted:  bool = False
    auto_blocked: bool = False   # True when critical override fired

    class Config:
        use_enum_values = True