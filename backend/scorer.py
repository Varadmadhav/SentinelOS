"""
scorer.py
---------
SentinelOS Threat Scoring Engine.

Scoring philosophy
~~~~~~~~~~~~~~~~~~
1. Every signal has a base weight (0.0 – 1.0).
2. Signals are normalised to a 0–100 integer score.
3. COMBO BONUSES fire for high-risk signal combinations
   (e.g. unknown_number + otp_requested = extra +15).
4. CRITICAL OVERRIDE: any critical-severity DB hit, or the UPI-on-call
   combo, jumps straight to BLOCK regardless of numeric score.
5. Action bands mirror the product spec:
       0–30  → SAFE
      31–65  → WARN
      66–85  → ALERT
      86–100 → BLOCK

Usage
-----
    from scorer import Scorer
    scorer = Scorer()
    result = scorer.score(input_signals)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Tuple

from models.scoring import Action, ScoringInput, ScoringResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Signal weight table
# — keep all magic numbers in ONE place so tuning is trivial
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _SignalWeights:
    # DB hits
    fraud_db_hit_critical: float = 0.95
    fraud_db_hit_high:     float = 0.80
    fraud_db_hit_medium:   float = 0.55
    fraud_db_hit_low:      float = 0.30

    # Call shield
    upi_pin_requested:  float = 0.85   # asking for PIN = almost always fraud
    otp_requested:      float = 0.75
    urgency_language:   float = 0.45
    unknown_number:     float = 0.35
    private_number:     float = 0.25

    # UPI shield
    upi_copied_on_call: float = 0.90   # killer feature — highest single signal

    # Link shield
    url_is_phishing:         float = 0.90
    url_flagged_external:    float = 0.70

    # App shield
    app_signature_mismatch:  float = 0.90

    # Screen shield
    fake_countdown_detected: float = 0.50
    dark_pattern_detected:   float = 0.35


@dataclass(frozen=True)
class _ComboBonus:
    """Extra weight added when a dangerous signal combination fires."""
    signals:     Tuple[str, ...]   # attribute names on ScoringInput
    bonus:       float
    reason:      str


_COMBOS: List[_ComboBonus] = [
    _ComboBonus(
        signals=("unknown_number", "otp_requested"),
        bonus=0.15,
        reason="Unknown caller requesting OTP — classic SIM-swap / bank fraud",
    ),
    _ComboBonus(
        signals=("unknown_number", "upi_pin_requested"),
        bonus=0.20,
        reason="Unknown caller asking for UPI PIN",
    ),
    _ComboBonus(
        signals=("fraud_db_hit", "otp_requested"),
        bonus=0.15,
        reason="Known fraud number requesting OTP",
    ),
    _ComboBonus(
        signals=("fraud_db_hit", "upi_pin_requested"),
        bonus=0.20,
        reason="Known fraud number asking for UPI PIN",
    ),
    _ComboBonus(
        signals=("urgency_language", "otp_requested"),
        bonus=0.10,
        reason="Urgency pressure combined with OTP request",
    ),
    _ComboBonus(
        signals=("url_is_phishing", "fraud_db_hit"),
        bonus=0.10,
        reason="Phishing URL from a known fraud entity",
    ),
]

# Signals that trigger CRITICAL OVERRIDE (straight to BLOCK, score capped at 95)
_CRITICAL_OVERRIDE_SIGNALS = {
    "upi_copied_on_call": "UPI ID copied during active call with unknown number — refund scam pattern",
    "app_signature_mismatch": "Fake app with mismatched digital signature — malware detected",
}

_WEIGHTS = _SignalWeights()


# ---------------------------------------------------------------------------
# Action bands
# ---------------------------------------------------------------------------

def _score_to_action(score: int) -> Action:
    if score <= 30:
        return Action.SAFE
    if score <= 65:
        return Action.WARN
    if score <= 85:
        return Action.ALERT
    return Action.BLOCK


# ---------------------------------------------------------------------------
# DB severity helper
# ---------------------------------------------------------------------------

def _db_weight(severity: str | None) -> float:
    return {
        "critical": _WEIGHTS.fraud_db_hit_critical,
        "high":     _WEIGHTS.fraud_db_hit_high,
        "medium":   _WEIGHTS.fraud_db_hit_medium,
        "low":      _WEIGHTS.fraud_db_hit_low,
    }.get(severity or "", _WEIGHTS.fraud_db_hit_medium)


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------

class Scorer:
    """
    Stateless scoring engine.  Instantiate once; call .score() many times.
    Thread-safe — no shared mutable state.
    """

    def score(self, signals: ScoringInput) -> ScoringResult:
        """
        Evaluate all signals and return a ScoringResult.
        """
        reasons: List[str] = []
        raw_weight: float  = 0.0
        auto_blocked       = False

        # ------------------------------------------------------------------
        # 1. Critical override check  (fires before any arithmetic)
        # ------------------------------------------------------------------
        for attr, reason in _CRITICAL_OVERRIDE_SIGNALS.items():
            if getattr(signals, attr, False):
                logger.info("Critical override fired: %s", attr)
                reasons.append(reason)
                auto_blocked = True

        if signals.fraud_db_hit and signals.db_severity == "critical":
            reasons.append(
                f"Number/UPI/URL is in fraud database with CRITICAL severity "
                f"(tags: {', '.join(signals.db_tags) or 'none'})"
            )
            auto_blocked = True

        if auto_blocked:
            return ScoringResult(
                score=95,
                action=Action.BLOCK,
                reasons=reasons,
                source=signals.source,
                is_blocked=True,
                is_alerted=False,
                auto_blocked=True,
            )

        # ------------------------------------------------------------------
        # 2. Base signal weights
        # ------------------------------------------------------------------
        def _add(condition: bool, weight: float, reason: str) -> None:
            nonlocal raw_weight
            if condition:
                raw_weight += weight
                reasons.append(reason)

        # DB hit (non-critical)
        if signals.fraud_db_hit:
            w = _db_weight(signals.db_severity)
            raw_weight += w
            tag_str = ", ".join(signals.db_tags) if signals.db_tags else "none"
            reasons.append(
                f"Found in fraud database — severity: {signals.db_severity}, "
                f"tags: {tag_str}"
            )

        # Call shield
        _add(signals.upi_pin_requested,  _WEIGHTS.upi_pin_requested,  "Caller asked for UPI PIN")
        _add(signals.otp_requested,      _WEIGHTS.otp_requested,      "Caller asked for OTP")
        _add(signals.urgency_language,   _WEIGHTS.urgency_language,   "Urgency / pressure language detected in call")
        _add(signals.unknown_number,     _WEIGHTS.unknown_number,     "Number not in contacts and unverified")
        _add(signals.private_number,     _WEIGHTS.private_number,     "Caller withheld their number")

        # Link shield
        _add(signals.url_is_phishing,       _WEIGHTS.url_is_phishing,       "URL identified as phishing page")
        _add(signals.url_flagged_external,  _WEIGHTS.url_flagged_external,  "URL flagged by external antivirus / SafeBrowsing")

        # Screen shield
        _add(signals.fake_countdown_detected, _WEIGHTS.fake_countdown_detected, "Fake countdown timer detected (dark pattern)")
        _add(signals.dark_pattern_detected,   _WEIGHTS.dark_pattern_detected,   "Manipulative UI dark pattern detected")

        # ------------------------------------------------------------------
        # 3. Combo bonuses
        # ------------------------------------------------------------------
        for combo in _COMBOS:
            if all(getattr(signals, s, False) for s in combo.signals):
                raw_weight += combo.bonus
                reasons.append(f"[Combo] {combo.reason}")

        # ------------------------------------------------------------------
        # 4. Normalise to 0-100
        #    Weights are designed so a single worst-case signal ≈ 0.95
        #    and a full combo pile-up can exceed 1.0 → cap at 100.
        # ------------------------------------------------------------------
        score = min(100, round(raw_weight * 100))

        action = _score_to_action(score)

        return ScoringResult(
            score=score,
            action=action,
            reasons=reasons,
            source=signals.source,
            is_blocked=action == Action.BLOCK,
            is_alerted=action in (Action.ALERT, Action.BLOCK),
            auto_blocked=False,
        )