"""
tests/test_scorer.py
--------------------
Full test coverage for the scoring engine.

Run with:  pytest tests/test_scorer.py -v
"""

from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from models.scoring import Action, ScoringInput, ShieldSource
from scorer import Scorer

s = Scorer()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def make(source=ShieldSource.manual, **kwargs) -> ScoringInput:
    return ScoringInput(source=source, **kwargs)


# ---------------------------------------------------------------------------
# Band boundaries
# ---------------------------------------------------------------------------

def test_clean_input_is_safe():
    result = s.score(make())
    assert result.score == 0
    assert result.action == Action.SAFE
    assert result.reasons == []


def test_unknown_number_alone_is_warn():
    result = s.score(make(unknown_number=True))
    assert result.action == Action.WARN
    assert result.score == 35


def test_otp_alone_is_warn():
    result = s.score(make(otp_requested=True))
    assert result.action == Action.WARN


def test_upi_pin_alone_is_alert():
    result = s.score(make(upi_pin_requested=True))
    assert result.action == Action.ALERT
    assert result.score == 85


def test_phishing_url_is_alert_or_block():
    result = s.score(make(url_is_phishing=True))
    assert result.action in (Action.ALERT, Action.BLOCK)


# ---------------------------------------------------------------------------
# Critical override — must always return BLOCK with auto_blocked=True
# ---------------------------------------------------------------------------

def test_critical_db_hit_auto_blocks():
    result = s.score(make(fraud_db_hit=True, db_severity="critical",
                          db_tags=["otp_scam"]))
    assert result.action == Action.BLOCK
    assert result.auto_blocked is True
    assert result.score == 95


def test_upi_copied_on_call_auto_blocks():
    result = s.score(make(upi_copied_on_call=True))
    assert result.action == Action.BLOCK
    assert result.auto_blocked is True


def test_app_signature_mismatch_auto_blocks():
    result = s.score(make(app_signature_mismatch=True))
    assert result.action == Action.BLOCK
    assert result.auto_blocked is True


def test_critical_override_skips_arithmetic():
    """Score should be exactly 95 regardless of other signals."""
    result = s.score(make(
        fraud_db_hit=True, db_severity="critical",
        otp_requested=True, urgency_language=True, unknown_number=True
    ))
    assert result.score == 95
    assert result.auto_blocked is True


# ---------------------------------------------------------------------------
# Combo bonuses
# ---------------------------------------------------------------------------

def test_unknown_number_plus_otp_combo():
    individual = (
        s.score(make(unknown_number=True)).score +
        s.score(make(otp_requested=True)).score
    )
    combo = s.score(make(unknown_number=True, otp_requested=True)).score
    assert combo > individual   # combo bonus fired


def test_unknown_number_plus_upi_pin_combo():
    result = s.score(make(unknown_number=True, upi_pin_requested=True))
    assert result.action == Action.BLOCK
    assert any("combo" in r.lower() or "upi pin" in r.lower()
               for r in result.reasons)


def test_urgency_plus_otp_combo():
    result = s.score(make(urgency_language=True, otp_requested=True))
    assert result.action in (Action.ALERT, Action.BLOCK)


# ---------------------------------------------------------------------------
# Reasons list
# ---------------------------------------------------------------------------

def test_reasons_populated_for_each_signal():
    result = s.score(make(
        otp_requested=True,
        urgency_language=True,
        unknown_number=True,
    ))
    assert len(result.reasons) >= 3


def test_no_reasons_for_clean_input():
    result = s.score(make())
    assert result.reasons == []


# ---------------------------------------------------------------------------
# Convenience booleans
# ---------------------------------------------------------------------------

def test_is_blocked_true_for_block_action():
    result = s.score(make(upi_copied_on_call=True))
    assert result.is_blocked is True
    assert result.is_alerted is True


def test_is_alerted_true_for_alert_action():
    result = s.score(make(upi_pin_requested=True))
    assert result.is_alerted is True


def test_is_blocked_false_for_safe():
    result = s.score(make())
    assert result.is_blocked is False
    assert result.is_alerted is False


# ---------------------------------------------------------------------------
# DB severity ladder
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("severity,min_score,max_score", [
    ("low",      20, 45),
    ("medium",   45, 65),
    ("high",     70, 90),
])
def test_db_severity_ladder(severity, min_score, max_score):
    result = s.score(make(fraud_db_hit=True, db_severity=severity))
    assert min_score <= result.score <= max_score, (
        f"severity={severity} gave score={result.score}, "
        f"expected {min_score}–{max_score}"
    )


# ---------------------------------------------------------------------------
# Score is always 0-100
# ---------------------------------------------------------------------------

def test_score_never_exceeds_100():
    """Pile on every signal — score must not exceed 100."""
    result = s.score(make(
        unknown_number=True,
        otp_requested=True,
        upi_pin_requested=True,
        urgency_language=True,
        private_number=True,
        url_is_phishing=True,
        url_flagged_external=True,
        dark_pattern_detected=True,
        fake_countdown_detected=True,
    ))
    assert result.score <= 100


def test_score_never_below_0():
    result = s.score(make())
    assert result.score >= 0


# ---------------------------------------------------------------------------
# Source passthrough
# ---------------------------------------------------------------------------

def test_source_preserved_in_result():
    result = s.score(make(source=ShieldSource.call_shield, otp_requested=True))
    assert result.source == ShieldSource.call_shield