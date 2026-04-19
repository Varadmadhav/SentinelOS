"""
tests/test_fraud_db.py
-----------------------
Full test coverage for the fraud database layer.

Run with:
    pytest tests/test_fraud_db.py -v
"""

from __future__ import annotations

import json
import pytest
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from db.fraud_db import FraudDB, JsonFileAdapter, _normalise_phone, _FraudIndex
from models.fraud import FraudPhoneNumber, FraudUPIId, FraudURL, Severity, LookupResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SEED_DATA = {
    "_meta": {"version": "1.0.0"},
    "phone_numbers": [
        {
            "number": "+919999999999",
            "tags": ["otp_scam"],
            "severity": "high",
            "reported_count": 50,
            "source": "reported",
        }
    ],
    "upi_ids": [
        {
            "upi_id": "scammer@ybl",
            "tags": ["fake_merchant"],
            "severity": "critical",
            "reported_count": 100,
            "source": "reported",
        }
    ],
    "urls": [
        {
            "url": "http://fake-sbi-kyc.com/login",
            "tags": ["phishing"],
            "severity": "critical",
            "reported_count": 200,
            "source": "imported",
        }
    ],
}


class MockAdapter:
    """In-memory adapter — no file I/O, fast tests."""
    def __init__(self, data: dict = None):
        self._data = data or SEED_DATA

    async def load_all(self) -> dict:
        return self._data


@pytest.fixture
async def db() -> FraudDB:
    instance = FraudDB(adapter=MockAdapter())
    await instance.initialise()
    return instance


# ---------------------------------------------------------------------------
# Phone lookup tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lookup_phone_found(db):
    result = await db.lookup_phone("+919999999999")
    assert result.found is True
    assert result.severity == Severity.high
    assert "otp_scam" in result.tags
    assert result.reported_count == 50
    assert result.entity_type == "phone_number"


@pytest.mark.asyncio
async def test_lookup_phone_not_found(db):
    result = await db.lookup_phone("+910000000000")
    assert result.found is False
    assert result.severity is None
    assert result.tags == []


@pytest.mark.asyncio
async def test_lookup_phone_10digit_auto_prefix(db):
    """10-digit Indian number should be auto-prefixed with +91."""
    result = await db.lookup_phone("9999999999")
    assert result.found is True


@pytest.mark.asyncio
async def test_lookup_phone_strips_spaces_dashes(db):
    result = await db.lookup_phone("+91 9999 999999")
    assert result.found is True


# ---------------------------------------------------------------------------
# UPI lookup tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lookup_upi_found(db):
    result = await db.lookup_upi("scammer@ybl")
    assert result.found is True
    assert result.severity == Severity.critical
    assert "fake_merchant" in result.tags


@pytest.mark.asyncio
async def test_lookup_upi_case_insensitive(db):
    result = await db.lookup_upi("SCAMMER@YBL")
    assert result.found is True


@pytest.mark.asyncio
async def test_lookup_upi_not_found(db):
    result = await db.lookup_upi("legit@okhdfc")
    assert result.found is False


# ---------------------------------------------------------------------------
# URL lookup tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lookup_url_exact_match(db):
    result = await db.lookup_url("http://fake-sbi-kyc.com/login")
    assert result.found is True
    assert result.severity == Severity.critical


@pytest.mark.asyncio
async def test_lookup_url_host_fallback(db):
    """Any path under a known bad host should still be caught."""
    result = await db.lookup_url("http://fake-sbi-kyc.com/different/path")
    assert result.found is True


@pytest.mark.asyncio
async def test_lookup_url_trailing_slash_ignored(db):
    result = await db.lookup_url("http://fake-sbi-kyc.com/login/")
    assert result.found is True


@pytest.mark.asyncio
async def test_lookup_url_not_found(db):
    result = await db.lookup_url("https://google.com")
    assert result.found is False


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stats(db):
    s = db.stats()
    assert s["phone_numbers"] == 1
    assert s["upi_ids"] == 1
    assert s["total_entries"] >= 2


# ---------------------------------------------------------------------------
# Runtime add
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_add_phone_at_runtime(db):
    new_entry = FraudPhoneNumber(
        number="+911234567890",
        tags=["test"],
        severity=Severity.low,
        reported_count=1,
        source="manual",
    )
    await db.add_phone(new_entry)
    result = await db.lookup_phone("+911234567890")
    assert result.found is True
    assert result.severity == Severity.low


@pytest.mark.asyncio
async def test_add_upi_at_runtime(db):
    new_entry = FraudUPIId(
        upi_id="new.fraud@paytm",
        tags=["test"],
        severity=Severity.medium,
        reported_count=5,
        source="manual",
    )
    await db.add_upi(new_entry)
    result = await db.lookup_upi("new.fraud@paytm")
    assert result.found is True


# ---------------------------------------------------------------------------
# Hot-reload
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reload_updates_index():
    """After reload with new data, new entries are immediately queryable."""
    adapter = MockAdapter(data={
        "phone_numbers": [],
        "upi_ids": [],
        "urls": [],
    })
    db = FraudDB(adapter=adapter)
    await db.initialise()

    result_before = await db.lookup_phone("+919999999999")
    assert result_before.found is False

    # Swap underlying data
    adapter._data = SEED_DATA
    await db.reload()

    result_after = await db.lookup_phone("+919999999999")
    assert result_after.found is True


# ---------------------------------------------------------------------------
# Uninitialised guard
# ---------------------------------------------------------------------------

def test_uninitialised_raises():
    db = FraudDB(adapter=MockAdapter())
    with pytest.raises(RuntimeError, match="not initialised"):
        _ = db._ready_index


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    ("+919999999999", "+919999999999"),
    ("9999999999",   "+919999999999"),
    ("+91 9999 999 999", "+919999999999"),
])
def test_normalise_phone(raw, expected):
    assert _normalise_phone(raw) == expected


# ---------------------------------------------------------------------------
# Model validation
# ---------------------------------------------------------------------------

def test_phone_model_rejects_no_prefix():
    with pytest.raises(Exception):
        FraudPhoneNumber(number="9999999999_bad", tags=[], severity="high",
                         reported_count=0, source="manual")


def test_severity_weight_ordering():
    assert Severity.low.weight < Severity.medium.weight
    assert Severity.medium.weight < Severity.high.weight
    assert Severity.high.weight < Severity.critical.weight


def test_lookup_result_helpers():
    r = LookupResult(found=True, entity_type="phone_number",
                     query="+91x", severity=Severity.critical)
    assert r.is_critical is True
    assert r.is_high_or_above is True

    r2 = LookupResult(found=True, entity_type="phone_number",
                      query="+91x", severity=Severity.medium)
    assert r2.is_critical is False
    assert r2.is_high_or_above is False