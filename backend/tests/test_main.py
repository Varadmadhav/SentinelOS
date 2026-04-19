"""
tests/test_main.py
------------------
Integration tests for all FastAPI routes.

Uses pytest + httpx AsyncClient — no real network calls, no Firebase.
The MockAdapter injects seed data in-memory.

Run:  pytest tests/test_main.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from fastapi.testclient import TestClient

# Patch init_db BEFORE importing main so the app uses mock data
from unittest.mock import AsyncMock, patch

SEED = {
    "phone_numbers": [{
        "number": "+919999999999",
        "tags": ["otp_scam"],
        "severity": "critical",
        "reported_count": 50,
        "source": "reported",
    }],
    "upi_ids": [{
        "upi_id": "scammer@ybl",
        "tags": ["fake_merchant"],
        "severity": "high",
        "reported_count": 30,
        "source": "reported",
    }],
    "urls": [{
        "url": "http://fake-sbi-kyc.com/login",
        "tags": ["phishing"],
        "severity": "critical",
        "reported_count": 200,
        "source": "imported",
    }],
}

# ---- patch init_db to use mock data ----
import db.dependencies as _dep
from db.fraud_db import FraudDB

class _MockAdapter:
    async def load_all(self): return SEED

async def _mock_init_db(*a, **kw):
    import db.dependencies as dep
    dep._db_instance = FraudDB(adapter=_MockAdapter())
    await dep._db_instance.initialise()
    return dep._db_instance

_dep.init_db = _mock_init_db   # swap before app import

from main import app

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------

def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# /stats
# ---------------------------------------------------------------------------

def test_stats(client):
    r = client.get("/stats")
    assert r.status_code == 200
    data = r.json()
    assert data["database"]["phone_numbers"] >= 1
    assert "BLOCK" in data["scoring_bands"]


# ---------------------------------------------------------------------------
# /check-number
# ---------------------------------------------------------------------------

def test_check_number_known_fraud_blocks(client):
    r = client.post("/check-number", json={"number": "+919999999999"})
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "BLOCK"
    assert body["auto_blocked"] is True


def test_check_number_clean_is_safe(client):
    r = client.post("/check-number", json={"number": "+910000000000"})
    assert r.status_code == 200
    assert r.json()["action"] == "SAFE"


def test_check_number_with_call_signals(client):
    r = client.post("/check-number", json={
        "number": "+910000000001",
        "otp_requested": True,
        "urgency_language": True,
        "unknown_number": True,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["action"] in ("ALERT", "BLOCK")
    assert body["score"] > 65


def test_check_number_10digit(client):
    r = client.post("/check-number", json={"number": "9999999999"})
    assert r.status_code == 200
    assert r.json()["action"] == "BLOCK"


# ---------------------------------------------------------------------------
# /check-url
# ---------------------------------------------------------------------------

def test_check_url_known_phishing_blocks(client):
    r = client.post("/check-url", json={"url": "http://fake-sbi-kyc.com/login"})
    assert r.status_code == 200
    assert r.json()["action"] == "BLOCK"


def test_check_url_host_fallback_blocks(client):
    r = client.post("/check-url", json={"url": "http://fake-sbi-kyc.com/other/page"})
    assert r.status_code == 200
    assert r.json()["action"] == "BLOCK"


def test_check_url_safe(client):
    r = client.post("/check-url", json={"url": "https://google.com"})
    assert r.status_code == 200
    assert r.json()["action"] == "SAFE"


def test_check_url_external_flag_raises_score(client):
    r = client.post("/check-url", json={
        "url": "https://unknown-site.xyz",
        "url_flagged_external": True,
    })
    assert r.status_code == 200
    assert r.json()["score"] >= 70


# ---------------------------------------------------------------------------
# /check-upi
# ---------------------------------------------------------------------------

def test_check_upi_known_fraud(client):
    r = client.post("/check-upi", json={"upi_id": "scammer@ybl"})
    assert r.status_code == 200
    body = r.json()
    assert body["action"] in ("ALERT", "BLOCK")


def test_check_upi_killer_combo_blocks(client):
    """UPI copied during call = auto BLOCK regardless of DB."""
    r = client.post("/check-upi", json={
        "upi_id": "anyone@okhdfc",
        "upi_copied_on_call": True,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "BLOCK"
    assert body["auto_blocked"] is True


def test_check_upi_clean(client):
    r = client.post("/check-upi", json={"upi_id": "legit@okaxis"})
    assert r.status_code == 200
    assert r.json()["action"] == "SAFE"


# ---------------------------------------------------------------------------
# /score-event
# ---------------------------------------------------------------------------

def test_score_event_multi_signal(client):
    r = client.post("/score-event", json={
        "source": "call_shield",
        "signals": {
            "fraud_db_hit": True,
            "db_severity": "high",
            "db_tags": ["otp_scam"],
            "otp_requested": True,
            "urgency_language": True,
            "unknown_number": True,
        }
    })
    assert r.status_code == 200
    body = r.json()
    assert body["action"] in ("ALERT", "BLOCK")
    assert len(body["reasons"]) >= 3


def test_score_event_auto_lookup(client):
    """entity_value triggers automatic DB lookup inside the route."""
    r = client.post("/score-event", json={
        "source": "call_shield",
        "signals": {
            "entity_value": "+919999999999",
            "otp_requested": True,
        }
    })
    assert r.status_code == 200
    assert r.json()["action"] == "BLOCK"


def test_score_event_clean(client):
    r = client.post("/score-event", json={
        "source": "screen_shield",
        "signals": {}
    })
    assert r.status_code == 200
    assert r.json()["action"] == "SAFE"


# ---------------------------------------------------------------------------
# /admin/reload
# ---------------------------------------------------------------------------

def test_admin_reload(client):
    r = client.post("/admin/reload")
    assert r.status_code == 200
    assert r.json()["status"] == "reloaded"


# ---------------------------------------------------------------------------
# /admin/report
# ---------------------------------------------------------------------------

def test_admin_report_phone(client):
    r = client.post("/admin/report", json={
        "entity_type": "phone_number",
        "value": "+911111111111",
        "tags": ["test"],
        "severity": "medium",
    })
    assert r.status_code == 201
    assert r.json()["status"] == "reported"

    # Verify it's now in the live index
    r2 = client.post("/check-number", json={"number": "+911111111111"})
    assert r2.json()["action"] in ("WARN", "ALERT", "BLOCK")


def test_admin_report_invalid_type(client):
    r = client.post("/admin/report", json={
        "entity_type": "invalid_type",
        "value": "test",
    })
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# Response timing header
# ---------------------------------------------------------------------------

def test_timing_header_present(client):
    r = client.get("/health")
    assert "x-response-time-ms" in r.headers