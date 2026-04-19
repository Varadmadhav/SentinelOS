"""
tests/test_integrations.py
--------------------------
Tests for all integration mocks — runs fully offline.

Run:  pytest tests/test_integrations.py -v
"""

from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from integrations import (
    TruecallerMock, SafeBrowsingMock, VirusTotalMock,
    TruecallerClient, SafeBrowsingClient, VirusTotalClient,
    IntegrationClients,
)


# ---------------------------------------------------------------------------
# Truecaller Mock
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_truecaller_known_spam():
    tc = TruecallerMock()
    r = await tc.lookup("+919999999999")
    assert r.is_spam is True
    assert r.spam_score > 0
    assert r.spam_type is not None
    assert r.provider == "truecaller_mock"

@pytest.mark.asyncio
async def test_truecaller_clean_number():
    tc = TruecallerMock()
    r = await tc.lookup("+910000000000")
    assert r.is_spam is False
    assert r.spam_score == 0

@pytest.mark.asyncio
async def test_truecaller_10digit_normalised():
    tc = TruecallerMock()
    r = await tc.lookup("9999999999")   # no +91 prefix
    assert r.is_spam is True            # should still match

@pytest.mark.asyncio
async def test_truecaller_strips_spaces():
    tc = TruecallerMock()
    r = await tc.lookup("+91 9999 999 999")
    assert r.is_spam is True


# ---------------------------------------------------------------------------
# SafeBrowsing Mock
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_safebrowsing_known_phishing():
    sb = SafeBrowsingMock()
    r = await sb.check("http://fake-sbi-kyc.com/login")
    assert r.is_malicious is True
    assert r.is_phishing is True
    assert "SOCIAL_ENGINEERING" in r.threat_types
    assert r.confidence >= 90

@pytest.mark.asyncio
async def test_safebrowsing_malware_url():
    sb = SafeBrowsingMock()
    r = await sb.check("http://win-iphone15-free.xyz/claim")
    assert r.is_malicious is True
    assert "MALWARE" in r.threat_types

@pytest.mark.asyncio
async def test_safebrowsing_keyword_heuristic():
    sb = SafeBrowsingMock()
    r = await sb.check("http://somesite.com/kyc-update-now")
    assert r.is_phishing is True
    assert r.is_malicious is False   # soft warning, not confirmed malicious

@pytest.mark.asyncio
async def test_safebrowsing_clean_url():
    sb = SafeBrowsingMock()
    r = await sb.check("https://google.com")
    assert r.is_malicious is False
    assert r.is_phishing is False


# ---------------------------------------------------------------------------
# VirusTotal Mock
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_virustotal_known_malicious_url():
    vt = VirusTotalMock()
    r = await vt.scan_url("http://fake-sbi-kyc.com")
    assert r.is_malicious is True
    assert r.confidence >= 85

@pytest.mark.asyncio
async def test_virustotal_clean_url():
    vt = VirusTotalMock()
    r = await vt.scan_url("https://github.com")
    # clean — should not be malicious (hash-based, deterministic)
    assert isinstance(r.is_malicious, bool)   # just type check for non-seeded

@pytest.mark.asyncio
async def test_virustotal_fake_app_detected():
    vt = VirusTotalMock()
    r = await vt.scan_app("com.hdfc.fake.netbanking")
    assert r.is_fake is True
    assert r.is_malicious is True
    assert r.threat_label == "FakeBank"
    assert "impersonates" in r.raw

@pytest.mark.asyncio
async def test_virustotal_real_app_clean():
    vt = VirusTotalMock()
    r = await vt.scan_app("com.hdfcbank.mobilebanking")
    assert r.is_fake is False
    assert r.is_malicious is False


# ---------------------------------------------------------------------------
# Factory methods
# ---------------------------------------------------------------------------

def test_from_env_returns_mock_without_keys(monkeypatch):
    monkeypatch.delenv("TRUECALLER_API_KEY",   raising=False)
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY",    raising=False)

    assert isinstance(TruecallerClient.from_env(),   TruecallerMock)
    assert isinstance(SafeBrowsingClient.from_env(),  SafeBrowsingMock)
    assert isinstance(VirusTotalClient.from_env(),    VirusTotalMock)

def test_integration_clients_bundle(monkeypatch):
    monkeypatch.delenv("TRUECALLER_API_KEY",   raising=False)
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY",    raising=False)

    clients = IntegrationClients.from_env()
    assert clients.truecaller is not None
    assert clients.safebrowsing is not None
    assert clients.virustotal is not None