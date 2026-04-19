"""
integrations.py
---------------
SentinelOS External API Integrations.

Architecture
~~~~~~~~~~~~
Every integration follows the same pattern:

  1. An abstract base class defines the interface.
  2. A Mock implementation works offline (hackathon / CI).
  3. A Real implementation is stubbed — swap in your API key and go live.

All methods return a typed IntegrationResult so the caller never
has to know which implementation is running.

Usage
-----
    from integrations import TruecallerClient, SafeBrowsingClient, VirusTotalClient

    # Auto-selects Mock or Real based on env vars
    truecaller   = TruecallerClient.from_env()
    safebrowsing = SafeBrowsingClient.from_env()
    virustotal   = VirusTotalClient.from_env()

    result = await truecaller.lookup("+919999999999")
    if result.is_spam:
        ...
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared result types
# ---------------------------------------------------------------------------

@dataclass
class NumberLookupResult:
    """Result from any phone-number intelligence source."""
    number:        str
    is_spam:       bool          = False
    spam_score:    int           = 0        # 0-100
    spam_type:     Optional[str] = None     # "telemarketer" | "fraud" | "bank" …
    name:          Optional[str] = None     # caller name if known
    reports:       int           = 0        # community reports
    provider:      str           = "unknown"
    raw:           dict          = field(default_factory=dict)


@dataclass
class URLScanResult:
    """Result from any URL safety scanner."""
    url:           str
    is_malicious:  bool          = False
    is_phishing:   bool          = False
    threat_types:  List[str]     = field(default_factory=list)
    confidence:    int           = 0        # 0-100
    provider:      str           = "unknown"
    raw:           dict          = field(default_factory=dict)


@dataclass
class AppScanResult:
    """Result from any app / APK scanner."""
    package_name:  str
    is_malicious:  bool          = False
    is_fake:       bool          = False
    threat_label:  Optional[str] = None
    confidence:    int           = 0
    provider:      str           = "unknown"
    raw:           dict          = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Known-spam seed data (used by mocks)
# ---------------------------------------------------------------------------

_SPAM_NUMBERS = {
    "+919999999999": {"spam_type": "fraud",        "name": "Fraud Caller",  "reports": 142},
    "+918888888888": {"spam_type": "bank_fraud",   "name": "Fake HDFC KYC", "reports": 89},
    "+917777777777": {"spam_type": "telemarketer", "name": "Spam Caller",   "reports": 34},
}

_MALICIOUS_URLS = {
    "fake-sbi-kyc.com":        {"phishing": True,  "threats": ["SOCIAL_ENGINEERING"]},
    "win-iphone15-free.xyz":   {"phishing": False, "threats": ["MALWARE", "UNWANTED_SOFTWARE"]},
    "hdfc-update-account.net": {"phishing": True,  "threats": ["SOCIAL_ENGINEERING"]},
}

_FAKE_APPS = {
    "com.hdfc.fake.netbanking": {"real": "com.hdfcbank.mobilebanking", "label": "FakeBank"},
    "com.sbi.fake.yono":        {"real": "com.onlinesbi.mobile",       "label": "FakeBank"},
}


# ---------------------------------------------------------------------------
# Truecaller
# ---------------------------------------------------------------------------

class _TruecallerBase(ABC):
    @abstractmethod
    async def lookup(self, number: str) -> NumberLookupResult: ...


class TruecallerMock(_TruecallerBase):
    """
    Offline mock — returns realistic responses for known spam numbers.
    All other numbers return clean results.
    """

    async def lookup(self, number: str) -> NumberLookupResult:
        # Normalise
        clean = number.strip().replace(" ", "").replace("-", "")
        if not clean.startswith("+"):
            clean = f"+91{clean}"

        if clean in _SPAM_NUMBERS:
            data = _SPAM_NUMBERS[clean]
            logger.debug("[Mock Truecaller] SPAM hit: %s", clean)
            return NumberLookupResult(
                number=clean,
                is_spam=True,
                spam_score=85,
                spam_type=data["spam_type"],
                name=data["name"],
                reports=data["reports"],
                provider="truecaller_mock",
            )

        return NumberLookupResult(
            number=clean,
            is_spam=False,
            spam_score=0,
            provider="truecaller_mock",
        )


class TruecallerReal(_TruecallerBase):
    """
    Real Truecaller API stub.
    Requires TRUECALLER_API_KEY in environment.

    Docs: https://docs.truecaller.com/truecaller-sdk
    Swap the mock with this by setting TRUECALLER_API_KEY in your .env
    """

    _BASE = "https://search5-noneu.truecaller.com/v2/search"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    async def lookup(self, number: str) -> NumberLookupResult:
        # TODO: install httpx and uncomment when going live
        #
        # import httpx
        # async with httpx.AsyncClient() as client:
        #     r = await client.get(
        #         self._BASE,
        #         params={"q": number, "countryCode": "IN", "type": 4},
        #         headers={"Authorization": f"Bearer {self._api_key}"},
        #         timeout=3.0,
        #     )
        #     r.raise_for_status()
        #     data = r.json()
        #     # Parse Truecaller response shape
        #     entry = data.get("data", [{}])[0]
        #     score = entry.get("spamInfo", {}).get("score", 0)
        #     return NumberLookupResult(
        #         number=number,
        #         is_spam=score > 2,
        #         spam_score=min(100, score * 20),
        #         spam_type=entry.get("spamInfo", {}).get("spamType"),
        #         name=entry.get("name"),
        #         reports=entry.get("spamInfo", {}).get("spammerReports", 0),
        #         provider="truecaller",
        #         raw=data,
        #     )
        raise NotImplementedError("Set TRUECALLER_API_KEY and uncomment the httpx block.")


class TruecallerClient:
    """Factory — returns Mock or Real based on environment."""

    @staticmethod
    def from_env() -> _TruecallerBase:
        key = os.getenv("TRUECALLER_API_KEY")
        if key:
            logger.info("Truecaller: using REAL client")
            return TruecallerReal(api_key=key)
        logger.info("Truecaller: using MOCK client (set TRUECALLER_API_KEY to go live)")
        return TruecallerMock()


# ---------------------------------------------------------------------------
# Google Safe Browsing
# ---------------------------------------------------------------------------

class _SafeBrowsingBase(ABC):
    @abstractmethod
    async def check(self, url: str) -> URLScanResult: ...


class SafeBrowsingMock(_SafeBrowsingBase):
    """
    Offline mock — matches against known-bad hostnames.
    Any URL with suspicious keywords also returns a soft warning.
    """

    _SUSPICIOUS_KEYWORDS = [
        "kyc", "update-account", "verify-now", "login-secure",
        "free-iphone", "win-prize", "refund-process", "otp-confirm",
    ]

    async def check(self, url: str) -> URLScanResult:
        host = urlparse(url).netloc.lower().replace("www.", "")
        path = url.lower()

        # Exact host match
        if host in _MALICIOUS_URLS:
            data = _MALICIOUS_URLS[host]
            logger.debug("[Mock SafeBrowsing] MALICIOUS hit: %s", host)
            return URLScanResult(
                url=url,
                is_malicious=True,
                is_phishing=data["phishing"],
                threat_types=data["threats"],
                confidence=95,
                provider="safebrowsing_mock",
            )

        # Keyword heuristic
        hits = [kw for kw in self._SUSPICIOUS_KEYWORDS if kw in path]
        if hits:
            return URLScanResult(
                url=url,
                is_malicious=False,
                is_phishing=True,
                threat_types=["SOCIAL_ENGINEERING"],
                confidence=55,
                provider="safebrowsing_mock",
                raw={"matched_keywords": hits},
            )

        return URLScanResult(url=url, provider="safebrowsing_mock")


class SafeBrowsingReal(_SafeBrowsingBase):
    """
    Real Google Safe Browsing v4 stub.
    Requires SAFE_BROWSING_API_KEY in environment.

    Docs: https://developers.google.com/safe-browsing/v4/lookup-api
    """

    _BASE = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    async def check(self, url: str) -> URLScanResult:
        # TODO: uncomment when going live
        #
        # import httpx
        # payload = {
        #     "client": {"clientId": "sentinelos", "clientVersion": "1.0.0"},
        #     "threatInfo": {
        #         "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"],
        #         "platformTypes": ["ANY_PLATFORM"],
        #         "threatEntryTypes": ["URL"],
        #         "threatEntries": [{"url": url}],
        #     },
        # }
        # async with httpx.AsyncClient() as client:
        #     r = await client.post(
        #         self._BASE, params={"key": self._api_key},
        #         json=payload, timeout=3.0,
        #     )
        #     r.raise_for_status()
        #     data = r.json()
        #     matches = data.get("matches", [])
        #     threats = [m["threatType"] for m in matches]
        #     return URLScanResult(
        #         url=url,
        #         is_malicious=bool(matches),
        #         is_phishing="SOCIAL_ENGINEERING" in threats,
        #         threat_types=threats,
        #         confidence=99 if matches else 0,
        #         provider="google_safe_browsing",
        #         raw=data,
        #     )
        raise NotImplementedError("Set SAFE_BROWSING_API_KEY and uncomment the httpx block.")


class SafeBrowsingClient:
    @staticmethod
    def from_env() -> _SafeBrowsingBase:
        key = os.getenv("SAFE_BROWSING_API_KEY")
        if key:
            logger.info("SafeBrowsing: using REAL client")
            return SafeBrowsingReal(api_key=key)
        logger.info("SafeBrowsing: using MOCK client")
        return SafeBrowsingMock()


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

class _VirusTotalBase(ABC):
    @abstractmethod
    async def scan_url(self, url: str) -> URLScanResult: ...
    @abstractmethod
    async def scan_app(self, package_name: str, apk_hash: Optional[str]) -> AppScanResult: ...


class VirusTotalMock(_VirusTotalBase):
    """
    Offline mock for both URL and APK scanning.
    Deterministic: same input always returns same output.
    """

    async def scan_url(self, url: str) -> URLScanResult:
        host = urlparse(url).netloc.lower().replace("www.", "")

        if host in _MALICIOUS_URLS:
            data = _MALICIOUS_URLS[host]
            logger.debug("[Mock VirusTotal] URL hit: %s", host)
            return URLScanResult(
                url=url,
                is_malicious=True,
                is_phishing=data["phishing"],
                threat_types=data["threats"],
                confidence=90,
                provider="virustotal_mock",
            )

        # Deterministic pseudo-random: sha256 of URL → low random hit rate
        h = int(hashlib.sha256(url.encode()).hexdigest(), 16) % 100
        if h < 5:   # ~5% false positive rate in mock
            return URLScanResult(
                url=url, is_malicious=True,
                threat_types=["MALWARE"],
                confidence=40,
                provider="virustotal_mock",
            )

        return URLScanResult(url=url, provider="virustotal_mock")

    async def scan_app(self, package_name: str,
                       apk_hash: Optional[str] = None) -> AppScanResult:
        if package_name in _FAKE_APPS:
            data = _FAKE_APPS[package_name]
            logger.debug("[Mock VirusTotal] Fake app hit: %s", package_name)
            return AppScanResult(
                package_name=package_name,
                is_malicious=True,
                is_fake=True,
                threat_label=data["label"],
                confidence=95,
                provider="virustotal_mock",
                raw={"impersonates": data["real"]},
            )

        return AppScanResult(package_name=package_name, provider="virustotal_mock")


class VirusTotalReal(_VirusTotalBase):
    """
    Real VirusTotal v3 API stub.
    Requires VIRUSTOTAL_API_KEY in environment.

    Docs: https://developers.virustotal.com/reference/overview
    """

    _BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._headers = {"x-apikey": api_key}

    async def scan_url(self, url: str) -> URLScanResult:
        # TODO: uncomment when going live
        #
        # import base64, httpx
        # url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        # async with httpx.AsyncClient() as client:
        #     r = await client.get(
        #         f"{self._BASE}/urls/{url_id}",
        #         headers=self._headers, timeout=5.0,
        #     )
        #     r.raise_for_status()
        #     data = r.json()
        #     stats = data["data"]["attributes"]["last_analysis_stats"]
        #     malicious = stats.get("malicious", 0)
        #     total = sum(stats.values()) or 1
        #     return URLScanResult(
        #         url=url,
        #         is_malicious=malicious > 2,
        #         is_phishing=malicious > 2,
        #         confidence=min(100, int(malicious / total * 100)),
        #         provider="virustotal",
        #         raw=stats,
        #     )
        raise NotImplementedError("Set VIRUSTOTAL_API_KEY and uncomment the httpx block.")

    async def scan_app(self, package_name: str,
                       apk_hash: Optional[str] = None) -> AppScanResult:
        # TODO: lookup apk_hash via /files/{hash} endpoint
        raise NotImplementedError("Set VIRUSTOTAL_API_KEY and uncomment the httpx block.")


class VirusTotalClient:
    @staticmethod
    def from_env() -> _VirusTotalBase:
        key = os.getenv("VIRUSTOTAL_API_KEY")
        if key:
            logger.info("VirusTotal: using REAL client")
            return VirusTotalReal(api_key=key)
        logger.info("VirusTotal: using MOCK client")
        return VirusTotalMock()


# ---------------------------------------------------------------------------
# Convenience: initialise all clients at once
# ---------------------------------------------------------------------------

@dataclass
class IntegrationClients:
    """Bundle of all integration clients. Init once, inject everywhere."""
    truecaller:   _TruecallerBase
    safebrowsing: _SafeBrowsingBase
    virustotal:   _VirusTotalBase

    @classmethod
    def from_env(cls) -> "IntegrationClients":
        return cls(
            truecaller=TruecallerClient.from_env(),
            safebrowsing=SafeBrowsingClient.from_env(),
            virustotal=VirusTotalClient.from_env(),
        )