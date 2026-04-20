"""
SentinelOS — Module 4: URL Analyzer
Multi-layer URL analysis. All free, no API keys needed for core checks.
Optional: VirusTotal free tier (500 req/day) and Google Safe Browsing (free).

Checks:
1. Structural analysis  — entropy, length, suspicious patterns
2. Domain analysis      — typosquatting, lookalike domains
3. Keyword detection    — phishing/scam keywords in URL
4. TLD check            — suspicious top-level domains
5. (Optional) VirusTotal API — free 500/day
6. (Optional) Google Safe Browsing — free
"""
import re
import math
import urllib.parse
from typing import Optional
import os
import requests
from dotenv import load_dotenv

env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(dotenv_path=env_path)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
print("VT KEY:", VIRUSTOTAL_API_KEY)
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")

def check_virustotal(url: str):
    if not VIRUSTOTAL_API_KEY:
        return None

    endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        # Step 1: Submit URL
        res = requests.post(endpoint, headers=headers, data={"url": url}, timeout=5)

        if res.status_code != 200:
            return None

        analysis_id = res.json()["data"]["id"]

        # Step 2: Get report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        report = requests.get(report_url, headers=headers, timeout=5)

        if report.status_code != 200:
            return None

        stats = report.json()["data"]["attributes"]["stats"]

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        }

    except Exception as e:
        print("⚠️ VirusTotal error:", e)
        return None

def check_google_safe_browsing(url: str):
    if not GOOGLE_SAFE_BROWSING_KEY:
        return False, []

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}"

    body = {
        "client": {
            "clientId": "sentinelos",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        res = requests.post(endpoint, json=body, timeout=2)

        if res.status_code != 200:
            return False, []

        data = res.json()

        if "matches" in data:
            return True, data["matches"]

        return False, []

    except requests.exceptions.Timeout:
        print("⚠️ Google API timeout")
        return False, []

    except Exception as e:
        print("⚠️ Google API error:", e)
        return False, []


# ─── Known Legit Domains (whitelist) ─────────────────────────────────────────

TRUSTED_DOMAINS = {
    # Banks
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "kotakbank.com", "pnbindia.in", "bankofbaroda.in", "canarabank.com",
    # UPI / Payments
    "npci.org.in", "upi.npci.org.in", "bhimupi.org.in",
    "paytm.com", "phonepe.com", "gpay.app",
    # Govt
    "gov.in", "nic.in", "india.gov.in", "uidai.gov.in",
    "incometax.gov.in", "epfindia.gov.in",
    # Big tech
    "google.com", "youtube.com", "facebook.com", "instagram.com",
    "amazon.in", "amazon.com", "flipkart.com", "myntra.com",
    "whatsapp.com", "telegram.org",
}

# ─── Suspicious TLDs ──────────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",   # free domain abuse
    ".top", ".click", ".link", ".work", ".loan",
    ".online", ".site", ".website", ".space",
    ".pw", ".cc", ".su", ".ws",
}

# ─── Phishing Keywords in URL ────────────────────────────────────────────────

PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "secure", "security", "update", "confirm", "account",
    "banking", "netbanking", "payment", "pay", "wallet",
    "kyc", "aadhar", "aadhaar", "pan", "reward", "prize",
    "winner", "lucky", "claim", "free", "offer",
    "otp", "password", "credential",
    # Indian bank names in URLs (potential impersonation)
    "sbi", "hdfc", "icici", "axis", "kotak", "pnb",
    "paytm", "phonepe", "gpay", "bhim",
]

# ─── Typosquatting Targets ───────────────────────────────────────────────────

TYPOSQUAT_TARGETS = [
    "sbi", "hdfc", "icici", "paytm", "phonepe", "amazon",
    "flipkart", "google", "paypal", "npci", "uidai",
]


def analyze_url(url: str) -> dict:
    """
    Full URL analysis pipeline.

    Args:
        url: raw URL string from clipboard or link intercept

    Returns:
        {
            "url": "http://sbi-kyc-update.xyz/login",
            "safe": false,
            "risk_score": 85,
            "risk_level": "DANGEROUS",
            "signals": [
                {"type": "SUSPICIOUS_TLD", "detail": ".xyz domain", "weight": 3},
                {"type": "PHISHING_KEYWORD", "detail": "keyword 'kyc' in URL", "weight": 2},
                {"type": "TYPOSQUAT", "detail": "resembles 'sbi'", "weight": 3}
            ],
            "recommendation": "BLOCK",
            "explanation": "This URL shows multiple phishing indicators."
        }
    """
    url = url.strip()
    if not url:
        return _safe_result(url)

    # Normalize
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return _error_result(url, "Could not parse URL")

    domain = parsed.netloc.lower().replace("www.", "")
    path = parsed.path.lower()
    full_lower = url.lower()
    signals = []


    # ── VirusTotal check
    vt_result = check_virustotal(url)

    if vt_result:
        malicious = vt_result["malicious"]
        suspicious = vt_result["suspicious"]

        if malicious > 0 or suspicious > 0:
            signals.append({
                "type": "VIRUSTOTAL",
                "detail": f"{malicious} engines flagged as malicious, {suspicious} suspicious",
                "weight": min(5, malicious + suspicious)
            })
       
    # ── 0. Google Safe Browsing
    is_flagged, matches = check_google_safe_browsing(url)

    if is_flagged:
        threat_types = list({m.get("threatType", "UNKNOWN") for m in matches})

        signals.append({
        "type": "GOOGLE_SAFE_BROWSING",
        "detail": f"Flagged by Google as: {', '.join(threat_types)}",
        "weight": 5
        })

    # ── 1. Whitelist check ───────────────────────────────────────────────────
    if _is_trusted(domain):
        return _safe_result(url, "Domain is on trusted whitelist.")

    # ── 2. TLD check ─────────────────────────────────────────────────────────
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            signals.append({"type": "SUSPICIOUS_TLD", "detail": f"{tld} is commonly used in scams", "weight": 3})
            break

    # ── 3. Phishing keywords in domain/path ──────────────────────────────────
    keyword_hits = []
    for kw in PHISHING_KEYWORDS:
        if kw in domain or kw in path:
            keyword_hits.append(kw)
    if keyword_hits:
        signals.append({
            "type": "PHISHING_KEYWORD",
            "detail": f"Suspicious keywords: {', '.join(keyword_hits[:5])}",
            "weight": min(3, len(keyword_hits))
        })

    # ── 4. Typosquatting detection ────────────────────────────────────────────
    for target in TYPOSQUAT_TARGETS:
        if _is_typosquat(domain, target):
            signals.append({
                "type": "TYPOSQUAT",
                "detail": f"Domain resembles '{target}' — possible impersonation",
                "weight": 3
            })
            break

    # ── 5. URL entropy (randomized/obfuscated domains) ────────────────────────
    entropy = _shannon_entropy(domain.split(".")[0])
    if entropy > 3.8:
        signals.append({
            "type": "HIGH_ENTROPY",
            "detail": f"Domain looks randomly generated (entropy: {entropy:.1f})",
            "weight": 2
        })

    # ── 6. URL length ────────────────────────────────────────────────────────
    if len(url) > 100:
        signals.append({
            "type": "LONG_URL",
            "detail": f"Unusually long URL ({len(url)} chars) — often used to hide destination",
            "weight": 1
        })

    # ── 7. IP address instead of domain ─────────────────────────────────────
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        signals.append({
            "type": "IP_URL",
            "detail": "URL uses IP address instead of domain name",
            "weight": 3
        })

    # ── 8. Multiple subdomains (subdomain abuse) ──────────────────────────────
    subdomain_count = len(domain.split(".")) - 2
    if subdomain_count >= 3:
        signals.append({
            "type": "SUBDOMAIN_ABUSE",
            "detail": f"{subdomain_count} subdomains — often fakes legitimate brand in subdomain",
            "weight": 2
        })

    # ── 9. HTTP (not HTTPS) ──────────────────────────────────────────────────
    if parsed.scheme == "http":
        signals.append({
            "type": "NO_HTTPS",
            "detail": "Site uses HTTP, not HTTPS — your data is not encrypted",
            "weight": 1
        })

    # ── 10. URL shortener ────────────────────────────────────────────────────
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.ly", "rb.gy", "is.gd"]
    if any(s in domain for s in shorteners):
        signals.append({
            "type": "URL_SHORTENER",
            "detail": "Shortened URL hides the real destination",
            "weight": 2
        })

    # ── Calculate score ──────────────────────────────────────────────────────
    total_weight = sum(s["weight"] for s in signals)
    risk_score = min(100, int((total_weight / 10) * 100))

    risk_level, recommendation = _classify(risk_score)

    return {
        "url": url,
        "domain": domain,
        "safe": risk_score < 30,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "recommendation": recommendation,
        "signals": signals,
        "explanation": _build_explanation(signals, risk_level)
    }


def _is_trusted(domain: str) -> bool:
    if domain in TRUSTED_DOMAINS:
        return True
    for trusted in TRUSTED_DOMAINS:
        if domain.endswith("." + trusted):
            return True
    return False


def _is_typosquat(domain: str, target: str) -> bool:
    """
    Check if domain is a typosquat of a target brand.
    Uses simple edit distance + substring heuristic.
    """
    domain_base = domain.split(".")[0]
    if target in domain_base and domain_base != target:
        # e.g. "sbi-kyc" contains "sbi" but isn't "sbi"
        return True
    if _edit_distance(domain_base, target) <= 2 and len(domain_base) > 3:
        return True
    return False


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance."""
    if len(a) < len(b):
        return _edit_distance(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _classify(score: int):
    if score >= 70:
        return "DANGEROUS", "BLOCK"
    elif score >= 40:
        return "SUSPICIOUS", "WARN"
    elif score >= 15:
        return "LOW_RISK", "CAUTION"
    return "SAFE", "ALLOW"


def _build_explanation(signals: list, risk_level: str) -> str:
    if not signals:
        return "No suspicious signals found."
    top = signals[0]["detail"]
    if risk_level == "DANGEROUS":
        return f"This URL is likely malicious. {top}"
    elif risk_level == "SUSPICIOUS":
        return f"This URL shows suspicious signs. {top}"
    return f"Minor concern: {top}"


def _safe_result(url: str = "", reason: str = "No suspicious signals found.") -> dict:
    return {
        "url": url, "domain": "", "safe": True,
        "risk_score": 0, "risk_level": "SAFE",
        "recommendation": "ALLOW", "signals": [],
        "explanation": reason
    }


def _error_result(url: str, reason: str) -> dict:
    return {
        "url": url, "domain": "", "safe": False,
        "risk_score": 50, "risk_level": "SUSPICIOUS",
        "recommendation": "WARN", "signals": [],
        "explanation": reason
    }


# ─── Quick test ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    test_urls = [
        "http://sbi-kyc-update.xyz/login/verify?user=abc",
        "https://hdfcbank.com/netbanking",
        "https://bit.ly/3xAb9k",
        "http://192.168.1.1/admin",
        "https://secure-paytm-wallet.login.click/update",
        "https://google.com",
        "https://amaz0n-offer-claim.tk/prize",
    ]

    for url in test_urls:
        result = analyze_url(url)
        print(f"\n{url}")
        print(f"  safe={result['safe']}  score={result['risk_score']}  level={result['risk_level']}  action={result['recommendation']}")
        if result["signals"]:
            for s in result["signals"]:
                print(f"    [{s['type']}] {s['detail']}")