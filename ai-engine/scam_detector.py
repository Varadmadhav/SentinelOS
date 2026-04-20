"""
SentinelOS — Module 2: Scam Pattern Detector
Pure rule-based NLP. Zero API cost. Works offline.

Detects patterns common in Indian phone/UPI scams:
- OTP scams
- KYC fraud
- Lottery/prize scams
- Impersonation (bank/police/TRAI)
- Urgency/threat language
- Money mule recruitment
"""

import re
from typing import Optional

# ─── Pattern Definitions ──────────────────────────────────────────────────────
# Each entry: (pattern, scam_type, weight)
# Weight 1–3: higher = more suspicious signal

SCAM_PATTERNS = [

    # ── OTP Scams ──────────────────────────────────────────────────────────────
    (r"\botp\b",                                    "OTP_SCAM",        3),
    (r"one[\s-]time[\s-]password",                  "OTP_SCAM",        3),
    (r"share.*\b(otp|pin|password|passcode)\b",     "OTP_SCAM",        3),
    (r"(otp|pin|code).*\b(share|send|bata|dena)\b", "OTP_SCAM",        3),
    (r"verify.*\b(otp|code|number)\b",              "OTP_SCAM",        2),
    (r"(otp|code)\s*(aa|aaya|received|mila)",       "OTP_SCAM",        2),

    # ── KYC / Account Freeze ───────────────────────────────────────────────────
    (r"\bkyc\b",                                    "KYC_FRAUD",       3),
    (r"kyc.*\b(update|complete|pending|expire)\b",  "KYC_FRAUD",       3),
    (r"account.*\b(block|freeze|suspend|band)\b",   "KYC_FRAUD",       3),
    (r"(block|freeze|suspend).*account",            "KYC_FRAUD",       3),
    (r"re[\s-]?verification",                       "KYC_FRAUD",       2),
    (r"update.*\b(details|information|aadhar|pan)\b","KYC_FRAUD",      2),

    # ── Bank / RBI Impersonation ───────────────────────────────────────────────
    (r"\b(rbi|reserve bank)\b",                     "IMPERSONATION",   3),
    (r"\b(sbi|hdfc|icici|axis|kotak|pnb)\b.*official","IMPERSONATION", 2),
    (r"(bank|insurance).*\b(officer|manager|executive)\b","IMPERSONATION",2),
    (r"calling from.*\b(bank|rbi|sebi|irdai)\b",    "IMPERSONATION",   3),
    (r"\b(trai|telecom)\b.*\b(disconnect|block|suspend)\b","IMPERSONATION",3),
    (r"your number.*\b(disconnect|block|deactivate)\b","IMPERSONATION", 3),

    # ── Police / Legal Threat ─────────────────────────────────────────────────
    (r"\b(police|cyber crime|cbi|ied|narcotics)\b", "LEGAL_THREAT",    3),
    (r"arrest.*\b(warrant|order)\b",                "LEGAL_THREAT",    3),
    (r"(fir|case|complaint).*\b(file|register|darz)\b","LEGAL_THREAT", 3),
    (r"legal.*\b(action|notice|proceeding)\b",      "LEGAL_THREAT",    2),
    (r"\b(court|judge|magistrate)\b.*\b(order|summon)\b","LEGAL_THREAT",3),

    # ── Urgency Language ──────────────────────────────────────────────────────
    (r"\b(immediately|turant|abhi|jaldi|urgent|emergency)\b","URGENCY", 2),
    (r"\b(last chance|final warning|deadline)\b",   "URGENCY",         2),
    (r"within.*\b(\d+\s*(hour|minute|min|ghante|minute))\b","URGENCY",  2),
    (r"(24|48|72)\s*hours?",                        "URGENCY",         1),
    (r"do not.*\b(disconnect|hang up|cut)\b",       "URGENCY",         2),
    (r"stay on.*\b(line|call|phone)\b",             "URGENCY",         2),

    # ── Remote Access / Screenshare ───────────────────────────────────────────
    (r"\b(anydesk|teamviewer|quick support|remote)\b","REMOTE_ACCESS",  3),
    (r"(install|download).*\b(app|application)\b",  "REMOTE_ACCESS",   2),
    (r"screen.*\b(share|sharing)\b",                "REMOTE_ACCESS",   3),
    (r"give.*\b(access|control|permission)\b",      "REMOTE_ACCESS",   2),

    # ── Prize / Lottery ───────────────────────────────────────────────────────
    (r"\b(lottery|lucky draw|prize|reward|won|winner)\b","LOTTERY_SCAM",2),
    (r"(congratulations|badhai).*\b(won|win|selected)\b","LOTTERY_SCAM",3),
    (r"(cash|prize|reward).*\b(crore|lakh|thousand)\b","LOTTERY_SCAM",  3),
    (r"processing.*\b(fee|charge|amount)\b",        "LOTTERY_SCAM",    2),

    # ── UPI / Payment Fraud ───────────────────────────────────────────────────
    (r"\b(upi|gpay|phonepe|paytm|bhim)\b.*\b(id|pin|number)\b","UPI_FRAUD",3),
    (r"(send|transfer|pay).*\b(money|amount|paisa|rupee)\b","UPI_FRAUD", 2),
    (r"upi.*\b(request|collect|demand)\b",          "UPI_FRAUD",       3),
    (r"(refund|cashback).*\b(process|credit|claim)\b","UPI_FRAUD",      2),
    (r"scan.*\b(qr|code|barcode)\b",                "UPI_FRAUD",       2),

    # ── Personal Info Phishing ────────────────────────────────────────────────
    (r"\b(aadhar|aadhaar|pan card|voter id)\b.*\b(number|share|send)\b","PHISHING",3),
    (r"(date of birth|dob|mother.*name).*\b(confirm|verify|share)\b","PHISHING",2),
    (r"(account number|ifsc|sort code).*\b(share|send|confirm)\b","PHISHING",3),
]

# ── Indian language urgency/scam words (transliteration) ─────────────────────
HINDI_SIGNALS = [
    r"\b(paisa|rupiya|khata|band|turant|abhi|jaldi)\b",
    r"\b(nahi|nahi|dena|lena|bata|share karo)\b",
    r"\b(ghar|family|police|case|arrest)\b",
]

# Compile all patterns once
_compiled = [
    (re.compile(pat, re.IGNORECASE), scam_type, weight)
    for pat, scam_type, weight in SCAM_PATTERNS
]
_compiled_hindi = [re.compile(p, re.IGNORECASE) for p in HINDI_SIGNALS]


def detect_scam(text: str) -> dict:
    """
    Analyze text for scam patterns.

    Args:
        text: transcript from Whisper or any text to analyze

    Returns:
        {
            "scam": true,
            "type": "OTP_SCAM",
            "confidence": 0.91,
            "risk_score": 85,
            "signals": ["otp", "share otp", "immediately"],
            "all_types": {"OTP_SCAM": 3, "URGENCY": 2}
        }
    """
    if not text:
        return _safe_result()

    text_lower = text.lower()
    matched_signals = []
    type_scores: dict[str, int] = {}

    # Run all pattern checks
    for pattern, scam_type, weight in _compiled:
        match = pattern.search(text_lower)
        if match:
            matched_signals.append(match.group(0).strip())
            type_scores[scam_type] = type_scores.get(scam_type, 0) + weight

    # Hindi signal bonus
    hindi_count = sum(1 for p in _compiled_hindi if p.search(text_lower))
    if hindi_count >= 2:
        type_scores["URGENCY"] = type_scores.get("URGENCY", 0) + 1

    if not type_scores:
        return _safe_result()

    # Determine dominant scam type
    dominant_type = max(type_scores, key=type_scores.get)
    total_weight = sum(type_scores.values())

    # Score: cap at 100, scale based on weight accumulation
    # Max realistic weight for a confirmed scam call ≈ 12
    risk_score = min(100, int((total_weight / 12) * 100))

    # Confidence: 0–1
    confidence = round(min(1.0, total_weight / 10), 2)

    return {
        "scam": risk_score >= 30,
        "type": dominant_type,
        "confidence": confidence,
        "risk_score": risk_score,
        "signals": list(set(matched_signals)),
        "all_types": type_scores,
        "explanation": _explain(dominant_type)
    }


def _safe_result() -> dict:
    return {
        "scam": False,
        "type": None,
        "confidence": 0.0,
        "risk_score": 0,
        "signals": [],
        "all_types": {},
        "explanation": "No scam patterns detected."
    }


def _explain(scam_type: str) -> str:
    explanations = {
        "OTP_SCAM":      "Caller is asking for OTP/PIN. Legitimate banks NEVER ask for OTP.",
        "KYC_FRAUD":     "Fake KYC update call. Banks do KYC in-branch or via official app only.",
        "IMPERSONATION": "Caller is pretending to be from RBI/Bank/TRAI. This is a known scam tactic.",
        "LEGAL_THREAT":  "Caller is using police/legal threats to create fear. Real authorities send written notices.",
        "URGENCY":       "Caller is creating artificial urgency. Scammers use time pressure to stop you from thinking.",
        "REMOTE_ACCESS": "Caller wants remote access to your device. Never allow this.",
        "LOTTERY_SCAM":  "You cannot win a lottery you did not enter. There is no real prize.",
        "UPI_FRAUD":     "Suspicious UPI-related request detected. Receiving money never requires sharing your PIN.",
        "PHISHING":      "Caller is trying to collect personal/financial information.",
    }
    return explanations.get(scam_type, "Suspicious pattern detected.")


# ─── Quick test ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    test_cases = [
        "Sir your KYC is pending, please share your OTP immediately to avoid account block",
        "Congratulations! You have won 50 lakh rupees in our lucky draw. Pay processing fee now.",
        "This is Mumbai cyber crime. An FIR has been registered against your Aadhar number.",
        "Hello, just calling to check how you are doing today.",
        "Please install AnyDesk on your phone so we can help you update your account.",
    ]

    for text in test_cases:
        result = detect_scam(text)
        print(f"\nInput: {text[:60]}...")
        print(f"  scam={result['scam']}  type={result['type']}  score={result['risk_score']}  confidence={result['confidence']}")
        print(f"  signals={result['signals']}")