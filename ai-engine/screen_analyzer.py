"""
SentinelOS — Module 3: Screen Analyzer
Detects dark patterns and scam UI from AccessibilityService text dumps.

Dark patterns detected:
- Fake countdown timers
- Pre-checked subscription boxes
- Hidden charges
- Urgency/FOMO language
- Misleading buttons (NO = YES trick)
- Fake security warnings
"""

import re
from typing import List, Optional

# ─── Dark Pattern Rules ───────────────────────────────────────────────────────
# (pattern, pattern_type, weight, description)

DARK_PATTERNS = [

    # ── Fake Urgency / Countdown ──────────────────────────────────────────────
    (r"\b(limited time|offer expires|ending soon|hurry|act now)\b",
     "FAKE_URGENCY", 2, "Limited time pressure language"),

    (r"\b(only \d+ (left|remaining|available))\b",
     "FAKE_SCARCITY", 2, "Fake scarcity claim"),

    (r"(expires?\s+in|valid\s+for\s+only)\s+\d+\s*(hour|minute|second|day)",
     "COUNTDOWN_TIMER", 3, "Artificial countdown timer"),

    (r"\d{2}:\d{2}:\d{2}",
     "COUNTDOWN_TIMER", 1, "Timer display detected"),

    (r"\b(today only|last day|final hours?|midnight deadline)\b",
     "FAKE_URGENCY", 2, "Deadline pressure tactic"),

    # ── Pre-checked Boxes / Forced Consent ───────────────────────────────────
    (r"(✓|✔|☑|[x✗])\s*.{0,40}(subscription|newsletter|offer|terms|consent)",
     "PRECHECKED_BOX", 3, "Pre-checked subscription or consent box"),

    (r"(auto[\s-]?renew|auto[\s-]?subscribe)",
     "PRECHECKED_BOX", 2, "Auto-renewal clause"),

    (r"(uncheck|deselect|opt[\s-]out).{0,30}(receive|offer|promo|marketing)",
     "PRECHECKED_BOX", 2, "Opt-out framed as default"),

    # ── Hidden Charges ────────────────────────────────────────────────────────
    (r"\*\s*.{0,60}(fee|charge|tax|additional|extra)",
     "HIDDEN_CHARGES", 3, "Asterisk hiding extra charges"),

    (r"(processing|convenience|platform|service)\s+fee",
     "HIDDEN_CHARGES", 2, "Hidden processing fee"),

    (r"\+\s*(gst|vat|tax|cess|surcharge)",
     "HIDDEN_CHARGES", 2, "Additional tax not shown upfront"),

    (r"(total|final|actual).{0,20}(different|may vary|subject to)",
     "HIDDEN_CHARGES", 2, "Price disclaimer"),

    # ── Misleading Buttons ────────────────────────────────────────────────────
    (r"\b(no\s*,?\s*thanks?|i\s+don.t\s+want|skip\s+savings?)\b",
     "MISLEADING_BUTTON", 2, "Shame/guilt decline button"),

    (r"(disagree|decline|cancel).{0,10}(subscribe|offer|deal)",
     "MISLEADING_BUTTON", 1, "Confusing cancel button"),

    # ── Fake Security Warnings ────────────────────────────────────────────────
    (r"(virus|malware|threat|infected|hacked).{0,30}(detected|found|alert)",
     "FAKE_SECURITY_WARNING", 3, "Fake virus/security alert"),

    (r"your (phone|device|system).{0,20}(at risk|compromised|infected)",
     "FAKE_SECURITY_WARNING", 3, "Fake device compromise warning"),

    (r"(immediate|urgent).{0,20}(action|scan|clean|fix).{0,20}(required|needed)",
     "FAKE_SECURITY_WARNING", 3, "Fake urgent action required"),

    (r"call.*\d{3,}.*\b(support|helpline|toll[\s-]?free)\b",
     "FAKE_SECURITY_WARNING", 3, "Tech support scam phone number"),

    # ── Fake Prizes / Rewards ─────────────────────────────────────────────────
    (r"(congratulations?|you.ve\s+won|selected|lucky\s+winner)",
     "FAKE_PRIZE", 3, "Fake prize or winner notification"),

    (r"(claim|collect|redeem).{0,20}(prize|reward|gift|cashback|bonus)",
     "FAKE_PRIZE", 2, "Claim your prize CTA"),

    (r"(spin|wheel|scratch).{0,20}(win|prize|reward)",
     "FAKE_PRIZE", 2, "Gamified fake prize"),

    # ── Data Collection / Privacy ─────────────────────────────────────────────
    (r"(share|provide).{0,20}(aadhar|pan|account|password|pin|otp)",
     "DATA_PHISHING", 3, "Requesting sensitive personal data on screen"),

    (r"(confirm|verify).{0,20}(identity|account|details)",
     "DATA_PHISHING", 2, "Identity verification prompt"),
]

_compiled = [
    (re.compile(pat, re.IGNORECASE), ptype, weight, desc)
    for pat, ptype, weight, desc in DARK_PATTERNS
]


def analyze_screen(screen_text: str, ui_elements: Optional[List] = None) -> dict:
    """
    Analyze screen content for dark patterns.

    Args:
        screen_text: full text from Android AccessibilityService
        ui_elements: list of UI elements [{type, text, checked, bounds}]
                     passed from Kotlin AccessibilityService dump

    Returns:
        {
            "dark_patterns_found": true,
            "risk_score": 65,
            "patterns": [
                {
                    "type": "COUNTDOWN_TIMER",
                    "description": "Artificial countdown timer",
                    "matched_text": "expires in 10 minutes",
                    "severity": "HIGH"
                }
            ],
            "highlight_elements": [...],
            "summary": "2 dark patterns detected: FAKE_URGENCY, COUNTDOWN_TIMER"
        }
    """
    if not screen_text:
        return _safe_result()

    found_patterns = []
    type_scores: dict[str, int] = {}

    # Text-based detection
    for pattern, ptype, weight, desc in _compiled:
        match = pattern.search(screen_text)
        if match:
            found_patterns.append({
                "type": ptype,
                "description": desc,
                "matched_text": match.group(0).strip(),
                "severity": _severity(weight)
            })
            type_scores[ptype] = type_scores.get(ptype, 0) + weight

    # UI element analysis (from Kotlin accessibility dump)
    if ui_elements:
        element_patterns = _analyze_ui_elements(ui_elements)
        found_patterns.extend(element_patterns)
        for ep in element_patterns:
            ptype = ep["type"]
            type_scores[ptype] = type_scores.get(ptype, 0) + 2

    # Deduplicate by type (keep highest severity per type)
    seen_types = set()
    deduped = []
    for p in found_patterns:
        if p["type"] not in seen_types:
            deduped.append(p)
            seen_types.add(p["type"])

    if not deduped:
        return _safe_result()

    total_weight = sum(type_scores.values())
    risk_score = min(100, int((total_weight / 10) * 100))

    return {
        "dark_patterns_found": True,
        "risk_score": risk_score,
        "patterns": deduped,
        "pattern_types": list(type_scores.keys()),
        "highlight_elements": _get_highlight_targets(deduped),
        "summary": f"{len(deduped)} dark pattern(s) detected: {', '.join(type_scores.keys())}"
    }


def _analyze_ui_elements(elements: List[dict]) -> list:
    """
    Analyze structured UI element list from AccessibilityService.
    Detects pre-checked checkboxes, suspicious buttons.
    """
    found = []
    for el in elements:
        el_type = el.get("type", "").lower()
        el_text = el.get("text", "").lower()
        el_checked = el.get("checked", False)

        # Pre-checked checkboxes for subscriptions/newsletters
        if el_type == "checkbox" and el_checked:
            subscription_keywords = ["subscribe", "newsletter", "offer", "auto", "renew", "consent", "agree", "terms"]
            if any(kw in el_text for kw in subscription_keywords):
                found.append({
                    "type": "PRECHECKED_BOX",
                    "description": "Pre-checked subscription/consent checkbox",
                    "matched_text": el.get("text", ""),
                    "severity": "HIGH"
                })

        # Shame buttons
        if el_type in ["button", "textview"]:
            shame_phrases = ["no thanks", "i don't want", "skip savings", "i prefer to pay more"]
            if any(ph in el_text for ph in shame_phrases):
                found.append({
                    "type": "MISLEADING_BUTTON",
                    "description": "Shame/guilt decline button",
                    "matched_text": el.get("text", ""),
                    "severity": "MEDIUM"
                })

    return found


def _get_highlight_targets(patterns: list) -> list:
    """
    Returns what the overlay UI should highlight/warn about.
    Kotlin overlay reads this to know what to flag on screen.
    """
    return [
        {
            "type": p["type"],
            "label": p["description"],
            "severity": p["severity"],
            "matched_text": p["matched_text"]
        }
        for p in patterns
    ]


def _severity(weight: int) -> str:
    if weight >= 3:
        return "HIGH"
    elif weight == 2:
        return "MEDIUM"
    return "LOW"


def _safe_result() -> dict:
    return {
        "dark_patterns_found": False,
        "risk_score": 0,
        "patterns": [],
        "pattern_types": [],
        "highlight_elements": [],
        "summary": "No dark patterns detected."
    }


# ─── Quick test ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    test_screens = [
        "OFFER EXPIRES IN 00:14:32\nOnly 3 seats left!\n✓ Subscribe to newsletter\nTotal: ₹999 + GST",
        "⚠️ VIRUS DETECTED on your device! Call 1800-XXX-XXXX immediately for support.",
        "Congratulations! You've been selected as today's lucky winner. Claim your ₹10,000 prize now!",
        "Welcome back! Your account balance is ₹12,430.",
    ]

    for screen in test_screens:
        result = analyze_screen(screen)
        print(f"\nScreen: {screen[:60]}...")
        print(f"  found={result['dark_patterns_found']}  score={result['risk_score']}")
        print(f"  summary={result['summary']}")