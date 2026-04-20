from models.scoring import ScoringInput, ScoringResult, Action

def compute_score(input: ScoringInput) -> ScoringResult:
    score = 0
    reasons = []
    if input.fraud_db_hit:
        score += 50
        reasons.append("fraud_db_hit")

    if input.url_flagged_external:
        score += 40
        reasons.append("external_flag")

    if input.url_is_phishing:
        score += 60
        reasons.append("phishing_detected")

    if input.otp_requested:
        score += 25
        reasons.append("otp_requested")

    if input.upi_pin_requested:
        score += 30
        reasons.append("upi_pin_requested")
    
    if input.urgency_language:
        score += 25
        reasons.append("urgency_language")
    if input.otp_requested:
        score += 30
        reasons.append("high_risk_upi_pattern")

    if input.upi_copied_on_call:
        score += 20
        reasons.append("upi_on_call")

    score = min(score, 100)

    if score >= 86:
        action = Action.BLOCK
    elif score >= 66:
        action = Action.ALERT
    elif score >= 31:
        action = Action.WARN
    else:
        action = Action.SAFE

    return ScoringResult(
        score=score,
        action=action,
        reasons=reasons,
        source=input.source,
        is_blocked=(action == Action.BLOCK),
        is_alerted=(action in [Action.ALERT, Action.BLOCK]),
        auto_blocked=(score >= 90)
    )