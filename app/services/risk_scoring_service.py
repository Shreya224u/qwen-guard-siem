"""
Risk Scoring — Phase 6.

This logic previously lived INLINE inside alert_investigation_service.py.
Extracted here for two reasons: (1) it matches the original architecture
doc, which specified services/risk_scoring_service.py as its own module,
and (2) it's now independently testable and tunable — you can adjust the
weights or thresholds here without touching investigation's control flow.

Nothing about the actual scoring FORMULA changed in this extraction —
same weights, same thresholds, same behavior. This is a refactor, not a
rewrite. (This matters if you're asked "did you change how alerts are
classified?" — answer is no, just where the logic lives.)
"""
from typing import Tuple

CONFIRM_THRESHOLD = 75
FALSE_POSITIVE_THRESHOLD = 30


def _clamp(value: float, lo: float = 0, hi: float = 100) -> float:
    return max(lo, min(hi, value))


def calculate_confidence_score(
    risk_score: float,
    related_event_count: int,
    ml_agrees: bool,
    prior_confirmed_threats: int,
) -> float:
    """
    Weighted combination of: original detection strength (50%), how much
    corroborating activity exists (up to +30), whether an independent ML
    pass agrees (+20/-15), and recidivism — has this IP been confirmed
    malicious before (up to +20).
    """
    score = 0.0
    score += 0.5 * risk_score
    score += min(related_event_count, 10) * 3
    score += 20 if ml_agrees else -15
    score += min(prior_confirmed_threats, 2) * 10
    return round(_clamp(score), 2)


def classify(
    confidence_score: float,
    related_event_count: int,
    ml_agrees: bool,
    severity: str,
) -> Tuple[str, str, str]:
    """Returns (status, investigation_result, recommended_action)."""
    if confidence_score >= CONFIRM_THRESHOLD:
        status = "CONFIRMED_THREAT"
        result = "Confirmed — corroborated by correlation and/or ML"
        action = (
            "Block source IP and escalate for remediation"
            if severity in ("critical", "high") else
            "Escalate to analyst for review"
        )
    elif confidence_score <= FALSE_POSITIVE_THRESHOLD and related_event_count == 0 and not ml_agrees:
        status = "FALSE_POSITIVE"
        result = "Likely false positive — isolated event, no ML corroboration"
        action = "No action needed"
    else:
        status = "UNDER_INVESTIGATION"
        result = "Inconclusive — needs analyst review"
        action = "Continue monitoring; manual review recommended"

    return status, result, action