"""
Rule Engine — Phase 4.

Detects signature-based threats and threshold/correlation-based attacks.

Supports:
    - Single-log evaluation
    - High-performance batch evaluation
    - Redis pipeline-based threshold correlation
    - MITRE ATT&CK mapping

The batch API is used by the log-upload pipeline so large log files
can be processed efficiently.
"""

from typing import Optional, Dict, Any, List, Tuple

from app.core.redis_client import ( increment_and_get_count, increment_and_get_counts_batch,)
from app.services import mitre_mapping_service

# SIGNATURE RULES
SIGNATURE_RULES: Dict[str, Dict[str, Any]] = {
    "brute_force": {
        "alert_type": "Brute Force Attempt",
        "base_score": 70,
        "confidence": 0.75,
    },
    "sql_injection": {
        "alert_type": "SQL Injection Attempt",
        "base_score": 80,
        "confidence": 0.85,
    },
    "port_scan": {
        "alert_type": "Port Scan Detected",
        "base_score": 55,
        "confidence": 0.70,
    },
    "ddos": {
        "alert_type": "DDoS Activity",
        "base_score": 90,
        "confidence": 0.80,
    },
    "malware": {
        "alert_type": "Malware Signature",
        "base_score": 95,
        "confidence": 0.90,
    },
    "unauthorized_access": {
        "alert_type": "Unauthorized Access",
        "base_score": 75,
        "confidence": 0.75,
    },
    "powershell_activity": {
        "alert_type": "Suspicious PowerShell Activity",
        "base_score": 65,
        "confidence": 0.70,
    },
    "process_creation": {
        "alert_type": "Suspicious Process Creation",
        "base_score": 60,
        "confidence": 0.60,
    },
}

# THRESHOLD / CORRELATION RULES

THRESHOLD_RULES: Dict[str, Dict[str, Any]] = {
    "brute_force": {
        "count": 5,
        "window_seconds": 300,
        "escalated_score": 95,
    },
    "port_scan": {
        "count": 10,
        "window_seconds": 120,
        "escalated_score": 85,
    },
}

# SCORE TO SEVERITY

def score_to_severity(score: float) -> str:
    """Convert numeric risk score into severity."""

    if score >= 85:
        return "critical"

    if score >= 65:
        return "high"

    if score >= 40:
        return "medium"

    return "low"

# ALERT BUILDER

def _build_alert(
    normalized: Dict[str, Any],
    log_id: int,
    *,
    base_score: float,
    confidence: float,
    rule_name: str,
    description: str,
) -> Dict[str, Any]:
    """
    Build the common alert structure.

    MITRE mapping is resolved through the in-memory cache.
    """

    event_type = normalized.get("event_type")
    ip = normalized.get("ip_address")

    signature = SIGNATURE_RULES[event_type]

    mitre_technique_fk = (
        mitre_mapping_service.get_db_id_for_event_type(
            event_type
        )
    )

    return {
        "log_id": log_id,
        "alert_type": signature["alert_type"],
        "rule_name": rule_name,
        "severity": score_to_severity(base_score),
        "risk_score": float(base_score),
        "confidence": float(confidence),
        "ip_address": ip,
        "description": description,
        "mitre_technique_fk": mitre_technique_fk,
    }

# SINGLE LOG EVALUATION

def evaluate(
    normalized: Dict[str, Any],
    log_id: int,
) -> Optional[Dict[str, Any]]:
    """
    Evaluate one normalized log entry.

    Used for individual log processing and testing.
    """

    event_type = normalized.get("event_type")

    signature = SIGNATURE_RULES.get(event_type)

    if not signature:
        return None

    ip = normalized.get("ip_address")

    base_score = signature["base_score"]
    confidence = signature["confidence"]

    rule_name = "signature_match"

    description = (
        f"Detected '{event_type}' pattern from {ip} "
        f"via signature matching."
    )

    threshold_rule = THRESHOLD_RULES.get(event_type)

    if (
        threshold_rule
        and ip
        and ip != "0.0.0.0"
    ):
        redis_key = f"corr:{event_type}:{ip}"

        count = increment_and_get_count(
            redis_key,
            threshold_rule["window_seconds"],
        )

        if count >= threshold_rule["count"]:
            base_score = threshold_rule["escalated_score"]

            confidence = min(
                confidence + 0.15,
                0.99,
            )

            rule_name = "threshold_correlation"

            description = (
                f"{count} '{event_type}' events from {ip} within "
                f"{threshold_rule['window_seconds']} seconds — "
                f"pattern confirmed, not a one-off."
            )

    return _build_alert(
        normalized,
        log_id,
        base_score=base_score,
        confidence=confidence,
        rule_name=rule_name,
        description=description,
    )


# ---------------------------------------------------------------------------
# BATCH EVALUATION
# ---------------------------------------------------------------------------

def evaluate_batch(
    rows: List[Dict[str, Any]],
    log_ids: List[int],
) -> List[Dict[str, Any]]:
    """
    Evaluate a batch of normalized logs.

    Performance design:

        1. Signature matching happens in memory.
        2. MITRE mapping uses the in-memory cache.
        3. Threshold counters are collected first.
        4. Redis counters are incremented through ONE pipeline.
        5. Alerts are constructed after Redis results are available.
        6. No PostgreSQL query is performed per log.

    This is substantially more efficient than calling evaluate()
    for every log because threshold correlation no longer requires
    a separate Redis network round trip for every event.
    """

    if not rows:
        return []

    if len(rows) != len(log_ids):
        raise ValueError(
            "rows and log_ids must contain the same number of items"
        )

    alerts: List[Dict[str, Any]] = []

    # -----------------------------------------------------------------------
    # STEP 1
    # Find signature matches and prepare Redis operations.
    # -----------------------------------------------------------------------

    matched_rows: List[
        Tuple[
            Dict[str, Any],
            int,
            Dict[str, Any],
            Optional[str],
        ]
    ] = []

    redis_items: List[Tuple[str, int]] = []

    for row, log_id in zip(rows, log_ids):

        event_type = row.get("event_type")

        signature = SIGNATURE_RULES.get(event_type)

        if not signature:
            continue

        ip = row.get("ip_address")

        redis_key = None

        threshold_rule = THRESHOLD_RULES.get(event_type)

        if (
            threshold_rule
            and ip
            and ip != "0.0.0.0"
        ):
            redis_key = f"corr:{event_type}:{ip}"

            redis_items.append(
                (
                    redis_key,
                    threshold_rule["window_seconds"],
                )
            )

        matched_rows.append(
            (
                row,
                log_id,
                signature,
                redis_key,
            )
        )

    if not matched_rows:
        return []

    # -----------------------------------------------------------------------
    # STEP 2
    # Batch Redis correlation.
    # -----------------------------------------------------------------------

    redis_counts = {}

    if redis_items:
        redis_counts = increment_and_get_counts_batch(
            redis_items
        )

    # -----------------------------------------------------------------------
    # STEP 3
    # Build alerts.
    # -----------------------------------------------------------------------

    for (
        row,
        log_id,
        signature,
        redis_key,
    ) in matched_rows:

        event_type = row.get("event_type")
        ip = row.get("ip_address")

        base_score = signature["base_score"]
        confidence = signature["confidence"]

        rule_name = "signature_match"

        description = (
            f"Detected '{event_type}' pattern from {ip} "
            f"via signature matching."
        )

        threshold_rule = THRESHOLD_RULES.get(event_type)

        if (
            threshold_rule
            and redis_key
        ):
            count = redis_counts.get(
                redis_key,
                0,
            )

            if count >= threshold_rule["count"]:

                base_score = threshold_rule["escalated_score"]

                confidence = min(
                    confidence + 0.15,
                    0.99,
                )

                rule_name = "threshold_correlation"

                description = (
                    f"{count} '{event_type}' events from {ip} within "
                    f"{threshold_rule['window_seconds']} seconds — "
                    f"pattern confirmed, not a one-off."
                )

        alerts.append(
            _build_alert(
                row,
                log_id,
                base_score=base_score,
                confidence=confidence,
                rule_name=rule_name,
                description=description,
            )
        )

    return alerts