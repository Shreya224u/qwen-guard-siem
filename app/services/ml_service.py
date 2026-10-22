"""
ML Alert Service.

Bridges the ML layer (app/ml/) into the same alert format produced by
the Rule Engine.

Only logs not already detected by the Rule Engine are evaluated here,
preventing duplicate alerts.

MITRE ATT&CK mapping is resolved through the same cached mapping service
used by the Rule Engine, so ML alerts do not require a database query
for every detected log.
"""

from typing import List, Dict, Any, Set

from app.ml.feature_engineering import build_feature_matrix
from app.ml import predict as ml_predict
from app.services import mitre_mapping_service


# ---------------------------------------------------------------------------
# ML LABELS
# ---------------------------------------------------------------------------

LABELS = [
    "Normal",
    "brute_force",
    "ddos",
    "sql_injection",
    "port_scan",
]


# ---------------------------------------------------------------------------
# SCORE TO SEVERITY
# ---------------------------------------------------------------------------

def score_to_severity(score: float) -> str:
    """Convert numeric risk score into severity."""

    if score >= 85:
        return "critical"

    if score >= 65:
        return "high"

    if score >= 40:
        return "medium"

    return "low"


# ---------------------------------------------------------------------------
# BATCH ML EVALUATION
# ---------------------------------------------------------------------------

def evaluate_batch(
    rows: List[Dict[str, Any]],
    log_ids: List[int],
    skip_ids: Set[int],
) -> List[Dict[str, Any]]:
    """
    Run ML detection on an entire upload batch in one vectorized pass.

    Rule Engine alerts are skipped to prevent duplicate alerts.

    Returns:
        List of alert dictionaries compatible with the Alert model.
    """

    if not rows:
        return []

    # -----------------------------------------------------------------------
    # Step 1: Build ML Feature Matrix
    # -----------------------------------------------------------------------

    X = build_feature_matrix(rows)

    # -----------------------------------------------------------------------
    # Step 2: Run ML Prediction
    # -----------------------------------------------------------------------

    is_anomaly, predicted_class, confidence = ml_predict.predict_batch(X)

    alerts: List[Dict[str, Any]] = []

    # -----------------------------------------------------------------------
    # Step 3: Process Predictions
    # -----------------------------------------------------------------------

    for i, (row, log_id) in enumerate(zip(rows, log_ids)):

        # Rule Engine already detected this log.
        if log_id in skip_ids:
            continue

        is_anom = bool(is_anomaly[i])
        pred_class = int(predicted_class[i])

        # Normal classification and no anomaly.
        if not is_anom and pred_class == 0:
            continue

        # -------------------------------------------------------------------
        # Step 4: Resolve ML Label
        # -------------------------------------------------------------------

        label = (
            LABELS[pred_class]
            if 0 <= pred_class < len(LABELS)
            else "Unknown"
        )

        conf = float(confidence[i])

        # -------------------------------------------------------------------
        # Step 5: Calculate ML Risk Score
        # -------------------------------------------------------------------

       
        # Step 5: Calculate ML Risk Score

        # Start with the model confidence, then add a smaller
        # adjustment when Isolation Forest detects an anomaly.
        base_score = (conf * 70) + (20 if is_anom else 0)

        # Keep the score within the valid 0–100 range.
        base_score = float(round(min(max(base_score, 0), 100), 2))

        # -------------------------------------------------------------------
        # Step 6: Determine Alert Type
        # -------------------------------------------------------------------

        alert_type = (
            label
            if label != "Normal"
            else "Anomalous Behavior"
        )

        rule_name = (
            "ml_isolation_forest"
            if is_anom
            else "ml_random_forest"
        )

        # Step 7: MITRE ATT&CK Mapping
        mitre_technique_fk = (
            mitre_mapping_service.get_db_id_for_event_type(label)
        )

        # Step 8: Build Alert

        alerts.append(
            {
                "log_id": log_id,
                "alert_type": alert_type,
                "rule_name": rule_name,
                "severity": score_to_severity(base_score),
                "risk_score": base_score,
                "confidence": round(conf, 3),
                "ip_address": row.get("ip_address"),
                "description": (
                    f"ML flagged this as "
                    f"{'an anomaly' if is_anom else f'a {label} pattern'} "
                    f"(confidence {conf:.0%}) — "
                    f"not caught by signature rules."
                ),

                "mitre_technique_fk": mitre_technique_fk,
            }
        )

    return alerts