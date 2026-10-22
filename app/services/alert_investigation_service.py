"""
Automatic Alert Investigation Service.

Runs AFTER an alert has already been created by the Rule Engine or ML
Engine. Detection and investigation are separate stages.

    DETECTION       -> something looks suspicious
    INVESTIGATION   -> gather evidence and assess seriousness
    CLASSIFICATION  -> CONFIRMED_THREAT / FALSE_POSITIVE
    RESOLUTION      -> RESOLVED

The service is idempotent through investigated_at. A completed
investigation is reused unless force=True is explicitly requested.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any

from sqlalchemy import update, func
from sqlalchemy.orm import Session
from app.graph import graph_sync_service

from app.db.postgres import SessionLocal
from app.models.alert import Alert
from app.models.log_entry import LogEntry
from app.ml.feature_engineering import build_feature_matrix
from app.ml import predict as ml_predict


logger = logging.getLogger("siem.investigation")


CORRELATION_WINDOW_HOURS = 24
CONFIRM_THRESHOLD = 75
FALSE_POSITIVE_THRESHOLD = 30


def _clamp(value: float,lo: float = 0,hi: float = 100,) -> float:
    return max(lo, min(hi, value))


def _build_result(alert: Alert) -> Dict[str, Any]:
    """
    Build an API-friendly investigation result.

    MITRE information is included because Alert exposes the
    mitre_technique relationship through properties.
    """
    return { "id": alert.id, "alert_type": alert.alert_type, "severity": alert.severity,"status": alert.status,"risk_score": alert.risk_score,"confidence": alert.confidence,

        "confidence_score": alert.confidence_score,"investigation_result": alert.investigation_result,"investigation_reason": alert.investigation_reason,"detected_by": alert.detected_by,
        "related_event_count": alert.related_event_count,"recommended_action": alert.recommended_action,"investigated_by": alert.investigated_by,"investigated_at": alert.investigated_at,

        "mitre_technique_id": alert.mitre_technique_id, "mitre_technique_name": alert.mitre_technique_name,"mitre_tactic": alert.mitre_tactic, }


def _run_ml_recheck(log: LogEntry) -> Dict[str, Any]:
    """
    Re-run the ML models on the source log as an independent
    investigation-time check.

    No training labels are used.
    """

    row = {"timestamp": log.timestamp,"severity": log.severity, "event_type": log.event_type, "raw_log": log.raw_log,}

    X = build_feature_matrix([row])

    is_anomaly, predicted_class, confidence = ml_predict.predict_batch(X)

    return {"is_anomaly": bool(is_anomaly[0]),"predicted_class": int(predicted_class[0]),"ml_confidence": float(confidence[0]),}

def _correlate(db: Session,log: LogEntry,alert: Alert,
) -> Dict[str, Any]:
    """
    Correlate recent activity from the same source IP.
    Looks at:
    - related events
    - distinct event types
    - previously confirmed threats from the same IP
    """

    if not log.ip_address or log.ip_address == "0.0.0.0":
        return {"related_event_count": 0, "distinct_event_types": 0, "prior_confirmed_threats": 0,}

    window_start = datetime.utcnow() - timedelta(
        hours=CORRELATION_WINDOW_HOURS
    )

    related_event_count = (
        db.query(func.count(LogEntry.id))
        .filter(
            LogEntry.ip_address == log.ip_address,
            LogEntry.created_at >= window_start,
            LogEntry.id != log.id,
        )
        .scalar()
        or 0
    )

    distinct_event_types = (
        db.query(func.count(func.distinct(LogEntry.event_type)))
        .filter(
            LogEntry.ip_address == log.ip_address,
            LogEntry.created_at >= window_start,
        )
        .scalar()
        or 0
    )

    prior_confirmed_threats = (
        db.query(func.count(Alert.id))
        .filter(
            Alert.ip_address == log.ip_address,
            Alert.status == "CONFIRMED_THREAT",
            Alert.id != alert.id,
        )
        .scalar()
        or 0
    )

    return {
        "related_event_count": related_event_count,
        "distinct_event_types": distinct_event_types,
        "prior_confirmed_threats": prior_confirmed_threats,
    }


def investigate_alert(
    db: Session,
    alert_id: int,
    triggered_by: str = "system",
    force: bool = False,
) -> Dict[str, Any]:
    alert = ( db.query(Alert) .filter(Alert.id == alert_id) .first())

    if not alert:
        raise ValueError(f"Alert {alert_id} not found")

    if alert.investigated_at is not None and not force:
        logger.debug(
            "Alert %s already investigated at %s — "
            "returning cached result",
            alert_id,
            alert.investigated_at,
        )
        return _build_result(alert)

    claimed = (
        db.execute(
            update(Alert)
            .where(
                Alert.id == alert_id,
                Alert.investigated_at.is_(None),
            )
            .values( status="UNDER_INVESTIGATION",))
        .rowcount
    )

    db.commit()

    if claimed == 0 and not force:
        db.refresh(alert)
        logger.debug( "Alert %s was claimed by another process — ""returning current state",alert_id, )
        return _build_result(alert)

    try:
       
        log = (
            db.query(LogEntry)
            .filter(LogEntry.id == alert.log_id)
            .first()
        )

        if not log:
            alert.status = "UNDER_INVESTIGATION"
            alert.investigation_reason = ("Source log entry could not be found — ""investigation incomplete.")
            alert.investigated_by = triggered_by
            alert.investigated_at = datetime.utcnow()
            db.commit()
            logger.warning(
                "Alert %s: log_id %s missing, "
                "cannot fully investigate",
                alert_id,
                alert.log_id,
            )

            return _build_result(alert)

        ml_result = _run_ml_recheck(log)

        correlation = _correlate(db,log, alert,)

        detected_by = (
            "ml_engine"
            if (alert.rule_name or "").startswith("ml_")
            else "rule_engine"
        )

        ml_agrees = (
            ml_result["is_anomaly"]
            or ml_result["predicted_class"] != 0
        )

        score = 0.0

        # Original detection strength
        score += 0.5 * alert.risk_score

        # Correlated activity
        score += min(
            correlation["related_event_count"],
            10,
        ) * 3

        # Independent ML confirmation
        score += 20 if ml_agrees else -15

        # Previous confirmed activity from same IP
        score += min(
            correlation["prior_confirmed_threats"],
            2,
        ) * 10

        confidence_score = _clamp(score)

        if confidence_score >= CONFIRM_THRESHOLD:
            new_status = "CONFIRMED_THREAT"

            investigation_result = ("Confirmed — corroborated by correlation and/or ML")

            recommended_action = ( "Block source IP and escalate for remediation"if alert.severity in ("critical", "high") else "Escalate to analyst for review")

        elif (
            confidence_score <= FALSE_POSITIVE_THRESHOLD
            and correlation["related_event_count"] == 0
            and not ml_agrees
        ):
            new_status = "FALSE_POSITIVE"

            investigation_result = (
                "Likely false positive — isolated event, "
                "no ML corroboration"
            )

            recommended_action = "No action needed"

        else:
            new_status = "UNDER_INVESTIGATION"

            investigation_result = (
                "Inconclusive — needs analyst review"
            )

            recommended_action = (
                "Continue monitoring; manual review recommended"
            )

        reason_parts = [
            (
                f"Detected by {detected_by} "
                f"(rule: {alert.rule_name}, "
                f"original risk score {alert.risk_score:.0f})."
            ),
            (
                f"Found {correlation['related_event_count']} "
                f"related events from {log.ip_address} "
                f"in the last {CORRELATION_WINDOW_HOURS}h "
                f"across {correlation['distinct_event_types']} "
                f"event type(s)."
            ),
            (
                f"Independent ML re-check "
                f"{'agrees' if ml_agrees else 'does not flag'} "
                f"this as suspicious "
                f"(confidence "
                f"{ml_result['ml_confidence']:.0%})."
            ),
        ]

        if correlation["prior_confirmed_threats"] > 0:
            reason_parts.append(
                f"This IP has "
                f"{correlation['prior_confirmed_threats']} "
                f"prior confirmed threat(s) on record."
            )

        alert.status = new_status
        alert.confidence_score = round(
            confidence_score,
            2,
        )
        alert.investigation_result = investigation_result
        alert.investigation_reason = " ".join(reason_parts)
        alert.detected_by = detected_by
        alert.related_event_count = (
            correlation["related_event_count"]
        )
        alert.recommended_action = recommended_action
        alert.investigated_by = triggered_by
        alert.investigated_at = datetime.utcnow()

        # If investigation itself resolves the alert, store
        # the resolution timestamp.
        if new_status == "RESOLVED":
            alert.resolved_at = datetime.utcnow()

        db.commit()
        db.refresh(alert)

        logger.debug(
            "Alert %s investigated -> %s "
            "(confidence %.1f)",
            alert_id,
            new_status,
            confidence_score,
        )
        try:
            graph_sync_service.sync_alert_to_graph(alert, log)
        except Exception:
            logger.exception(
                f"Graph sync raised unexpectedly for alert {alert_id} — investigation result unaffected"
            )


        return _build_result(alert)

    except Exception:
        db.rollback()

        logger.exception(
            "Investigation failed for alert %s",
            alert_id,
        )

        raise


def investigate_alert_background(
    alert_id: int,
) -> None:

    db = SessionLocal()

    try:
        investigate_alert(
            db,
            alert_id,
            triggered_by="system",
        )

    except Exception:
        logger.exception(
            "Background investigation crashed for alert %s",
            alert_id,
        )

    finally:
        db.close()


def investigate_alerts_batch(
    alert_ids: list[int],
) -> None:
    """
    Investigate multiple alerts sequentially.
    """

    logger.info(
        "Starting investigation batch with %s alerts",
        len(alert_ids),
    )

    for alert_id in alert_ids:
        try:
            investigate_alert_background(alert_id)

        except Exception:
            logger.exception(
                "Investigation failed for alert ID %s",
                alert_id,
            )

    logger.info(
        "Completed investigation batch with %s alerts",
        len(alert_ids),
    )