from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional
import re

from app.api.deps import get_db, get_current_user
from app.models.alert import Alert
from app.models.log_entry import LogEntry
from app.ml.models.audit_log import AuditLog
from app.ml.models.user import User
from app.schemas.alert import AlertListResponse, AlertAction, AlertOut, AlertStatus
from app.services.log_parser_service import parse_source_timestamp

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=AlertListResponse)
def get_alerts(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    alert_id: Optional[int] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    source_file: Optional[str] = Query(default=None, min_length=1),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = (
        db.query(Alert)
        .join(LogEntry, Alert.log_id == LogEntry.id)
        .filter(LogEntry.user_id == current_user.id)
    )

    if alert_id is not None:
        query = query.filter(Alert.id == alert_id)

    if severity:
        query = query.filter(Alert.severity == severity)

    if status:
        query = query.filter(Alert.status == status)

    if source_file:
        query = query.filter(LogEntry.source_file == source_file)

    total = query.count()

    rows = (
        query
        .with_entities(
            Alert,
            LogEntry.timestamp.label("event_timestamp"),
            LogEntry.source.label("event_source"),
            LogEntry.event_type.label("event_type"),
            LogEntry.id.label("event_id"),
            LogEntry.raw_log.label("event_raw_log"),
        )
        .order_by(Alert.created_at.desc(), Alert.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    alerts = []
    for alert, event_timestamp, event_source, event_type, log_id, event_raw_log in rows:
        source_timestamp = parse_source_timestamp(event_raw_log or "")
        alerts.append({
            **AlertOut.model_validate(alert).model_dump(),
            "event_id": f"EVT-{log_id}",
            # Only expose an event timestamp when it was actually present in
            # the original log; never mistake the parser's ingestion fallback
            # for source event time.
            "event_timestamp": source_timestamp,
            "has_event_timestamp": source_timestamp is not None,
            "event_source": (
                re.search(
                    r"(?:^|\s)(?:source_name|channel)=([^\r\n]*?)(?=\s+[A-Za-z_][A-Za-z0-9_]*=|$)",
                    event_raw_log or "",
                    re.IGNORECASE,
                ).group(1).strip()
                if event_source and event_source.lower() in {"windows", "unknown"}
                and re.search(
                    r"(?:^|\s)(?:source_name|channel)=([^\r\n]*?)(?=\s+[A-Za-z_][A-Za-z0-9_]*=|$)",
                    event_raw_log or "",
                    re.IGNORECASE,
                )
                else event_source
            ),
            "event_type": event_type,
            "raw_log": event_raw_log,
        })

    return AlertListResponse(
        total=total,
        alerts=alerts
    )


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert_by_id(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    alert = (
        db.query(Alert)
        .join(LogEntry, Alert.log_id == LogEntry.id)
        .filter(Alert.id == alert_id, LogEntry.user_id == current_user.id)
        .first()
    )

    if not alert:
        raise HTTPException(
            status_code=404,
            detail=f"Alert with ID {alert_id} not found"
        )

    return alert


@router.post("/{alert_id}/investigate", response_model=AlertOut)
def investigate_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    alert = (
        db.query(Alert)
        .join(LogEntry, Alert.log_id == LogEntry.id)
        .filter(Alert.id == alert_id, LogEntry.user_id == current_user.id)
        .first()
    )

    if not alert:
        raise HTTPException(
            status_code=404,
            detail=f"Alert with ID {alert_id} not found"
        )

    # Prevent duplicate investigation
    if alert.status == AlertStatus.UNDER_INVESTIGATION.value:
        raise HTTPException(
            status_code=409,
            detail="Alert is already under investigation"
        )

    if alert.status == AlertStatus.RESOLVED.value:
        raise HTTPException(
            status_code=400,
            detail="Resolved alerts cannot be investigated again"
        )

    # Mark alert as under investigation
    alert.status = AlertStatus.UNDER_INVESTIGATION.value
    alert.investigated_by = current_user.username

    # Audit log
    audit_log = AuditLog(
        user=current_user.username,
        action="alert_investigation_started",
        target=f"alert:{alert_id}"
    )

    db.add(audit_log)
    db.commit()
    db.refresh(alert)

    return alert


@router.put("/{alert_id}/action")
def take_action(
    alert_id: int,
    payload: AlertAction,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    alert = (
        db.query(Alert)
        .join(LogEntry, Alert.log_id == LogEntry.id)
        .filter(Alert.id == alert_id, LogEntry.user_id == current_user.id)
        .first()
    )

    if not alert:
        raise HTTPException(
            status_code=404,
            detail=f"Alert with ID {alert_id} not found"
        )

    new_status = payload.action.value

    # Validate lifecycle transitions
    if alert.status == AlertStatus.RESOLVED.value:
        raise HTTPException(
            status_code=400,
            detail="Resolved alerts cannot be modified"
        )

    # Update alert status
    alert.status = new_status

    # Store investigator information
    if new_status in [
        AlertStatus.CONFIRMED_THREAT.value,
        AlertStatus.FALSE_POSITIVE.value,
        AlertStatus.RESOLVED.value,
    ]:
        alert.investigated_by = current_user.username

    # Store resolution timestamp
    if new_status == AlertStatus.RESOLVED.value:
        from datetime import datetime, timezone
        alert.resolved_at = datetime.now(timezone.utc)

    # Create audit log entry
    audit_log = AuditLog(
        user=current_user.username,
        action=f"alert_{new_status.lower()}",
        target=f"alert:{alert_id}"
    )

    db.add(audit_log)

    db.commit()
    db.refresh(alert)

    return {
        "message": f"Alert marked as {new_status}",
        "alert_id": alert.id,
        "status": alert.status
    }
