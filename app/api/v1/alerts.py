from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional

from app.api.deps import get_db, get_current_user
from app.models.alert import Alert
from app.ml.models.audit_log import AuditLog
from app.ml.models.user import User
from app.schemas.alert import AlertListResponse, AlertAction, AlertOut, AlertStatus

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=AlertListResponse)
def get_alerts(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    alert_id: Optional[int] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Alert)

    if alert_id is not None:
        query = query.filter(Alert.id == alert_id)

    if severity:
        query = query.filter(Alert.severity == severity)

    if status:
        query = query.filter(Alert.status == status)

    total = query.count()

    alerts = (
        query
        .order_by(Alert.created_at.desc(), Alert.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

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
        .filter(Alert.id == alert_id)
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
        .filter(Alert.id == alert_id)
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
        .filter(Alert.id == alert_id)
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
