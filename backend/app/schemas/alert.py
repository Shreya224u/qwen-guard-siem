from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class AlertStatus(str, Enum):
    NEW = "NEW"
    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"
    CONFIRMED_THREAT = "CONFIRMED_THREAT"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"


class AlertAction(BaseModel):
    """Manual analyst action for changing alert lifecycle status."""
    action: AlertStatus


class InvestigateRequest(BaseModel):
    """Request to investigate an alert."""
    force: bool = False


class AlertOut(BaseModel):
    id: int
    log_id: int
    event_id: Optional[str] = None
    event_timestamp: Optional[datetime] = None
    has_event_timestamp: bool = False
    event_source: Optional[str] = None
    event_type: Optional[str] = None
    raw_log: Optional[str] = None

    # Detection Information
    alert_type: str
    rule_name: str
    severity: str
    risk_score: float
    confidence: float

    # Source Information
    ip_address: Optional[str] = None
    description: Optional[str] = None

    # Alert Lifecycle
    status: AlertStatus

    # Investigation Information
    confidence_score: Optional[float] = None
    investigation_result: Optional[str] = None
    investigation_reason: Optional[str] = None
    detected_by: Optional[str] = None
    related_event_count: Optional[int] = 0
    recommended_action: Optional[str] = None
    investigated_by: Optional[str] = None
    investigated_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None

    # Creation Timestamp
    created_at: datetime

    # MITRE ATT&CK Mapping
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_tactic: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AlertListResponse(BaseModel):
    total: int
    alerts: List[AlertOut]
