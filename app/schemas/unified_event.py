from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class UnifiedEvent(BaseModel):
    timestamp: datetime
    source: str
    event_type: str
    username: Optional[str] = None
    ip_address: Optional[str] = None
    device: Optional[str] = None
    severity: str
    platform: Optional[str] = None
    country: Optional[str] = None
    raw_log: str
    source_file: Optional[str] = None

    # Network-specific fields
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    user_agent: Optional[str] = None
    url: Optional[str] = None
    is_internal_traffic: Optional[bool] = None

    # Dataset ground truth; used only during ML evaluation
    label: Optional[str] = None
    attack_type: Optional[str] = None