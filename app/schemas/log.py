from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict

class LogOut(BaseModel):
    id: int
    timestamp: datetime
    source: Optional[str] = None
    event_type: Optional[str] = None
    username: Optional[str] = None
    ip_address: Optional[str] = None
    device: Optional[str] = None
    severity: Optional[str] = None
    platform: Optional[str] = None
    country: Optional[str] = None
    raw_log: Optional[str] = None
    source_file: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class LogListResponse(BaseModel):
    total: int
    logs: List[LogOut]

class LogUploadResponse(BaseModel):
    message: str
    filename: str
    logs_parsed: int
    logs_failed: int
    alerts_created: int = 0
    
class LogUploadJobResponse(BaseModel):
    job_id: str
    message: str
    filename: str
    status: str