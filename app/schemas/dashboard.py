from typing import List
from pydantic import BaseModel

class CountItem(BaseModel):
    name: str
    count: int

class DayCount(BaseModel):
    date: str   # "YYYY-MM-DD"
    count: int

class DashboardSummary(BaseModel):
    total_logs: int
    total_alerts: int
    threats_today: int
    critical_open_alerts: int
    confirmed_threats: int
    threat_trend: List[DayCount]       # alerts per day, last 7 days
    log_volume: List[DayCount]         # logs per day, last 7 days
    attack_types: List[CountItem]
    status_breakdown: List[CountItem]
    severity_breakdown: List[CountItem]
    top_ips: List[CountItem]
    top_countries: List[CountItem]
    generated_at: str