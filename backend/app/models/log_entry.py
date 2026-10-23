from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from datetime import datetime
from app.db.base import Base


class LogEntry(Base):
    __tablename__ = "log_entries"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String, index=True)          # e.g. "linux_auth", "apache", "firewall"
    event_type = Column(String, index=True)      # normalized event category
    username = Column(String, index=True)
    ip_address = Column(String, index=True)
    device = Column(String, nullable=True)
    severity = Column(String, index=True)        # critical / high / medium / low
    platform = Column(String, nullable=True)      # Linux / Windows / Apache / Nginx
    country = Column(String, nullable=True)
    raw_log = Column(Text)
    source_file = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)