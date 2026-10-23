from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from app.db.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user = Column(String, nullable=False)
    action = Column(String, nullable=False)
    target = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
