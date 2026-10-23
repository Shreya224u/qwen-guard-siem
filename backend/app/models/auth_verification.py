from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, Integer, String
from app.db.base import Base


class AuthVerificationChallenge(Base):
    __tablename__ = "auth_verification_challenges"

    id = Column(String(64), primary_key=True)
    channel = Column(String(16), nullable=False, index=True)
    destination = Column(String(320), nullable=False, index=True)
    code_hash = Column(String(64), nullable=False)
    verification_token_hash = Column(String(64), nullable=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    attempts = Column(Integer, nullable=False, default=0)
    verified_at = Column(DateTime, nullable=True)
    consumed = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
