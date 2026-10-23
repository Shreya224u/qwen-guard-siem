from sqlalchemy import Column, Integer, String, DateTime, Enum, UniqueConstraint
from datetime import datetime
import enum
from app.db.base import Base


class UserRole(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("oauth_provider", "oauth_subject", name="uq_users_oauth_identity"),)

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    phone = Column(String(32), unique=True, index=True, nullable=True)
    oauth_provider = Column(String(16), nullable=True)
    oauth_subject = Column(String(128), nullable=True)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.analyst, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
