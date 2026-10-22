from sqlalchemy import Column, Integer, String, DateTime, Enum
from datetime import datetime
import enum
from app.db.base import Base


class UserRole(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.analyst, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
