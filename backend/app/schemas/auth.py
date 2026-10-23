from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime
from app.ml.models.user import UserRole


class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    phone: Optional[str] = None
    email_verification_token: str
    phone_verification_token: Optional[str] = None
    role: UserRole = UserRole.analyst


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    phone: Optional[str] = None
    role: UserRole
    created_at: datetime

    class Config:
        from_attributes = True  # allows reading directly from SQLAlchemy objects


class UserRoleUpdate(BaseModel):
    role: UserRole


class AuditLogOut(BaseModel):
    id: int
    user: str
    action: str
    target: Optional[str] = None
    timestamp: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: UserRole
