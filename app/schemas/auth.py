from pydantic import BaseModel, EmailStr
from datetime import datetime
from app.ml.models.user import UserRole


class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: UserRole = UserRole.analyst


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: UserRole
    created_at: datetime

    class Config:
        from_attributes = True  # allows reading directly from SQLAlchemy objects


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: UserRole