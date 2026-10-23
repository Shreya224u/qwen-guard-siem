from datetime import datetime, timedelta
from functools import lru_cache
from typing import Optional
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.config import settings
from app.db.postgres import get_db
from app.ml.models.user import User
from app.models.account_security import AccountSecurity, SecuritySession

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login"
    )


@lru_cache(maxsize=1)
def _password_context():
    from passlib.context import CryptContext
    return CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return _password_context().verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return _password_context().hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    from jose import jwt
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    from jose import JWTError, jwt
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        session_id = payload.get("sid")
        token_version = payload.get("ver", 0)
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    security = db.query(AccountSecurity).filter_by(user_id=user.id).first()
    if security and token_version != security.token_version:
        raise credentials_exception
    if session_id:
        active_session = db.query(SecuritySession).filter_by(
            id=session_id,
            user_id=user.id,
            revoked_at=None,
        ).filter(SecuritySession.expires_at > datetime.utcnow()).first()
        if not active_session:
            raise credentials_exception
    request.state.session_id = session_id
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user
