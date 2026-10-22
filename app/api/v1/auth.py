from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_user
from app.config import settings
from app.core.security import verify_password, get_password_hash, create_access_token
from app.core.redis_client import rate_limit_check
from app.ml.models.user import User
from app.ml.models.audit_log import AuditLog
from app.schemas.auth import UserRegister, UserOut, Token


router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserOut)
def register(
    payload: UserRegister,
    db: Session = Depends(get_db)
):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(
            status_code=400,
            detail="Username already taken")

    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=get_password_hash(payload.password),
        role=payload.role,
)

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


@router.post("/login", response_model=Token)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    # Redis rate limiting is optional.
    # Disabled locally when Redis is not running.

    if settings.REDIS_ENABLED:
        client_ip = request.client.host

        allowed = rate_limit_check(
            f"ratelimit:login:{client_ip}",
            max_attempts=5,
            window_seconds=900
        )

        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="Too many login attempts. Try again in 15 minutes."
            )

    # Find user in PostgreSQL
    user = db.query(User).filter(
        User.username == form_data.username
    ).first()

    # Verify password
    if not user or not verify_password(
        form_data.password,
        user.hashed_password
    ):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password"
        )

    # Create JWT token
    token = create_access_token(
        data={
            "sub": user.username,
            "role": user.role.value
        },
        expires_delta=timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        ),
    )

    # Save login audit event
    db.add(
        AuditLog(
            user=user.username,
            action="login",
            target=None
        )
    )

    db.commit()

    return Token(
        access_token=token,
        username=user.username,
        role=user.role
    )


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user