import secrets
from datetime import datetime, timedelta

from fastapi import Request
from sqlalchemy.orm import Session

from app.config import settings
from app.core.security import create_access_token
from app.ml.models.user import User
from app.models.account_security import AccountSecurity, SecuritySession


def get_account_security(db: Session, user_id: int) -> AccountSecurity:
    security = db.query(AccountSecurity).filter_by(user_id=user_id).first()
    if security is None:
        security = AccountSecurity(user_id=user_id)
        db.add(security)
        db.flush()
    return security


def create_login_session(db: Session, user: User, request: Request) -> str:
    security = get_account_security(db, user.id)
    session_id = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    session = SecuritySession(
        id=session_id,
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:1000],
        expires_at=expires_at,
    )
    db.add(session)
    return create_access_token(
        {
            "sub": user.username,
            "role": user.role.value,
            "sid": session_id,
            "ver": security.token_version,
        },
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )


def start_login_email_challenge(db: Session, user: User) -> dict:
    from app.api.v1.auth_verification import _challenge_response, _new_challenge
    from app.models.auth_verification import AuthVerificationChallenge

    now = datetime.utcnow()
    # A login request may be repeated (for example, after a slow response).
    # Reuse a still-valid challenge instead of sending another email and
    # consuming the per-address verification request limit.
    challenge = db.query(AuthVerificationChallenge).filter_by(
        channel="login_email",
        destination=user.email,
        consumed=False,
    ).filter(
        AuthVerificationChallenge.expires_at > now,
    ).order_by(AuthVerificationChallenge.created_at.desc()).first()
    development_code = None
    if challenge is None:
        challenge, development_code = _new_challenge(db, "login_email", user.email)
    return {
        "requires_email_verification": True,
        **_challenge_response(challenge, development_code),
    }
