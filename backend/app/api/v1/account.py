from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.api.v1.auth_verification import _challenge_response, _check_code, _new_challenge
from app.core.security import get_password_hash, verify_password
from app.ml.models.audit_log import AuditLog
from app.ml.models.user import User
from app.models.account_security import AccountSecurity, SecuritySession
from app.models.auth_verification import AuthVerificationChallenge
from app.models.oauth_identity import OAuthIdentity
from app.schemas.auth import Token
from app.services.account_security_service import create_login_session, get_account_security

router = APIRouter(prefix="/auth", tags=["Account center"])


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class EmailTwoFactorConfirmation(BaseModel):
    challenge_id: str = Field(min_length=1, max_length=64)
    code: str = Field(min_length=6, max_length=6)
    enabled: bool


class LoginEmailTwoFactorVerification(BaseModel):
    challenge_id: str = Field(min_length=1, max_length=64)
    code: str = Field(min_length=6, max_length=6)


@router.get("/account/overview")
def account_overview(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    identities = db.query(OAuthIdentity).filter_by(user_id=current_user.id).all()
    providers = {identity.provider for identity in identities}
    if current_user.oauth_provider:
        providers.add(current_user.oauth_provider)
    security = get_account_security(db, current_user.id)
    db.commit()
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "phone": current_user.phone,
        "role": current_user.role.value,
        "created_at": current_user.created_at,
        "linked_providers": sorted(providers),
        "email_two_factor_enabled": security.email_two_factor_enabled,
    }


@router.post("/account/password")
def change_password(
    payload: PasswordChange,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")

    security = get_account_security(db, current_user.id)
    security.token_version += 1
    current_user.hashed_password = get_password_hash(payload.new_password)
    db.query(SecuritySession).filter(
        SecuritySession.user_id == current_user.id,
        SecuritySession.revoked_at.is_(None),
    ).update({"revoked_at": datetime.utcnow()}, synchronize_session=False)
    token = create_login_session(db, current_user, request)
    db.add(AuditLog(user=current_user.username, action="password_change", target="account"))
    db.commit()
    return Token(access_token=token, username=current_user.username, role=current_user.role)


@router.post("/account/email-2fa/send")
def send_email_two_factor_code(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    challenge, development_code = _new_challenge(
        db, "account_email", current_user.email,
    )
    return _challenge_response(challenge, development_code)


@router.post("/account/email-2fa/confirm")
def confirm_email_two_factor(
    payload: EmailTwoFactorConfirmation,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    challenge = _check_code(
        db, "account_email", current_user.email, payload.challenge_id, payload.code,
    )
    challenge.consumed = True
    security = get_account_security(db, current_user.id)
    security.email_two_factor_enabled = payload.enabled
    db.add(AuditLog(
        user=current_user.username,
        action="email_two_factor_enabled" if payload.enabled else "email_two_factor_disabled",
        target="account",
    ))
    db.commit()
    return {"email_two_factor_enabled": security.email_two_factor_enabled}


@router.post("/login/email-2fa/verify", response_model=Token)
def verify_login_email_two_factor(
    payload: LoginEmailTwoFactorVerification,
    request: Request,
    db: Session = Depends(get_db),
):
    challenge = db.query(AuthVerificationChallenge).filter_by(
        id=payload.challenge_id,
        channel="login_email",
    ).first()
    if not challenge:
        raise HTTPException(status_code=400, detail="That sign-in code is invalid or expired.")
    user = db.query(User).filter_by(email=challenge.destination).first()
    if not user:
        raise HTTPException(status_code=400, detail="That sign-in code is invalid or expired.")
    security = db.query(AccountSecurity).filter_by(user_id=user.id).first()
    if not security or not security.email_two_factor_enabled:
        raise HTTPException(status_code=400, detail="Email two-factor authentication is no longer enabled.")
    challenge = _check_code(
        db, "login_email", user.email, payload.challenge_id, payload.code,
    )
    challenge.consumed = True
    token = create_login_session(db, user, request)
    db.add(AuditLog(user=user.username, action="login", target="email_two_factor"))
    db.commit()
    return Token(access_token=token, username=user.username, role=user.role)


@router.get("/account/sessions")
def list_account_sessions(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    now = datetime.utcnow()
    sessions = db.query(SecuritySession).filter(
        SecuritySession.user_id == current_user.id,
        SecuritySession.revoked_at.is_(None),
        SecuritySession.expires_at > now,
    ).order_by(SecuritySession.last_seen_at.desc()).all()
    current_session_id = getattr(request.state, "session_id", None)
    now = datetime.utcnow()
    for item in sessions:
        if item.id == current_session_id:
            item.last_seen_at = now
    if current_session_id:
        db.commit()
    return {
        "sessions": [
            {
                "id": item.id,
                "ip_address": item.ip_address,
                "user_agent": item.user_agent,
                "created_at": item.created_at,
                "last_seen_at": item.last_seen_at,
                "expires_at": item.expires_at,
                "current": item.id == current_session_id,
            }
            for item in sessions
        ],
        "tracking_current_session": current_session_id is not None,
    }


@router.delete("/account/sessions/{session_id}")
def revoke_account_session(
    session_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    session = db.query(SecuritySession).filter_by(
        id=session_id,
        user_id=current_user.id,
        revoked_at=None,
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="That active device session was not found.")
    session.revoked_at = datetime.utcnow()
    db.commit()
    return {"revoked": True, "current_session_revoked": session_id == getattr(request.state, "session_id", None)}


@router.post("/account/sessions/revoke-others")
def revoke_other_sessions(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    current_session_id = getattr(request.state, "session_id", None)
    query = db.query(SecuritySession).filter(
        SecuritySession.user_id == current_user.id,
        SecuritySession.revoked_at.is_(None),
    )
    if current_session_id:
        query = query.filter(SecuritySession.id != current_session_id)
    revoked_count = query.update(
        {"revoked_at": datetime.utcnow()}, synchronize_session=False,
    )
    db.commit()
    return {"revoked_count": revoked_count}


@router.post("/account/sessions/revoke-all")
def revoke_all_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    security = get_account_security(db, current_user.id)
    security.token_version += 1
    revoked_count = db.query(SecuritySession).filter(
        SecuritySession.user_id == current_user.id,
        SecuritySession.revoked_at.is_(None),
    ).update({"revoked_at": datetime.utcnow()}, synchronize_session=False)
    db.add(AuditLog(user=current_user.username, action="sessions_revoke_all", target="account"))
    db.commit()
    return {"revoked_count": revoked_count, "signed_out": True}
