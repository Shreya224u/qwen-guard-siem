from datetime import datetime, timedelta
import ipaddress
import logging
import secrets
import smtplib
import ssl
from email.message import EmailMessage

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.api.deps import get_db, get_current_user
from app.config import settings
from app.core.security import verify_password, get_password_hash
from app.core.redis_client import rate_limit_check
from app.ml.models.user import User, UserRole
from app.ml.models.audit_log import AuditLog
from app.schemas.auth import UserRegister, UserOut, Token
from app.api.v1.auth_verification import consume_verification_token, _hash
from app.models.auth_verification import AuthVerificationChallenge
from app.models.account_security import AccountSecurity, SecuritySession
from app.services.account_security_service import create_login_session, get_account_security, start_login_email_challenge
from pydantic import BaseModel, EmailStr, Field


router = APIRouter(prefix="/auth", tags=["Authentication"])


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str = Field(min_length=20, max_length=256)
    new_password: str = Field(min_length=8, max_length=128)


def _password_reset_frontend_url(request: Request) -> str:
    configured = settings.FRONTEND_URL.rstrip("/")
    request_origin = (request.headers.get("origin") or "").rstrip("/")
    allowed_origins = {
        configured,
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
    }
    if request_origin not in allowed_origins:
        return configured
    if request_origin.startswith("http://localhost:"):
        return request_origin.replace("localhost", "127.0.0.1", 1)
    return request_origin


def _send_password_reset_email(destination: str, reset_url: str) -> None:
    sender = settings.SMTP_FROM or settings.SMTP_USERNAME
    if not settings.SMTP_HOST or not sender:
        raise HTTPException(status_code=503, detail="Password reset email is not configured. Set SMTP_HOST and SMTP_USERNAME in backend/.env.")
    message = EmailMessage()
    message["Subject"] = "Reset your SIEM-ai password"
    message["From"] = sender
    message["To"] = destination
    message.set_content(f"Use this link to reset your SIEM-ai password. It expires in 30 minutes.\n\n{reset_url}\n\nIf you did not request this, ignore this email.")
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as client:
            if settings.SMTP_USE_TLS:
                client.starttls(context=ssl.create_default_context())
            if settings.SMTP_USERNAME:
                smtp_password = settings.SMTP_PASSWORD
                if "gmail.com" in settings.SMTP_HOST.lower():
                    smtp_password = "".join(smtp_password.split())
                client.login(settings.SMTP_USERNAME, smtp_password)
            client.send_message(message)
    except smtplib.SMTPAuthenticationError as error:
        logging.getLogger("siem.auth").exception("SMTP rejected password-reset authentication")
        raise HTTPException(status_code=502, detail="SMTP authentication was rejected. Check SMTP_USERNAME and use your provider's App Password in SMTP_PASSWORD.") from error
    except smtplib.SMTPServerDisconnected as error:
        logging.getLogger("siem.auth").exception("SMTP server disconnected during password-reset delivery")
        raise HTTPException(status_code=502, detail="SMTP closed the connection during authentication. Check the account's SMTP access and SMTP credentials.") from error
    except Exception as error:
        logging.getLogger("siem.auth").exception("Password-reset email delivery failed")
        raise HTTPException(status_code=502, detail="The email provider could not send the password reset link. Check the SMTP settings.") from error


@router.post("/password-reset/request")
def request_password_reset(payload: PasswordResetRequest, request: Request, db: Session = Depends(get_db)):
    email = str(payload.email).strip().lower()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return {"message": "If an account exists for that email, a password reset link has been sent."}
    now = datetime.utcnow()
    recent = db.query(AuthVerificationChallenge).filter(
        AuthVerificationChallenge.channel == "reset",
        AuthVerificationChallenge.destination == email,
        AuthVerificationChallenge.created_at >= now - timedelta(minutes=15),
    ).count()
    if recent >= 3:
        raise HTTPException(status_code=429, detail="Too many reset requests. Try again in 15 minutes.")
    reset_token = secrets.token_urlsafe(32)
    challenge = AuthVerificationChallenge(
        id=secrets.token_hex(16), channel="reset", destination=email,
        code_hash=_hash(reset_token), verification_token_hash=_hash(reset_token),
        verified_at=now, expires_at=now + timedelta(minutes=30),
    )
    db.add(challenge)
    db.commit()
    reset_url = f"{_password_reset_frontend_url(request)}/?reset_token={reset_token}"
    try:
        _send_password_reset_email(email, reset_url)
    except HTTPException:
        client_host = request.client.host if request.client else ""
        try:
            local_request = ipaddress.ip_address(client_host).is_loopback
        except ValueError:
            local_request = False
        if settings.PASSWORD_RESET_LOCAL_LINK_ENABLED and local_request:
            logging.getLogger("siem.auth").warning("SMTP unavailable; returning a local-only password reset link")
            return {
                "message": "Email delivery is unavailable in local development. Use the reset link below.",
                "delivery_mode": "development",
                "development_reset_url": reset_url,
            }
        db.delete(challenge)
        db.commit()
        raise
    return {"message": "If an account exists for that email, a password reset link has been sent."}


@router.post("/password-reset/confirm")
def confirm_password_reset(payload: PasswordResetConfirm, request: Request, db: Session = Depends(get_db)):
    token_hash = _hash(payload.token)
    now = datetime.utcnow()
    challenge = db.query(AuthVerificationChallenge).filter_by(
        channel="reset", verification_token_hash=token_hash, consumed=False,
    ).filter(AuthVerificationChallenge.expires_at > now).with_for_update().first()
    if not challenge:
        raise HTTPException(status_code=400, detail="This password reset link is invalid or expired. Request a new one.")
    user = db.query(User).filter(User.email == challenge.destination).first()
    if not user:
        challenge.consumed = True
        db.commit()
        raise HTTPException(status_code=400, detail="This password reset link is invalid or expired. Request a new one.")
    user.hashed_password = get_password_hash(payload.new_password)
    challenge.consumed = True
    security = get_account_security(db, user.id)
    security.token_version += 1
    db.query(SecuritySession).filter(
        SecuritySession.user_id == user.id,
        SecuritySession.revoked_at.is_(None),
    ).update({"revoked_at": datetime.utcnow()}, synchronize_session=False)
    if security.email_two_factor_enabled:
        access_token = None
    else:
        access_token = create_login_session(db, user, request)
    db.commit()
    if not access_token:
        return {
            "message": "Password reset successfully. Sign in with your new password and email verification code.",
            "username": user.username,
            "role": user.role,
        }
    return {
        "message": "Password reset successfully. Signing you in.",
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username,
        "role": user.role,
    }


@router.post("/register", response_model=UserOut)
def register(
    payload: UserRegister,
    db: Session = Depends(get_db)
):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(
            status_code=400,
            detail="Username already taken")

    email = str(payload.email).strip().lower()
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    phone = None
    if payload.phone and payload.phone.strip():
        phone = "".join(character for character in payload.phone if character not in " ()-.")
        if not phone.startswith("+") or not phone[1:].isdigit() or not 8 <= len(phone[1:]) <= 15:
            raise HTTPException(status_code=422, detail="Enter a valid mobile number with country code.")
        if db.query(User).filter(User.phone == phone).first():
            raise HTTPException(status_code=400, detail="Mobile number already registered")
        if not payload.phone_verification_token:
            raise HTTPException(status_code=400, detail="Verify the mobile number or leave it blank to register with email only.")
    consume_verification_token(db, "email", email, payload.email_verification_token)
    if phone:
        consume_verification_token(db, "phone", phone, payload.phone_verification_token)
    user = User(
        username=payload.username,
        email=email,
        phone=phone,
        hashed_password=get_password_hash(payload.password),
        role=UserRole.analyst,
    )

    db.add(user)
    db.add(AuditLog(user=payload.username, action="account_registered"))
    db.commit()
    db.refresh(user)

    return user


@router.post("/login")
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
        or_(User.username == form_data.username, User.email == form_data.username.strip().lower())
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

    token = create_login_session(db, user, request)

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
