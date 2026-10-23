import hashlib
import hmac
import json
import logging
import secrets
import smtplib
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from email.message import EmailMessage
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from fastapi import Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.config import settings
from app.ml.models.user import User
from app.ml.models.audit_log import AuditLog
from app.models.auth_verification import AuthVerificationChallenge
from app.schemas.auth import Token
from app.models.account_security import AccountSecurity
from app.services.account_security_service import create_login_session, start_login_email_challenge

router = APIRouter(prefix="/auth", tags=["Authentication verification"])
OTP_TTL = 300
MAX_ATTEMPTS = 5


class EmailSend(BaseModel):
    email: EmailStr


class PhoneSend(BaseModel):
    phone: str = Field(min_length=8, max_length=32)


class EmailVerify(EmailSend):
    code: str = Field(min_length=6, max_length=6)
    challenge_id: str


class PhoneVerify(PhoneSend):
    code: str = Field(min_length=6, max_length=6)
    challenge_id: str


def _phone(value: str) -> str:
    normalized = "".join(character for character in value if character not in " ()-.")
    if not normalized.startswith("+") or not normalized[1:].isdigit() or not 8 <= len(normalized[1:]) <= 15:
        raise HTTPException(status_code=422, detail="Enter a valid mobile number with country code.")
    return normalized


def _hash(value: str) -> str:
    return hmac.new(settings.SECRET_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()


def _deliver_email(destination: str, code: str) -> None:
    host = settings.SMTP_HOST
    sender = settings.SMTP_FROM
    if not host or not sender:
        raise HTTPException(status_code=503, detail="Email verification is not configured on the backend.")
    message = EmailMessage()
    message["Subject"] = "Your SIEM verification code"
    message["From"] = sender
    message["To"] = destination
    message.set_content(f"Your SIEM verification code is {code}. It expires in 5 minutes.")
    try:
        with smtplib.SMTP(host, settings.SMTP_PORT, timeout=15) as client:
            if settings.SMTP_USE_TLS:
                client.starttls(context=ssl.create_default_context())
            username = settings.SMTP_USERNAME
            if username:
                smtp_password = settings.SMTP_PASSWORD
                if "gmail.com" in host.lower():
                    smtp_password = "".join(smtp_password.split())
                client.login(username, smtp_password)
            client.send_message(message)
    except Exception as error:
        logging.getLogger("siem.auth").exception("Email verification delivery failed")
        if isinstance(error, smtplib.SMTPRecipientsRefused):
            detail = "Your email provider rejected this recipient. Check the email address and provider sending restrictions."
        elif isinstance(error, smtplib.SMTPSenderRefused):
            detail = "Your email provider rejected SMTP_FROM. Set it to the authenticated SMTP account address."
        elif isinstance(error, smtplib.SMTPAuthenticationError):
            detail = "Your email provider rejected SMTP authentication. Check the SMTP app password."
        elif isinstance(error, smtplib.SMTPResponseException):
            detail = f"Your email provider rejected the verification email (SMTP {error.smtp_code}). Check sender permissions, recipient policy, and sending quota."
        elif isinstance(error, (TimeoutError, OSError, smtplib.SMTPServerDisconnected)):
            detail = "Could not connect to the email provider. Check SMTP host, port, TLS, and network access."
        else:
            detail = f"Email verification delivery failed ({type(error).__name__}). Check the backend SMTP settings."
        raise HTTPException(status_code=502, detail=detail) from error


def _deliver_sms(destination: str, code: str) -> None:
    account = settings.TWILIO_ACCOUNT_SID
    token = settings.TWILIO_AUTH_TOKEN
    sender = settings.TWILIO_FROM_NUMBER
    if not account or not token or not sender:
        raise HTTPException(status_code=503, detail="Mobile verification is not configured on the backend.")
    body = urllib.parse.urlencode({"To": destination, "From": sender, "Body": f"Your SIEM verification code is {code}. It expires in 5 minutes."}).encode()
    request = urllib.request.Request(
        f"https://api.twilio.com/2010-04-01/Accounts/{account}/Messages.json",
        data=body,
        headers={"Authorization": "Basic " + __import__("base64").b64encode(f"{account}:{token}".encode()).decode()},
    )
    try:
        with urllib.request.urlopen(request, timeout=15):
            pass
    except urllib.error.HTTPError as error:
        try:
            provider_error = json.loads(error.read().decode("utf-8"))
            provider_code = provider_error.get("code")
            provider_message = provider_error.get("message")
        except (UnicodeDecodeError, json.JSONDecodeError):
            provider_code = None
            provider_message = None
        detail = "The mobile provider could not send the verification code."
        if provider_message:
            code_text = f" (Twilio {provider_code})" if provider_code else ""
            detail = f"Twilio rejected the SMS{code_text}: {provider_message}"
        raise HTTPException(status_code=502, detail=detail) from error
    except urllib.error.URLError as error:
        reason = str(error.reason)
        detail = "Could not connect to the mobile provider. Check backend network access."
        if reason:
            detail = f"{detail} ({reason[:160]})"
        raise HTTPException(status_code=502, detail=detail) from error


def _twilio_verify_request(resource: str, values: dict[str, str]) -> dict:
    account = settings.TWILIO_ACCOUNT_SID
    token = settings.TWILIO_AUTH_TOKEN
    service_sid = settings.TWILIO_VERIFY_SERVICE_SID
    if not account or not token or not service_sid:
        raise HTTPException(status_code=503, detail="Twilio Verify is not configured on the backend.")
    auth = __import__("base64").b64encode(f"{account}:{token}".encode()).decode()
    request = urllib.request.Request(
        f"https://verify.twilio.com/v2/Services/{service_sid}/{resource}",
        data=urllib.parse.urlencode(values).encode(),
        headers={"Authorization": "Basic " + auth},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        try:
            provider_error = json.loads(error.read().decode("utf-8"))
            provider_code = provider_error.get("code")
            provider_message = provider_error.get("message")
        except (UnicodeDecodeError, json.JSONDecodeError):
            provider_code = None
            provider_message = None
        detail = "Twilio Verify could not process the verification request."
        if provider_message:
            code_text = f" (Twilio {provider_code})" if provider_code else ""
            detail = f"Twilio Verify rejected the request{code_text}: {provider_message}"
        raise HTTPException(status_code=502, detail=detail) from error
    except urllib.error.URLError as error:
        raise HTTPException(
            status_code=502,
            detail=f"Could not connect to Twilio Verify: {str(error.reason)[:160]}",
        ) from error


def _start_twilio_verification(destination: str) -> None:
    _twilio_verify_request("Verifications", {"To": destination, "Channel": "sms"})


def _check_twilio_verification(destination: str, code: str) -> bool:
    result = _twilio_verify_request("VerificationCheck", {"To": destination, "Code": code})
    return result.get("status") == "approved" and result.get("valid") is True


def _new_challenge(db: Session, channel: str, destination: str):
    now = datetime.utcnow()
    recent = db.query(AuthVerificationChallenge).filter(
        AuthVerificationChallenge.channel == channel,
        AuthVerificationChallenge.destination == destination,
        AuthVerificationChallenge.created_at >= now - timedelta(minutes=15),
    ).count()
    if recent >= 3:
        raise HTTPException(status_code=429, detail="Too many code requests. Try again in 15 minutes.")
    challenge_id = uuid4().hex
    code = f"{secrets.randbelow(1_000_000):06d}"
    development_code = None
    if channel in ("email", "account_email", "login_email"):
        if settings.SMTP_HOST and settings.SMTP_FROM:
            _deliver_email(destination, code)
        elif settings.AUTH_OTP_DEV_MODE:
            development_code = code
        else:
            _deliver_email(destination, code)
    elif settings.TWILIO_VERIFY_SERVICE_SID:
        _start_twilio_verification(destination)
        code = "provider-managed"
    elif settings.TWILIO_ACCOUNT_SID and settings.TWILIO_AUTH_TOKEN and settings.TWILIO_FROM_NUMBER:
        _deliver_sms(destination, code)
    elif settings.AUTH_OTP_DEV_MODE:
        development_code = code
    else:
        _deliver_sms(destination, code)
    challenge = AuthVerificationChallenge(
        id=challenge_id,
        channel=channel,
        destination=destination,
        code_hash=_hash(f"{challenge_id}:{code}"),
        expires_at=now + timedelta(seconds=OTP_TTL),
    )
    db.add(challenge)
    db.commit()
    return challenge, development_code


def _challenge_response(challenge: AuthVerificationChallenge, development_code: str | None):
    response = {"challenge_id": challenge.id, "expires_in_seconds": OTP_TTL}
    if development_code:
        response.update({"delivery_mode": "development", "development_code": development_code})
    else:
        response["delivery_mode"] = "provider"
    return response


def _check_code(db: Session, channel: str, destination: str, challenge_id: str, code: str) -> AuthVerificationChallenge:
    challenge = db.query(AuthVerificationChallenge).filter_by(
        id=challenge_id, channel=channel, destination=destination,
    ).with_for_update().first()
    if not challenge or challenge.consumed or challenge.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="That code has expired. Request a new one.")
    if challenge.attempts >= MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many incorrect codes. Request a new one.")
    challenge.attempts += 1
    if not hmac.compare_digest(challenge.code_hash, _hash(f"{challenge_id}:{code}")):
        db.commit()
        raise HTTPException(status_code=400, detail="That verification code is incorrect.")
    return challenge


def _check_phone_code(db: Session, destination: str, challenge_id: str, code: str) -> AuthVerificationChallenge:
    if not settings.TWILIO_VERIFY_SERVICE_SID:
        return _check_code(db, "phone", destination, challenge_id, code)
    challenge = db.query(AuthVerificationChallenge).filter_by(
        id=challenge_id, channel="phone", destination=destination,
    ).with_for_update().first()
    if not challenge or challenge.consumed or challenge.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="That code has expired. Request a new one.")
    if challenge.attempts >= MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many incorrect codes. Request a new one.")
    challenge.attempts += 1
    db.commit()
    if not _check_twilio_verification(destination, code):
        raise HTTPException(status_code=400, detail="That verification code is incorrect or expired.")
    return challenge


def consume_verification_token(db: Session, channel: str, destination: str, token: str) -> None:
    challenge = db.query(AuthVerificationChallenge).filter_by(
        channel=channel,
        destination=destination,
        verification_token_hash=_hash(token),
        consumed=False,
    ).filter(
        AuthVerificationChallenge.verified_at.is_not(None),
        AuthVerificationChallenge.expires_at > datetime.utcnow(),
    ).with_for_update().first()
    if not challenge:
        raise HTTPException(status_code=400, detail=f"Verify your {channel} before creating the account.")
    challenge.consumed = True


@router.post("/verification/email/send")
def send_email_code(payload: EmailSend, db: Session = Depends(get_db)):
    destination = str(payload.email).strip().lower()
    challenge, development_code = _new_challenge(db, "email", destination)
    return _challenge_response(challenge, development_code)


@router.post("/verification/phone/send")
def send_phone_code(payload: PhoneSend, db: Session = Depends(get_db)):
    challenge, development_code = _new_challenge(db, "phone", _phone(payload.phone))
    return _challenge_response(challenge, development_code)


@router.post("/verification/email/verify")
def verify_email_code(payload: EmailVerify, db: Session = Depends(get_db)):
    destination = str(payload.email).strip().lower()
    challenge = _check_code(db, "email", destination, payload.challenge_id, payload.code)
    verification_token = secrets.token_urlsafe(32)
    challenge.verification_token_hash = _hash(verification_token)
    challenge.verified_at = datetime.utcnow()
    db.commit()
    return {"verification_token": verification_token}


@router.post("/verification/phone/verify")
def verify_phone_code(payload: PhoneVerify, db: Session = Depends(get_db)):
    destination = _phone(payload.phone)
    challenge = _check_phone_code(db, destination, payload.challenge_id, payload.code)
    verification_token = secrets.token_urlsafe(32)
    challenge.verification_token_hash = _hash(verification_token)
    challenge.verified_at = datetime.utcnow()
    db.commit()
    return {"verification_token": verification_token}


@router.post("/phone/login")
def phone_login(payload: PhoneVerify, request: Request, db: Session = Depends(get_db)):
    destination = _phone(payload.phone)
    challenge = _check_phone_code(db, destination, payload.challenge_id, payload.code)
    challenge.consumed = True
    user = db.query(User).filter(User.phone == destination).first()
    if not user:
        db.commit()
        raise HTTPException(status_code=401, detail="No account is registered with that mobile number.")
    challenge.consumed = True
    security = db.query(AccountSecurity).filter_by(user_id=user.id).first()
    if security and security.email_two_factor_enabled:
        return start_login_email_challenge(db, user)
    token = create_login_session(db, user, request)
    db.add(AuditLog(user=user.username, action="login", target="phone"))
    db.commit()
    return Token(access_token=token, username=user.username, role=user.role)
