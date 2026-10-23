import json
import logging
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.config import settings
from app.core.security import get_password_hash
from app.ml.models.user import User, UserRole
from app.ml.models.audit_log import AuditLog
from app.models.oauth_state import OAuthLinkState, OAuthState
from app.models.oauth_identity import OAuthIdentity
from app.models.account_security import AccountSecurity
from app.services.account_security_service import create_login_session, start_login_email_challenge
from app.ml.models.user import User

router = APIRouter(prefix="/auth/oauth", tags=["OAuth sign-in"] )
logger = logging.getLogger(__name__)
STATE_TTL = 600


def _frontend_url(origin: str | None = None) -> str:
    configured = settings.FRONTEND_URL.rstrip("/")
    if not origin:
        return configured
    try:
        candidate = urllib.parse.urlsplit(origin)
        port = candidate.port
    except ValueError:
        return configured
    if candidate.path or candidate.query or candidate.fragment or candidate.username or candidate.password:
        return configured
    if candidate.scheme == "http" and candidate.hostname in {"localhost", "127.0.0.1"} and port in {3000, 5173, 5174}:
        return origin.rstrip("/")
    if origin.rstrip("/") == configured:
        return configured
    return configured


def _settings(provider):
    if provider == "google":
        values = (settings.OAUTH_GOOGLE_CLIENT_ID, settings.OAUTH_GOOGLE_CLIENT_SECRET, settings.OAUTH_GOOGLE_REDIRECT_URI)
    elif provider == "github":
        values = (settings.OAUTH_GITHUB_CLIENT_ID, settings.OAUTH_GITHUB_CLIENT_SECRET, settings.OAUTH_GITHUB_REDIRECT_URI)
    else:
        raise HTTPException(status_code=404, detail="OAuth provider not supported.")
    if not all(values):
        raise HTTPException(status_code=503, detail=f"{provider.title()} sign-in is not configured on the backend.")
    return values


@router.get("/providers")
def oauth_providers():
    return {
        "google": bool(settings.OAUTH_GOOGLE_CLIENT_ID and settings.OAUTH_GOOGLE_CLIENT_SECRET and settings.OAUTH_GOOGLE_REDIRECT_URI),
        "github": bool(settings.OAUTH_GITHUB_CLIENT_ID and settings.OAUTH_GITHUB_CLIENT_SECRET and settings.OAUTH_GITHUB_REDIRECT_URI),
    }


@router.get("/{provider}/start")
def oauth_start(
    provider: str,
    request: Request,
    frontend_origin: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    client_id, _, redirect_uri = _settings(provider)
    state = secrets.token_urlsafe(32)
    db.add(OAuthState(
        state=state,
        provider=provider,
        frontend_url=_frontend_url(frontend_origin or request.headers.get("origin")),
        expires_at=datetime.utcnow() + timedelta(seconds=STATE_TTL),
    ))
    db.commit()
    return RedirectResponse(_authorization_url(provider, state, client_id, redirect_uri), status_code=302)


def _authorization_url(provider, state, client_id, redirect_uri):
    if provider == "google":
        query = urllib.parse.urlencode({
            "client_id": client_id, "redirect_uri": redirect_uri,
            "response_type": "code", "scope": "openid email profile",
            "state": state, "prompt": "select_account",
        })
        return "https://accounts.google.com/o/oauth2/v2/auth?" + query
    query = urllib.parse.urlencode({
        "client_id": client_id, "redirect_uri": redirect_uri,
        "scope": "read:user user:email", "state": state,
    })
    return "https://github.com/login/oauth/authorize?" + query


@router.get("/{provider}/link")
def oauth_link_start(
    provider: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    client_id, _, redirect_uri = _settings(provider)
    state = secrets.token_urlsafe(32)
    db.add(OAuthLinkState(
        state=state,
        provider=provider,
        user_id=current_user.id,
        frontend_url=_frontend_url(request.headers.get("origin")),
        expires_at=datetime.utcnow() + timedelta(seconds=STATE_TTL),
    ))
    db.commit()
    return {"authorization_url": _authorization_url(provider, state, client_id, redirect_uri)}


def _provider_profile(provider, code, redirect_uri, client_id, client_secret):
    if provider == "google":
        token_url = "https://oauth2.googleapis.com/token"
        token_body = urllib.parse.urlencode({
            "code": code, "client_id": client_id, "client_secret": client_secret,
            "redirect_uri": redirect_uri, "grant_type": "authorization_code",
        }).encode()
        token_request = urllib.request.Request(token_url, data=token_body, headers={"Accept": "application/json"})
        with urllib.request.urlopen(token_request, timeout=15) as response:
            access_token = json.loads(response.read()).get("access_token")
        request = urllib.request.Request(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            profile = json.loads(response.read())
        if not profile.get("sub") or not profile.get("email") or not profile.get("email_verified"):
            raise ValueError("Google did not return a verified email address.")
        return str(profile["sub"]), str(profile["email"]).lower()

    token_body = urllib.parse.urlencode({
        "code": code, "client_id": client_id, "client_secret": client_secret,
        "redirect_uri": redirect_uri,
    }).encode()
    token_request = urllib.request.Request(
        "https://github.com/login/oauth/access_token", data=token_body,
        headers={"Accept": "application/json"},
    )
    with urllib.request.urlopen(token_request, timeout=15) as response:
        access_token = json.loads(response.read()).get("access_token")
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json", "User-Agent": "Sentinel-SIEM"}
    profile_request = urllib.request.Request("https://api.github.com/user", headers=headers)
    with urllib.request.urlopen(profile_request, timeout=15) as response:
        profile = json.loads(response.read())
    user_id = profile.get("id")
    if not user_id:
        raise ValueError("GitHub did not return an account ID.")
    email_request = urllib.request.Request("https://api.github.com/user/emails", headers=headers)
    with urllib.request.urlopen(email_request, timeout=15) as response:
        emails = json.loads(response.read())
    email = next((item.get("email") for item in emails if item.get("primary") and item.get("verified")), None)
    if not email:
        raise ValueError("Add a verified primary email to your GitHub account and try again.")
    return str(user_id), str(email).lower()


def _get_or_create_user(db, provider, subject, email):
    identity = db.query(OAuthIdentity).filter_by(provider=provider, subject=subject).first()
    if identity:
        user = db.query(User).filter(User.id == identity.user_id).first()
        if user:
            return user

    # Keep the original single-provider columns working for identities created
    # before OAuthIdentity was introduced, then register them in the identity table.
    user = db.query(User).filter_by(oauth_provider=provider, oauth_subject=subject).first()
    if user:
        if not identity:
            db.add(OAuthIdentity(provider=provider, subject=subject, user_id=user.id))
            db.commit()
        return user

    # Both supported providers return a verified email. Use that verified address
    # to link another provider to the account instead of rejecting the callback.
    user = db.query(User).filter(User.email == email).first()
    if user:
        db.add(OAuthIdentity(provider=provider, subject=subject, user_id=user.id))
        db.commit()
        return user

    base = re.sub(r"[^a-z0-9._-]+", "_", email.split("@", 1)[0].lower()).strip("._-") or provider
    username, suffix = base[:40], 1
    while db.query(User.id).filter(User.username == username).first():
        suffix += 1
        username = f"{base[:32]}_{suffix}"
    user = User(
        username=username, email=email,
        hashed_password=get_password_hash(secrets.token_urlsafe(48)),
        role=UserRole.analyst, oauth_provider=provider, oauth_subject=subject,
    )
    db.add(user)
    db.flush()
    db.add(OAuthIdentity(provider=provider, subject=subject, user_id=user.id))
    db.commit()
    db.refresh(user)
    return user


@router.get("/{provider}/callback")
def oauth_callback(
    provider: str,
    request: Request,
    state: str = Query(...),
    code: str | None = Query(default=None),
    error: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    frontend = settings.FRONTEND_URL.rstrip("/")
    link_state = db.query(OAuthLinkState).filter_by(state=state, provider=provider).with_for_update().first()
    state_row = db.query(OAuthState).filter_by(state=state, provider=provider).with_for_update().first()
    if link_state:
        frontend = link_state.frontend_url or frontend
    elif state_row and state_row.frontend_url:
        frontend = state_row.frontend_url
    if error:
        if link_state:
            db.delete(link_state)
        if state_row:
            db.delete(state_row)
        db.commit()
        if link_state:
            return RedirectResponse(f"{frontend}/#oauth_link_error=provider_cancelled")
        return RedirectResponse(f"{frontend}/#oauth_error=provider_cancelled")
    if not code:
        if link_state:
            db.delete(link_state)
        if state_row:
            db.delete(state_row)
        db.commit()
        if link_state:
            return RedirectResponse(f"{frontend}/#oauth_link_error=sign_in_failed")
        return RedirectResponse(f"{frontend}/#oauth_error=sign_in_failed")
    if link_state:
        if link_state.expires_at < datetime.utcnow():
            db.delete(link_state)
            db.commit()
            return RedirectResponse(f"{frontend}/#oauth_link_error=expired_state")
        try:
            client_id, client_secret, redirect_uri = _settings(provider)
            subject, email = _provider_profile(provider, code, redirect_uri, client_id, client_secret)
            identity = db.query(OAuthIdentity).filter_by(provider=provider, subject=subject).first()
            if identity and identity.user_id != link_state.user_id:
                db.delete(link_state)
                db.commit()
                return RedirectResponse(f"{frontend}/#oauth_link_error=already_linked")
            if not identity:
                db.add(OAuthIdentity(provider=provider, subject=subject, user_id=link_state.user_id))
            linked_user = db.query(User).filter_by(id=link_state.user_id).first()
            if not linked_user:
                db.delete(link_state)
                db.commit()
                return RedirectResponse(f"{frontend}/#oauth_link_error=account_not_found")
            if not linked_user.oauth_provider:
                linked_user.oauth_provider = provider
                linked_user.oauth_subject = subject
            db.add(AuditLog(user=linked_user.username, action="oauth_link", target=provider))
            db.delete(link_state)
            db.commit()
            return RedirectResponse(f"{frontend}/#oauth_link={provider}")
        except Exception:
            logger.exception("OAuth account linking failed for provider %s", provider)
            db.rollback()
            return RedirectResponse(f"{frontend}/#oauth_link_error=link_failed")

    if not state_row or state_row.expires_at < datetime.utcnow():
        if state_row:
            db.delete(state_row)
            db.commit()
        return RedirectResponse(f"{frontend}/#oauth_error=expired_state")
    db.delete(state_row)
    db.commit()
    try:
        client_id, client_secret, redirect_uri = _settings(provider)
        subject, email = _provider_profile(provider, code, redirect_uri, client_id, client_secret)
        user = _get_or_create_user(db, provider, subject, email)
        security = db.query(AccountSecurity).filter_by(user_id=user.id).first()
        if security and security.email_two_factor_enabled:
            challenge = start_login_email_challenge(db, user)
            fragment = urllib.parse.urlencode({
                "email_2fa_challenge": challenge["challenge_id"],
                "email_2fa_delivery": challenge["delivery_mode"],
            })
            if challenge.get("development_code"):
                fragment += "&email_2fa_code=" + urllib.parse.quote(challenge["development_code"])
            return RedirectResponse(f"{frontend}/#{fragment}")
        db.add(AuditLog(user=user.username, action="login", target=provider))
        db.commit()
        token = create_login_session(db, user, request)
        db.commit()
        fragment = urllib.parse.urlencode({"oauth_token": token, "oauth_user": user.username, "oauth_role": user.role.value})
        return RedirectResponse(f"{frontend}/#{fragment}")
    except Exception:
        logger.exception("OAuth callback failed for provider %s", provider)
        db.rollback()
        return RedirectResponse(f"{frontend}/#oauth_error=sign_in_failed")
