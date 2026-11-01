"""
OpenID Connect (OIDC) endpoints:
- Discovery: /.well-known/openid-configuration
- JWKS: /.well-known/jwks.json
- Authorization: /authorize
- Token exchange: /token (with PKCE S256 verification and single-use code hash)
- UserInfo: /userinfo
"""

from __future__ import annotations

import datetime
import secrets
from typing import Optional
from urllib.parse import urlencode

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    Form,
    Header,
    HTTPException,
    Request,
    status,
)
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.core.pkce import verify_pkce
from app.database import get_db
from app.models import AuthorizationCode, Client, TotpCredential, User
from app.schemas import (
    OpenIDConfigurationResponse,
    TokenResponse,
    UserInfoResponse,
)
from app.services.audit_service import log_audit_event
from app.services.auth_service import (
    get_all_jwks,
    get_or_create_jwt_service,
    get_session_by_token,
    hash_token,
    is_ip_allowed,
)

router = APIRouter(tags=["OpenID Connect"])


@router.get("/.well-known/openid-configuration", response_model=OpenIDConfigurationResponse)
def openid_configuration():
    """Returns standard OpenID Connect Discovery metadata."""
    base = settings.ISSUER_URL.rstrip("/")
    return OpenIDConfigurationResponse(
        issuer=base,
        authorization_endpoint=f"{base}/authorize",
        token_endpoint=f"{base}/token",
        userinfo_endpoint=f"{base}/userinfo",
        jwks_uri=f"{base}/.well-known/jwks.json",
        response_types_supported=["code"],
        subject_types_supported=["public"],
        id_token_signing_alg_values_supported=["RS256"],
        scopes_supported=["openid", "profile", "email"],
        token_endpoint_auth_methods_supported=["none"],
        code_challenge_methods_supported=["S256"],
    )


@router.get("/.well-known/jwks.json")
def jwks(db: Session = Depends(get_db)):
    """Returns the JSON Web Key Set (JWKS) containing active and retired public keys for verifying ID tokens."""
    return get_all_jwks(db)


@router.get("/authorize")
def authorize(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: str = "openid profile email",
    state: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "S256",
    nonce: Optional[str] = None,
    session_token: Optional[str] = Cookie(None, alias=settings.SESSION_COOKIE_NAME),
    db: Session = Depends(get_db),
):
    """
    OpenID Connect Authorization Endpoint.
    1. Validates client_id and exact redirect_uri match.
    2. Validates client IP allowlist if configured.
    3. Requires S256 PKCE code challenge.
    4. If not signed in or MFA not verified: redirects browser to IdP UI.
    5. If session is valid: creates short-lived hashed authorization code and redirects to redirect_uri.
    """
    client_ip = request.client.host if request.client else "unknown"

    # 1. Validate response_type
    if response_type != "code":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="unsupported_response_type: only 'code' is supported",
        )

    # 2. Validate client_id
    client = db.scalars(select(Client).where(Client.client_id == client_id)).first()
    if not client:
        log_audit_event(
            db,
            event="authorize_rejected",
            outcome="failure",
            client_id=client_id,
            ip=client_ip,
            details="Unknown client_id",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_client: Unknown client_id",
        )

    # 3. Check client IP CIDR allowlist (stretch goal)
    if not is_ip_allowed(client, client_ip):
        log_audit_event(
            db,
            event="authorize_ip_blocked",
            outcome="blocked",
            client_id=client_id,
            ip=client_ip,
            details=f"Client IP {client_ip} not in client allowed CIDRs",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="access_denied: IP address not allowed for this client",
        )

    # 4. Exact redirect_uri matching
    if redirect_uri not in client.redirect_uris:
        log_audit_event(
            db,
            event="authorize_rejected",
            outcome="failure",
            client_id=client_id,
            ip=client_ip,
            details=f"Redirect URI mismatch: {redirect_uri}",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_request: redirect_uri does not match registered client redirect URIs",
        )

    # 5. Enforce PKCE S256 only
    if not code_challenge or code_challenge_method != "S256":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_request: code_challenge is required and code_challenge_method must be S256",
        )

    # 6. Check user session
    session_rec = None
    raw_token = session_token
    if not raw_token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Session "):
            raw_token = auth_header.replace("Session ", "").strip()
        elif request.headers.get("X-Session-Token"):
            raw_token = request.headers.get("X-Session-Token")

    if raw_token:
        session_rec = get_session_by_token(db, raw_token)

    auth_query = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": response_type,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }
    if nonce:
        auth_query["nonce"] = nonce

    # Check if UI request wants JSON return rather than browser 302
    accept = request.headers.get("accept", "")
    wants_json = "application/json" in accept and "text/html" not in accept

    if not session_rec:
        # Prompt login
        login_url = f"{settings.IDP_UI_URL}/login?{urlencode(auth_query)}"
        if wants_json:
            return JSONResponse({"status": "login_required", "redirect_to": login_url})
        return RedirectResponse(url=login_url, status_code=status.HTTP_302_FOUND)

    # Check if user has enrolled TOTP and needs MFA verification
    user = db.scalars(select(User).where(User.id == session_rec.user_id)).first()
    if not user:
        login_url = f"{settings.IDP_UI_URL}/login?{urlencode(auth_query)}"
        return RedirectResponse(url=login_url, status_code=status.HTTP_302_FOUND)

    totp_cred = db.scalars(
        select(TotpCredential).where(
            TotpCredential.user_id == user.id,
            TotpCredential.confirmed_at.is_not(None),
        )
    ).first()

    if totp_cred and session_rec.mfa_verified_at is None:
        mfa_url = f"{settings.IDP_UI_URL}/mfa-verify?{urlencode(auth_query)}"
        if wants_json:
            return JSONResponse({"status": "mfa_required", "redirect_to": mfa_url})
        return RedirectResponse(url=mfa_url, status_code=status.HTTP_302_FOUND)

    # User is fully authenticated: generate single-use authorization code
    raw_code = secrets.token_urlsafe(32)
    code_hash = hash_token(raw_code)

    now = datetime.datetime.now(datetime.timezone.utc)
    expires_at = now + datetime.timedelta(seconds=settings.AUTH_CODE_LIFETIME_SECONDS)

    auth_code_rec = AuthorizationCode(
        code_hash=code_hash,
        client_id=client_id,
        user_id=user.id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        nonce=nonce,
        expires_at=expires_at,
        used_at=None,
    )
    db.add(auth_code_rec)
    db.commit()

    log_audit_event(
        db,
        event="code_issued",
        outcome="success",
        user_id=user.id,
        client_id=client_id,
        ip=client_ip,
    )

    # Redirect to demo app with code & state
    callback_params = {"code": raw_code}
    if state:
        callback_params["state"] = state

    sep = "&" if "?" in redirect_uri else "?"
    target_url = f"{redirect_uri}{sep}{urlencode(callback_params)}"

    if wants_json:
        return JSONResponse({"status": "authorized", "redirect_to": target_url, "code": raw_code})

    return RedirectResponse(url=target_url, status_code=status.HTTP_302_FOUND)


@router.post("/token", response_model=TokenResponse)
async def token(
    request: Request,
    db: Session = Depends(get_db),
    grant_type: Optional[str] = Form(None),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),
):
    """
    OpenID Connect Token Endpoint.
    Exchanges one-time authorization code + PKCE code_verifier for ID Token and Access Token.
    Accepts both form-encoded and JSON request bodies.
    """
    client_ip = request.client.host if request.client else "unknown"

    # Support JSON payload if body is JSON
    if not grant_type:
        try:
            body = await request.json()
            grant_type = body.get("grant_type")
            code = body.get("code")
            redirect_uri = body.get("redirect_uri")
            client_id = body.get("client_id")
            code_verifier = body.get("code_verifier")
        except Exception:
            pass

    if grant_type != "authorization_code":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="unsupported_grant_type: grant_type must be 'authorization_code'",
        )

    if not code or not redirect_uri or not client_id or not code_verifier:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_request: code, redirect_uri, client_id, and code_verifier are required",
        )

    # Lookup authorization code by hash
    code_hash = hash_token(code)
    auth_code_rec = db.scalars(
        select(AuthorizationCode).where(AuthorizationCode.code_hash == code_hash)
    ).first()

    if not auth_code_rec:
        log_audit_event(
            db,
            event="token_request_failed",
            outcome="failure",
            client_id=client_id,
            ip=client_ip,
            details="Unknown or invalid authorization code",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_grant: Invalid authorization code",
        )

    # Prevent replay / code reuse
    if auth_code_rec.used_at is not None:
        log_audit_event(
            db,
            event="code_replay_attempt",
            outcome="blocked",
            user_id=auth_code_rec.user_id,
            client_id=client_id,
            ip=client_ip,
            details="Authorization code was already used",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_grant: Authorization code has already been used",
        )

    # Check expiration
    now = datetime.datetime.now(datetime.timezone.utc)
    expires_at = auth_code_rec.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)

    if expires_at < now:
        log_audit_event(
            db,
            event="token_request_failed",
            outcome="failure",
            user_id=auth_code_rec.user_id,
            client_id=client_id,
            ip=client_ip,
            details="Authorization code expired",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_grant: Authorization code has expired",
        )

    # Check client binding
    if auth_code_rec.client_id != client_id:
        log_audit_event(
            db,
            event="token_request_failed",
            outcome="failure",
            client_id=client_id,
            ip=client_ip,
            details="client_id mismatch",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_grant: Client mismatch",
        )

    # Check redirect_uri binding
    if auth_code_rec.redirect_uri != redirect_uri:
        log_audit_event(
            db,
            event="token_request_failed",
            outcome="failure",
            client_id=client_id,
            ip=client_ip,
            details="redirect_uri mismatch",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_grant: redirect_uri mismatch",
        )

    # Verify PKCE S256 code verifier
    if not verify_pkce(code_verifier, auth_code_rec.code_challenge, method="S256"):
        log_audit_event(
            db,
            event="pkce_verification_failed",
            outcome="failure",
            user_id=auth_code_rec.user_id,
            client_id=client_id,
            ip=client_ip,
            details="PKCE S256 code_verifier challenge mismatch",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_grant: PKCE verification failed",
        )

    # Mark code used immediately
    auth_code_rec.used_at = now
    db.commit()

    # Retrieve user
    user = db.scalars(select(User).where(User.id == auth_code_rec.user_id)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User record not found",
        )

    # Sign tokens with RS256
    jwt_svc = get_or_create_jwt_service(db)
    id_token = jwt_svc.issue_id_token(
        subject=user.id,
        audience=client_id,
        email=user.email,
        nonce=auth_code_rec.nonce,
        expires_in=settings.ID_TOKEN_LIFETIME_SECONDS,
    )
    access_token = jwt_svc.issue_access_token(
        subject=user.id,
        audience=client_id,
        expires_in=settings.ACCESS_TOKEN_LIFETIME_SECONDS,
    )

    log_audit_event(
        db,
        event="token_issued",
        outcome="success",
        user_id=user.id,
        client_id=client_id,
        ip=client_ip,
    )

    return TokenResponse(
        access_token=access_token,
        token_type="Bearer",
        expires_in=settings.ACCESS_TOKEN_LIFETIME_SECONDS,
        id_token=id_token,
        scope="openid profile email",
    )


@router.get("/userinfo", response_model=UserInfoResponse)
def userinfo(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """
    OpenID Connect UserInfo Endpoint.
    Validates Bearer Access Token (RS256) and returns profile claims.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required in Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_token = authorization.replace("Bearer ", "").strip()
    jwt_svc = get_or_create_jwt_service(db)

    try:
        payload = jwt_svc.verify_token(raw_token)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired access token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )

    sub = payload.get("sub")
    user = db.scalars(select(User).where(User.id == sub)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return UserInfoResponse(
        sub=user.id,
        email=user.email,
        email_verified=True,
    )
