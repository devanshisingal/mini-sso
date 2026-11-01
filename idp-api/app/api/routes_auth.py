"""
Authentication, Registration, Session, and MFA endpoints.
"""

from __future__ import annotations

import datetime
from typing import Optional

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.core.rate_limiter import login_rate_limiter, mfa_rate_limiter
from app.core.security import SecretCipher, hash_password, verify_password
from app.core.totp import (
    generate_qr_svg_data_uri,
    generate_totp_secret,
    get_totp_provisioning_uri,
    verify_totp,
)
from app.database import get_db
from app.models import SessionRecord, TotpCredential, User
from app.schemas import (
    LoginResponse,
    MfaEnrollResponse,
    MfaRecoveryRequest,
    MfaVerifyRequest,
    MfaVerifyResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)
from app.services.audit_service import log_audit_event
from app.services.auth_service import (
    create_session,
    delete_session,
    generate_and_store_recovery_codes,
    get_session_by_token,
    verify_and_consume_recovery_code,
)

router = APIRouter(tags=["Authentication"])
cipher = SecretCipher()


def get_current_user_and_session(
    request: Request,
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None, alias=settings.SESSION_COOKIE_NAME),
) -> tuple[User, SessionRecord]:
    """Dependency that extracts and validates the user and session from cookie."""
    # Also support Authorization: Session <token> or X-Session-Token header for programmatic API testing
    raw_token = session_token
    if not raw_token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Session "):
            raw_token = auth_header.replace("Session ", "").strip()
        elif request.headers.get("X-Session-Token"):
            raw_token = request.headers.get("X-Session-Token")

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    session_rec = get_session_by_token(db, raw_token)
    if not session_rec:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid",
        )

    user = db.scalars(select(User).where(User.id == session_rec.user_id)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return user, session_rec


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(
    req: UserRegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Registers a new user with Argon2id password hashing."""
    client_ip = request.client.host if request.client else "unknown"

    existing = db.scalars(select(User).where(User.email == req.email.lower())).first()
    if existing:
        log_audit_event(
            db,
            event="registration_failed",
            outcome="failure",
            ip=client_ip,
            details=f"Email already registered: {req.email.lower()}",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already registered",
        )

    if not settings.ALLOW_OPEN_REGISTRATION:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Open registration is disabled",
        )

    # Prevent first-user takeover: admin role granted only to designated ADMIN_EMAIL
    is_admin = (req.email.lower() == settings.ADMIN_EMAIL.lower())

    user = User(
        email=req.email.lower(),
        password_hash=hash_password(req.password),
        is_admin=is_admin,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_audit_event(
        db,
        event="user_registered",
        outcome="success",
        user_id=user.id,
        ip=client_ip,
    )

    return UserResponse(
        id=user.id,
        email=user.email,
        is_admin=user.is_admin,
        has_mfa=False,
        created_at=user.created_at,
    )


@router.post("/login", response_model=LoginResponse)
def login(
    req: UserLoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Checks email and password. Enforces rate limiting on failed attempts.
    Returns MFA challenge if user has enrolled TOTP, or sets session cookie.
    """
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent")
    rate_key = f"ip:{client_ip}:email:{req.email.lower()}"

    # Check Rate Limit
    is_limited, retry_after = login_rate_limiter.is_rate_limited(rate_key)
    if is_limited:
        log_audit_event(
            db,
            event="login_rate_limited",
            outcome="blocked",
            ip=client_ip,
            details=f"Rate limited. Retry after {retry_after}s",
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Please try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )

    user = db.scalars(select(User).where(User.email == req.email.lower())).first()
    # Generic error message: prevents user enumeration
    if not user or not verify_password(req.password, user.password_hash):
        login_rate_limiter.record_failure(rate_key)
        log_audit_event(
            db,
            event="login_failed",
            outcome="failure",
            ip=client_ip,
            user_agent=user_agent,
            details="Invalid email or password",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Check if user has confirmed MFA
    totp_cred = db.scalars(
        select(TotpCredential).where(
            TotpCredential.user_id == user.id,
            TotpCredential.confirmed_at.is_not(None),
        )
    ).first()

    if totp_cred:
        # Create unverified session requiring MFA step
        raw_token, _ = create_session(
            db, user.id, ip=client_ip, user_agent=user_agent, mfa_verified=False
        )
        response.set_cookie(
            key=settings.SESSION_COOKIE_NAME,
            value=raw_token,
            max_age=settings.SESSION_MAX_AGE_SECONDS,
            httponly=True,
            secure=settings.COOKIE_SECURE,
            samesite=settings.COOKIE_SAMESITE,
        )
        return LoginResponse(
            status="mfa_required",
            message="TOTP verification required",
            next_step="/mfa/verify",
            user=UserResponse(
                id=user.id,
                email=user.email,
                is_admin=user.is_admin,
                has_mfa=True,
                created_at=user.created_at,
            ),
        )

    # Authentication successful without MFA
    login_rate_limiter.reset(rate_key)
    raw_token, _ = create_session(
        db, user.id, ip=client_ip, user_agent=user_agent, mfa_verified=True
    )
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=settings.SESSION_MAX_AGE_SECONDS,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
    )

    log_audit_event(
        db,
        event="login_success",
        outcome="success",
        user_id=user.id,
        ip=client_ip,
        user_agent=user_agent,
    )

    return LoginResponse(
        status="authenticated",
        message="Login successful",
        user=UserResponse(
            id=user.id,
            email=user.email,
            is_admin=user.is_admin,
            has_mfa=False,
            created_at=user.created_at,
        ),
    )


@router.post("/mfa/enroll", response_model=MfaEnrollResponse)
def enroll_mfa(
    auth_data: tuple[User, SessionRecord] = Depends(get_current_user_and_session),
    db: Session = Depends(get_db),
):
    """
    Initiates TOTP 2FA enrollment. Generates secret, encrypts at rest,
    and returns QR code and provisioning URI.
    """
    user, _ = auth_data

    # Generate fresh base32 secret
    raw_secret = generate_totp_secret()
    encrypted_secret = cipher.encrypt(raw_secret)

    # Save or update unconfirmed credential
    totp_cred = db.scalars(
        select(TotpCredential).where(TotpCredential.user_id == user.id)
    ).first()

    if not totp_cred:
        totp_cred = TotpCredential(
            user_id=user.id,
            secret=encrypted_secret,
            confirmed_at=None,
            last_used_step=None,
        )
        db.add(totp_cred)
    else:
        totp_cred.secret = encrypted_secret
        totp_cred.confirmed_at = None
        totp_cred.last_used_step = None

    db.commit()

    provisioning_uri = get_totp_provisioning_uri(
        secret=raw_secret,
        account_name=user.email,
        issuer="Mini SSO",
    )
    qr_svg = generate_qr_svg_data_uri(provisioning_uri)

    recovery_codes = generate_and_store_recovery_codes(db, user.id, count=10)

    log_audit_event(
        db,
        event="mfa_enroll_started",
        outcome="success",
        user_id=user.id,
    )

    return MfaEnrollResponse(
        secret=raw_secret,
        provisioning_uri=provisioning_uri,
        qr_code_svg=qr_svg,
        recovery_codes=recovery_codes,
    )


@router.post("/mfa/verify", response_model=MfaVerifyResponse)
def verify_mfa(
    req: MfaVerifyRequest,
    request: Request,
    auth_data: tuple[User, SessionRecord] = Depends(get_current_user_and_session),
    db: Session = Depends(get_db),
):
    """
    Verifies a TOTP 6-digit code.
    Protects against clock drift (+- 1 step) and replay attacks (last_used_step).
    On success: marks credential confirmed and session mfa_verified_at.
    """
    user, session_rec = auth_data
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"mfa:{user.id}"

    is_limited, retry_after = mfa_rate_limiter.is_rate_limited(rate_key)
    if is_limited:
        log_audit_event(
            db,
            event="mfa_rate_limited",
            outcome="blocked",
            user_id=user.id,
            ip=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many incorrect TOTP attempts. Please wait {retry_after} seconds.",
        )

    totp_cred = db.scalars(
        select(TotpCredential).where(TotpCredential.user_id == user.id)
    ).first()

    if not totp_cred:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA has not been initiated for this account",
        )

    raw_secret = cipher.decrypt(totp_cred.secret)
    is_valid, step_used = verify_totp(
        secret=raw_secret,
        code=req.code,
        window=1,
        last_used_step=totp_cred.last_used_step,
    )

    if not is_valid or step_used is None:
        mfa_rate_limiter.record_failure(rate_key)
        log_audit_event(
            db,
            event="mfa_verify_failed",
            outcome="failure",
            user_id=user.id,
            ip=client_ip,
            details="Invalid TOTP code or replayed step",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or replayed verification code",
        )

    # Success: update last used step to prevent replay attacks
    now = datetime.datetime.now(datetime.timezone.utc)
    totp_cred.last_used_step = step_used
    if totp_cred.confirmed_at is None:
        totp_cred.confirmed_at = now

    session_rec.mfa_verified_at = now
    db.commit()

    mfa_rate_limiter.reset(rate_key)
    log_audit_event(
        db,
        event="mfa_verify_success",
        outcome="success",
        user_id=user.id,
        ip=client_ip,
    )

    return MfaVerifyResponse(
        status="success",
        message="Two-factor authentication verified successfully",
        user=UserResponse(
            id=user.id,
            email=user.email,
            is_admin=user.is_admin,
            has_mfa=True,
            created_at=user.created_at,
        ),
    )


@router.post("/mfa/recovery", response_model=MfaVerifyResponse)
def verify_mfa_recovery(
    req: MfaRecoveryRequest,
    request: Request,
    auth_data: tuple[User, SessionRecord] = Depends(get_current_user_and_session),
    db: Session = Depends(get_db),
):
    """
    Verifies and consumes a single-use backup recovery code when user cannot provide TOTP.
    """
    user, session_rec = auth_data
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"recovery:{user.id}"

    is_limited, retry_after = mfa_rate_limiter.is_rate_limited(rate_key)
    if is_limited:
        log_audit_event(
            db,
            event="recovery_rate_limited",
            outcome="blocked",
            user_id=user.id,
            ip=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many incorrect attempts. Please wait {retry_after} seconds.",
        )

    consumed = verify_and_consume_recovery_code(db, user.id, req.code)
    if not consumed:
        mfa_rate_limiter.record_failure(rate_key)
        log_audit_event(
            db,
            event="recovery_code_failed",
            outcome="failure",
            user_id=user.id,
            ip=client_ip,
            details="Invalid or already-consumed recovery code",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or already-used recovery code",
        )

    now = datetime.datetime.now(datetime.timezone.utc)
    session_rec.mfa_verified_at = now
    db.commit()

    mfa_rate_limiter.reset(rate_key)
    log_audit_event(
        db,
        event="recovery_code_success",
        outcome="success",
        user_id=user.id,
        ip=client_ip,
        details="User authenticated via single-use backup recovery code",
    )

    return MfaVerifyResponse(
        status="success",
        message="Recovery code accepted. Session authenticated.",
        user=UserResponse(
            id=user.id,
            email=user.email,
            is_admin=user.is_admin,
            has_mfa=True,
            created_at=user.created_at,
        ),
    )


@router.get("/me", response_model=UserResponse)
def get_me(
    auth_data: tuple[User, SessionRecord] = Depends(get_current_user_and_session),
    db: Session = Depends(get_db),
):
    """Returns profile of currently authenticated session user."""
    user, _ = auth_data
    totp_cred = db.scalars(
        select(TotpCredential).where(
            TotpCredential.user_id == user.id,
            TotpCredential.confirmed_at.is_not(None),
        )
    ).first()

    return UserResponse(
        id=user.id,
        email=user.email,
        is_admin=user.is_admin,
        has_mfa=totp_cred is not None,
        created_at=user.created_at,
    )


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None, alias=settings.SESSION_COOKIE_NAME),
):
    """Terminates session and removes session cookie."""
    raw_token = session_token
    if not raw_token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Session "):
            raw_token = auth_header.replace("Session ", "").strip()

    if raw_token:
        delete_session(db, raw_token)

    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        httponly=True,
        samesite=settings.COOKIE_SAMESITE,
        secure=settings.COOKIE_SECURE,
    )
    return {"status": "success", "message": "Logged out successfully"}
