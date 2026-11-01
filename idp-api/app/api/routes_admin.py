"""
Admin Endpoints: Client Application Management and Audit Log Inspection.
"""

from __future__ import annotations

import os
from typing import Optional

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import AuditLog, Client, User
from app.schemas import (
    AuditLogResponse,
    AuditVerificationResponse,
    ClientCreateRequest,
    ClientResponse,
    KeyRotationResponse,
    MaintenanceCleanupResponse,
)
from app.services.audit_service import log_audit_event, verify_audit_log_integrity
from app.services.auth_service import (
    cleanup_expired_records,
    get_session_by_token,
    rotate_signing_key,
)

router = APIRouter(prefix="/admin", tags=["Admin"])


def require_admin(
    request: Request,
    db: Session = Depends(get_db),
    session_token: Optional[str] = Cookie(None, alias=settings.SESSION_COOKIE_NAME),
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
) -> User | None:
    """
    Enforces administrator authorization:
    Validates either an authenticated session where user.is_admin is True,
    or a configured X-Admin-Key header.
    """
    admin_key_env = os.getenv("ADMIN_API_KEY", "mini-sso-default-admin-secret-key")
    if x_admin_key and x_admin_key == admin_key_env:
        return None

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
            detail="Admin authentication required",
        )

    session_rec = get_session_by_token(db, raw_token)
    if not session_rec:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session invalid or expired",
        )

    user = db.scalars(select(User).where(User.id == session_rec.user_id)).first()
    if not user or not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Admin privilege required",
        )

    return user


@router.get("/clients", response_model=list[ClientResponse])
def list_clients(
    db: Session = Depends(get_db),
    _admin: User | None = Depends(require_admin),
):
    """Lists all registered OpenID Connect client applications."""
    clients = db.scalars(select(Client).order_by(Client.created_at.desc())).all()
    return clients


@router.post("/clients", response_model=ClientResponse, status_code=status.HTTP_201_CREATED)
def create_client(
    req: ClientCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    _admin: User | None = Depends(require_admin),
):
    """Registers a new client application with exact redirect URIs and optional CIDRs."""
    existing = db.scalars(select(Client).where(Client.client_id == req.client_id)).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Client ID '{req.client_id}' is already registered",
        )

    client = Client(
        client_id=req.client_id,
        name=req.name,
        redirect_uris=req.redirect_uris,
        allowed_cidrs=req.allowed_cidrs or None,
    )
    db.add(client)
    db.commit()
    db.refresh(client)

    client_ip = request.client.host if request.client else "unknown"
    log_audit_event(
        db,
        event="client_registered",
        outcome="success",
        client_id=client.client_id,
        ip=client_ip,
        details=f"Registered client application: {client.name}",
    )
    return client


@router.get("/audit-log", response_model=list[AuditLogResponse])
def get_audit_log(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    event: Optional[str] = Query(None),
    outcome: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _admin: User | None = Depends(require_admin),
):
    """Retrieves authentication audit logs with filtering and pagination."""
    query = select(AuditLog).order_by(AuditLog.timestamp.desc())

    if event:
        query = query.where(AuditLog.event == event)
    if outcome:
        query = query.where(AuditLog.outcome == outcome)

    query = query.offset(offset).limit(limit)
    logs = db.scalars(query).all()
    return logs


@router.get("/audit-log/verify", response_model=AuditVerificationResponse)
def verify_audit_log(
    db: Session = Depends(get_db),
    _admin: User | None = Depends(require_admin),
):
    """
    Cryptographically verifies the SHA-256 hash chain of the entire audit log.
    Detects any tampering, alteration, omission, or insertion in audit records.
    """
    result = verify_audit_log_integrity(db)
    return AuditVerificationResponse(**result)


@router.post("/keys/rotate", response_model=KeyRotationResponse)
def rotate_key(
    request: Request,
    db: Session = Depends(get_db),
    _admin: User | None = Depends(require_admin),
):
    """
    Rotates the active RSA signing key pair.
    Existing keys are preserved in JWKS for token validation until natural expiry.
    """
    client_ip = request.client.host if request.client else "unknown"
    new_kid, previous_kid = rotate_signing_key(db)

    log_audit_event(
        db,
        event="key_rotated",
        outcome="success",
        ip=client_ip,
        details=f"Rotated RSA signing key from '{previous_kid}' to '{new_kid}'",
    )

    return KeyRotationResponse(
        status="success",
        new_kid=new_kid,
        previous_kid=previous_kid,
        message=f"Successfully rotated signing key. New active kid: {new_kid}",
    )


@router.post("/maintenance/cleanup", response_model=MaintenanceCleanupResponse)
def run_maintenance_cleanup(
    request: Request,
    db: Session = Depends(get_db),
    _admin: User | None = Depends(require_admin),
):
    """
    Sweeps and removes expired authorization codes and expired sessions from database.
    """
    client_ip = request.client.host if request.client else "unknown"
    purged_codes, purged_sessions = cleanup_expired_records(db)

    log_audit_event(
        db,
        event="maintenance_cleanup",
        outcome="success",
        ip=client_ip,
        details=f"Purged {purged_codes} expired/used auth codes and {purged_sessions} expired sessions",
    )

    return MaintenanceCleanupResponse(
        purged_codes=purged_codes,
        purged_sessions=purged_sessions,
        message=f"Cleaned up {purged_codes} expired codes and {purged_sessions} expired sessions.",
    )
