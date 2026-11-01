"""
Authentication and session management services.
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import secrets
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.core.jwt_service import JwtService, generate_rsa_key_pair, rsa_public_pem_to_jwk
from app.models import AuthorizationCode, Client, RecoveryCode, SessionRecord, SigningKey, utcnow


def hash_token(raw_token: str) -> str:
    """Computes a SHA-256 hex digest of a token (for authorization codes or session IDs)."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_session(
    db: Session,
    user_id: str,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    mfa_verified: bool = False,
) -> tuple[str, SessionRecord]:
    """Creates a new session record in DB and returns the raw cookie token and record."""
    raw_token = secrets.token_urlsafe(32)
    id_hash = hash_token(raw_token)
    now = datetime.datetime.now(datetime.timezone.utc)
    expires_at = now + datetime.timedelta(seconds=settings.SESSION_MAX_AGE_SECONDS)
    mfa_verified_at = now if mfa_verified else None

    session_rec = SessionRecord(
        id_hash=id_hash,
        user_id=user_id,
        mfa_verified_at=mfa_verified_at,
        expires_at=expires_at,
        ip=ip,
        user_agent=user_agent,
    )
    db.add(session_rec)
    db.commit()
    db.refresh(session_rec)
    return raw_token, session_rec


def get_session_by_token(db: Session, raw_token: str) -> Optional[SessionRecord]:
    """Looks up and validates a session record by raw token."""
    if not raw_token:
        return None

    id_hash = hash_token(raw_token)
    session_rec = db.scalars(select(SessionRecord).where(SessionRecord.id_hash == id_hash)).first()
    if not session_rec:
        return None

    now = datetime.datetime.now(datetime.timezone.utc)
    expires_at = session_rec.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)

    if expires_at < now:
        db.delete(session_rec)
        db.commit()
        return None

    return session_rec


def delete_session(db: Session, raw_token: str) -> None:
    """Removes a session from database."""
    if not raw_token:
        return
    id_hash = hash_token(raw_token)
    session_rec = db.scalars(select(SessionRecord).where(SessionRecord.id_hash == id_hash)).first()
    if session_rec:
        db.delete(session_rec)
        db.commit()


def get_or_create_jwt_service(db: Session) -> JwtService:
    """
    Retrieves the currently active RSA signing key from the database,
    or generates and persists one if none exists.
    """
    key_record = db.scalars(
        select(SigningKey).where(SigningKey.active.is_(True)).order_by(SigningKey.created_at.desc())
    ).first()

    if not key_record:
        kid, priv_pem, pub_pem = generate_rsa_key_pair(2048)
        key_record = SigningKey(
            kid=kid,
            private_key=priv_pem,
            public_key=pub_pem,
            active=True,
        )
        db.add(key_record)
        db.commit()
        db.refresh(key_record)

    return JwtService(
        kid=key_record.kid,
        private_pem=key_record.private_key,
        public_pem=key_record.public_key,
        issuer=settings.ISSUER_URL,
    )


def rotate_signing_key(db: Session) -> tuple[str, str]:
    """
    Retires the currently active RSA signing key and issues a new active key.
    Returns (new_kid, previous_kid).
    """
    active_key = db.scalars(
        select(SigningKey).where(SigningKey.active.is_(True)).order_by(SigningKey.created_at.desc())
    ).first()

    previous_kid = active_key.kid if active_key else ""
    if active_key:
        active_key.active = False
        active_key.retired_at = utcnow()

    kid, priv_pem, pub_pem = generate_rsa_key_pair(2048)
    new_key = SigningKey(
        kid=kid,
        private_key=priv_pem,
        public_key=pub_pem,
        active=True,
    )
    db.add(new_key)
    db.commit()
    db.refresh(new_key)
    return new_key.kid, previous_kid


def get_all_jwks(db: Session) -> dict[str, list[dict[str, str]]]:
    """Returns the JWKS dictionary containing all active and retired public keys."""
    keys = db.scalars(select(SigningKey).order_by(SigningKey.created_at.desc())).all()
    jwks_keys = [rsa_public_pem_to_jwk(k.kid, k.public_key) for k in keys]
    return {"keys": jwks_keys}


def generate_and_store_recovery_codes(db: Session, user_id: str, count: int = 10) -> list[str]:
    """Generates single-use alphanumeric backup recovery codes (e.g. ABCD-EFGH) and stores SHA-256 hashes."""
    existing = db.scalars(select(RecoveryCode).where(RecoveryCode.user_id == user_id)).all()
    for rec in existing:
        db.delete(rec)

    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    plain_codes = []
    for _ in range(count):
        part1 = "".join(secrets.choice(alphabet) for _ in range(4))
        part2 = "".join(secrets.choice(alphabet) for _ in range(4))
        code = f"{part1}-{part2}"
        plain_codes.append(code)

        db.add(RecoveryCode(
            user_id=user_id,
            code_hash=hash_token(code),
        ))
    db.commit()
    return plain_codes


def verify_and_consume_recovery_code(db: Session, user_id: str, raw_code: str) -> bool:
    """Verifies a single-use backup recovery code against stored hashes and consumes it."""
    clean_code = raw_code.strip().upper()
    code_hash = hash_token(clean_code)

    rec = db.scalars(
        select(RecoveryCode).where(
            RecoveryCode.user_id == user_id,
            RecoveryCode.code_hash == code_hash,
            RecoveryCode.used_at.is_(None),
        )
    ).first()

    if not rec:
        return False

    rec.used_at = utcnow()
    db.commit()
    return True


def cleanup_expired_records(db: Session) -> tuple[int, int]:
    """
    Sweeps and deletes expired authorization codes and expired sessions.
    Returns (purged_codes_count, purged_sessions_count).
    """
    now = utcnow()

    codes = db.scalars(
        select(AuthorizationCode).where(
            (AuthorizationCode.expires_at < now) | (AuthorizationCode.used_at.is_not(None))
        )
    ).all()
    purged_codes = len(codes)
    for c in codes:
        db.delete(c)

    sessions = db.scalars(select(SessionRecord).where(SessionRecord.expires_at < now)).all()
    purged_sessions = len(sessions)
    for s in sessions:
        db.delete(s)

    db.commit()
    return purged_codes, purged_sessions


def is_ip_allowed(client: Client, client_ip: Optional[str]) -> bool:
    """
    Checks if client_ip matches client's allowed CIDR ranges.
    Returns True if allowed or if no restrictions are configured.
    """
    if not client.allowed_cidrs:
        return True

    if not client_ip:
        return False

    try:
        ip_obj = ipaddress.ip_address(client_ip)
        for cidr_str in client.allowed_cidrs:
            network = ipaddress.ip_network(cidr_str.strip(), strict=False)
            if ip_obj in network:
                return True
        return False
    except ValueError:
        return False
