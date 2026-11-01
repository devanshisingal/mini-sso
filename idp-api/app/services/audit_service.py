"""
Audit log service to record all authentication and authorization events with cryptographic hash-chaining.
"""

from __future__ import annotations

import datetime
import hashlib
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog, utcnow


def format_timestamp(dt: datetime.datetime) -> str:
    """Normalizes UTC datetime representation across SQLite and PostgreSQL."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    else:
        dt = dt.astimezone(datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def calculate_audit_hash(
    prev_hash: str,
    timestamp_str: str,
    event: str,
    outcome: str,
    user_id: Optional[str] = None,
    client_id: Optional[str] = None,
    ip: Optional[str] = None,
    details: Optional[str] = None,
) -> str:
    """Computes SHA-256 hash chaining over immutable audit event properties."""
    raw = f"{prev_hash}|{timestamp_str}|{user_id or ''}|{client_id or ''}|{event}|{outcome}|{ip or ''}|{details or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def log_audit_event(
    db: Session,
    event: str,
    outcome: str,
    user_id: Optional[str] = None,
    client_id: Optional[str] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[str] = None,
) -> AuditLog:
    """Creates and persists a tamper-evident audit log entry linked to previous hash."""
    last_entry = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(1)).first()
    prev_hash = last_entry.entry_hash if last_entry and last_entry.entry_hash else "GENESIS"

    timestamp = utcnow()
    entry_hash = calculate_audit_hash(
        prev_hash=prev_hash,
        timestamp_str=format_timestamp(timestamp),
        event=event,
        outcome=outcome,
        user_id=user_id,
        client_id=client_id,
        ip=ip,
        details=details,
    )

    entry = AuditLog(
        timestamp=timestamp,
        event=event,
        outcome=outcome,
        user_id=user_id,
        client_id=client_id,
        ip=ip,
        user_agent=user_agent,
        details=details,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def verify_audit_log_integrity(db: Session) -> dict:
    """
    Cryptographically verifies the entire audit log hash chain from genesis to head.
    Returns whether the log is intact, count verified, and tampering details if compromised.
    """
    entries = db.scalars(select(AuditLog).order_by(AuditLog.id.asc())).all()
    if not entries:
        return {"valid": True, "total_verified": 0, "message": "Audit log is empty"}

    expected_prev = "GENESIS"
    verified_count = 0
    for entry in entries:
        if entry.prev_hash != expected_prev:
            return {
                "valid": False,
                "total_verified": verified_count,
                "tampered_id": entry.id,
                "reason": f"Broken chain: expected prev_hash '{expected_prev}', found '{entry.prev_hash}'",
            }

        recalculated = calculate_audit_hash(
            prev_hash=entry.prev_hash,
            timestamp_str=format_timestamp(entry.timestamp),
            event=entry.event,
            outcome=entry.outcome,
            user_id=entry.user_id,
            client_id=entry.client_id,
            ip=entry.ip,
            details=entry.details,
        )
        if entry.entry_hash != recalculated:
            return {
                "valid": False,
                "total_verified": verified_count,
                "tampered_id": entry.id,
                "reason": f"Content tampering: stored entry_hash '{entry.entry_hash}' does not match recomputed hash '{recalculated}'",
            }
        expected_prev = entry.entry_hash
        verified_count += 1

    return {
        "valid": True,
        "total_verified": len(entries),
        "latest_hash": expected_prev,
        "message": f"All {len(entries)} audit log entries verified against SHA-256 cryptographic chain.",
    }
