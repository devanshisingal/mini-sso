"""
Audit log service to record all authentication and authorization events.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from app.models import AuditLog


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
    """Creates and persists an audit log entry in the database."""
    entry = AuditLog(
        event=event,
        outcome=outcome,
        user_id=user_id,
        client_id=client_id,
        ip=ip,
        user_agent=user_agent,
        details=details,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
