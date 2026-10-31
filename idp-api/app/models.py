"""
SQLAlchemy 2.0 ORM Models matching the Mini SSO schema specifications.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    totp_credential: Mapped[Optional["TotpCredential"]] = relationship(
        "TotpCredential", back_populates="user", uselist=False, cascade="all, delete-orphan"
    )
    sessions: Mapped[list["SessionRecord"]] = relationship(
        "SessionRecord", back_populates="user", cascade="all, delete-orphan"
    )


class TotpCredential(Base):
    __tablename__ = "totp_credentials"

    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    secret: Mapped[str] = mapped_column(Text, nullable=False)  # Encrypted at rest
    confirmed_at: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_step: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="totp_credential")


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    client_id: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    redirect_uris: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    allowed_cidrs: Mapped[Optional[list[str]]] = mapped_column(JSON, nullable=True)  # IP allowlist stretch goal
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class AuthorizationCode(Base):
    __tablename__ = "authorization_codes"

    code_hash: Mapped[str] = mapped_column(String(64), primary_key=True)  # SHA-256 hex
    client_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    redirect_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    code_challenge: Mapped[str] = mapped_column(String(128), nullable=False)
    nonce: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class SessionRecord(Base):
    __tablename__ = "sessions"

    id_hash: Mapped[str] = mapped_column(String(64), primary_key=True)  # SHA-256 of session cookie token
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    mfa_verified_at: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="sessions")


class SigningKey(Base):
    __tablename__ = "signing_keys"

    kid: Mapped[str] = mapped_column(String(64), primary_key=True)
    private_key: Mapped[str] = mapped_column(Text, nullable=False)  # PEM format
    public_key: Mapped[str] = mapped_column(Text, nullable=False)   # PEM format
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    client_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    event: Mapped[str] = mapped_column(String(50), nullable=False)  # login, mfa_enrolled, token_issued, etc.
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)  # success, failure, blocked
    ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
