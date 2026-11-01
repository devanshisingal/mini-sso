"""
Pydantic v2 schemas for request validation and response serialization.
"""

from __future__ import annotations

import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# User & Auth
class UserRegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(max_length=128)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    is_admin: bool
    has_mfa: bool = False
    created_at: datetime.datetime


class LoginResponse(BaseModel):
    status: str  # "authenticated" | "mfa_required"
    message: str
    user: Optional[UserResponse] = None
    next_step: Optional[str] = None  # e.g., "/mfa/verify" if 2FA needed


# MFA / TOTP / Recovery
class MfaEnrollResponse(BaseModel):
    secret: str
    provisioning_uri: str
    qr_code_svg: str
    recovery_codes: list[str] = Field(default_factory=list)


class MfaVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class MfaRecoveryRequest(BaseModel):
    code: str = Field(min_length=6, max_length=64)


class MfaVerifyResponse(BaseModel):
    status: str
    message: str
    user: Optional[UserResponse] = None


# OIDC & OAuth
class AuthorizeParams(BaseModel):
    response_type: str
    client_id: str
    redirect_uri: str
    scope: str = "openid profile email"
    state: str
    code_challenge: str
    code_challenge_method: str = "S256"
    nonce: Optional[str] = None


class TokenRequest(BaseModel):
    grant_type: str = "authorization_code"
    code: str
    redirect_uri: str
    client_id: str
    code_verifier: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    id_token: str
    scope: str = "openid profile email"


class UserInfoResponse(BaseModel):
    sub: str
    email: str
    email_verified: bool = True


class OpenIDConfigurationResponse(BaseModel):
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    response_types_supported: list[str] = ["code"]
    subject_types_supported: list[str] = ["public"]
    id_token_signing_alg_values_supported: list[str] = ["RS256"]
    scopes_supported: list[str] = ["openid", "profile", "email"]
    token_endpoint_auth_methods_supported: list[str] = ["none"]  # Public client (PKCE)
    code_challenge_methods_supported: list[str] = ["S256"]


# Admin & Clients
class ClientCreateRequest(BaseModel):
    client_id: str = Field(min_length=3, max_length=100)
    name: str = Field(min_length=2, max_length=255)
    redirect_uris: list[str] = Field(min_length=1)
    allowed_cidrs: Optional[list[str]] = None


class ClientResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    client_id: str
    name: str
    redirect_uris: list[str]
    allowed_cidrs: Optional[list[str]] = None
    created_at: datetime.datetime


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime.datetime
    user_id: Optional[str] = None
    client_id: Optional[str] = None
    event: str
    outcome: str
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    details: Optional[str] = None
    prev_hash: Optional[str] = None
    entry_hash: Optional[str] = None


class AuditVerificationResponse(BaseModel):
    valid: bool
    total_verified: int = 0
    latest_hash: Optional[str] = None
    tampered_id: Optional[int] = None
    reason: Optional[str] = None
    message: Optional[str] = None


class KeyRotationResponse(BaseModel):
    status: str
    new_kid: str
    previous_kid: str
    message: str


class MaintenanceCleanupResponse(BaseModel):
    purged_codes: int
    purged_sessions: int
    message: str
