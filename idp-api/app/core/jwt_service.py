"""
JSON Web Token (JWT) and JWKS Service using RS256 with PyJWT and cryptography.
"""

from __future__ import annotations

import base64
import time
import uuid
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def int_to_base64url(val: int) -> str:
    """Encodes a big integer to base64url string without padding."""
    num_bytes = (val.bit_length() + 7) // 8
    raw_bytes = val.to_bytes(num_bytes, byteorder="big")
    return base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")


def generate_rsa_key_pair(key_size: int = 2048) -> tuple[str, str, str]:
    """
    Generates a new RSA private/public key pair and assigns a random Key ID (kid).
    Returns (kid, private_pem, public_pem).
    """
    kid = str(uuid.uuid4())
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return kid, private_pem, public_pem


def rsa_public_pem_to_jwk(kid: str, public_pem: str) -> dict[str, str]:
    """
    Extracts RSA modulus (n) and exponent (e) and formats as an RFC 7517 JWK.
    """
    public_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Key is not an RSA public key")

    public_numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": int_to_base64url(public_numbers.n),
        "e": int_to_base64url(public_numbers.e),
    }


class JwtService:
    def __init__(
        self,
        kid: str,
        private_pem: str,
        public_pem: str,
        issuer: str = "http://localhost:8000",
    ) -> None:
        self.kid = kid
        self.private_pem = private_pem
        self.public_pem = public_pem
        self.issuer = issuer

    def get_jwks(self) -> dict[str, Any]:
        """Returns the JWKS dictionary containing the active public key."""
        jwk = rsa_public_pem_to_jwk(self.kid, self.public_pem)
        return {"keys": [jwk]}

    def issue_id_token(
        self,
        subject: str,
        audience: str,
        email: str,
        nonce: str | None = None,
        auth_time: int | None = None,
        expires_in: int = 3600,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """
        Signs an OpenID Connect ID Token with RS256.
        Claims: iss, sub, aud, exp, iat, auth_time, email, nonce
        """
        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "exp": now + expires_in,
            "iat": now,
            "auth_time": auth_time or now,
            "email": email,
            "email_verified": True,
        }
        if nonce:
            payload["nonce"] = nonce
        if extra_claims:
            payload.update(extra_claims)

        headers = {"kid": self.kid, "alg": "RS256", "typ": "JWT"}
        return jwt.encode(payload, self.private_pem, algorithm="RS256", headers=headers)

    def issue_access_token(
        self,
        subject: str,
        audience: str,
        scope: str = "openid profile email",
        expires_in: int = 900,  # 15 minutes
    ) -> str:
        """Signs an OAuth 2.0 Access Token with RS256."""
        now = int(time.time())
        payload = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "exp": now + expires_in,
            "iat": now,
            "scope": scope,
            "token_type": "Bearer",
        }
        headers = {"kid": self.kid, "alg": "RS256", "typ": "at+jwt"}
        return jwt.encode(payload, self.private_pem, algorithm="RS256", headers=headers)

    def verify_token(self, token: str, audience: str | None = None) -> dict[str, Any]:
        """Verifies RS256 signature and validates issuer and audience."""
        options = {"verify_aud": audience is not None}
        return jwt.decode(
            token,
            self.public_pem,
            algorithms=["RS256"],
            issuer=self.issuer,
            audience=audience,
            options=options,
        )
