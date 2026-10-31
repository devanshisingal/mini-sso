"""
Security utilities: Argon2id password hashing and symmetric encryption for TOTP secrets.
"""

from __future__ import annotations

import base64
import os
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Configure Argon2id according to RFC 9106 recommended interactive parameters:
# t=3 iterations, m=64MB memory (65536 KiB), p=4 threads
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    """Hashes a password with Argon2id and a fresh cryptographically random salt."""
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against an Argon2id hash in constant time."""
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed_password: str) -> bool:
    """Checks if hash needs re-hashing due to upgraded parameters."""
    return _hasher.check_needs_rehash(hashed_password)


class SecretCipher:
    """
    Encrypts and decrypts sensitive values at rest (e.g. TOTP secrets)
    using authenticated symmetric encryption (Fernet / AES-128-CBC + HMAC-SHA256).
    """

    def __init__(self, key: str | bytes | None = None) -> None:
        if key is None:
            key = os.getenv("SECRET_ENCRYPTION_KEY", "mini-sso-default-secret-encryption-key-32b")
        if isinstance(key, str):
            key = key.encode("utf-8")

        # Derive a 32-byte urlsafe base64 key suitable for Fernet
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"mini-sso-salt-at-rest",
            info=b"totp-secret-encryption",
        )
        derived_key = base64.urlsafe_b64encode(hkdf.derive(key))
        self._fernet = Fernet(derived_key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypts a plaintext string and returns a base64 ciphertext string."""
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypts a base64 ciphertext string back to plaintext."""
        return self._fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")


def generate_secure_token(nbytes: int = 32) -> str:
    """Generates a URL-safe random string for authorization codes or session IDs."""
    return secrets.token_urlsafe(nbytes)
