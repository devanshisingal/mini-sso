"""
Proof Key for Code Exchange (PKCE) by OAuth Public Clients (RFC 7636).
Mini SSO enforces S256 only. The 'plain' transform method is rejected for security.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re

# RFC 7636 Section 4.1: unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
PKCE_VERIFIER_PATTERN = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")


def is_valid_verifier_format(code_verifier: str) -> bool:
    """Verifies that code_verifier complies with RFC 7636 length and character set."""
    if not code_verifier or not isinstance(code_verifier, str):
        return False
    return bool(PKCE_VERIFIER_PATTERN.match(code_verifier))


def calculate_s256_challenge(code_verifier: str) -> str:
    """
    Computes code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    without '=' padding, as required by RFC 7636 Section 4.2.
    """
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def verify_pkce(code_verifier: str, code_challenge: str, method: str = "S256") -> bool:
    """
    Validates the authorization code verifier against stored challenge.
    Rejects 'plain' method to protect against unauthorized intercept attacks.
    Uses constant-time comparison to prevent timing leaks.
    """
    if method != "S256":
        return False

    if not is_valid_verifier_format(code_verifier):
        return False

    computed_challenge = calculate_s256_challenge(code_verifier)
    return hmac.compare_digest(computed_challenge, code_challenge.rstrip("="))
