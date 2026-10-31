"""
RFC 6238 Time-Based One-Time Password (TOTP) Implementation.

Built on standard library hmac and hashlib without third-party TOTP libraries.
Strictly conforms to RFC 6238 and RFC 4226 (HOTP) specifications.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote


def _normalize_base32_secret(secret: str | bytes) -> bytes:
    """
    Normalizes and decodes a base32 encoded secret.
    Handles unpadded strings, whitespace, and lower/uppercase.
    """
    if isinstance(secret, bytes):
        secret_str = secret.decode("utf-8")
    else:
        secret_str = secret

    cleaned = secret_str.strip().replace(" ", "").upper()
    # Add base32 padding if missing
    missing_padding = len(cleaned) % 8
    if missing_padding != 0:
        cleaned += "=" * (8 - missing_padding)

    return base64.b32decode(cleaned, casefold=True)


def generate_totp_secret(num_bytes: int = 20) -> str:
    """
    Generates a cryptographically secure random base32 TOTP secret.
    RFC 6238 recommends at least 160 bits (20 bytes) for SHA-1.
    """
    raw_bytes = secrets.token_bytes(num_bytes)
    # Return unpadded base32 string for maximum authenticator compatibility
    return base64.b32encode(raw_bytes).decode("ascii").rstrip("=")


def hotp(key: bytes, counter: int, digits: int = 6, digest=hashlib.sha1) -> str:
    """
    HMAC-based One-Time Password (HOTP) algorithm as defined in RFC 4226 Section 5.3.

    1. Generate HMAC-SHA-1 of the 8-byte big-endian counter: HS = HMAC(key, counter)
    2. Dynamic Truncation:
       - Low-order 4 bits of HS[-1] define offset (0..15)
       - Extract 4 bytes from HS starting at offset
       - Mask MSB with 0x7FFFFFFF to avoid signed integer issues
    3. Modulo 10^digits and format with leading zeroes
    """
    counter_bytes = struct.pack(">Q", counter)
    hs = hmac.new(key, counter_bytes, digest).digest()

    offset = hs[-1] & 0x0F
    truncated_hash = (
        ((hs[offset] & 0x7F) << 24)
        | ((hs[offset + 1] & 0xFF) << 16)
        | ((hs[offset + 2] & 0xFF) << 8)
        | (hs[offset + 3] & 0xFF)
    )

    code = truncated_hash % (10**digits)
    return f"{code:0{digits}d}"


def generate_totp(
    secret: str | bytes,
    time_val: int | float | None = None,
    step: int = 30,
    digits: int = 6,
    digest=hashlib.sha1,
    is_raw_key: bool = False,
) -> str:
    """
    Generates a TOTP value according to RFC 6238.

    :param secret: Base32-encoded string (or raw bytes if is_raw_key is True)
    :param time_val: Unix timestamp (default: current time)
    :param step: Time step in seconds (default: 30s)
    :param digits: Number of digits (default: 6, RFC vectors use 8)
    :param digest: Hash function (default: hashlib.sha1)
    :param is_raw_key: Set True for RFC test vectors where secret is raw bytes
    """
    if time_val is None:
        time_val = time.time()

    counter = int(time_val // step)
    key_bytes = secret if is_raw_key and isinstance(secret, bytes) else _normalize_base32_secret(secret)
    return hotp(key_bytes, counter, digits=digits, digest=digest)


def verify_totp(
    secret: str | bytes,
    code: str,
    current_time: int | float | None = None,
    step: int = 30,
    digits: int = 6,
    window: int = 1,
    last_used_step: int | None = None,
    digest=hashlib.sha1,
    is_raw_key: bool = False,
) -> tuple[bool, int | None]:
    """
    Verifies a TOTP token against clock drift and replay attacks.

    :param secret: Base32 encoded secret (or raw bytes if is_raw_key is True)
    :param code: User supplied OTP code (must be digits only)
    :param current_time: Reference unix timestamp
    :param step: Time step in seconds (30s)
    :param digits: Length of code (6)
    :param window: Steps before and after to accept (+- 1 step = 30s drift tolerance)
    :param last_used_step: Highest counter step already consumed (replay protection)
    :param digest: Hash function
    :param is_raw_key: If raw key bytes are supplied
    :return: (is_valid, step_used)
    """
    if not code or len(code.strip()) != digits or not code.strip().isdigit():
        return False, None

    code_clean = code.strip()

    if current_time is None:
        current_time = time.time()

    current_step = int(current_time // step)
    key_bytes = secret if is_raw_key and isinstance(secret, bytes) else _normalize_base32_secret(secret)

    # Check window from -window to +window
    for offset in range(-window, window + 1):
        step_to_check = current_step + offset

        # Replay prevention: do not allow any step <= last_used_step
        if last_used_step is not None and step_to_check <= last_used_step:
            continue

        candidate = hotp(key_bytes, step_to_check, digits=digits, digest=digest)
        # Constant-time comparison to prevent timing side channels
        if hmac.compare_digest(candidate, code_clean):
            return True, step_to_check

    return False, None


def get_totp_provisioning_uri(
    secret: str,
    account_name: str,
    issuer: str = "Mini SSO",
    period: int = 30,
    digits: int = 6,
) -> str:
    """
    Generates standard Key URI format according to Google Authenticator specification:
    otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30
    """
    encoded_issuer = quote(issuer)
    encoded_account = quote(account_name)
    label = f"{encoded_issuer}:{encoded_account}"
    return (
        f"otpauth://totp/{label}"
        f"?secret={secret}&issuer={encoded_issuer}&algorithm=SHA1&digits={digits}&period={period}"
    )


def generate_qr_svg_data_uri(uri: str) -> str:
    """
    Generates an inline SVG data URI for rendering in web browsers without disk I/O.
    """
    import segno

    qr = segno.make(uri, error="M")
    svg_data = qr.svg_data_uri(scale=4, border=2)
    return svg_data
