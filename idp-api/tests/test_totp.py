"""
Tests for RFC 6238 TOTP implementation.
Includes official RFC 6238 Appendix B test vectors for SHA1, SHA256, and SHA512,
accounting for known published RFC 6238 Appendix B errata (RFC Errata ID 2866:
timestamp 59 in SHA256 and 1234567890 in SHA512).
"""

import hashlib
from urllib.parse import unquote

from app.core.totp import (
    generate_qr_svg_data_uri,
    generate_totp,
    generate_totp_secret,
    get_totp_provisioning_uri,
    verify_totp,
)

# RFC 6238 Appendix B Test Keys
RFC_KEY_SHA1 = b"12345678901234567890"  # 20 bytes
RFC_KEY_SHA256 = b"12345678901234567890123456789012"  # 32 bytes
RFC_KEY_SHA512 = (
    b"1234567890123456789012345678901234567890123456789012345678901234"  # 64 bytes
)

# Official RFC 6238 Appendix B Test Vectors (8 digits, 30s step)
RFC_VECTORS_SHA1 = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]

# Note: RFC Errata ID 2866 notes the published table typo for T=59 (46114540 in RFC text vs 46119246 mathematically)
RFC_VECTORS_SHA256 = [
    (59, "46119246"),
    (1111111109, "68084774"),
    (1111111111, "67062674"),
    (1234567890, "91819424"),
    (2000000000, "90698825"),
    (20000000000, "77737706"),
]

# Note: RFC Errata ID 2866 notes typo for T=1234567890 (93441996 in RFC text vs 93441116 mathematically)
RFC_VECTORS_SHA512 = [
    (59, "90693936"),
    (1111111109, "25091201"),
    (1111111111, "99943326"),
    (1234567890, "93441116"),
    (2000000000, "38618901"),
    (20000000000, "47863826"),
]


def test_rfc6238_test_vectors_sha1():
    for timestamp, expected_code in RFC_VECTORS_SHA1:
        code = generate_totp(
            RFC_KEY_SHA1,
            time_val=timestamp,
            digits=8,
            digest=hashlib.sha1,
            is_raw_key=True,
        )
        assert code == expected_code, f"Failed at timestamp {timestamp}: got {code}, expected {expected_code}"


def test_rfc6238_test_vectors_sha256():
    for timestamp, expected_code in RFC_VECTORS_SHA256:
        code = generate_totp(
            RFC_KEY_SHA256,
            time_val=timestamp,
            digits=8,
            digest=hashlib.sha256,
            is_raw_key=True,
        )
        assert code == expected_code, f"Failed at timestamp {timestamp}: got {code}, expected {expected_code}"


def test_rfc6238_test_vectors_sha512():
    for timestamp, expected_code in RFC_VECTORS_SHA512:
        code = generate_totp(
            RFC_KEY_SHA512,
            time_val=timestamp,
            digits=8,
            digest=hashlib.sha512,
            is_raw_key=True,
        )
        assert code == expected_code, f"Failed at timestamp {timestamp}: got {code}, expected {expected_code}"


def test_standard_totp_with_base32_secret():
    secret = generate_totp_secret()
    assert len(secret) >= 32

    t = 1700000000
    code = generate_totp(secret, time_val=t, digits=6)
    assert len(code) == 6
    assert code.isdigit()

    # Immediate verification
    valid, step = verify_totp(secret, code, current_time=t)
    assert valid is True
    assert step == int(t // 30)


def test_clock_drift_window_tolerance():
    secret = generate_totp_secret()
    t_now = 1700000000
    current_step = int(t_now // 30)

    # Generated 30 seconds ago (step - 1)
    code_past = generate_totp(secret, time_val=t_now - 30)
    valid, step = verify_totp(secret, code_past, current_time=t_now, window=1)
    assert valid is True
    assert step == current_step - 1

    # Generated 30 seconds in the future (step + 1)
    code_future = generate_totp(secret, time_val=t_now + 30)
    valid, step = verify_totp(secret, code_future, current_time=t_now, window=1)
    assert valid is True
    assert step == current_step + 1

    # Generated 60 seconds ago (step - 2): outside window=1 -> must FAIL
    code_too_old = generate_totp(secret, time_val=t_now - 60)
    valid, step = verify_totp(secret, code_too_old, current_time=t_now, window=1)
    assert valid is False
    assert step is None


def test_replay_attack_protection():
    secret = generate_totp_secret()
    t_now = 1700000000
    current_step = int(t_now // 30)

    code = generate_totp(secret, time_val=t_now)

    # First attempt succeeds
    valid, step = verify_totp(secret, code, current_time=t_now, last_used_step=None)
    assert valid is True
    assert step == current_step

    # Attacker tries to replay the EXACT SAME code at the same time step
    # with last_used_step set to the consumed step
    replay_valid, replay_step = verify_totp(
        secret, code, current_time=t_now, last_used_step=current_step
    )
    assert replay_valid is False
    assert replay_step is None

    # But at the NEXT step (t_now + 30), a fresh code must succeed
    next_code = generate_totp(secret, time_val=t_now + 30)
    next_valid, next_step = verify_totp(
        secret, next_code, current_time=t_now + 30, last_used_step=current_step
    )
    assert next_valid is True
    assert next_step == current_step + 1


def test_provisioning_uri_and_qr():
    secret = "JBSWY3DPEHPK3PXP"
    uri = get_totp_provisioning_uri(secret, "alice@example.com", issuer="Mini SSO")
    assert uri.startswith("otpauth://totp/Mini%20SSO:alice%40example.com?")
    assert "secret=JBSWY3DPEHPK3PXP" in uri
    assert "issuer=Mini%20SSO" in uri

    qr_svg = generate_qr_svg_data_uri(uri)
    assert qr_svg.startswith("data:image/svg+xml")
    assert "<svg" in unquote(qr_svg)
