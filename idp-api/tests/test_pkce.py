"""
Tests for PKCE (RFC 7636) S256 challenge generation and verification.
"""

from app.core.pkce import (
    calculate_s256_challenge,
    is_valid_verifier_format,
    verify_pkce,
)


def test_pkce_valid_s256():
    # Example RFC 7636 test verifier
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert is_valid_verifier_format(verifier) is True

    challenge = calculate_s256_challenge(verifier)
    # RFC 7636 Appendix B test vector challenge for this verifier:
    # "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

    assert verify_pkce(verifier, challenge, method="S256") is True


def test_pkce_rejects_wrong_verifier():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = calculate_s256_challenge(verifier)

    wrong_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXz"
    assert verify_pkce(wrong_verifier, challenge, method="S256") is False


def test_pkce_rejects_plain_method():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    # Even if challenge == verifier, 'plain' method must be rejected
    assert verify_pkce(verifier, verifier, method="plain") is False
    assert verify_pkce(verifier, verifier, method="none") is False


def test_pkce_verifier_length_constraints():
    # RFC 7636 requires 43 <= len <= 128
    too_short = "A" * 42
    valid_min = "A" * 43
    valid_max = "A" * 128
    too_long = "A" * 129

    assert is_valid_verifier_format(too_short) is False
    assert is_valid_verifier_format(valid_min) is True
    assert is_valid_verifier_format(valid_max) is True
    assert is_valid_verifier_format(too_long) is False

    # Disallowed characters
    invalid_chars = "A" * 42 + "@"
    assert is_valid_verifier_format(invalid_chars) is False
