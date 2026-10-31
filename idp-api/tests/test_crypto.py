"""
Tests for RS256 token signing, JWKS generation, and claim validation.
"""

import jwt
import pytest

from app.core.jwt_service import JwtService, generate_rsa_key_pair


@pytest.fixture
def jwt_service():
    kid, priv_pem, pub_pem = generate_rsa_key_pair(2048)
    return JwtService(kid=kid, private_pem=priv_pem, public_pem=pub_pem, issuer="http://test-idp:8000")


def test_jwks_export_format(jwt_service):
    jwks = jwt_service.get_jwks()
    assert "keys" in jwks
    assert len(jwks["keys"]) == 1

    key = jwks["keys"][0]
    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"
    assert key["kid"] == jwt_service.kid
    assert "n" in key
    assert "e" in key


def test_issue_and_verify_id_token(jwt_service):
    token = jwt_service.issue_id_token(
        subject="user-123",
        audience="client-abc",
        email="user@example.com",
        nonce="random-nonce-xyz",
    )

    # Check unverified header has kid and RS256
    headers = jwt.get_unverified_header(token)
    assert headers["alg"] == "RS256"
    assert headers["kid"] == jwt_service.kid

    # Verify token
    payload = jwt_service.verify_token(token, audience="client-abc")
    assert payload["iss"] == "http://test-idp:8000"
    assert payload["sub"] == "user-123"
    assert payload["aud"] == "client-abc"
    assert payload["email"] == "user@example.com"
    assert payload["nonce"] == "random-nonce-xyz"
    assert "exp" in payload
    assert "iat" in payload


def test_verify_token_rejects_wrong_audience(jwt_service):
    token = jwt_service.issue_id_token(
        subject="user-123",
        audience="client-correct",
        email="user@example.com",
    )

    with pytest.raises(jwt.InvalidAudienceError):
        jwt_service.verify_token(token, audience="client-wrong")


def test_verify_token_rejects_tampered_signature(jwt_service):
    token = jwt_service.issue_id_token(
        subject="user-123",
        audience="client-abc",
        email="user@example.com",
    )
    # Tamper with the token string
    tampered = token[:-4] + "AAAA"

    with pytest.raises(jwt.PyJWTError):
        jwt_service.verify_token(tampered, audience="client-abc")
