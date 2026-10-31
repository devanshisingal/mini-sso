"""
Integration tests for the full OpenID Connect Authorization Code Flow with PKCE S256,
JWKS verification, and failure modes.
"""

from urllib.parse import parse_qs, urlparse

import jwt

from app.core.pkce import calculate_s256_challenge


def test_discovery_and_jwks(client):
    # Discovery
    resp = client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    data = resp.json()
    assert data["issuer"] == "http://localhost:8000"
    assert "/authorize" in data["authorization_endpoint"]
    assert "/token" in data["token_endpoint"]
    assert "/userinfo" in data["userinfo_endpoint"]
    assert "/.well-known/jwks.json" in data["jwks_uri"]
    assert "S256" in data["code_challenge_methods_supported"]

    # JWKS
    resp_jwks = client.get("/.well-known/jwks.json")
    assert resp_jwks.status_code == 200
    jwks = resp_jwks.json()
    assert "keys" in jwks
    assert len(jwks["keys"]) >= 1
    assert jwks["keys"][0]["kty"] == "RSA"
    assert jwks["keys"][0]["alg"] == "RS256"


def test_full_oidc_pkce_flow(client):
    # 1. Register a user
    email = "bob@example.com"
    password = "SecurePassword123!"
    reg_resp = client.post("/register", json={"email": email, "password": password})
    assert reg_resp.status_code == 201

    # 2. Login to establish session
    login_resp = client.post("/login", json={"email": email, "password": password})
    assert login_resp.status_code == 200
    assert login_resp.json()["status"] == "authenticated"

    # Extract session cookie
    session_cookie = login_resp.cookies.get("mini_sso_session")
    assert session_cookie is not None

    # 3. Demo App prepares PKCE
    code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    code_challenge = calculate_s256_challenge(code_verifier)
    state = "random-state-12345"
    nonce = "random-nonce-67890"

    # 4. GET /authorize
    auth_params = {
        "response_type": "code",
        "client_id": "test-client-id",
        "redirect_uri": "http://localhost:5174/callback",
        "scope": "openid profile email",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "nonce": nonce,
    }

    auth_resp = client.get(
        "/authorize",
        params=auth_params,
        cookies={"mini_sso_session": session_cookie},
        follow_redirects=False,
    )
    assert auth_resp.status_code == 302
    redirect_target = auth_resp.headers["location"]
    parsed = urlparse(redirect_target)
    query_params = parse_qs(parsed.query)

    assert "code" in query_params
    assert query_params["state"][0] == state
    auth_code = query_params["code"][0]

    # 5. Swap code + verifier at /token
    token_resp = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": "http://localhost:5174/callback",
            "client_id": "test-client-id",
            "code_verifier": code_verifier,
        },
    )
    assert token_resp.status_code == 200
    tokens = token_resp.json()
    assert "access_token" in tokens
    assert "id_token" in tokens
    assert tokens["token_type"] == "Bearer"

    # 6. Verify ID token claims
    id_token = tokens["id_token"]
    unverified_payload = jwt.decode(id_token, options={"verify_signature": False})
    assert unverified_payload["email"] == email
    assert unverified_payload["aud"] == "test-client-id"
    assert unverified_payload["nonce"] == nonce

    # 7. Call /userinfo with Access Token
    userinfo_resp = client.get(
        "/userinfo",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert userinfo_resp.status_code == 200
    userinfo = userinfo_resp.json()
    assert userinfo["email"] == email

    # 8. Replay check: attempting to reuse the SAME authorization code must FAIL
    replay_token_resp = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": "http://localhost:5174/callback",
            "client_id": "test-client-id",
            "code_verifier": code_verifier,
        },
    )
    assert replay_token_resp.status_code == 400
    assert "already been used" in replay_token_resp.json()["detail"]


def test_authorize_rejects_unregistered_redirect_uri(client):
    client.post("/register", json={"email": "carol@example.com", "password": "Password123!"})
    login_resp = client.post("/login", json={"email": "carol@example.com", "password": "Password123!"})
    session_cookie = login_resp.cookies.get("mini_sso_session")

    code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    code_challenge = calculate_s256_challenge(code_verifier)

    auth_resp = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "test-client-id",
            "redirect_uri": "https://attacker.evil.com/callback",  # Unregistered URI
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": "xyz",
        },
        cookies={"mini_sso_session": session_cookie},
    )
    assert auth_resp.status_code == 400
    assert "redirect_uri does not match" in auth_resp.json()["detail"]


def test_token_rejects_wrong_code_verifier(client):
    client.post("/register", json={"email": "dave@example.com", "password": "Password123!"})
    login_resp = client.post("/login", json={"email": "dave@example.com", "password": "Password123!"})
    session_cookie = login_resp.cookies.get("mini_sso_session")

    code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    code_challenge = calculate_s256_challenge(code_verifier)

    auth_resp = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "test-client-id",
            "redirect_uri": "http://localhost:5174/callback",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": "xyz",
        },
        cookies={"mini_sso_session": session_cookie},
        follow_redirects=False,
    )
    query_params = parse_qs(urlparse(auth_resp.headers["location"]).query)
    auth_code = query_params["code"][0]

    # Wrong verifier
    wrong_verifier = "wrong_code_verifier_123456789012345678901234567890"
    token_resp = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": "http://localhost:5174/callback",
            "client_id": "test-client-id",
            "code_verifier": wrong_verifier,
        },
    )
    assert token_resp.status_code == 400
    assert "PKCE verification failed" in token_resp.json()["detail"]
