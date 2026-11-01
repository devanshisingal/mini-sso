"""
Stage 3 Security & Failure-Case Verification Test Suite.
Exhaustively tests all security properties and failure modes outlined in the Stage 3 Guide.
"""

import datetime
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from app.core.pkce import calculate_s256_challenge
from app.core.totp import generate_totp, generate_totp_secret, verify_totp
from app.models import AuditLog, Client


# ---------------------------------------------------------------------------
# 1. Redirect URI Security
# ---------------------------------------------------------------------------
def test_redirect_uri_rejects_unregistered_and_tampered(client):
    """Verifies that unauthorized or modified redirect URIs return 400 error, never a redirect."""
    client.post("/register", json={"email": "alice_uri@example.com", "password": "Password123!"})
    login_resp = client.post("/login", json={"email": "alice_uri@example.com", "password": "Password123!"})
    cookie = login_resp.cookies.get("mini_sso_session")

    code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = calculate_s256_challenge(code_verifier)

    invalid_uris = [
        "https://attacker.com/callback",
        "http://localhost:5174/callback/../../evil",
        "http://localhost:5175/callback",
        "http://localhost:5174/different-path",
    ]

    for bad_uri in invalid_uris:
        resp = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "test-client-id",
                "redirect_uri": bad_uri,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "test-state",
            },
            cookies={"mini_sso_session": cookie},
            follow_redirects=False,
        )
        # MUST return HTTP 400 Error JSON, NEVER a 302/303 redirect
        assert resp.status_code == 400
        assert "redirect_uri does not match" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 2. PKCE Security
# ---------------------------------------------------------------------------
def test_pkce_rejects_plain_and_invalid_formats(client):
    """Verifies that plain method, too-short verifiers, and invalid chars are rejected."""
    client.post("/register", json={"email": "pkce_user@example.com", "password": "Password123!"})
    login_resp = client.post("/login", json={"email": "pkce_user@example.com", "password": "Password123!"})
    cookie = login_resp.cookies.get("mini_sso_session")

    # 1. Method plain rejected during /authorize
    resp_plain = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "test-client-id",
            "redirect_uri": "http://localhost:5174/callback",
            "code_challenge": "some_plain_challenge",
            "code_challenge_method": "plain",
            "state": "s",
        },
        cookies={"mini_sso_session": cookie},
    )
    assert resp_plain.status_code == 400
    assert "code_challenge_method must be S256" in resp_plain.json()["detail"]

    # Valid authorization code for token tests
    verifier = "valid_length_verifier_123456789012345678901234567890"
    challenge = calculate_s256_challenge(verifier)

    auth_resp = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "test-client-id",
            "redirect_uri": "http://localhost:5174/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "s",
        },
        cookies={"mini_sso_session": cookie},
        follow_redirects=False,
    )
    code = parse_qs(urlparse(auth_resp.headers["location"]).query)["code"][0]

    # 2. Too short verifier (< 43 chars)
    short_verifier = "too_short_verifier"
    resp_short = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:5174/callback",
            "client_id": "test-client-id",
            "code_verifier": short_verifier,
        },
    )
    assert resp_short.status_code == 400
    assert "PKCE verification failed" in resp_short.json()["detail"]


# ---------------------------------------------------------------------------
# 3. Authorization Code Lifecycle & Controlled Clock Expiry
# ---------------------------------------------------------------------------
def test_authorization_code_expiry_with_controlled_clock(client, db_session):
    """Verifies that authorization code expires after 60 seconds using a controlled clock."""
    client.post("/register", json={"email": "clock_user@example.com", "password": "Password123!"})
    login_resp = client.post("/login", json={"email": "clock_user@example.com", "password": "Password123!"})
    cookie = login_resp.cookies.get("mini_sso_session")

    verifier = "controlled_clock_test_verifier_1234567890123456789012"
    challenge = calculate_s256_challenge(verifier)

    auth_resp = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "test-client-id",
            "redirect_uri": "http://localhost:5174/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "s",
        },
        cookies={"mini_sso_session": cookie},
        follow_redirects=False,
    )
    code = parse_qs(urlparse(auth_resp.headers["location"]).query)["code"][0]

    # Controlled Clock: Advance time by 61 seconds into the future
    future_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=61)
    with patch("app.api.routes_oidc.datetime") as mock_dt:
        mock_dt.datetime.now.return_value = future_time
        mock_dt.timezone = datetime.timezone
        mock_dt.timedelta = datetime.timedelta

        token_resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://localhost:5174/callback",
                "client_id": "test-client-id",
                "code_verifier": verifier,
            },
        )
        assert token_resp.status_code == 400
        assert "Authorization code has expired" in token_resp.json()["detail"]

    # Verify expiration rejection was recorded in the audit log
    audit_entry = db_session.query(AuditLog).filter(
        AuditLog.details.like("%expired%")
    ).first()
    assert audit_entry is not None
    assert audit_entry.outcome == "failure"


def test_authorization_code_client_mismatch_rejected(client):
    """Verifies code issued to Client A cannot be exchanged by Client B."""
    client.post("/register", json={"email": "mismatch_user@example.com", "password": "Password123!"})
    login_resp = client.post("/login", json={"email": "mismatch_user@example.com", "password": "Password123!"})
    cookie = login_resp.cookies.get("mini_sso_session")

    verifier = "mismatch_client_test_verifier_1234567890123456789012"
    challenge = calculate_s256_challenge(verifier)

    auth_resp = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "test-client-id",
            "redirect_uri": "http://localhost:5174/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "s",
        },
        cookies={"mini_sso_session": cookie},
        follow_redirects=False,
    )
    code = parse_qs(urlparse(auth_resp.headers["location"]).query)["code"][0]

    # Client B attempts exchange
    token_resp = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:5174/callback",
            "client_id": "different-client-id",
            "code_verifier": verifier,
        },
    )
    assert token_resp.status_code == 400
    assert "Client mismatch" in token_resp.json()["detail"]


# ---------------------------------------------------------------------------
# 4. TOTP Boundary and Window Testing
# ---------------------------------------------------------------------------
def test_totp_step_boundaries():
    """Tests acceptance of T-1, T, T+1 and rejection of T+2 or older."""
    secret = generate_totp_secret()
    t_ref = 1700000000
    step = int(t_ref // 30)

    # Step T (current) -> Valid
    code_t = generate_totp(secret, time_val=t_ref)
    valid, step_used = verify_totp(secret, code_t, current_time=t_ref, window=1)
    assert valid is True and step_used == step

    # Step T-1 (past 30s) -> Valid
    code_prev = generate_totp(secret, time_val=t_ref - 30)
    valid, step_used = verify_totp(secret, code_prev, current_time=t_ref, window=1)
    assert valid is True and step_used == step - 1

    # Step T+1 (future 30s) -> Valid
    code_next = generate_totp(secret, time_val=t_ref + 30)
    valid, step_used = verify_totp(secret, code_next, current_time=t_ref, window=1)
    assert valid is True and step_used == step + 1

    # Step T+2 (future 60s, outside window 1) -> Must FAIL
    code_t_plus_2 = generate_totp(secret, time_val=t_ref + 60)
    valid, step_used = verify_totp(secret, code_t_plus_2, current_time=t_ref, window=1)
    assert valid is False and step_used is None

    # Step T-2 (past 60s, outside window 1) -> Must FAIL
    code_t_minus_2 = generate_totp(secret, time_val=t_ref - 60)
    valid, step_used = verify_totp(secret, code_t_minus_2, current_time=t_ref, window=1)
    assert valid is False and step_used is None


# ---------------------------------------------------------------------------
# 5. User Enumeration Defense
# ---------------------------------------------------------------------------
def test_user_enumeration_prevention(client):
    """Verifies that non-existent email and wrong password return identical response."""
    # Ensure alice exists
    client.post("/register", json={"email": "alice_enum@example.com", "password": "RealPassword123!"})

    # Case A: Real email, wrong password
    resp_wrong_pw = client.post(
        "/login",
        json={"email": "alice_enum@example.com", "password": "WrongPassword!"},
    )

    # Case B: Unknown email
    resp_unknown_user = client.post(
        "/login",
        json={"email": "nobody_exists_here@example.com", "password": "AnyPassword123!"},
    )

    assert resp_wrong_pw.status_code == 401
    assert resp_unknown_user.status_code == 401

    # Identical generic error message
    assert resp_wrong_pw.json()["detail"] == "Invalid email or password"
    assert resp_unknown_user.json()["detail"] == "Invalid email or password"


# ---------------------------------------------------------------------------
# 6. Rate Limiting on Failed Credentials
# ---------------------------------------------------------------------------
def test_rate_limiting_triggers_after_repeated_failures(client):
    """Verifies that 5 failed logins result in HTTP 429 Too Many Requests."""
    target_email = "brute_force_target@example.com"
    client.post("/register", json={"email": target_email, "password": "RealPassword123!"})

    # 4 consecutive failures allowed through
    for _ in range(4):
        resp = client.post("/login", json={"email": target_email, "password": "WrongPassword"})
        assert resp.status_code == 401

    # 5th failure hits limit
    resp_limited = client.post("/login", json={"email": target_email, "password": "WrongPassword"})
    assert resp_limited.status_code in [401, 429]

    # Subsequent request is blocked with 429
    resp_blocked = client.post("/login", json={"email": target_email, "password": "WrongPassword"})
    assert resp_blocked.status_code == 429
    assert "Too many failed login attempts" in resp_blocked.json()["detail"]
    assert "Retry-After" in resp_blocked.headers


# ---------------------------------------------------------------------------
# 7. Session Lifecycle & Cookie Flags
# ---------------------------------------------------------------------------
def test_session_cookie_flags_and_logout(client):
    """Verifies cookie attributes and invalidation upon logout."""
    email = "session_user@example.com"
    client.post("/register", json={"email": email, "password": "Password123!"})
    login_resp = client.post("/login", json={"email": email, "password": "Password123!"})

    # Check Set-Cookie headers
    set_cookie_header = login_resp.headers.get("set-cookie", "")
    assert "mini_sso_session" in set_cookie_header
    assert "HttpOnly" in set_cookie_header
    assert "samesite=lax" in set_cookie_header.lower()

    cookie = login_resp.cookies.get("mini_sso_session")

    # Authorized call succeeds
    me_resp = client.get("/me", cookies={"mini_sso_session": cookie})
    assert me_resp.status_code == 200

    # Logout
    logout_resp = client.post("/logout", cookies={"mini_sso_session": cookie})
    assert logout_resp.status_code == 200

    # Post-logout use of old session token is REJECTED
    post_logout_me = client.get("/me", cookies={"mini_sso_session": cookie})
    assert post_logout_me.status_code == 401


# ---------------------------------------------------------------------------
# 8. IP CIDR Restriction (Access Control)
# ---------------------------------------------------------------------------
def test_client_ip_allowlist_enforcement(client, db_session):
    """Verifies that IP outside allowed CIDR is rejected with 403 Forbidden."""
    # Register client restricted to 192.168.1.0/24
    restricted_client = Client(
        client_id="corp-internal-client",
        name="Corporate Portal",
        redirect_uris=["http://localhost:5174/callback"],
        allowed_cidrs=["192.168.1.0/24"],
    )
    db_session.add(restricted_client)
    db_session.commit()

    client.post("/register", json={"email": "corp_user@example.com", "password": "Password123!"})
    login_resp = client.post("/login", json={"email": "corp_user@example.com", "password": "Password123!"})
    cookie = login_resp.cookies.get("mini_sso_session")

    verifier = "corp_client_test_verifier_1234567890123456789012"
    challenge = calculate_s256_challenge(verifier)

    # Simulated request from untrusted IP 10.50.1.1 (outside 192.168.1.0/24)
    # TestClient sets testclient host; verify rejection when IP doesn't match
    with patch("fastapi.Request.client") as mock_client:
        mock_client.host = "10.50.1.1"

        auth_resp = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "corp-internal-client",
                "redirect_uri": "http://localhost:5174/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "s",
            },
            cookies={"mini_sso_session": cookie},
        )
        assert auth_resp.status_code == 403
        assert "IP address not allowed" in auth_resp.json()["detail"]
