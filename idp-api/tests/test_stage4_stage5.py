"""
Stage 4 & Stage 5 Feature Tests:
- X-Request-ID middleware & structured logging
- Password max_length DoS mitigation
- Tamper-evident cryptographic audit log verification & tampering detection
- MFA backup recovery codes generation, authentication, and single-use enforcement
- RSA signing key rotation & multi-key JWKS continuity
- Maintenance cleanup of expired records
"""

import datetime

from sqlalchemy import select

from app.models import AuditLog, AuthorizationCode, SessionRecord, utcnow


def test_request_id_middleware(client):
    # 1. Automatic generation of X-Request-ID
    resp1 = client.get("/health")
    assert resp1.status_code == 200
    assert "x-request-id" in resp1.headers
    req_id = resp1.headers["x-request-id"]
    assert len(req_id) > 10

    # 2. Propagation of client-supplied X-Request-ID
    custom_trace_id = "trace-custom-uuid-12345"
    resp2 = client.get("/health", headers={"X-Request-ID": custom_trace_id})
    assert resp2.status_code == 200
    assert resp2.headers.get("x-request-id") == custom_trace_id


def test_password_max_length_dos_protection(client):
    # Passwords longer than 128 chars must be rejected at input schema level
    oversized_password = "A" * 2048

    # Registration rejection
    reg_resp = client.post(
        "/register",
        json={"email": "dos_test@example.com", "password": oversized_password},
    )
    assert reg_resp.status_code == 422

    # Login rejection
    login_resp = client.post(
        "/login",
        json={"email": "dos_test@example.com", "password": oversized_password},
    )
    assert login_resp.status_code == 422


def test_tamper_evident_audit_log_verification(client, db_session):
    admin_headers = {"X-Admin-Key": "mini-sso-default-admin-secret-key"}

    # 1. Trigger legitimate operations to build audit chain
    client.post("/register", json={"email": "audit_user1@example.com", "password": "Password123!"})
    client.post("/register", json={"email": "audit_user2@example.com", "password": "Password123!"})

    # 2. Check verification endpoint: intact chain
    verify_resp = client.get("/admin/audit-log/verify", headers=admin_headers)
    assert verify_resp.status_code == 200
    data = verify_resp.json()
    assert data["valid"] is True
    assert data["total_verified"] >= 2
    assert data["latest_hash"] is not None

    # 3. Simulate database tampering by modifying an entry's event without updating hash
    tampered_entry = db_session.scalars(
        select(AuditLog).order_by(AuditLog.id.desc()).limit(1)
    ).first()
    assert tampered_entry is not None
    tampered_id = tampered_entry.id
    tampered_entry.details = "ATTACKER_TAMPERED_DETAILS"
    db_session.commit()

    # 4. Verification must detect tampering and report tampered ID
    tamper_check_resp = client.get("/admin/audit-log/verify", headers=admin_headers)
    assert tamper_check_resp.status_code == 200
    tamper_data = tamper_check_resp.json()
    assert tamper_data["valid"] is False
    assert tamper_data["tampered_id"] == tampered_id
    assert "Content tampering" in tamper_data["reason"]


def test_backup_recovery_codes_flow(client):
    # 1. Register and login
    email = "recovery_user@example.com"
    pwd = "RecoveryPassword123!"
    client.post("/register", json={"email": email, "password": pwd})
    login_resp = client.post("/login", json={"email": email, "password": pwd})
    cookie = login_resp.cookies.get("mini_sso_session")

    # 2. Enroll MFA: must return 10 recovery codes
    enroll_resp = client.post("/mfa/enroll", cookies={"mini_sso_session": cookie})
    assert enroll_resp.status_code == 200
    data = enroll_resp.json()
    recovery_codes = data.get("recovery_codes", [])
    assert len(recovery_codes) == 10
    code_to_use = recovery_codes[0]

    # Confirm MFA with valid TOTP to complete enrollment
    from app.core.totp import generate_totp
    totp_code = generate_totp(data["secret"])
    confirm_resp = client.post("/mfa/verify", json={"code": totp_code}, cookies={"mini_sso_session": cookie})
    assert confirm_resp.status_code == 200

    # 3. User logs in from fresh browser (TOTP required)
    login_mfa_resp = client.post("/login", json={"email": email, "password": pwd})
    assert login_mfa_resp.status_code == 200
    assert login_mfa_resp.json()["status"] == "mfa_required"
    temp_cookie = login_mfa_resp.cookies.get("mini_sso_session")

    # 4. User lost phone, authenticates with backup recovery code
    recovery_resp = client.post(
        "/mfa/recovery",
        json={"code": code_to_use},
        cookies={"mini_sso_session": temp_cookie},
    )
    assert recovery_resp.status_code == 200
    assert recovery_resp.json()["status"] == "success"

    # User can now access protected /me endpoint
    me_resp = client.get("/me", cookies={"mini_sso_session": temp_cookie})
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == email

    # 5. Replay attempt: same recovery code cannot be used again
    # Log in again to get fresh unverified session
    replay_login = client.post("/login", json={"email": email, "password": pwd})
    fresh_temp_cookie = replay_login.cookies.get("mini_sso_session")
    replay_resp = client.post(
        "/mfa/recovery",
        json={"code": code_to_use},
        cookies={"mini_sso_session": fresh_temp_cookie},
    )
    assert replay_resp.status_code == 400
    assert "Invalid or already-used" in replay_resp.json()["detail"]


def test_signing_key_rotation_and_graceful_jwks(client):
    admin_headers = {"X-Admin-Key": "mini-sso-default-admin-secret-key"}

    # Initial JWKS check
    jwks1 = client.get("/.well-known/jwks.json").json()
    assert len(jwks1["keys"]) >= 1
    initial_kid = jwks1["keys"][0]["kid"]

    # Rotate signing key
    rotate_resp = client.post("/admin/keys/rotate", headers=admin_headers)
    assert rotate_resp.status_code == 200
    rotate_data = rotate_resp.json()
    assert rotate_data["status"] == "success"
    assert rotate_data["new_kid"] != initial_kid
    assert rotate_data["previous_kid"] == initial_kid

    # Check updated JWKS contains BOTH keys for backward-compatible verification
    jwks2 = client.get("/.well-known/jwks.json").json()
    kids = [k["kid"] for k in jwks2["keys"]]
    assert rotate_data["new_kid"] in kids
    assert initial_kid in kids


def test_maintenance_cleanup_expired_records(client, db_session):
    admin_headers = {"X-Admin-Key": "mini-sso-default-admin-secret-key"}
    past_time = utcnow() - datetime.timedelta(hours=2)

    # Seed an expired authorization code
    expired_code = AuthorizationCode(
        code_hash="expired_hash_12345",
        client_id="demo-client-app",
        user_id="dummy-user-id",
        redirect_uri="http://localhost:5174/callback",
        code_challenge="dummy_challenge",
        expires_at=past_time,
    )
    db_session.add(expired_code)

    # Seed an expired session
    expired_session = SessionRecord(
        id_hash="expired_session_hash_12345",
        user_id="dummy-user-id",
        expires_at=past_time,
    )
    db_session.add(expired_session)
    db_session.commit()

    # Run maintenance cleanup
    cleanup_resp = client.post("/admin/maintenance/cleanup", headers=admin_headers)
    assert cleanup_resp.status_code == 200
    result = cleanup_resp.json()
    assert result["purged_codes"] >= 1
    assert result["purged_sessions"] >= 1

    # Verify records no longer exist in database
    remaining_code = db_session.scalars(
        select(AuthorizationCode).where(AuthorizationCode.code_hash == "expired_hash_12345")
    ).first()
    assert remaining_code is None

    remaining_session = db_session.scalars(
        select(SessionRecord).where(SessionRecord.id_hash == "expired_session_hash_12345")
    ).first()
    assert remaining_session is None
