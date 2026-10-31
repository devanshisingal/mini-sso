"""
Integration tests for TOTP 2FA enrollment, login requirement, and replay protection.
"""

from app.core.totp import generate_totp


def test_mfa_enrollment_and_enforced_login(client):
    # 1. Register & login
    email = "eve@example.com"
    pwd = "StrongPassword987!"
    client.post("/register", json={"email": email, "password": pwd})
    login_resp = client.post("/login", json={"email": email, "password": pwd})
    cookie = login_resp.cookies.get("mini_sso_session")

    # 2. Enroll MFA
    enroll_resp = client.post("/mfa/enroll", cookies={"mini_sso_session": cookie})
    assert enroll_resp.status_code == 200
    enroll_data = enroll_resp.json()
    secret = enroll_data["secret"]
    assert "data:image/svg+xml" in enroll_data["qr_code_svg"]
    assert f"secret={secret}" in enroll_data["provisioning_uri"]

    # 3. Verify with wrong code -> fails
    bad_verify = client.post(
        "/mfa/verify",
        json={"code": "000000"},
        cookies={"mini_sso_session": cookie},
    )
    assert bad_verify.status_code == 400

    # 4. Verify with genuine code -> succeeds
    valid_code = generate_totp(secret)
    good_verify = client.post(
        "/mfa/verify",
        json={"code": valid_code},
        cookies={"mini_sso_session": cookie},
    )
    assert good_verify.status_code == 200
    assert good_verify.json()["status"] == "success"

    # 5. Logout
    client.post("/logout", cookies={"mini_sso_session": cookie})

    # 6. Re-login now MUST return mfa_required
    login2 = client.post("/login", json={"email": email, "password": pwd})
    assert login2.status_code == 200
    data2 = login2.json()
    assert data2["status"] == "mfa_required"
    cookie2 = login2.cookies.get("mini_sso_session")

    # 7. Submitting same OTP code immediately fails if within same step (replay protection)
    replay_verify = client.post(
        "/mfa/verify",
        json={"code": valid_code},
        cookies={"mini_sso_session": cookie2},
    )
    assert replay_verify.status_code == 400
