"""
Integration tests for Admin endpoints: client management, CIDR restrictions, and audit logging.
"""


def test_admin_access_control(client):
    # 1. First user registered becomes Admin
    client.post("/register", json={"email": "admin@example.com", "password": "AdminPassword123!"})
    admin_login = client.post("/login", json={"email": "admin@example.com", "password": "AdminPassword123!"})
    admin_cookie = admin_login.cookies.get("mini_sso_session")

    # 2. Second user registered is a regular non-admin
    client.post("/register", json={"email": "regular@example.com", "password": "UserPass123!"})
    login_resp = client.post("/login", json={"email": "regular@example.com", "password": "UserPass123!"})
    user_cookie = login_resp.cookies.get("mini_sso_session")

    # Regular user forbidden from admin endpoints
    resp_clients = client.get("/admin/clients", cookies={"mini_sso_session": user_cookie})
    assert resp_clients.status_code == 403

    resp_audit = client.get("/admin/audit-log", cookies={"mini_sso_session": user_cookie})
    assert resp_audit.status_code == 403

    # Admin user permitted
    resp_admin_clients = client.get("/admin/clients", cookies={"mini_sso_session": admin_cookie})
    assert resp_admin_clients.status_code == 200

    # Admin access using X-Admin-Key permitted
    resp_with_key = client.get(
        "/admin/clients",
        headers={"X-Admin-Key": "mini-sso-default-admin-secret-key"},
    )
    assert resp_with_key.status_code == 200


def test_admin_client_registration_and_audit_log(client):
    headers = {"X-Admin-Key": "mini-sso-default-admin-secret-key"}

    # 1. Register a new client application
    new_client_payload = {
        "client_id": "analytics-dashboard",
        "name": "Internal Analytics Service",
        "redirect_uris": ["https://analytics.example.com/auth/callback"],
        "allowed_cidrs": ["10.0.0.0/8", "192.168.1.0/24"],
    }
    create_resp = client.post("/admin/clients", json=new_client_payload, headers=headers)
    assert create_resp.status_code == 201
    created = create_resp.json()
    assert created["client_id"] == "analytics-dashboard"
    assert created["redirect_uris"] == ["https://analytics.example.com/auth/callback"]

    # 2. List clients
    list_resp = client.get("/admin/clients", headers=headers)
    assert list_resp.status_code == 200
    clients_list = list_resp.json()
    client_ids = [c["client_id"] for c in clients_list]
    assert "analytics-dashboard" in client_ids

    # 3. View audit log
    audit_resp = client.get("/admin/audit-log", headers=headers)
    assert audit_resp.status_code == 200
    logs = audit_resp.json()
    assert len(logs) > 0
    # Audit log entries have timestamp, event, outcome
    assert "timestamp" in logs[0]
    assert "event" in logs[0]
    assert "outcome" in logs[0]
