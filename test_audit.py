
import os
import uuid

os.environ.setdefault(
    "TRUSTVAULT_SECRET_KEY",
    "trustvault-dev-secret-key-123456789"
)

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def create_user(username, role):
    response = client.post(
        "/api/register",
        json={
            "username": username,
            "password": "TestPass123!",
            "role": role
        }
    )
    assert response.status_code == 200, response.text

    login = client.post(
        "/api/login",
        data={
            "username": username,
            "password": "TestPass123!"
        }
    )
    assert login.status_code == 200, login.text

    token = login.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_audit_log_access_control():
    unique = uuid.uuid4().hex[:10]

    owner_headers = create_user(f"audit_owner_{unique}", "owner")
    viewer_headers = create_user(f"audit_viewer_{unique}", "viewer")

    # Viewer must not be allowed to view admin-only audit logs.
    response = client.get(
        "/api/audit-logs",
        headers=viewer_headers
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Access denied. Admins only."
