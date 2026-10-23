import os
import uuid

os.environ.setdefault(
    "TRUSTVAULT_SECRET_KEY",
    "trustvault-dev-secret-key-123456789"
)

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def register_and_login(username, role):
    register = client.post(
        "/api/register",
        json={
            "username": username,
            "password": "TestPass123!",
            "role": role
        }
    )
    assert register.status_code == 200, register.text

    login = client.post(
        "/api/login",
        json={
            "username": username,
            "password": "TestPass123!"
        }
    )
    assert login.status_code == 200, login.text

    return {
        "Authorization":
        f"Bearer {login.json()['access_token']}"
    }


def test_revoked_permission_blocks_download_immediately():
    unique = uuid.uuid4().hex[:8]
    owner_name = f"revoke_owner_{unique}"
    viewer_name = f"revoke_viewer_{unique}"

    owner_headers = register_and_login(owner_name, "owner")
    viewer_headers = register_and_login(viewer_name, "viewer")

    upload = client.post(
        "/api/documents/upload",
        headers=owner_headers,
        data={
            "title": f"RevocationTest_{unique}",
            "category": "Confidential"
        },
        files={
            "file": (
                "revocation.txt",
                b"Test immediate revocation",
                "text/plain"
            )
        }
    )
    assert upload.status_code == 200, upload.text
    doc_id = upload.json()["document_id"]

    permission = {
        "username": viewer_name,
        "access_type": "read"
    }

    grant = client.post(
        f"/api/documents/{doc_id}/grant",
        headers=owner_headers,
        json=permission
    )
    assert grant.status_code == 200, grant.text

    # Download must work before revocation.
    before = client.get(
        f"/api/documents/{doc_id}/download",
        headers=viewer_headers
    )
    assert before.status_code == 200

    revoke = client.post(
        f"/api/documents/{doc_id}/revoke",
        headers=owner_headers,
        json=permission
    )
    assert revoke.status_code == 200, revoke.text

    # The same token must no longer allow downloading.
    after = client.get(
        f"/api/documents/{doc_id}/download",
        headers=viewer_headers
    )
    assert after.status_code == 403
