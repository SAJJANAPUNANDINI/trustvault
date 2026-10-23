import os
import uuid

# Set the secret before importing main.py.
os.environ.setdefault(
    "TRUSTVAULT_SECRET_KEY",
    "trustvault-dev-secret-key-123456789"
)

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def register_and_login(username, role):
    # Register a new user.
    register_response = client.post(
        "/api/register",
        json={
            "username": username,
            "password": "TestPass123!",
            "role": role
        }
    )
    assert register_response.status_code == 200, register_response.text

    # Login using form data.
    login_response = client.post(
        "/api/login",
        json={
            "username": username,
            "password": "TestPass123!"
        }
    )
    assert login_response.status_code == 200, login_response.text

    token = login_response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_grant_and_revoke_permission():
    unique_id = uuid.uuid4().hex[:10]
    owner_name = f"owner_{unique_id}"
    viewer_name = f"viewer_{unique_id}"

    # 1. Create owner and viewer accounts.
    owner_headers = register_and_login(owner_name, "owner")
    viewer_headers = register_and_login(viewer_name, "viewer")

    # 2. Owner uploads a document.
    upload_response = client.post(
        "/api/documents/upload",
        headers=owner_headers,
        data={
            "title": "Permission Test Document",
            "category": "Confidential"
        },
        files={
            "file": (
                "permission_test.txt",
                b"This is a confidential test document.",
                "text/plain"
            )
        }
    )

    assert upload_response.status_code == 200, upload_response.text
    document_id = upload_response.json()["document_id"]

    # 3. Before permission is granted, viewer must be denied.
    denied_response = client.get(
        f"/api/documents/{document_id}/download",
        headers=viewer_headers
    )
    assert denied_response.status_code == 403

    # 4. Owner grants read permission to the viewer.
    grant_response = client.post(
        f"/api/documents/{document_id}/grant",
        headers=owner_headers,
        json={
            "username": viewer_name,
            "access_type": "read"
        }
    )
    assert grant_response.status_code == 200, grant_response.text

    # 5. Viewer can now download the document.
    allowed_response = client.get(
        f"/api/documents/{document_id}/download",
        headers=viewer_headers
    )
    assert allowed_response.status_code == 200
    assert allowed_response.content == (
        b"This is a confidential test document."
    )

    # 6. Owner revokes the viewer's permission.
    revoke_response = client.post(
        f"/api/documents/{document_id}/revoke",
        headers=owner_headers,
        json={
            "username": viewer_name,
            "access_type": "read"
        }
    )
    assert revoke_response.status_code == 200, revoke_response.text
    assert revoke_response.json()["permission_removed"] is True

    # 7. After revocation, viewer must be denied again.
    revoked_response = client.get(
        f"/api/documents/{document_id}/download",
        headers=viewer_headers
    )
    assert revoked_response.status_code == 403
    assert revoked_response.json()["detail"] == "Access denied"
