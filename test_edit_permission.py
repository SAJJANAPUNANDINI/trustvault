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


def test_edit_permission_allows_metadata_update():
    unique = uuid.uuid4().hex[:8]

    owner_name = f"edit_owner_{unique}"
    viewer_name = f"edit_viewer_{unique}"

    owner_headers = register_and_login(owner_name, "owner")
    viewer_headers = register_and_login(viewer_name, "viewer")

    upload = client.post(
        "/api/documents/upload",
        headers=owner_headers,
        data={
            "title": f"Original_{unique}",
            "category": "General"
        },
        files={
            "file": (
                "edit_test.txt",
                b"Edit permission test",
                "text/plain"
            )
        }
    )
    assert upload.status_code == 200, upload.text
    doc_id = upload.json()["document_id"]

    # Grant edit permission to the viewer.
    grant = client.post(
        f"/api/documents/{doc_id}/grant",
        headers=owner_headers,
        json={
            "username": viewer_name,
            "access_type": "edit"
        }
    )
    assert grant.status_code == 200, grant.text

    # User with edit permission should update metadata.
    update = client.post(
        f"/api/documents/{doc_id}/update",
        headers=viewer_headers,
        json={
            "title": f"Updated_{unique}",
            "category": "Project Documents"
        }
    )

    assert update.status_code == 200, update.text
    assert update.json()["title"] == f"Updated_{unique}"
