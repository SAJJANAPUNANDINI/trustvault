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


def test_unauthorized_user_cannot_download_document():
    unique = uuid.uuid4().hex[:8]

    owner_headers = register_and_login(
        f"owner_{unique}", "owner"
    )
    viewer_headers = register_and_login(
        f"viewer_{unique}", "viewer"
    )

    upload = client.post(
        "/api/documents/upload",
        headers=owner_headers,
        data={
            "title": f"PrivateDocument_{unique}",
            "category": "Confidential"
        },
        files={
            "file": (
                "private.txt",
                b"Confidential test content",
                "text/plain"
            )
        }
    )
    assert upload.status_code == 200, upload.text

    # Find the uploaded document.
    response = client.get(
        "/api/documents",
        headers=owner_headers
    )
    assert response.status_code == 200

    documents = response.json()["documents"]

    document = next(
        row for row in documents
        if row[1] == f"PrivateDocument_{unique}"
    )
    document_id = document[0]

    # Viewer has no permission, so download must be denied.
    download = client.get(
        f"/api/documents/{document_id}/download",
        headers=viewer_headers
    )

    assert download.status_code == 403
