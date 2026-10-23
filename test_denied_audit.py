import os
import uuid

os.environ.setdefault(
    "TRUSTVAULT_SECRET_KEY",
    "trustvault-dev-secret-key-123456789"
)

from fastapi.testclient import TestClient
from main import app, get_db

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


def test_denied_download_is_recorded_in_audit_log():
    unique = uuid.uuid4().hex[:8]

    owner_headers = register_and_login(
        f"audit_owner_{unique}", "owner"
    )
    viewer_headers = register_and_login(
        f"audit_viewer_{unique}", "viewer"
    )

    upload = client.post(
        "/api/documents/upload",
        headers=owner_headers,
        data={
            "title": f"Private_{unique}",
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
    doc_id = upload.json()["document_id"]

    # Viewer has no permission to download this document.
    denied = client.get(
        f"/api/documents/{doc_id}/download",
        headers=viewer_headers
    )
    assert denied.status_code == 403

    # Verify the refused attempt was saved in the database.
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT action, details
            FROM audit_logs
            WHERE action = 'DOWNLOAD_DENIED'
            ORDER BY id DESC
            """
        ).fetchall()

    assert any(
        f"document id={doc_id}" in details
        for action, details in rows
    )
