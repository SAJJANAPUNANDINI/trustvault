
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

    return {
        "Authorization":
        f"Bearer {login.json()['access_token']}"
    }


def test_viewer_cannot_upload():
    username = f"viewer_{uuid.uuid4().hex[:10]}"
    headers = register_and_login(username, "viewer")

    response = client.post(
        "/api/upload",
        headers=headers,
        data={
            "title": "Test Document",
            "category": "General"
        },
        files={
            "file": (
                "test.txt",
                b"Test content",
                "text/plain"
            )
        }
    )

    assert response.status_code == 403


def test_invalid_file_extension_is_rejected():
    username = f"owner_{uuid.uuid4().hex[:10]}"
    headers = register_and_login(username, "owner")

    response = client.post(
        "/api/upload",
        headers=headers,
        data={
            "title": "Invalid File",
            "category": "General"
        },
        files={
            "file": (
                "malicious.exe",
                b"Test content",
                "application/octet-stream"
            )
        }
    )

    assert response.status_code == 400


def test_public_registration_cannot_create_admin():
    username = f"admin_{uuid.uuid4().hex[:10]}"

    response = client.post(
        "/api/register",
        json={
            "username": username,
            "password": "TestPass123!",
            "role": "admin"
        }
    )

    assert response.status_code == 422


def test_owner_can_upload_valid_file():
    username = f"owner_{uuid.uuid4().hex[:10]}"
    headers = register_and_login(username, "owner")

    response = client.post(
        "/api/upload",
        headers=headers,
        data={
            "title": "Valid Test Document",
            "category": "General"
        },
        files={
            "file": (
                "valid.txt",
                b"This is a valid test file.",
                "text/plain"
            )
        }
    )

    assert response.status_code == 200, response.text
    assert "document_id" in response.json()
