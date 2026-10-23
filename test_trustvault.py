from fastapi.testclient import TestClient
from main import app
import uuid

client = TestClient(app)


def test_user_document_isolation():
    suffix = uuid.uuid4().hex[:8]
    username_a = f"owner_{suffix}"
    username_b = f"viewer_{suffix}"
    password = "password123"

    # Register owner
    reg_a = client.post(
        "/api/register",
        json={
            "username": username_a,
            "password": password,
            "role": "owner",
        },
    )
    assert reg_a.status_code == 200, reg_a.text

    # Register viewer
    reg_b = client.post(
        "/api/register",
        json={
            "username": username_b,
            "password": password,
            "role": "viewer",
        },
    )
    assert reg_b.status_code == 200, reg_b.text

    # Login owner
    res_a = client.post(
        "/api/login",
        json={"username": username_a, "password": password},
    )
    assert res_a.status_code == 200, res_a.text
    token_a = res_a.json()["access_token"]

    # Login viewer
    res_b = client.post(
        "/api/login",
        json={"username": username_b, "password": password},
    )
    assert res_b.status_code == 200, res_b.text
    token_b = res_b.json()["access_token"]

    # Owner uploads a private document
    upload_res = client.post(
        "/api/documents/upload",
        data={
            "title": "User A Secret",
            "category": "Confidential",
        },
        files={
            "file": (
                "confidential.txt",
                b"Top secret data belonging to User A",
                "text/plain",
            )
        },
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert upload_res.status_code == 200, upload_res.text
    document_id = upload_res.json()["document_id"]

    # Viewer must not download the owner's private document
    download_res = client.get(
        f"/api/documents/{document_id}/download",
        headers={"Authorization": f"Bearer {token_b}"},
    )

    assert download_res.status_code == 403, download_res.text
    assert download_res.json()["detail"] == (
        "You do not have permission to read this document"
    )
