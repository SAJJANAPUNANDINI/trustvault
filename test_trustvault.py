from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_user_document_isolation():
    # Use unique usernames so repeated local test runs don't collide with old records.
    import uuid
    suffix = uuid.uuid4().hex[:8]
    username_a = f"owner_{suffix}"
    username_b = f"viewer_{suffix}"
    password = "password123"

    reg_a = client.post(
        "/api/register",
        json={"username": username_a, "password": password, "role": "owner"},
    )
    assert reg_a.status_code == 200, reg_a.text

    reg_b = client.post(
        "/api/register",
        json={"username": username_b, "password": password, "role": "viewer"},
    )
    assert reg_b.status_code == 200, reg_b.text

    res_a = client.post(
        "/api/login",
        data={"username": username_a, "password": password},
    )
    assert res_a.status_code == 200, res_a.text
    token_a = res_a.json()["access_token"]

    res_b = client.post(
        "/api/login",
        data={"username": username_b, "password": password},
    )
    assert res_b.status_code == 200, res_b.text
    token_b = res_b.json()["access_token"]

    upload_res = client.post(
        "/api/upload",
        data={"title": "User A Secret", "category": "Confidential"},
        files={"file": ("confidential.txt", b"Top secret data belonging to User A", "text/plain")},
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert upload_res.status_code == 200, upload_res.text
    document_id = upload_res.json()["document_id"]

    download_res = client.get(
        f"/api/documents/{document_id}/download",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert download_res.status_code == 403, download_res.text
    assert download_res.json()["detail"] == "Access denied"
