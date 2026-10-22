from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_user_document_isolation():
    # 1. Register User A and User B
    client.post("/api/register", json={"username": "usera", "password": "password123", "role": "viewer"})
    client.post("/api/register", json={"username": "userb", "password": "password123", "role": "viewer"})

    # 2. Login as User A to get token
    res_a = client.post("/api/login", data={"username": "usera", "password": "password123"})
    token_a = res_a.json()["access_token"]

    # 3. Login as User B to get token
    res_b = client.post("/api/login", data={"username": "userb", "password": "password123"})
    token_b = res_b.json()["access_token"]

    # 4. User A uploads a confidential document
    file_data = {"file": ("confidential.txt", b"Top secret data belonging to User A")}
    upload_res = client.post(
        "/api/upload",
        data={"title": "User A Secret", "category": "Confidential"},
        files=file_data,
        headers={"Authorization": f"Bearer {token_a}"}
    )
    assert upload_res.status_code == 200

    # 5. User B attempts to download User A's file -> Should be blocked with 403 Forbidden
    download_res = client.get(
        "/api/download/confidential.txt",
        headers={"Authorization": f"Bearer {token_b}"}
    )
    assert download_res.status_code == 403
    assert download_res.json()["detail"] == "Access denied. You do not have permission to access this document."