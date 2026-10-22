
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


def test_search_documents_by_title_category_and_owner():
    unique = uuid.uuid4().hex[:8]
    owner_name = f"search_owner_{unique}"
    headers = register_and_login(owner_name, "owner")

    # Upload a document with a unique title and category.
    upload = client.post(
        "/api/upload",
        headers=headers,
        data={
            "title": f"ProjectReport_{unique}",
            "category": f"ProjectCategory_{unique}"
        },
        files={
            "file": (
                "search_report.txt",
                b"Search test document",
                "text/plain"
            )
        }
    )
    assert upload.status_code == 200, upload.text

    # Search by document title.
    title_result = client.get(
        "/api/documents",
        headers=headers,
        params={"search": f"ProjectReport_{unique}"}
    )
    assert title_result.status_code == 200
    assert len(title_result.json()["documents"]) == 1

    # Filter by category.
    category_result = client.get(
        "/api/documents",
        headers=headers,
        params={"category": f"ProjectCategory_{unique}"}
    )
    assert category_result.status_code == 200
    assert len(category_result.json()["documents"]) == 1

    # Filter by owner username.
    owner_result = client.get(
        "/api/documents",
        headers=headers,
        params={"owner": owner_name}
    )
    assert owner_result.status_code == 200
    assert len(owner_result.json()["documents"]) == 1
