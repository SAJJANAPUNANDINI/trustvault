
import os
import uuid
from datetime import date

os.environ.setdefault(
    "TRUSTVAULT_SECRET_KEY",
    "trustvault-dev-secret-key-123456789"
)

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_search_documents_by_date():
    unique = uuid.uuid4().hex[:8]
    username = f"date_owner_{unique}"

    register = client.post(
        "/api/register",
        json={
            "username": username,
            "password": "TestPass123!",
            "role": "owner"
        }
    )
    assert register.status_code == 200, register.text

    login = client.post(
        "/api/login",
        data={
            "username": username,
            "password": "TestPass123!"
        }
    )
    assert login.status_code == 200, login.text

    headers = {
        "Authorization":
        f"Bearer {login.json()['access_token']}"
    }

    upload = client.post(
        "/api/upload",
        headers=headers,
        data={
            "title": f"DateReport_{unique}",
            "category": "General"
        },
        files={
            "file": (
                "date_report.txt",
                b"Date filter test",
                "text/plain"
            )
        }
    )
    assert upload.status_code == 200, upload.text

    today = date.today().isoformat()

    response = client.get(
        "/api/documents",
        headers=headers,
        params={"date": today}
    )

    
    
    assert response.status_code == 200
    documents = response.json()["documents"]

    assert any(
        document[1] == f"DateReport_{unique}"
        for document in documents
    )
