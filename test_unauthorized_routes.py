from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_protected_routes_require_authentication():
    # Protected GET routes must reject requests without a token.
    requests = [
        ("GET", "/api/documents"),
        ("GET", "/api/audit-logs"),
        ("GET", "/api/audit-logs/verify"),
    ]

    for method, url in requests:
        response = client.request(method, url)

        assert response.status_code == 401, (
            f"{method} {url}: expected 401, "
            f"got {response.status_code}. "
            f"Response: {response.text}"
        )

    # Upload request includes required fields but no authentication token.
    upload_response = client.post(
        "/api/documents/upload",
        data={
            "title": "Authentication test",
            "category": "Test",
        },
        files={
            "file": (
                "test.txt",
                b"Test content",
                "text/plain",
            )
        },
    )

    assert upload_response.status_code == 401, (
        f"POST /api/documents/upload: expected 401, "
        f"got {upload_response.status_code}. "
        f"Response: {upload_response.text}"
    )
