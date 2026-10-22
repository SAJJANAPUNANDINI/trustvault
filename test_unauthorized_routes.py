
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_protected_routes_require_authentication():
    # These routes require a valid login token.
    requests = [
        ("GET", "/api/documents"),
        ("GET", "/api/audit-logs"),
        ("GET", "/api/audit-logs/verify"),
        ("POST", "/api/upload"),
    ]

    for method, url in requests:
        response = client.request(method, url)
        assert response.status_code == 401, (
            f"{method} {url}: expected 401, "
            f"got {response.status_code}"
        )
