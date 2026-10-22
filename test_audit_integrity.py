
import os
import uuid

os.environ.setdefault(
    "TRUSTVAULT_SECRET_KEY",
    "trustvault-dev-secret-key-123456789"
)

import sqlite3
import main
from fastapi.testclient import TestClient

client = TestClient(main.app)


def test_audit_integrity_detects_tampering(tmp_path, monkeypatch):
    # Use a separate temporary database for this test.
    test_db = tmp_path / "audit_test.sqlite"
    monkeypatch.setattr(main, "DB_PATH", test_db)
    main.init_db()

    username = f"audit_admin_{uuid.uuid4().hex[:10]}"

    # Create an admin directly; public registration must not allow this.
    with sqlite3.connect(test_db) as conn:
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (
                username,
                main.pwd_context.hash("TestPass123!"),
                "admin"
            )
        )

    login = client.post(
        "/api/login",
        data={
            "username": username,
            "password": "TestPass123!"
        }
    )
    assert login.status_code == 200, login.text

    headers = {
        "Authorization": f"Bearer {login.json()['access_token']}"
    }

    # Login audit entry should have a valid hash chain.
    initial = client.get("/api/audit-logs/verify", headers=headers)
    assert initial.status_code == 200, initial.text
    assert initial.json()["valid"] is True

    # Add an audit entry through normal registration.
    register = client.post(
        "/api/register",
        json={
            "username": f"viewer_{uuid.uuid4().hex[:10]}",
            "password": "TestPass123!",
            "role": "viewer"
        }
    )
    assert register.status_code == 200, register.text

    # Change the latest audit entry without updating its hash.
    with sqlite3.connect(test_db) as conn:
        row = conn.execute(
            "SELECT id FROM audit_logs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row is not None

        conn.execute(
            "UPDATE audit_logs SET details = ? WHERE id = ?",
            ("TAMPERED TEST ENTRY", row[0])
        )

    # Verification should detect the change.
    result = client.get("/api/audit-logs/verify", headers=headers)
    assert result.status_code == 200, result.text
    assert result.json()["valid"] is False
    assert result.json()["failed_entry_id"] == row[0]
