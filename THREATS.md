# Threat Modeling & Security Analysis - TrustVault

This document outlines the security threats identified during the development of TrustVault, the mitigations implemented, and the accepted trade-offs for this evaluation build.

---

## 1. Unauthorized Direct File Access / IDOR (Insecure Direct Object Reference)
- **Threat**: A user might try to guess or directly request a download URL of a file they do not own or have permission to access.
- **Mitigation Implemented**: 
  - Server-side authorization checks are enforced on every download request (`/api/download/{filename}`). 
  - The server explicitly queries the `permissions` table and validates if the user is the owner, admin, or has an active explicit permission grant. If false, the server blocks access with a `403 Forbidden` and logs an `UNAUTHORIZED_ACCESS` event in the audit trail.
- **Status**: Fully Mitigated.

---

## 2. Stale Permissions / Delayed Revocation
- **Threat**: A user whose access was revoked might still be able to download a file if permissions are cached in their JWT token or session.
- **Mitigation Implemented**: 
  - TrustVault does **not** cache document permissions inside the JWT token. 
  - Every single download request triggers a fresh, dynamic SQL lookup against the database `permissions` table. Revoking access takes effect **instantly** on the very next request.
- **Status**: Fully Mitigated.

---

## 3. SQLite Concurrency & Database Locks (`database is locked`)
- **Threat**: Under high concurrent load or automated testing (`pytest`), multiple rapid writes can cause SQLite `OperationalError: database is locked`.
- **Mitigation Implemented**: 
  - Configured database connections with a `timeout=30.0` to gracefully wait for locks to release.
  - Used Python `with` context managers across all endpoints to ensure connections are properly closed and released immediately after execution.
- **Status**: Fully Mitigated.

---

## 4. Malicious File Uploads (RCE / Unsafe Extensions)
- **Threat**: Users might upload executable scripts (`.exe`, `.sh`, `.php`) posing as documents to compromise the server environment.
- **Mitigation Implemented**: 
  - Strict file extension validation whitelist (`ALLOWED_EXTENSIONS = {".pdf", ".docx", ".txt", ".png", ".jpg", ".jpeg"}`). Any invalid extension is rejected at the API boundary with a `400 Bad Request`.
- **Status**: Fully Mitigated.

---

## 5. Hardcoded JWT Secret Key (Accepted Trade-Off)
- **Threat**: The `SECRET_KEY` for JWT token generation is hardcoded in `main.py` for simplicity during evaluation. In a production environment, this could lead to token forgery if the codebase is exposed.
- **Accepted Trade-Off**: 
  - Accepted for this take-home challenge to ensure plug-and-play local evaluation without complex environment variable (`.env`) setup. For production deployment, this must be migrated to secure environment variables (`os.getenv("SECRET_KEY")`).
- **Status**: Accepted Risk for Challenge Scope.