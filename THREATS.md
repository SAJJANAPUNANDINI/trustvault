# TrustVault — Threat Model

## 1. Project Overview

TrustVault is a secure document-sharing platform designed to protect confidential documents through authentication, role-based access control, document permissions, and audit logging.

The system supports three roles:
- **Administrator:** Manages documents and permissions and views audit logs.
- **Owner:** Uploads and manages owned documents and grants or revokes access.
- **Viewer:** Accesses documents only when permitted.

## 2. Assets to Protect

- Confidential uploaded documents.
- User credentials and authentication tokens.
- Document ownership and permission records.
- Audit logs and their integrity.
- Application secrets and database contents.

## 3. Threats and Mitigations

| Threat | Potential impact | Mitigation |
|---|---|---|
| Unauthorized document access | Confidential information may be exposed. | Server-side authentication and document-level permission checks. |
| Privilege escalation | A user may gain administrator privileges. | Public registration permits only viewer and owner roles. |
| Unauthorized upload | Users may upload files without permission. | Upload access is restricted to administrators and owners. |
| Malicious or unsupported file uploads | Unsafe or unexpected files may enter storage. | File-extension validation and a 10 MB upload limit. |
| Unauthorized metadata modification | Document information may be changed. | Owner, administrator, or users with edit permission may update metadata. |
| Unauthorized deletion | Documents may be lost. | Deletion is restricted to administrators and document owners. |
| Permission abuse | A user may retain access after permission is revoked. | Permissions are checked during each download request; revocation should take effect immediately. |
| Unauthorized audit-log access | Sensitive activity information may be exposed. | Audit-log viewing is restricted to administrators. |
| Audit-log tampering | Evidence of document activity may be altered. | HMAC-based hash chaining and an audit-integrity verification endpoint. |
| Brute-force or stolen credentials | An attacker may impersonate a legitimate user. | Password hashing and token-based authentication are implemented. Additional rate limiting and token-lifecycle controls require review. |
| Secret exposure | An attacker may forge authentication tokens or audit hashes. | The application requires a secret key supplied through an environment variable. Production secret storage and rotation require appropriate deployment controls. |
| Database or storage compromise | Documents, permissions, or audit records may be exposed or changed. | Access controls reduce application-level risks; database and storage hardening are still necessary. |

## 4. Security Controls Implemented

- Password hashing.
- JWT-based authentication.
- Role-based access control.
- Document-level read and edit permissions.
- Permission grant and revocation.
- Upload extension and size validation.
- Server-side checks for document operations.
- Audit logging for important actions and selected denied attempts.
- HMAC-based audit-integrity verification.
- Automated tests for access isolation, permissions, uploads, searching, denied downloads, and immediate revocation.

## 5. Known Limitations and Remaining Risks

- HMAC-based audit logs are tamper-evident, not absolutely tamper-proof. An attacker who can modify the database and obtain the secret key may be able to forge records.
- Existing audit records migrated into the hash chain cannot be independently proven authentic merely because hashes are generated during migration.
- File-extension validation alone does not prove that uploaded file contents are safe.
- Rate limiting, malware scanning, production-grade secret management, backup security, and comprehensive monitoring need further review.
- Audit coverage must be checked for every failure path, including invalid uploads, missing files, denied requests, and administrative verification failures.
- HTTPS, production CORS configuration, token expiry, and deployment settings must be verified before production use.

## 6. Testing Strategy

Automated tests are used to verify that:
- Users cannot access documents without permission.
- Public registration cannot create an administrator.
- Permission grants and revocations work correctly.
- Unauthorized downloads are rejected and recorded.
- Audit-log tampering can be detected.
- Upload validation and document search behave as expected.

The current complete test run reported **15 passed**. Further tests and deployment checks should be performed whenever security-related code changes.

## 7. Conclusion

TrustVault implements several important security controls for document sharing. However, passing automated tests does not guarantee complete security. Remaining risks must be assessed, and production deployment should use secure configuration, monitoring, backups, and additional testing.
