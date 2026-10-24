# TrustVault — Threat Model

## 1. Project Overview

TrustVault is a secure document-sharing platform designed to protect confidential documents through authentication, role-based access control, document permissions, and audit logging.

The system supports three roles:

- **Administrator:** Manages documents and permissions and views audit logs, according to the application's authorization rules.
- **Owner:** Uploads and manages owned documents and grants or revokes access, according to the configured permissions.
- **Viewer:** Accesses documents only when permitted.

## 2. Assets to Protect

The main assets that TrustVault must protect are:

- Confidential uploaded documents.
- User credentials and authentication tokens.
- Document ownership and permission records.
- Audit logs and their integrity.
- Application secrets and database contents.

## 3. Threats and Mitigations

| Threat | Potential Impact | Mitigation |
|---|---|---|
| Unauthorized document access | Confidential information may be exposed. | Server-side authentication and document-level permission checks. |
| Privilege escalation | A user may gain unauthorized administrative privileges. | Public registration must not allow users to assign themselves the administrator role. |
| Unauthorized upload | Users may upload files without permission. | Restrict uploads to roles authorized by the backend. |
| Malicious or unsupported file uploads | Unsafe or unexpected files may enter storage. | File-extension validation and a 10 MB upload limit; additional content validation may be required. |
| Unauthorized metadata modification | Document information may be changed without permission. | Restrict metadata updates to owners, administrators, or users with the required edit permission. |
| Unauthorized deletion | Documents may be lost or removed without authorization. | Restrict deletion to authorized administrators and document owners. |
| Permission abuse | A user may retain access after permission is revoked. | Check current permissions on every protected document request and verify that revocation takes effect immediately. |
| Unauthorized audit-log access | Sensitive activity information may be exposed. | Restrict audit-log viewing to authorized administrators. |
| Audit-log tampering | Evidence of document activity may be altered. | HMAC-based hash chaining and audit-integrity verification, if correctly implemented and configured. |
| Brute-force or stolen credentials | An attacker may impersonate a legitimate user. | Password hashing and token-based authentication. Rate limiting, token expiry, and token-lifecycle controls require review. |
| Secret exposure | An attacker may forge authentication tokens or audit hashes. | Load secrets from environment variables and protect them from disclosure. Production secret storage and rotation require appropriate controls. |
| Database or storage compromise | Documents, permissions, or audit records may be exposed or changed. | Apply database and filesystem access controls, secure deployment configuration, and appropriate backup protection. |

## 4. Security Controls Implemented

The following controls are documented as implemented in the project and should be kept consistent with the actual code and test results:

- Password hashing.
- JWT-based authentication.
- Role-based access control.
- Document-level read and edit permissions.
- Permission grant and revocation.
- Upload extension and size validation.
- Server-side checks for protected document operations.
- Audit logging for important actions and selected denied attempts.
- HMAC-based audit-integrity verification.
- Automated tests for access isolation, permissions, uploads, searching, denied downloads, and permission revocation.

A control should be described as implemented only when it exists in the application. Automated tests should verify the relevant behavior.

## 5. Known Limitations and Remaining Risks

- **Audit-log integrity:** HMAC-based audit logs can help detect tampering, but they are not absolutely tamper-proof. An attacker who can modify the database and obtain the HMAC secret may be able to forge records.
- **Historical audit records:** Adding hashes to existing audit records during migration does not independently prove that the original records were authentic or unmodified.
- **File validation:** File-extension validation alone cannot establish that uploaded file contents are safe. Content inspection, malware scanning, and safe file handling may be needed.
- **Brute-force protection:** Rate limiting and monitoring of repeated failed login attempts require review.
- **Secret management:** Production-grade secret storage, rotation, and access restrictions require appropriate deployment controls.
- **Backup and recovery:** Database and uploaded-file backups should be secured, and recovery procedures should be tested.
- **Audit coverage:** Every important success and failure path should be reviewed, including invalid uploads, missing files, denied requests, and audit-verification failures.
- **Deployment configuration:** HTTPS, CORS configuration, token expiry, persistent storage, and production settings must be verified before production use.
- **Availability:** A single application instance or database may be vulnerable to outages, resource exhaustion, or data loss without suitable monitoring and recovery measures.

## 6. Testing Strategy

Automated tests should verify the following security and functional requirements:

- Users cannot access documents without the required permissions.
- Public registration cannot create an administrator account.
- Permission grants and revocations behave correctly.
- Revoked users cannot access protected documents through subsequent requests.
- Unauthorized downloads are rejected and recorded in the audit log where supported.
- Audit-log tampering can be detected by the integrity-verification mechanism.
- Upload validation rejects unsupported files and files exceeding the configured limit.
- Document search behaves as expected.
- Unauthorized users cannot perform protected administrative operations.

The previously reported test run completed with **15 passed**. Run the tests again after security-related changes and update this result if it changes.

Automated tests provide evidence of tested behavior but do not guarantee that the entire application is secure.

## 7. Risk Prioritization

The following risks should receive particular attention before production deployment:

1. **High:** Unauthorized access to confidential documents or privilege escalation.
2. **High:** Incorrect permission checks or continued access after revocation.
3. **High:** Exposure of authentication secrets or sensitive database contents.
4. **Medium to High:** Audit-log tampering or missing records for important security events.
5. **Medium:** Malicious uploads, brute-force attacks, and insecure deployment settings.
6. **Medium:** Data loss caused by missing persistent storage or inadequate backups.

These priorities are preliminary and should be reassessed based on the actual deployment, testing, and threat environment.

## 8. Conclusion

TrustVault implements several important security controls for document sharing. However, passing automated tests does not guarantee complete security. Remaining risks must be assessed, and production deployment should use secure configuration, monitoring, protected backups, and additional testing.

This threat model should be updated whenever authentication, authorization, document permissions, audit logging, file handling, or deployment architecture changes.