# TrustVault - Secure Document Management System

TrustVault is a document-sharing and management platform built with **FastAPI, SQLite, and JWT authentication**. It aims to protect confidential documents through server-side authorization, document-level permissions, permission revocation, and audit logging.

## Features

- **Server-Side Authorization:** The backend checks permissions for protected operations instead of relying on frontend controls.
- **Role-Based Access:** Supports administrative, document-owner, and viewer roles, according to the configured application permissions.
- **Granular Document Permissions:** Allows document access to be granted and revoked.
- **Audit Logging:** Records supported user actions and unauthorized access attempts.
- **File Validation:** Applies file-extension validation to uploaded documents.
- **Document Search:** Supports searching documents by available fields, including title, filename, category, owner, and upload date.
- **Automated Tests:** Includes tests for application behavior and security checks.

## Live Demo

- **Website:** https://trustvault-jv0l.onrender.com
- **GitHub Repository:** https://github.com/SAJJANAPUNANDINI/trustvault

## Technologies Used

- Python
- FastAPI
- SQLite
- JWT authentication
- HTML, CSS, and JavaScript
- Pytest

## Local Setup and Installation

### 1. Clone the repository

```bash
git clone https://github.com/SAJJANAPUNANDINI/trustvault.git
cd trustvault
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it in Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Configure the environment variables required by the application, including a strong JWT secret if the application uses one. Do not commit secret keys, passwords, or private credentials to GitHub.

Check the project configuration for any required database or upload-directory settings.

### 5. Run the application

For a standard FastAPI application whose entry point is `main.py` and whose FastAPI instance is named `app`, run:

```bash
uvicorn main:app --reload
```

If the application uses a different entry-point or instance name, use the command defined by the project configuration.

Open the following address in your browser:

http://127.0.0.1:8000

## Automated Tests

Run the test suite from the project directory:

```bash
python -m pytest -q
```

**Previously reported test result:** 15 passed. Run the tests again after making code changes to confirm the current result.

## Security and Authorization

- The backend should validate authorization for every protected request.
- Document permissions should be checked before reading, downloading, editing, or deleting documents, as applicable.
- Revoked permissions should no longer authorize subsequent requests.
- Unauthorized access attempts should be recorded in the audit log where implemented.
- Administrative operations should be restricted to authorized administrators.
- Authentication secrets and private credentials must not be published in the repository.

## API Documentation

When the application is running, FastAPI's interactive API documentation is commonly available at:

- Swagger UI: http://127.0.0.1:8000/docs
- ReDoc: http://127.0.0.1:8000/redoc

These addresses are available only if the corresponding documentation routes are enabled in the application.

Document the actual API endpoints, required authentication, permitted roles, request parameters, and expected responses for this project.

## Database and File Storage

TrustVault uses SQLite for application data. Review the database initialization code to identify the actual tables and relationships, including users, documents, permissions, and audit records where present.

Uploaded files may be stored on the local filesystem, depending on the application configuration. Production deployments should use persistent storage or another suitable storage service if files must survive redeployments.

## Limitations and Accepted Risks

- **Database persistence:** Data persistence depends on the SQLite database location and the deployment environment's storage configuration.
- **File storage:** Files stored on an ephemeral local filesystem may be lost during redeployment or service replacement.
- **Audit-log integrity:** Application-managed audit logs are not automatically tamper-proof. Stronger integrity guarantees require additional controls.
- **Backup and recovery:** Database and uploaded-file backups should be configured and recovery tested separately.
- **Upload validation:** Checking file extensions alone cannot guarantee that uploaded content is safe.
- **Production hardening:** Deployment security also depends on secret management, HTTPS, access controls, monitoring, and appropriate storage configuration.

## Demo Accounts and Seed Data

Use the demo accounts and sample documents configured for this project, if available. Document the supported roles and their permissions here.

Do not publish real user passwords, production credentials, or secret keys. Provide only intentionally created demo credentials that are safe to share.

## License

Add the applicable project license here if one has been selected.