
import os
import re
import uuid
import hmac
import hashlib
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import FastAPI, UploadFile, File, Form, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from passlib.context import CryptContext


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database.sqlite"
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

SECRET_KEY = os.getenv("TRUSTVAULT_SECRET_KEY", "")
if len(SECRET_KEY) < 32:
    raise RuntimeError(
        "Set TRUSTVAULT_SECRET_KEY to a secret of at least 32 characters."
    )

ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60

MAX_FILE_SIZE = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {
    ".pdf", ".docx", ".txt", ".png", ".jpg", ".jpeg"
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="TrustVault API", version="1.3")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'owner', 'viewer')),
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            filename TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            category TEXT DEFAULT '',
            upload_date TEXT NOT NULL,
            storage_name TEXT NOT NULL UNIQUE,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            access_type TEXT NOT NULL CHECK(access_type IN ('read', 'edit')),
            UNIQUE(document_id, user_id),
            FOREIGN KEY(document_id) REFERENCES documents(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            document_id INTEGER,
            details TEXT DEFAULT '',
            timestamp TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL
        );
        """)


init_db()


# --------------------------------------------------
# REQUEST MODELS
# --------------------------------------------------

class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)
    role: str = Field(pattern=r"^(viewer|owner)$")


class LoginRequest(BaseModel):
    username: str
    password: str


class UpdateDocumentRequest(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    category: Optional[str] = Field(default=None, max_length=100)


class GrantPermissionRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    access_type: str = Field(pattern=r"^(read|edit)$")


# --------------------------------------------------
# AUDIT LOGGING
# --------------------------------------------------

def audit_hash(previous_hash, username, action, document_id, details, timestamp):
    payload = "|".join([
        str(previous_hash),
        str(username),
        str(action),
        str(document_id),
        str(details),
        str(timestamp)
    ])
    return hmac.new(
        SECRET_KEY.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def log_action(username, action, document_id=None, details=""):
    timestamp = datetime.now(timezone.utc).isoformat()

    with get_db() as conn:
        previous = conn.execute(
            "SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
        ).fetchone()

        previous_hash = previous["entry_hash"] if previous else "GENESIS"

        entry_hash = audit_hash(
            previous_hash, username, action, document_id, details, timestamp
        )

        conn.execute("""
            INSERT INTO audit_logs
            (username, action, document_id, details, timestamp,
             previous_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            username, action, document_id, details,
            timestamp, previous_hash, entry_hash
        ))


# --------------------------------------------------
# AUTHENTICATION HELPERS
# --------------------------------------------------

def create_token(user):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user["username"],
        "id": user["id"],
        "iat": now,
        "exp": now + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")

    token = authorization.split(" ", 1)[1].strip()

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    with get_db() as conn:
        user = conn.execute(
            "SELECT id, username, role FROM users WHERE id = ?",
            (payload.get("id"),)
        ).fetchone()

    if not user or user["username"] != payload.get("sub"):
        raise HTTPException(status_code=401, detail="User no longer exists")

    return dict(user)


def require_admin(user):
    if user["role"] != "admin":
        log_action(
            user["username"],
            "DENIED_ADMIN_ACTION",
            details="Admin role required"
        )
        raise HTTPException(status_code=403, detail="Admin access required")


def get_document(document_id):
    with get_db() as conn:
        document = conn.execute(
            "SELECT * FROM documents WHERE id = ?", (document_id,)
        ).fetchone()

    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    return dict(document)


def permission_for(document_id, user_id):
    with get_db() as conn:
        row = conn.execute("""
            SELECT access_type FROM permissions
            WHERE document_id = ? AND user_id = ?
        """, (document_id, user_id)).fetchone()

    return row["access_type"] if row else None


def can_read(user, document):
    if user["role"] == "admin":
        return True
    if document["owner_id"] == user["id"]:
        return True
    return permission_for(document["id"], user["id"]) in ("read", "edit")


def can_edit(user, document):
    if user["role"] == "admin":
        return True
    if document["owner_id"] == user["id"]:
        return True
    return permission_for(document["id"], user["id"]) == "edit"


def can_manage_permissions(user, document):
    return user["role"] == "admin" or document["owner_id"] == user["id"]


def safe_storage_path(storage_name):
    path = (UPLOAD_DIR / storage_name).resolve()
    if path.parent != UPLOAD_DIR.resolve():
        raise HTTPException(status_code=400, detail="Invalid storage path")
    return path


# --------------------------------------------------
# BASIC ENDPOINTS
# --------------------------------------------------

@app.get("/")
def home():
    return {
        "message": "TrustVault API is running",
        "docs": "/docs"
    }


@app.get("/api/health")
def health():
    return {"status": "ok"}


# --------------------------------------------------
# REGISTER AND LOGIN
# --------------------------------------------------

@app.post("/api/register")
def register(request: RegisterRequest):
    username = request.username.strip()

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,50}", username):
        raise HTTPException(
            status_code=400,
            detail="Username must contain 3-50 letters, numbers, dots, underscores or hyphens"
        )

    password_hash = pwd_context.hash(request.password)

    try:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO users (username, password_hash, role, created_at)
                VALUES (?, ?, ?, ?)
            """, (
                username,
                password_hash,
                request.role,
                datetime.now(timezone.utc).isoformat()
            ))
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username already exists")

    log_action(username, "REGISTER", details=f"Registered as {request.role}")
    return {"message": "Registration successful", "role": request.role}


@app.post("/api/login")
def login(request: LoginRequest):
    username = request.username.strip()

    with get_db() as conn:
        user = conn.execute("""
            SELECT id, username, password_hash, role
            FROM users WHERE username = ?
        """, (username,)).fetchone()

    if not user or not pwd_context.verify(request.password, user["password_hash"]):
        log_action(username, "LOGIN_FAILED", details="Invalid username or password")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_token(user)
    log_action(username, "LOGIN")

    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"],
        "username": user["username"],
        "user_id": user["id"]
    }


# --------------------------------------------------
# DOCUMENT UPLOAD
# --------------------------------------------------

@app.post("/api/documents/upload")
async def upload_document(
    file: UploadFile = File(...),
    title: str = Form(...),
    category: str = Form(""),
    user=None,
    authorization: Optional[str] = Header(default=None)
):
    user = get_current_user(authorization)

    if user["role"] not in ("admin", "owner"):
        log_action(user["username"], "DENIED_UPLOAD", details="Role cannot upload")
        raise HTTPException(
            status_code=403,
            detail="Only owners and admins can upload"
        )

    clean_title = title.strip()
    if not clean_title or len(clean_title) > 200:
        raise HTTPException(
            status_code=400,
            detail="Title must be 1-200 characters"
        )

    extension = Path(file.filename or "").suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        log_action(
            user["username"],
            "UPLOAD_REJECTED",
            details="Unsupported file extension"
        )
        raise HTTPException(status_code=400, detail="File type not allowed")

    storage_name = f"{uuid.uuid4().hex}{extension}"
    destination = safe_storage_path(storage_name)

    size = 0
    try:
        with destination.open("wb") as output:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)

                if size > MAX_FILE_SIZE:
                    output.close()
                    destination.unlink(missing_ok=True)
                    log_action(
                        user["username"],
                        "UPLOAD_REJECTED",
                        details="File exceeds size limit"
                    )
                    raise HTTPException(
                        status_code=413,
                        detail="Maximum file size is 10 MB"
                    )

                output.write(chunk)
    finally:
        await file.close()

    upload_date = datetime.now(timezone.utc).isoformat()

    try:
        with get_db() as conn:
            cursor = conn.execute("""
                INSERT INTO documents
                (title, filename, owner_id, category, upload_date, storage_name)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                clean_title,
                Path(file.filename or "uploaded_file").name,
                user["id"],
                category.strip()[:100],
                upload_date,
                storage_name
            ))
            document_id = cursor.lastrowid
    except Exception:
        destination.unlink(missing_ok=True)
        raise

    log_action(
        user["username"],
        "UPLOAD",
        document_id,
        f"File: {Path(file.filename or '').name}"
    )
    return {"message": "Upload successful", "document_id": document_id}


# --------------------------------------------------
# LIST AND SEARCH DOCUMENTS
# --------------------------------------------------

@app.get("/api/documents")
def list_documents(
    search: Optional[str] = Query(default=None, max_length=200),
    owner: Optional[str] = Query(default=None, max_length=50),
    category: Optional[str] = Query(default=None, max_length=100),
    date: Optional[str] = Query(default=None, max_length=30),
    authorization: Optional[str] = Header(default=None)
):
    user = get_current_user(authorization)

    with get_db() as conn:
        rows = conn.execute("""
            SELECT d.id, d.title, d.filename, d.owner_id, d.category,
                   d.upload_date, u.username AS owner_name
            FROM documents d
            JOIN users u ON u.id = d.owner_id
            ORDER BY d.id DESC
        """).fetchall()

    results = []

    for row in rows:
        document = dict(row)

        if not can_read(user, document):
            continue

        if search and search.casefold() not in (
            document["title"] + " " +
            document["filename"] + " " +
            document["category"] + " " +
            document["owner_name"]
        ).casefold():
            continue

        if owner and owner.casefold() not in document["owner_name"].casefold():
            continue

        if category and category.casefold() not in (
            document["category"] or ""
        ).casefold():
            continue

        if date and not document["upload_date"].startswith(date):
            continue

        results.append([
            document["id"],
            document["title"],
            document["filename"],
            document["owner_id"],
            document["category"],
            document["upload_date"],
            document["owner_name"]
        ])

    log_action(
        user["username"],
        "LIST_DOCUMENTS",
        details=f"Returned {len(results)} documents"
    )
    return {"documents": results}


# --------------------------------------------------
# DOWNLOAD DOCUMENT
# --------------------------------------------------

@app.get("/api/documents/{document_id}/download")
def download_document(
    document_id: int,
    authorization: Optional[str] = Header(default=None)
):
    user = get_current_user(authorization)

    try:
        document = get_document(document_id)
    except HTTPException:
        log_action(
            user["username"],
            "DOWNLOAD_DENIED",
            document_id,
            "Document not found"
        )
        raise

    if not can_read(user, document):
        with get_db() as conn:
            revoked = conn.execute("""
                SELECT 1
                FROM audit_logs
                WHERE action = 'REVOKE'
                  AND document_id = ?
                  AND details LIKE ?
                ORDER BY id DESC
                LIMIT 1
            """, (
                document_id,
                f"user={user['username']}%"
            )).fetchone()

        detail = (
            "Access denied"
            if revoked
            else "You do not have permission to read this document"
        )

        log_action(
            user["username"],
            "DOWNLOAD_DENIED",
            document_id,
            f"document id={document_id}; No read permission"
        )

        raise HTTPException(status_code=403, detail=detail)

    path = safe_storage_path(document["storage_name"])
    if not path.is_file():
        log_action(
            user["username"],
            "DOWNLOAD_FAILED",
            document_id,
            "Stored file missing"
        )
        raise HTTPException(status_code=404, detail="Stored file not found")

    log_action(user["username"], "DOWNLOAD", document_id)

    return FileResponse(
        path=str(path),
        filename=document["filename"],
        media_type="application/octet-stream"
    )


# --------------------------------------------------
# UPDATE DOCUMENT METADATA
# --------------------------------------------------

@app.post("/api/documents/{document_id}/update")
def update_document(
    document_id: int,
    request: UpdateDocumentRequest,
    authorization: Optional[str] = Header(default=None)
):
    user = get_current_user(authorization)

    try:
        document = get_document(document_id)
    except HTTPException:
        log_action(
            user["username"],
            "UPDATE_DENIED",
            document_id,
            "Document not found"
        )
        raise

    if not can_edit(user, document):
        log_action(
            user["username"],
            "UPDATE_DENIED",
            document_id,
            "No edit permission"
        )
        raise HTTPException(status_code=403, detail="Edit permission required")

    title = request.title.strip() if request.title is not None else document["title"]
    category = (
        request.category.strip()
        if request.category is not None
        else document["category"]
    )

    if not title or len(title) > 200:
        raise HTTPException(
            status_code=400,
            detail="Title must be 1-200 characters"
        )

    if len(category or "") > 100:
        raise HTTPException(
            status_code=400,
            detail="Category must be at most 100 characters"
        )

    with get_db() as conn:
        conn.execute("""
            UPDATE documents SET title = ?, category = ? WHERE id = ?
        """, (title, category, document_id))

    log_action(
        user["username"],
        "UPDATE",
        document_id,
        f"title={title}; category={category}"
    )

    return {
        "message": "Document updated successfully",
        "id": document_id,
        "title": title,
        "category": category
    }


# --------------------------------------------------
# DELETE DOCUMENT
# --------------------------------------------------

@app.post("/api/documents/{document_id}/delete")
def delete_document(
    document_id: int,
    authorization: Optional[str] = Header(default=None)
):
    user = get_current_user(authorization)

    try:
        document = get_document(document_id)
    except HTTPException:
        log_action(
            user["username"],
            "DELETE_DENIED",
            document_id,
            "Document not found"
        )
        raise

    if not can_manage_permissions(user, document):
        log_action(
            user["username"],
            "DELETE_DENIED",
            document_id,
            "Not admin or document owner"
        )
        raise HTTPException(
            status_code=403,
            detail="Only the document owner or admin can delete"
        )

    path = safe_storage_path(document["storage_name"])

    with get_db() as conn:
        conn.execute("DELETE FROM permissions WHERE document_id = ?", (document_id,))
        conn.execute("DELETE FROM documents WHERE id = ?", (document_id,))

    path.unlink(missing_ok=True)

    log_action(
        user["username"],
        "DELETE",
        document_id,
        f"Deleted {document['filename']}"
    )

    return {"message": "Document deleted successfully"}


# --------------------------------------------------
# GRANT PERMISSION
# --------------------------------------------------

@app.post("/api/documents/{document_id}/grant")
def grant_permission(
    document_id: int,
    request: GrantPermissionRequest,
    authorization: Optional[str] = Header(default=None)
):
    user = get_current_user(authorization)

    try:
        document = get_document(document_id)
    except HTTPException:
        log_action(
            user["username"],
            "GRANT_DENIED",
            document_id,
            "Document not found"
        )
        raise

    if not can_manage_permissions(user, document):
        log_action(
            user["username"],
            "GRANT_DENIED",
            document_id,
            "Not admin or document owner"
        )
        raise HTTPException(
            status_code=403,
            detail="Only the document owner or admin can grant access"
        )

    with get_db() as conn:
        target = conn.execute(
            "SELECT id, username FROM users WHERE username = ?",
            (request.username.strip(),)
        ).fetchone()

        if not target:
            log_action(
                user["username"],
                "GRANT_FAILED",
                document_id,
                "Target user not found"
            )
            raise HTTPException(status_code=404, detail="Target user not found")

        if target["id"] == document["owner_id"]:
            raise HTTPException(
                status_code=400,
                detail="The owner already has full access"
            )

        conn.execute("""
            INSERT INTO permissions (document_id, user_id, access_type)
            VALUES (?, ?, ?)
            ON CONFLICT(document_id, user_id)
            DO UPDATE SET access_type = excluded.access_type
        """, (document_id, target["id"], request.access_type))

    log_action(
        user["username"],
        "GRANT",
        document_id,
        f"user={request.username}; access={request.access_type}"
    )

    return {"message": f"{request.access_type} permission granted"}


# --------------------------------------------------
# REVOKE PERMISSION
# --------------------------------------------------

@app.post("/api/documents/{document_id}/revoke")
def revoke_permission(
    document_id: int,
    request: GrantPermissionRequest,
    authorization: Optional[str] = Header(default=None)
):
    username = request.username.strip()
    user = get_current_user(authorization)

    try:
        document = get_document(document_id)
    except HTTPException:
        log_action(
            user["username"],
            "REVOKE_DENIED",
            document_id,
            "Document not found"
        )
        raise

    if not can_manage_permissions(user, document):
        log_action(
            user["username"],
            "REVOKE_DENIED",
            document_id,
            "Not admin or document owner"
        )
        raise HTTPException(
            status_code=403,
            detail="Only the document owner or admin can revoke access"
        )

    with get_db() as conn:
        target = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if not target:
            raise HTTPException(status_code=404, detail="Target user not found")

        cursor = conn.execute("""
            DELETE FROM permissions
            WHERE document_id = ? AND user_id = ?
        """, (document_id, target["id"]))

    log_action(
        user["username"],
        "REVOKE",
        document_id,
        f"user={username}"
    )

    return {
        "message": (
            "Permission revoked"
            if cursor.rowcount
            else "No permission existed for that user"
        ),
        "permission_removed": cursor.rowcount > 0
    }


# --------------------------------------------------
# LIST PERMISSIONS
# --------------------------------------------------

@app.get("/api/documents/{document_id}/permissions")
def list_permissions(
    document_id: int,
    authorization: Optional[str] = Header(default=None)
):
    user = get_current_user(authorization)
    document = get_document(document_id)

    if not can_manage_permissions(user, document):
        log_action(user["username"], "PERMISSIONS_DENIED", document_id)
        raise HTTPException(
            status_code=403,
            detail="Only the document owner or admin can view permissions"
        )

    with get_db() as conn:
        rows = conn.execute("""
            SELECT u.username, p.access_type
            FROM permissions p
            JOIN users u ON u.id = p.user_id
            WHERE p.document_id = ?
            ORDER BY u.username
        """, (document_id,)).fetchall()

    return {
        "document_id": document_id,
        "permissions": [
            {"username": row["username"], "access_type": row["access_type"]}
            for row in rows
        ]
    }


# --------------------------------------------------
# AUDIT LOGS - ADMIN ONLY
# --------------------------------------------------

@app.get("/api/audit-logs")
def audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    authorization: Optional[str] = Header(default=None)
):
    user = get_current_user(authorization)
    require_admin(user)

    with get_db() as conn:
        rows = conn.execute("""
            SELECT id, username, action, document_id, details,
                   timestamp, previous_hash, entry_hash
            FROM audit_logs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return {"audit_logs": [dict(row) for row in rows]}


@app.get("/api/audit-logs/verify")
def verify_audit_logs(
    authorization: Optional[str] = Header(default=None)
):
    user = get_current_user(authorization)
    require_admin(user)

    with get_db() as conn:
        rows = conn.execute("""
            SELECT id, username, action, document_id, details,
                   timestamp, previous_hash, entry_hash
            FROM audit_logs ORDER BY id ASC
        """).fetchall()

    expected_previous = "GENESIS"

    for row in rows:
        expected_hash = audit_hash(
            expected_previous,
            row["username"],
            row["action"],
            row["document_id"],
            row["details"],
            row["timestamp"]
        )

        if (
            row["previous_hash"] != expected_previous
            or not hmac.compare_digest(row["entry_hash"], expected_hash)
        ):
            return {
                "valid": False,
                "tampered_entry_id": row["id"],
                "message": "Audit chain verification failed"
            }

        expected_previous = row["entry_hash"]

    return {
        "valid": True,
        "entries_checked": len(rows),
        "message": "Audit chain is valid"
    }


# --------------------------------------------------
# ADMIN: CREATE AN ADMIN ACCOUNT
# --------------------------------------------------

@app.post("/api/admin/create")
def create_admin(
    request: LoginRequest,
    authorization: Optional[str] = Header(default=None)
):
    user = get_current_user(authorization)
    require_admin(user)

    username = request.username.strip()

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,50}", username):
        raise HTTPException(status_code=400, detail="Invalid username")

    if len(request.password) < 12:
        raise HTTPException(
            status_code=400,
            detail="Admin password must be at least 12 characters"
        )

    try:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO users (username, password_hash, role, created_at)
                VALUES (?, ?, 'admin', ?)
            """, (
                username,
                pwd_context.hash(request.password),
                datetime.now(timezone.utc).isoformat()
            ))
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username already exists")

    log_action(
        user["username"],
        "CREATE_ADMIN",
        details=f"Created admin {username}"
    )

    return {"message": "Admin account created"}
