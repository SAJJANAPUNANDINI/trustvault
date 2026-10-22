from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from jose import JWTError, jwt
from pathlib import Path
from uuid import uuid4
import sqlite3
import os
import hashlib
import hmac
import json

app = FastAPI(title="TrustVault API", version="1.2")

# Same-origin deployment is recommended. Set trusted origins explicitly if needed.
_allowed_origins = os.environ.get(
    "TRUSTVAULT_ALLOWED_ORIGINS",
    "http://127.0.0.1:8000,http://localhost:8000"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in _allowed_origins.split(",") if origin.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

SECRET_KEY = os.environ.get("TRUSTVAULT_SECRET_KEY", "")
if len(SECRET_KEY) < 32:
    raise RuntimeError(
        "Set TRUSTVAULT_SECRET_KEY to a random secret of at least 32 characters."
    )

ALGORITHM = "HS256"
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database.sqlite"
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/login")
ALLOWED_EXTENSIONS = {".pdf", ".docx", ".txt", ".png", ".jpg", ".jpeg"}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB


def db_connect():
    return sqlite3.connect(DB_PATH, timeout=30.0)


def init_db():
    with db_connect() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer'
                    CHECK(role IN ('admin', 'owner', 'viewer'))
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                filename TEXT NOT NULL,
                owner_id INTEGER NOT NULL,
                category TEXT DEFAULT 'General',
                upload_date DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                access_type TEXT NOT NULL CHECK(access_type IN ('read', 'edit')),
                UNIQUE(document_id, user_id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Safe migration for databases created by the earlier version.
        columns = {row[1] for row in cursor.execute("PRAGMA table_info(documents)").fetchall()}
        if "storage_name" not in columns:
            cursor.execute("ALTER TABLE documents ADD COLUMN storage_name TEXT")
            rows = cursor.execute("SELECT id, filename FROM documents").fetchall()
            for doc_id, filename in rows:
                safe_name = Path(filename or "").name
                if safe_name and safe_name == filename and safe_name not in {".", ".."} and "/" not in safe_name and "\\" not in safe_name:
                    cursor.execute(
                        "UPDATE documents SET storage_name = ? WHERE id = ?",
                        (safe_name, doc_id)
                    )
                else:
                    cursor.execute("UPDATE documents SET storage_name = NULL WHERE id = ?", (doc_id,))

        # Older databases may contain duplicate permission rows; keep the latest.
        cursor.execute("""
            DELETE FROM permissions
            WHERE id NOT IN (
                SELECT MAX(id) FROM permissions GROUP BY document_id, user_id
            )
        """)
        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_permissions_document_user
            ON permissions(document_id, user_id)
        """)

        # Add a hash column for tamper-evident audit chaining.
        audit_columns = {row[1] for row in cursor.execute("PRAGMA table_info(audit_logs)").fetchall()}
        if "entry_hash" not in audit_columns:
            cursor.execute("ALTER TABLE audit_logs ADD COLUMN entry_hash TEXT")
            # Existing historical rows are chained during migration; this cannot prove
            # the pre-migration history was not already altered.
            previous_hash = "GENESIS"
            rows = cursor.execute(
                "SELECT id, user_id, action, details, timestamp FROM audit_logs ORDER BY id"
            ).fetchall()
            for row in rows:
                entry_hash = calculate_audit_hash(previous_hash, row)
                cursor.execute(
                    "UPDATE audit_logs SET entry_hash = ? WHERE id = ?",
                    (entry_hash, row[0])
                )
                previous_hash = entry_hash

        conn.commit()


def calculate_audit_hash(previous_hash, row):
    # HMAC uses the same server secret as a demo-friendly tamper-evident chain.
    payload = json.dumps(
        {
            "previous_hash": previous_hash,
            "id": row[0],
            "user_id": row[1],
            "action": row[2],
            "details": row[3],
            "timestamp": row[4],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(SECRET_KEY.encode("utf-8"), payload, hashlib.sha256).hexdigest()


init_db()


@app.get("/", include_in_schema=False)
def serve_frontend():
    index_path = BASE_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return {"message": "index.html not found"}


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        user_id = payload.get("id")
        if not username or not isinstance(user_id, int):
            raise credentials_exception

        # Reload role each request so role changes take effect immediately.
        with db_connect() as conn:
            row = conn.execute(
                "SELECT id, username, role FROM users WHERE id = ?",
                (user_id,)
            ).fetchone()
        if not row or row[1] != username:
            raise credentials_exception
        return {"id": row[0], "username": row[1], "role": row[2]}
    except JWTError:
        raise credentials_exception


def log_audit(user_id: int | None, action: str, details: str):
    with db_connect() as conn:
        cursor = conn.cursor()
        last = cursor.execute(
            "SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous_hash = last[0] if last and last[0] else "GENESIS"
        timestamp = cursor.execute("SELECT CURRENT_TIMESTAMP").fetchone()[0]
        # Insert placeholder row to obtain its id, then calculate its hash.
        cursor.execute(
            "INSERT INTO audit_logs (user_id, action, details, timestamp, entry_hash) VALUES (?, ?, ?, ?, NULL)",
            (user_id, action, details, timestamp)
        )
        row_id = cursor.lastrowid
        row = (row_id, user_id, action, details, timestamp)
        entry_hash = calculate_audit_hash(previous_hash, row)
        cursor.execute("UPDATE audit_logs SET entry_hash = ? WHERE id = ?", (entry_hash, row_id))
        conn.commit()


class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)
    # Public registration may create owner/viewer only; never self-assign admin.
    role: str = Field(default="viewer", pattern="^(viewer|owner)$")


class PermissionRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    access_type: str = Field(default="read", pattern="^(read|edit)$")


class DocumentUpdate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    category: str = Field(default="General", max_length=100)


@app.post("/api/register")
def register(user: UserRegister):
    username = user.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username cannot be blank")

    hashed_password = pwd_context.hash(user.password)
    try:
        with db_connect() as conn:
            cursor = conn.cursor()
            assigned_role = user.role
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hashed_password, assigned_role)
            )
            user_id = cursor.lastrowid
            conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already registered")

    log_audit(user_id, "REGISTER", f"New {assigned_role} account registered: {username}")
    return {"message": "User registered successfully!", "role": assigned_role}


@app.post("/api/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    with db_connect() as conn:
        db_user = conn.execute(
            "SELECT id, username, password, role FROM users WHERE username = ?",
            (form_data.username,)
        ).fetchone()

    if not db_user or not pwd_context.verify(form_data.password, db_user[2]):
        log_audit(None, "LOGIN_FAILED", f"Failed login attempt for username: {form_data.username[:50]}")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token_data = {"sub": db_user[1], "id": db_user[0]}
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
    log_audit(db_user[0], "LOGIN", f"User {db_user[1]} logged in successfully")
    return {"access_token": token, "token_type": "bearer", "role": db_user[3], "username": db_user[1]}


@app.post("/api/upload")
def upload_document(
    title: str = Form(...),
    category: str = Form("General"),
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
):
    if current_user["role"] not in {"admin", "owner"}:
        log_audit(current_user["id"], "UPLOAD_DENIED", "Unauthorized user attempted to upload a document")
        raise HTTPException(
            status_code=403,
            detail="Only admins and owners can upload documents"
        )

    original_name = Path(file.filename or "").name
    ext = Path(original_name).suffix.lower()
    if not original_name or original_name in {".", ".."}:
        raise HTTPException(status_code=400, detail="A valid filename is required")
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Allowed: PDF, DOCX, TXT, PNG, JPG, JPEG."
        )
    if not title.strip():
        raise HTTPException(status_code=400, detail="Document title cannot be blank")

    storage_name = f"{uuid4().hex}{ext}"
    file_path = (UPLOAD_DIR / storage_name).resolve()
    if file_path.parent != UPLOAD_DIR.resolve():
        raise HTTPException(status_code=400, detail="Invalid file path")

    size = 0
    try:
        with file_path.open("xb") as output:
            while True:
                chunk = file.file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    output.close()
                    file_path.unlink(missing_ok=True)
                    raise HTTPException(status_code=413, detail="File exceeds 10 MB limit")
                output.write(chunk)

        with db_connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO documents (title, filename, owner_id, category, storage_name)
                   VALUES (?, ?, ?, ?, ?)""",
                (title.strip(), original_name, current_user["id"], category.strip() or "General", storage_name)
            )
            doc_id = cursor.lastrowid
            conn.commit()
    except Exception:
        file_path.unlink(missing_ok=True)
        raise
    finally:
        file.file.close()

    log_audit(current_user["id"], "UPLOAD", f"Uploaded document id={doc_id}, title={title.strip()}")
    return {"message": "Document uploaded successfully!", "filename": original_name, "document_id": doc_id}


@app.get("/api/documents")
def get_documents(
    search: str | None = None,
    owner: str | None = None,
    category: str | None = None,
    date: str | None = None,
    current_user: dict = Depends(get_current_user),
):
    with db_connect() as conn:
        query = """
            SELECT DISTINCT d.id, d.title, d.filename, d.owner_id, d.category, d.upload_date, u.username
            FROM documents d
            JOIN users u ON d.owner_id = u.id
            LEFT JOIN permissions p ON d.id = p.document_id
            WHERE (
                d.owner_id = ?
                OR ? = 'admin'
                OR (p.user_id = ? AND p.access_type IN ('read', 'edit'))
            )
        """
        params = [current_user["id"], current_user["role"], current_user["id"]]
        if search:
            query += " AND (d.title LIKE ? OR d.filename LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])
        if owner:
            query += " AND u.username LIKE ?"
            params.append(f"%{owner}%")
        if category:
            query += " AND d.category LIKE ?"
            params.append(f"%{category}%")
        if date:
            query += " AND DATE(d.upload_date) = ?"
            params.append(date)
        query += " ORDER BY d.upload_date DESC"
        docs = conn.execute(query, params).fetchall()
    return {"documents": docs}


@app.get("/api/documents/{doc_id}/download")
def download_document(doc_id: int, current_user: dict = Depends(get_current_user)):
    with db_connect() as conn:
        doc = conn.execute(
            "SELECT id, title, filename, owner_id, storage_name FROM documents WHERE id = ?",
            (doc_id,)
        ).fetchone()
        if not doc:
            log_audit(current_user["id"], "DOWNLOAD_DENIED", f"Document id={doc_id} does not exist")
            raise HTTPException(status_code=404, detail="Document not found")

        actual_doc_id, title, original_name, owner_id, storage_name = doc
        is_owner_or_admin = current_user["role"] == "admin" or owner_id == current_user["id"]
        access_type = None
        if not is_owner_or_admin:
            permission = conn.execute(
                "SELECT access_type FROM permissions WHERE document_id = ? AND user_id = ?",
                (actual_doc_id, current_user["id"])
            ).fetchone()
            access_type = permission[0] if permission else None

    if not is_owner_or_admin and access_type not in {"read", "edit"}:
        log_audit(current_user["id"], "DOWNLOAD_DENIED", f"Denied download for document id={doc_id}")
        raise HTTPException(status_code=403, detail="Access denied")

    if not storage_name or Path(storage_name).name != storage_name or storage_name in {".", ".."}:
        log_audit(current_user["id"], "DOWNLOAD_DENIED", f"Unsafe storage path for document id={doc_id}")
        raise HTTPException(status_code=404, detail="Stored file is unavailable")

    file_path = (UPLOAD_DIR / storage_name).resolve()
    if file_path.parent != UPLOAD_DIR.resolve() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="File not found on server")

    log_audit(current_user["id"], "DOWNLOAD", f"Downloaded document id={doc_id}")
    return FileResponse(file_path, filename=original_name)


@app.post("/api/documents/{doc_id}/update")
def update_document(
    doc_id: int,
    update: DocumentUpdate,
    current_user: dict = Depends(get_current_user),
):
    title = update.title.strip()
    category = update.category.strip() or "General"
    if not title:
        raise HTTPException(status_code=400, detail="Document title cannot be blank")

    with db_connect() as conn:
        doc = conn.execute(
            "SELECT id, owner_id FROM documents WHERE id = ?", (doc_id,)
        ).fetchone()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")

        owner_id = doc[1]
        permission = conn.execute(
            "SELECT access_type FROM permissions WHERE document_id = ? AND user_id = ?",
            (doc_id, current_user["id"])
        ).fetchone()

        can_edit = (
            current_user["role"] == "admin"
            or owner_id == current_user["id"]
            or (permission is not None and permission[0] == "edit")
        )
        if not can_edit:
            log_audit(
                current_user["id"],
                "UPDATE_DENIED",
                f"Denied metadata update for document id={doc_id}"
            )
            raise HTTPException(status_code=403, detail="Edit permission required")

        conn.execute(
            "UPDATE documents SET title = ?, category = ? WHERE id = ?",
            (title, category, doc_id)
        )
        conn.commit()

    log_audit(current_user["id"], "UPDATE_DOCUMENT", f"Updated details for document id={doc_id}")
    return {
        "message": "Document details updated successfully",
        "document_id": doc_id,
        "title": title,
        "category": category
    }


@app.post("/api/documents/{doc_id}/delete")
def delete_document(doc_id: int, current_user: dict = Depends(get_current_user)):
    with db_connect() as conn:
        doc = conn.execute(
            "SELECT id, title, storage_name, owner_id FROM documents WHERE id = ?",
            (doc_id,)
        ).fetchone()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")

        _, title, storage_name, owner_id = doc
        # Admins and owners may delete; edit permission alone does not grant delete.
        if current_user["role"] != "admin" and owner_id != current_user["id"]:
            log_audit(
                current_user["id"],
                "DELETE_DENIED",
                f"Denied delete attempt for document id={doc_id}"
            )
            raise HTTPException(status_code=403, detail="Only the document owner or admin can delete")

        conn.execute("DELETE FROM permissions WHERE document_id = ?", (doc_id,))
        conn.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
        conn.commit()

    if storage_name and Path(storage_name).name == storage_name and storage_name not in {".", ".."}:
        file_path = (UPLOAD_DIR / storage_name).resolve()
        if file_path.parent == UPLOAD_DIR.resolve() and file_path.is_file():
            file_path.unlink()

    log_audit(current_user["id"], "DELETE_DOCUMENT", f"Deleted document id={doc_id}, title={title}")
    return {"message": "Document deleted successfully", "document_id": doc_id}


@app.post("/api/documents/{doc_id}/grant")
def grant_permission(doc_id: int, perm: PermissionRequest, current_user: dict = Depends(get_current_user)):
    with db_connect() as conn:
        doc = conn.execute(
            "SELECT id, owner_id FROM documents WHERE id = ?", (doc_id,)
        ).fetchone()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")
        if current_user["role"] != "admin" and doc[1] != current_user["id"]:
            log_audit(current_user["id"], "GRANT_DENIED", f"Denied grant attempt for document id={doc_id}")
            raise HTTPException(status_code=403, detail="Only owner or admin can grant permissions")

        target_user = conn.execute(
            "SELECT id FROM users WHERE username = ?", (perm.username.strip(),)
        ).fetchone()
        if not target_user:
            raise HTTPException(status_code=404, detail="Target user not found")
        target_user_id = target_user[0]
        conn.execute(
            """INSERT INTO permissions (document_id, user_id, access_type)
               VALUES (?, ?, ?)
               ON CONFLICT(document_id, user_id)
               DO UPDATE SET access_type = excluded.access_type""",
            (doc_id, target_user_id, perm.access_type)
        )
        conn.commit()

    log_audit(current_user["id"], "GRANT_PERMISSION",
              f"Granted {perm.access_type} access for document id={doc_id} to {perm.username}")
    return {"message": f"{perm.access_type.title()} access granted to {perm.username}."}


@app.post("/api/documents/{doc_id}/revoke")
def revoke_permission(doc_id: int, perm: PermissionRequest, current_user: dict = Depends(get_current_user)):
    with db_connect() as conn:
        doc = conn.execute(
            "SELECT id, owner_id FROM documents WHERE id = ?", (doc_id,)
        ).fetchone()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")
        if current_user["role"] != "admin" and doc[1] != current_user["id"]:
            log_audit(current_user["id"], "REVOKE_DENIED", f"Denied revoke attempt for document id={doc_id}")
            raise HTTPException(status_code=403, detail="Only owner or admin can revoke permissions")

        target_user = conn.execute(
            "SELECT id FROM users WHERE username = ?", (perm.username.strip(),)
        ).fetchone()
        if not target_user:
            raise HTTPException(status_code=404, detail="Target user not found")
        cursor = conn.execute(
            "DELETE FROM permissions WHERE document_id = ? AND user_id = ?",
            (doc_id, target_user[0])
        )
        conn.commit()
        removed = cursor.rowcount

    log_audit(current_user["id"], "REVOKE_PERMISSION",
              f"Revoked access for document id={doc_id} from {perm.username}")
    return {"message": f"Access revoked from {perm.username}.", "permission_removed": removed > 0}


@app.get("/api/audit-logs")
def get_audit_logs(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        log_audit(current_user["id"], "AUDIT_LOGS_DENIED", "Non-admin attempted to view audit logs")
        raise HTTPException(status_code=403, detail="Access denied. Admins only.")

    with db_connect() as conn:
        logs = conn.execute(
            "SELECT id, user_id, action, details, timestamp, entry_hash FROM audit_logs ORDER BY timestamp DESC, id DESC"
        ).fetchall()
    return {"audit_logs": logs}


@app.get("/api/audit-logs/verify")
def verify_audit_logs(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admins only.")

    with db_connect() as conn:
        rows = conn.execute(
            "SELECT id, user_id, action, details, timestamp, entry_hash FROM audit_logs ORDER BY id ASC"
        ).fetchall()

    previous_hash = "GENESIS"
    for row in rows:
        base_row = (row[0], row[1], row[2], row[3], row[4])
        expected = calculate_audit_hash(previous_hash, base_row)
        if not row[5] or not hmac.compare_digest(row[5], expected):
            return {"valid": False, "failed_entry_id": row[0]}
        previous_hash = row[5]

    return {"valid": True, "entries_checked": len(rows)}
