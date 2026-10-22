from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
import sqlite3
import shutil
import os

app = FastAPI(title="TrustVault API", version="1.0")

# CORS Setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "trustvault_secure_python_secret"
ALGORITHM = "HS256"
UPLOAD_DIR = "uploads"

if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/login")

# Allowed file extensions for Point 8 (Validation)
ALLOWED_EXTENSIONS = {".pdf", ".docx", ".txt", ".png", ".jpg", ".jpeg"}

# Database Setup with timeout
def init_db():
    with sqlite3.connect("database.sqlite", timeout=30.0) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                role TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                filename TEXT,
                owner_id INTEGER,
                category TEXT DEFAULT 'General',
                upload_date DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER,
                user_id INTEGER,
                access_type TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT,
                details TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

init_db()

# Serve Frontend Index Page directly at Root URL (http://127.0.0.1:8000)
@app.get("/", include_in_schema=False)
def serve_frontend():
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    return {"message": "index.html not found"}

# Helper: Get Current User from JWT Token
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("id")
        role: str = payload.get("role")
        if username is None:
            raise credentials_exception
        return {"id": user_id, "username": username, "role": role}
    except JWTError:
        raise credentials_exception

# Helper: Log Audit Trail
def log_audit(user_id: int, action: str, details: str):
    with sqlite3.connect("database.sqlite", timeout=30.0) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)", 
                       (user_id, action, details))
        conn.commit()

class UserRegister(BaseModel):
    username: str
    password: str
    role: str = "viewer"

class PermissionRequest(BaseModel):
    username: str
    access_type: str = "read"

# 1. Register Endpoint
@app.post("/api/register")
def register(user: UserRegister):
    hashed_password = pwd_context.hash(user.password)
    try:
        with sqlite3.connect("database.sqlite", timeout=30.0) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                           (user.username, hashed_password, user.role))
            conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already registered")
    return {"message": "User registered successfully!"}

# 2. Login Endpoint
@app.post("/api/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    with sqlite3.connect("database.sqlite", timeout=30.0) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, role FROM users WHERE username = ?", (form_data.username,))
        db_user = cursor.fetchone()

    if not db_user or not pwd_context.verify(form_data.password, db_user[2]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    token_data = {"sub": db_user[1], "id": db_user[0], "role": db_user[3]}
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
    
    log_audit(db_user[0], "LOGIN", f"User {db_user[1]} logged in successfully.")
    return {"access_token": token, "token_type": "bearer"}

# 3. Upload Document Endpoint with Validation (Point 8)
@app.post("/api/upload")
def upload_document(
    title: str = Form(...), 
    category: str = Form("General"), 
    file: UploadFile = File(...), 
    current_user: dict = Depends(get_current_user)
):
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid file type '{ext}'. Only PDF, DOCX, TXT, and Image files are allowed."
        )

    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    with sqlite3.connect("database.sqlite", timeout=30.0) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO documents (title, filename, owner_id, category) VALUES (?, ?, ?, ?)", 
                       (title, file.filename, current_user["id"], category))
        conn.commit()

    log_audit(current_user["id"], "UPLOAD", f"Uploaded document: {title} under category: {category}")
    return {"message": "Document uploaded successfully!", "filename": file.filename}

# 4. Advanced Search Endpoint
@app.get("/api/documents")
def get_documents(
    search: str = None, 
    owner: str = None, 
    category: str = None, 
    date: str = None, 
    current_user: dict = Depends(get_current_user)
):
    with sqlite3.connect("database.sqlite", timeout=30.0) as conn:
        cursor = conn.cursor()
        
        query = """
            SELECT DISTINCT d.id, d.title, d.filename, d.owner_id, d.category, d.upload_date, u.username 
            FROM documents d 
            JOIN users u ON d.owner_id = u.id
            LEFT JOIN permissions p ON d.id = p.document_id 
            WHERE (1=1)
        """
        params = []
        
        if current_user["role"] != "admin":
            query += " AND (d.owner_id = ? OR p.user_id = ?)"
            params.extend([current_user["id"], current_user["id"]])
            
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
            
        cursor.execute(query, params)
        docs = cursor.fetchall()

    return {"documents": docs}

# 5. Secure Document Download Endpoint (Point 5)
@app.get("/api/download/{filename}")
def download_document(filename: str, current_user: dict = Depends(get_current_user)):
    with sqlite3.connect("database.sqlite", timeout=30.0) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, title, filename, owner_id FROM documents WHERE filename = ?", (filename,))
        doc = cursor.fetchone()

        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")
        
        doc_id, doc_title, doc_filename, owner_id = doc

        has_access = False
        if current_user["role"] == "admin" or owner_id == current_user["id"]:
            has_access = True
        else:
            cursor.execute("SELECT id FROM permissions WHERE document_id = ? AND user_id = ?", (doc_id, current_user["id"]))
            if cursor.fetchone():
                has_access = True

    if not has_access:
        log_audit(current_user["id"], "UNAUTHORIZED_ACCESS", f"Attempted to download document: {filename}")
        raise HTTPException(status_code=403, detail="Access denied. You do not have permission to access this document.")

    file_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found on server")

    log_audit(current_user["id"], "DOWNLOAD", f"Downloaded document: {filename}")
    return FileResponse(file_path, filename=filename)

# 6. Grant Access Endpoint
@app.post("/api/documents/{doc_id}/grant")
def grant_permission(doc_id: int, perm: PermissionRequest, current_user: dict = Depends(get_current_user)):
    with sqlite3.connect("database.sqlite", timeout=30.0) as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, owner_id FROM documents WHERE id = ?", (doc_id,))
        doc = cursor.fetchone()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")
            
        if current_user["role"] != "admin" and doc[1] != current_user["id"]:
            raise HTTPException(status_code=403, detail="Only owner or admin can grant permissions")
            
        cursor.execute("SELECT id FROM users WHERE username = ?", (perm.username,))
        target_user = cursor.fetchone()
        if not target_user:
            raise HTTPException(status_code=404, detail="Target user not found")
            
        target_user_id = target_user[0]
        
        cursor.execute("INSERT INTO permissions (document_id, user_id, access_type) VALUES (?, ?, ?)",
                       (doc_id, target_user_id, perm.access_type))
        conn.commit()
    
    log_audit(current_user["id"], "GRANT_PERMISSION", f"Granted {perm.access_type} access for doc {doc_id} to user {perm.username}")
    return {"message": f"Access granted successfully to {perm.username}!"}

# 7. Revoke Access Endpoint
@app.post("/api/documents/{doc_id}/revoke")
def revoke_permission(doc_id: int, perm: PermissionRequest, current_user: dict = Depends(get_current_user)):
    with sqlite3.connect("database.sqlite", timeout=30.0) as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, owner_id FROM documents WHERE id = ?", (doc_id,))
        doc = cursor.fetchone()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")
            
        if current_user["role"] != "admin" and doc[1] != current_user["id"]:
            raise HTTPException(status_code=403, detail="Only owner or admin can revoke permissions")
            
        cursor.execute("SELECT id FROM users WHERE username = ?", (perm.username,))
        target_user = cursor.fetchone()
        if not target_user:
            raise HTTPException(status_code=404, detail="Target user not found")
            
        target_user_id = target_user[0]
        
        cursor.execute("DELETE FROM permissions WHERE document_id = ? AND user_id = ?", (doc_id, target_user_id))
        conn.commit()
    
    log_audit(current_user["id"], "REVOKE_PERMISSION", f"Revoked access for doc {doc_id} from user {perm.username}")
    return {"message": f"Access revoked successfully from {perm.username}!"}

# 8. Get Audit Logs (Admin only)
@app.get("/api/audit-logs")
def get_audit_logs(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Access denied. Admins only.")
    
    with sqlite3.connect("database.sqlite", timeout=30.0) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, user_id, action, details, timestamp FROM audit_logs ORDER BY timestamp DESC")
        logs = cursor.fetchall()
        
    return {"audit_logs": logs}