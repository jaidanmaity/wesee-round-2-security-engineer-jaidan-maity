"""
WeSee FileShare — a small internal file-sharing API.
"""

import base64
import json
import os
import sqlite3
# CHANGED: Added required standard libraries for security implementations
import time
import hmac
import hashlib

from flask import Flask, request, jsonify, g
# CHANGED: Added werkzeug utilities for safe path and password handling
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "fileshare.db")
STORAGE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "storage"))
SECRET_KEY = "dev-secret-123"
# CHANGED: Removed MASTER_PASSWORD variable completely to eliminate the backdoor

# ADDED: Configuration for Brute-Force Rate Limiting
FAILED_LOGINS = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 60  # seconds

# ADDED: Simple Audit Log helper function
def audit_log(event_type, details):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    client_ip = request.remote_addr or "unknown"
    with open("security_audit.log", "a") as f:
        f.write(f"[{timestamp}] IP:{client_ip} - {event_type} - {details}\n")


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    d = g.pop("db", None)
    if d is not None:
        d.close()


def make_token(user):
    payload = {"uid": user["id"], "username": user["username"], "role": user["role"]}
    raw = json.dumps(payload).encode()
    b64_payload = base64.urlsafe_b64encode(raw).decode()
    # CHANGED: Appended an HMAC-SHA256 signature to the token to prevent forgery
    signature = hmac.new(SECRET_KEY.encode(), b64_payload.encode(), hashlib.sha256).hexdigest()
    return f"{b64_payload}.{signature}"


def read_token():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[len("Bearer "):]
    try:
        # CHANGED: Verify the cryptographic HMAC signature before trusting the token
        if "." not in token:
            return None
        b64_payload, provided_signature = token.split(".", 1)
        expected_signature = hmac.new(SECRET_KEY.encode(), b64_payload.encode(), hashlib.sha256).hexdigest()
        
        if not hmac.compare_digest(provided_signature, expected_signature):
            audit_log("TOKEN_TAMPERING", "Invalid signature detected")
            return None
            
        raw = base64.urlsafe_b64decode(b64_payload.encode())
        return json.loads(raw)
    except Exception:
        return None


# ADDED: Helper function to enforce secure file paths and prevent traversal
def get_safe_path(filename):
    # 1. Strictly check if the raw filename attempts to escape the storage directory
    raw_target_path = os.path.abspath(os.path.join(STORAGE_DIR, filename))
    
    try:
        # Use commonpath to guarantee the target stays fully inside STORAGE_DIR
        if os.path.commonpath([STORAGE_DIR, raw_target_path]) != os.path.abspath(STORAGE_DIR):
            return None
    except ValueError:
        # Failsafe for OS edge cases (like different drives on Windows)
        return None

    # 2. If it's safely within bounds, sanitize it for the filesystem
    safe_name = secure_filename(filename)
    if not safe_name:
        return None
        
    return os.path.join(STORAGE_DIR, safe_name)

@app.post("/login")
def login():
    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")

    # ADDED: Brute-Force Rate Limiting check
    client_ip = request.remote_addr
    tracker_key = f"{client_ip}_{username}"
    if tracker_key in FAILED_LOGINS:
        attempts, lockout_end = FAILED_LOGINS[tracker_key]
        if time.time() < lockout_end:
            audit_log("BRUTE_FORCE_BLOCK", f"Locked out IP for {username}")
            return jsonify({"error": "Too many attempts, please try again later"}), 429

    # CHANGED: Implemented parameterized queries to prevent SQL Injection (SQLi)
    row = db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    # CHANGED: Removed the MASTER_PASSWORD logic. Added check_password_hash verification
    if row is None or not check_password_hash(row["password"], password):
        # ADDED: Update Brute-Force failure counter
        attempts = FAILED_LOGINS.get(tracker_key, (0, 0))[0] + 1
        lockout_end = time.time() + LOCKOUT_TIME if attempts >= MAX_ATTEMPTS else 0
        FAILED_LOGINS[tracker_key] = (attempts, lockout_end)
        
        audit_log("LOGIN_FAILED", f"Failed attempt for {username}")
        return jsonify({"error": "invalid credentials"}), 401

    # ADDED: Reset Brute-Force counter on successful login
    if tracker_key in FAILED_LOGINS:
        del FAILED_LOGINS[tracker_key]

    audit_log("LOGIN_SUCCESS", f"User {username} successfully authenticated")
    return jsonify({"token": make_token(row), "role": row["role"]})


@app.get("/api/me")
def me():
    tok = read_token()
    if not tok:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(tok)


@app.get("/api/files")
def list_files():
    tok = read_token()
    if not tok:
        return jsonify({"error": "unauthorized"}), 401
    rows = db().execute(
        "SELECT id, filename, is_private, owner_id FROM files WHERE owner_id = ?",
        (tok["uid"],),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/files/<int:file_id>")
def get_file(file_id):
    tok = read_token()
    if not tok:
        return jsonify({"error": "unauthorized"}), 401
        
    row = db().execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404

    # ADDED: Broken Object Level Authorization (BOLA) verification
    if row["owner_id"] != tok["uid"] and tok.get("role") != "admin":
        audit_log("BOLA_VIEW_ATTEMPT", f"User {tok['uid']} tried to view unauthorized file ID {file_id}")
        return jsonify({"error": "forbidden"}), 403

    # CHANGED: Utilize safe path helper to prevent path traversal
    path = get_safe_path(row["filename"])
    if not path or not os.path.exists(path):
        return jsonify({"error": "file not found"}), 404
        
    content = ""
    with open(path) as f:
        content = f.read()
    return jsonify({**dict(row), "content": content})


@app.post("/api/files")
def create_file():
    tok = read_token()
    if not tok:
        return jsonify({"error": "unauthorized"}), 401
        
    data = request.get_json(force=True)
    filename = data.get("filename", "untitled.txt")
    content = data.get("content", "")
    
    # CHANGED: Validate and strip malicious input from filename to prevent traversal
    path = get_safe_path(filename)
    if not path:
        audit_log("PATH_TRAVERSAL_WRITE", f"User {tok['uid']} attempted illegal filename write")
        return jsonify({"error": "invalid filename"}), 400
        
    safe_filename = secure_filename(filename)

    with open(path, "w") as f:
        f.write(content)
        
    cur = db().execute(
        "INSERT INTO files (owner_id, filename, is_private) VALUES (?, ?, ?)",
        (tok["uid"], safe_filename, 1),
    )
    db().commit()
    
    audit_log("FILE_CREATED", f"User {tok['uid']} created {safe_filename}")
    return jsonify({"id": cur.lastrowid, "filename": safe_filename}), 201


@app.delete("/api/files/<int:file_id>")
def delete_file(file_id):
    tok = read_token()
    if not tok:
        return jsonify({"error": "unauthorized"}), 401
        
    row = db().execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404
        
    # ADDED: Broken Object Level Authorization (BOLA) verification for deletion
    if row["owner_id"] != tok["uid"] and tok.get("role") != "admin":
        audit_log("BOLA_DELETE_ATTEMPT", f"User {tok['uid']} tried to delete unauthorized file ID {file_id}")
        return jsonify({"error": "forbidden"}), 403

    db().execute("DELETE FROM files WHERE id = ?", (file_id,))
    db().commit()
    
    # ADDED: Physically delete the file safely from the storage directory
    path = get_safe_path(row["filename"])
    if path and os.path.exists(path):
        os.remove(path)
        
    audit_log("FILE_DELETED", f"User {tok['uid']} deleted file ID {file_id}")
    return jsonify({"deleted": file_id})


@app.get("/api/download")
def download():
    tok = read_token()
    if not tok:
        return jsonify({"error": "unauthorized"}), 401
        
    name = request.args.get("name", "")
    
    # CHANGED: Resolve and constrain path to prevent file read traversal
    path = get_safe_path(name)
    if not path or not os.path.exists(path):
        audit_log("PATH_TRAVERSAL_READ", f"User {tok['uid']} attempted illegal download: {name}")
        return jsonify({"error": "not found"}), 404

    # ADDED: Enforce BOLA authorization rules on arbitrary download by name
    safe_name = secure_filename(name)
    row = db().execute("SELECT * FROM files WHERE filename = ?", (safe_name,)).fetchone()
    if row and row["owner_id"] != tok["uid"] and tok.get("role") != "admin":
        audit_log("BOLA_DOWNLOAD_ATTEMPT", f"User {tok['uid']} tried to download unauthorized file: {name}")
        return jsonify({"error": "forbidden"}), 403

    with open(path) as f:
        return jsonify({"name": safe_name, "content": f.read()})


@app.get("/api/users")
def users():
    # CHANGED: Added authentication middleware to protect sensitive endpoint
    tok = read_token()
    if not tok:
        return jsonify({"error": "unauthorized"}), 401
        
    # CHANGED: Explicitly omit the 'password' column from being selected and broadcasted
    rows = db().execute("SELECT id, username, role, email FROM users").fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/admin")
def admin():
    tok = read_token()
    if not tok or tok.get("role") != "admin":
        audit_log("ADMIN_BYPASS", f"Non-admin access attempted by ID {tok.get('uid') if tok else 'unknown'}")
        return jsonify({"error": "forbidden"}), 403
        
    count = db().execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    return jsonify({"message": "welcome admin", "user_count": count})


if __name__ == "__main__":
    # CHANGED: Disabled debug mode to prevent remote code execution in production
    app.run(host="127.0.0.1", port=5000, debug=False)
