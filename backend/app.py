from fastapi import FastAPI, UploadFile, File, HTTPException, Header
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import shutil
import uuid
import os
import json
from datetime import datetime

# Import teammates' modules
from file_parser.parser import parse_file
from detector.detector import PIIDetector
from sanitizer.sanitizer import FileSanitizer

# Initialize detector and sanitizer
detector = PIIDetector(use_nlp=True)
sanitizer = FileSanitizer()

# ── App Setup ─────────────────────────────────────────────
app = FastAPI(
    title="🛡️ PII Sanitizer API",
    description="""
## Automated PII Detection & Sanitization Platform
Upload files containing sensitive data. The system automatically detects and masks:
- **Names**, **Phone Numbers**, **Email Addresses**
- **Aadhaar Numbers**, **PAN Numbers**, **Addresses**
- **Bank details**, **IP addresses**, and more

### User Roles
- `admin` → upload, view original, view sanitized, manage users, see audit logs
- `user`  → upload, view and download sanitized files, search records
    """,
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Folder Paths ──────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
AUDIT_LOG  = os.path.join(BASE_DIR, "audit_log.jsonl")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

frontend_path = os.path.join(BASE_DIR, "frontend")
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")
else:
    print(f"[WARNING] Frontend not found at: {frontend_path}")

# ── In-Memory Storage ─────────────────────────────────────
file_registry = {}

user_registry = {
    "admin": {"username": "admin", "role": "admin", "created_at": datetime.now().isoformat()},
    "user1": {"username": "user1", "role": "user",  "created_at": datetime.now().isoformat()},
}

# ── Audit Logger ──────────────────────────────────────────
def log_event(action: str, file_id: str, user_role: str, details: dict = {}):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "action":    action,
        "file_id":   file_id,
        "user_role": user_role,
        **details
    }
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ── Helper: Extract text from parser output ───────────────
def extract_text(parsed):
    """Handles plain string or dict return from parser"""
    if isinstance(parsed, str):
        return parsed
    elif isinstance(parsed, dict):
        return parsed.get("text", "")
    else:
        return str(parsed)


# ── Helper: Build PII summary from positions list ─────────
def build_summary(pii_list: list) -> dict:
    """Count PII items by type"""
    summary = {}
    for item in pii_list:
        t = item.get("type", "unknown")
        summary[t] = summary.get(t, 0) + 1
    return summary


# ══════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════

@app.get("/", tags=["Health"], include_in_schema=False)
@app.get("/ui", tags=["Health"], include_in_schema=False)
def serve_ui():
    ui_path = os.path.join(BASE_DIR, "frontend", "index.html")
    if os.path.exists(ui_path):
        return FileResponse(ui_path)
    return {"status": "PII Sanitizer is running", "docs": "/docs"}


# ── File Operations ───────────────────────────────────────

@app.post("/upload", tags=["File Operations"], summary="Upload file for PII sanitization")
async def upload_file(
    file: UploadFile = File(...),
    role: str = Header(default="user")
):
    # REMOVED admin-only restriction — both admin and user can upload

    # Validate format
    ext = file.filename.split(".")[-1].lower()
    supported = ["sql", "pdf", "docx", "txt", "csv", "json", "png", "jpg", "jpeg"]
    if ext not in supported:
        raise HTTPException(status_code=400, detail=f"❌ Unsupported format: {ext}")

    # Save original file
    file_id = str(uuid.uuid4())[:8]
    original_path = os.path.join(UPLOAD_DIR, f"{file_id}_original.{ext}")
    with open(original_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    log_event("upload", file_id, role, {"filename": file.filename, "format": ext})

    # Step 1: Parse → extract text from file
    try:
        parsed = parse_file(original_path)
        text = extract_text(parsed)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Parsing failed: {str(e)}")

    # Step 2: Detect PII → get list with positions
    try:
        pii_list = detector.detect_with_positions(text)
        pii_summary = build_summary(pii_list)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Detection failed: {str(e)}")

    # Step 3: Sanitize → use sanitize_file() to preserve original format
    try:
        sanitized_path = sanitizer.sanitize_file(original_path, OUTPUT_DIR, pii_list, detector=detector)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sanitization failed: {str(e)}")

    # Store in registry
    file_registry[file_id] = {
        "original_filename": file.filename,
        "format":            ext,
        "original_path":     original_path,
        "sanitized_path":    sanitized_path,
        "pii_found":         pii_list,
        "pii_count":         len(pii_list),
        "pii_summary":       pii_summary,
        "uploaded_at":       datetime.now().isoformat()
    }
    log_event("pii_detected", file_id, role, {
        "pii_count":   len(pii_list),
        "pii_summary": pii_summary
    })

    return {
        "file_id":            file_id,
        "status":             "✅ Sanitization complete",
        "original_filename":  file.filename,
        "pii_detected_count": len(pii_list),
        "pii_summary":        pii_summary,
        "download_url":       f"/download/{file_id}"
    }


@app.get("/download/{file_id}", tags=["File Operations"], summary="Download sanitized file")
def download_file(
    file_id:  str,
    role:     str  = Header(default="user"),
    original: bool = False
):
    if file_id not in file_registry:
        raise HTTPException(status_code=404, detail="❌ File not found")

    info = file_registry[file_id]

    if original and role == "admin":
        path   = info["original_path"]
        action = "download_original"
    else:
        path   = info["sanitized_path"]
        action = "download_sanitized"

    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="❌ File not found on disk")

    log_event(action, file_id, role)
    actual_san_ext = info["sanitized_path"].rsplit(".", 1)[-1]
    original_base = info["original_filename"].rsplit(".", 1)[0]
    return FileResponse(path, filename=f"sanitized_{original_base}.{actual_san_ext}")


# ── File Operations ───────────────────────────────────────

@app.delete("/delete/{file_id}", tags=["File Operations"], summary="Delete a file (admin only)")
def delete_file(file_id: str, role: str = Header(default="user")):
    if role != "admin":
        raise HTTPException(status_code=403, detail="❌ Only admins can delete files")
    if file_id not in file_registry:
        raise HTTPException(status_code=404, detail="❌ File not found")

    info = file_registry[file_id]

    # Delete original file from disk
    if os.path.exists(info["original_path"]):
        os.remove(info["original_path"])

    # Delete sanitized file from disk
    if os.path.exists(info["sanitized_path"]):
        os.remove(info["sanitized_path"])

    # Remove from registry
    del file_registry[file_id]

    log_event("delete", file_id, role, {"filename": info["original_filename"]})
    return {"status": "✅ File deleted", "file_id": file_id}


# ── Admin Endpoints ───────────────────────────────────────

@app.get("/files", tags=["Admin"], summary="List all files")
def list_files(role: str = Header(default="user")):
    if role == "admin":
        return [
            {
                "file_id":      fid,
                "filename":     info["original_filename"],
                "format":       info["format"],
                "pii_count":    info["pii_count"],
                "uploaded_at":  info["uploaded_at"],
                "download_url": f"/download/{fid}"
            }
            for fid, info in file_registry.items()
        ]
    return [
        {
            "file_id":      fid,
            "filename":     info["original_filename"],
            "download_url": f"/download/{fid}"
        }
        for fid, info in file_registry.items()
    ]


@app.get("/files/search", tags=["File Operations"], summary="Search and filter files")
def search_files(
    query:  str = "",
    format: str = "",
    role:   str = Header(default="user")
):
    results = []
    for fid, info in file_registry.items():
        if query  and query.lower()  not in info["original_filename"].lower(): continue
        if format and info["format"].lower() != format.lower():                continue

        if role == "admin":
            results.append({"file_id": fid, "filename": info["original_filename"], "format": info["format"], "pii_count": info["pii_count"], "download_url": f"/download/{fid}"})
        else:
            results.append({"file_id": fid, "filename": info["original_filename"], "download_url": f"/download/{fid}"})

    return {"query": query, "format": format, "count": len(results), "results": results}


@app.get("/files/{file_id}/pii-report", tags=["Admin"], summary="View PII detection report")
def pii_report(file_id: str, role: str = Header(default="user")):
    if role != "admin":
        raise HTTPException(status_code=403, detail="❌ Admin access required")
    if file_id not in file_registry:
        raise HTTPException(status_code=404, detail="❌ File not found")

    info = file_registry[file_id]
    return {
        "file_id":         file_id,
        "filename":        info["original_filename"],
        "total_pii_found": info["pii_count"],
        "pii_summary":     info["pii_summary"],
        "pii_details":     info["pii_found"]
    }


# ── User Management ───────────────────────────────────────

@app.get("/users", tags=["User Management"], summary="List all users")
def list_users(role: str = Header(default="user")):
    if role != "admin":
        raise HTTPException(status_code=403, detail="❌ Admin access required")
    return list(user_registry.values())


@app.post("/users", tags=["User Management"], summary="Add a new user")
def add_user(username: str, user_role: str = "user", role: str = Header(default="user")):
    if role != "admin":
        raise HTTPException(status_code=403, detail="❌ Admin access required")
    if username in user_registry:
        raise HTTPException(status_code=400, detail="❌ User already exists")

    user_registry[username] = {
        "username":   username,
        "role":       user_role,
        "created_at": datetime.now().isoformat()
    }
    log_event("user_created", username, role, {"new_user_role": user_role})
    return {"status": "✅ User created", "username": username, "role": user_role}


@app.delete("/users/{username}", tags=["User Management"], summary="Delete a user")
def delete_user(username: str, role: str = Header(default="user")):
    if role != "admin":
        raise HTTPException(status_code=403, detail="❌ Admin access required")
    if username not in user_registry:
        raise HTTPException(status_code=404, detail="❌ User not found")

    del user_registry[username]
    log_event("user_deleted", username, role)
    return {"status": "✅ User deleted", "username": username}


# ── Audit Logs & Stats ────────────────────────────────────

@app.get("/audit-logs", tags=["Admin"], summary="View audit logs")
def get_audit_logs(role: str = Header(default="user")):
    if role != "admin":
        raise HTTPException(status_code=403, detail="❌ Admin access required")
    if not os.path.exists(AUDIT_LOG):
        return []
    logs = []
    with open(AUDIT_LOG, "r") as f:
        for line in f:
            try:
                logs.append(json.loads(line.strip()))
            except:
                pass
    return logs


@app.get("/stats", tags=["Admin"], summary="System statistics")
def get_stats(role: str = Header(default="user")):
    if role != "admin":
        raise HTTPException(status_code=403, detail="❌ Admin access required")

    total_pii = sum(info["pii_count"] for info in file_registry.values())
    formats = {}
    for info in file_registry.values():
        fmt = info["format"]
        formats[fmt] = formats.get(fmt, 0) + 1

    return {
        "total_files_processed":   len(file_registry),
        "total_pii_items_removed": total_pii,
        "total_users":             len(user_registry),
        "files_by_format":         formats,
        "system_status":           "🟢 Online"
    }


# ── Run Server ────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
