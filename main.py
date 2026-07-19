"""
LocalDrop — app.py
==================
Architecture decisions explained:

TEXT transfers  → stored directly in Redis (tiny payload, TTL handles deletion)
FILE transfers  → stored on DISK with UUID filename, Redis holds ONLY metadata
                  This keeps Redis payloads under 500 bytes per transfer regardless of file size.

Token cost per transfer:
  Before (files in Redis): hundreds of tokens per MB
  After  (metadata only) : 3-5 tokens per transfer, always
"""

import io
import json
import logging
import os
import random
import time
import uuid
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, send_file, url_for
from upstash_redis import Redis
from werkzeug.utils import secure_filename

# ─── Logging — replace print() with proper structured logs ───────────────────
# In production you will see these in Railway/Render log dashboards
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def _load_environment_file():
    """Load values from a local .env file when present."""
    dotenv_path = BASE_DIR / ".env"
    if not dotenv_path.exists():
        return

    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value

    log.info("Loaded environment variables from %s", dotenv_path)


# ─── App setup ───────────────────────────────────────────────────────────────
app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
_load_environment_file()

# SECRET_KEY: no fallback — fail loudly in production if not set
flask_env = os.environ.get("FLASK_ENV", "development")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    if flask_env == "development":
        app.config["SECRET_KEY"] = "dev-only-insecure-key"
        log.warning("SECRET_KEY not set — using insecure dev key. Never do this in production.")
    else:
        raise RuntimeError("SECRET_KEY environment variable is required.")

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024   # 10 MB hard limit — Flask enforces this
app.config["TRANSFER_TTL_SECONDS"] = 900               # 15 minutes (changed from 5)

configured_upload_folder = os.environ.get("UPLOAD_FOLDER")
if configured_upload_folder:
    upload_folder_path = Path(configured_upload_folder).expanduser()
    if not upload_folder_path.is_absolute():
        upload_folder_path = BASE_DIR / upload_folder_path
else:
    upload_folder_path = BASE_DIR / "uploads"

app.config["UPLOAD_FOLDER"] = upload_folder_path.resolve()
app.config["UPLOAD_FOLDER"].mkdir(parents=True, exist_ok=True)

# ─── Allowed file types — validated on SERVER not just browser ───────────────
# We check BOTH extension AND mimetype. Extension alone can be spoofed.
ALLOWED = {
    ".png":  ["image/png"],
    ".jpg":  ["image/jpeg"],
    ".jpeg": ["image/jpeg"],
    ".pdf":  ["application/pdf"],
    ".doc":  ["application/msword"],
    ".docx": ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
    ".txt":  ["text/plain"],
}

# ─── Redis client — credentials ONLY from environment, never hardcoded ───────
_redis_url   = os.environ.get("UPSTASH_REDIS_REST_URL")
_redis_token = os.environ.get("UPSTASH_REDIS_REST_TOKEN")

if not _redis_url or not _redis_token:
    raise RuntimeError(
        "UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN must be set as environment variables. "
        "Create a .env file locally and use python-dotenv, or set them in your deployment dashboard."
    )

redis_client = Redis(url=_redis_url, token=_redis_token)
log.info("Redis client initialised.")


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _validate_file(file_storage):
    """
    Server-side file validation. Returns error string or None if valid.
    Two-layer check: extension whitelist + MIME type match.
    Extension alone can be renamed (e.g. malware.exe → malware.pdf).
    MIME alone can be spoofed in the Content-Type header.
    Both together are significantly harder to bypass.
    """
    filename = file_storage.filename or ""
    ext = Path(filename).suffix.lower()

    if ext not in ALLOWED:
        return f"File type '{ext or 'unknown'}' is not supported. Allowed: PNG, JPEG, PDF, Word, TXT."

    # Check if the reported mimetype is consistent with the extension
    reported_mime = (file_storage.mimetype or "").split(";")[0].strip().lower()
    if reported_mime and reported_mime not in ALLOWED[ext]:
        return f"File content does not match its extension. Expected {ALLOWED[ext]}, got '{reported_mime}'."

    return None


def _generate_unique_code():
    """
    Generate a 7-digit code guaranteed unique in Redis at this moment.
    Pattern: check-then-insert with Redis as the source of truth.
    The while loop handles the (very rare) collision case.
    No ACID transaction needed here — Redis SET NX (set if not exists)
    would be even safer but this is sufficient for this scale.
    """
    attempts = 0
    while attempts < 10:
        code = str(random.randint(1000000, 9999999))  # uniform distribution, no modulo bias
        if not redis_client.get(code):
            return code
        attempts += 1
        log.warning("Code collision on attempt %d, retrying...", attempts)
    raise RuntimeError("Could not generate a unique code after 10 attempts. Redis may be overloaded.")


def _store_metadata(code, payload: dict, ttl: int):
    """Store ONLY metadata in Redis. Never file bytes."""
    redis_client.set(code, json.dumps(payload), ex=ttl)
    log.info("Stored transfer code=%s type=%s ttl=%ds", code, payload.get("type"), ttl)


def _get_metadata(code) -> dict | None:
    raw = redis_client.get(code)
    if not raw:
        return None
    return json.loads(raw)


def _delete_transfer(code, metadata: dict):
    """Delete Redis key AND the physical file if this was a file transfer."""
    redis_client.delete(code)
    if metadata.get("type") == "file" and metadata.get("file_path"):
        file_path = Path(metadata["file_path"])
        try:
            file_path.unlink(missing_ok=True)
            log.info("Deleted file from disk: %s", file_path)
        except OSError as e:
            log.error("Failed to delete file %s: %s", file_path, e)
    log.info("Deleted transfer code=%s", code)


def _cleanup_expired_transfers():
    """Remove expired transfers and their temporary files automatically."""
    now = time.time()

    try:
        keys = redis_client.keys("*") or []
    except Exception as exc:
        log.exception("Failed to list Redis keys for cleanup: %s", exc)
        return

    for key in keys:
        key_str = key.decode("utf-8") if isinstance(key, bytes) else str(key)
        if len(key_str) != 7 or not key_str.isdigit():
            continue

        metadata = _get_metadata(key_str)
        if not metadata:
            continue

        expires_at = metadata.get("expires_at", 0)
        if expires_at and now > expires_at:
            _delete_transfer(key_str, metadata)
            log.info("Expired transfer cleaned up: code=%s", key_str)


@app.before_request
def cleanup_expired_transfers_on_request():
    """Run cleanup before each request so expired uploads are removed promptly."""
    try:
        _cleanup_expired_transfers()
    except Exception as exc:
        log.exception("Expired transfer cleanup failed: %s", exc)


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", created_transfer=None, retrieved_transfer=None)


@app.route("/send", methods=["POST"])
def send_transfer():
    mode = request.form.get("mode", "text")
    ttl = app.config["TRANSFER_TTL_SECONDS"]
    expires_at = int(time.time()) + ttl

    # ── FILE TRANSFER ─────────────────────────────────────────────────────────
    if mode == "file":
        uploaded_file = request.files.get("file")

        if not uploaded_file or not uploaded_file.filename:
            flash("Select a file before creating a transfer.", "error")
            return render_template("index.html", created_transfer=None, retrieved_transfer=None)

        # Server-side validation (extension + MIME)
        err = _validate_file(uploaded_file)
        if err:
            flash(err, "error")
            return render_template("index.html", created_transfer=None, retrieved_transfer=None)

        # Read file bytes — Flask's MAX_CONTENT_LENGTH will 413 before this
        # if the file is over the limit, so len(raw_bytes) <= 10MB here
        raw_bytes = uploaded_file.read()
        file_size = len(raw_bytes)

        # secure_filename strips path traversal attacks like "../../../etc/passwd"
        # Use UUID filename on disk — never the user-supplied name
        safe_original_name = secure_filename(uploaded_file.filename) or f"upload_{uuid.uuid4().hex[:8]}"
        ext = Path(safe_original_name).suffix.lower()
        disk_filename = f"{uuid.uuid4().hex}{ext}"
        file_path = app.config["UPLOAD_FOLDER"] / disk_filename

        # Write to disk — ONLY raw bytes, not base64
        # base64 adds 33% overhead and has no benefit when writing to disk
        with open(file_path, "wb") as f:
            f.write(raw_bytes)
        log.info("Saved file to disk: %s (%d bytes)", file_path, file_size)

        code = _generate_unique_code()

        # Redis stores ONLY metadata — under 500 bytes regardless of file size
        # This is the key architectural fix — Redis token cost is now flat and tiny
        metadata = {
            "code": code,
            "type": "file",
            "filename": safe_original_name,          # original name shown to user
            "file_path": str(file_path),             # disk path for retrieval
            "mimetype": uploaded_file.mimetype or "application/octet-stream",
            "size": file_size,
            "expires_at": expires_at,
            "downloaded": False,
        }
        _store_metadata(code, metadata, ttl)

        flash("Transfer created — share the code below.", "success")
        return render_template("index.html", created_transfer=metadata, retrieved_transfer=None)

    # ── TEXT TRANSFER ─────────────────────────────────────────────────────────
    # Text is small — storing directly in Redis is correct here
    content = request.form.get("text", "").strip()
    if not content:
        flash("Type or paste some text before creating a transfer.", "error")
        return render_template("index.html", created_transfer=None, retrieved_transfer=None)

    if len(content) > 5000:
        flash("Text is too long. Maximum is 5,000 characters.", "error")
        return render_template("index.html", created_transfer=None, retrieved_transfer=None)

    code = _generate_unique_code()
    metadata = {
        "code": code,
        "type": "text",
        "content": content,
        "expires_at": expires_at,
    }
    _store_metadata(code, metadata, ttl)

    flash("Transfer created — share the code below.", "success")
    return render_template("index.html", created_transfer=metadata, retrieved_transfer=None)


@app.route("/retrieve", methods=["POST"])
def retrieve_transfer():
    code = request.form.get("code", "").strip()

    # Input validation before touching Redis
    if not code or not code.isdigit() or len(code) != 7:
        flash("Enter a valid 7-digit numeric code.", "error")
        return render_template("index.html", created_transfer=None, retrieved_transfer=None)

    metadata = _get_metadata(code)
    if not metadata:
        flash("No transfer found for that code. It may have expired or been mistyped.", "error")
        return render_template("index.html", created_transfer=None, retrieved_transfer=None)

    # Check server-side expiry as extra safety net
    if time.time() > metadata.get("expires_at", 0):
        _delete_transfer(code, metadata)
        flash("That transfer has expired and been deleted.", "error")
        return render_template("index.html", created_transfer=None, retrieved_transfer=None)

    # Burn text after read — delete immediately on retrieval
    # Files are NOT deleted here — user still needs /download to get the file
    if metadata["type"] == "text":
        _delete_transfer(code, metadata)
        log.info("Text transfer consumed: code=%s", code)

    flash("Transfer retrieved successfully.", "success")
    return render_template("index.html", created_transfer=None, retrieved_transfer=metadata)


@app.route("/download/<code>")
def download_transfer(code):
    """
    Serve the file from disk.
    After download, delete the file and the Redis key (burn after read for files).
    """
    # Basic code format check — avoids pointless Redis call for garbage input
    if not code or not code.isdigit() or len(code) != 7:
        flash("Invalid transfer code.", "error")
        return redirect(url_for("index"))

    metadata = _get_metadata(code)

    if not metadata or metadata.get("type") != "file":
        flash("That file transfer is no longer available.", "error")
        return redirect(url_for("index"))

    if time.time() > metadata.get("expires_at", 0):
        _delete_transfer(code, metadata)
        flash("That file has expired and been deleted.", "error")
        return redirect(url_for("index"))

    file_path = Path(metadata["file_path"])
    if not file_path.exists():
        # File on disk is missing — clean up the orphaned Redis key
        redis_client.delete(code)
        log.error("File missing from disk for code=%s path=%s", code, file_path)
        flash("File could not be found. It may have already been downloaded.", "error")
        return redirect(url_for("index"))

    # Read file into memory buffer, then delete from disk immediately
    # This ensures file is removed even if the download stream is interrupted
    file_bytes = file_path.read_bytes()
    _delete_transfer(code, metadata)   # burn after read
    log.info("File downloaded and deleted: code=%s filename=%s", code, metadata["filename"])

    return send_file(
        io.BytesIO(file_bytes),
        as_attachment=True,
        download_name=metadata["filename"],
        mimetype=metadata["mimetype"],
    )


# ─── Error handlers ───────────────────────────────────────────────────────────

@app.errorhandler(413)
def file_too_large(e):
    flash("File is too large. Maximum size is 10 MB.", "error")
    return render_template("index.html", created_transfer=None, retrieved_transfer=None), 413


@app.errorhandler(404)
def not_found(e):
    return render_template("index.html", created_transfer=None, retrieved_transfer=None), 404


@app.errorhandler(500)
def server_error(e):
    log.error("500 error: %s", e)
    flash("Something went wrong on our end. Please try again.", "error")
    return render_template("index.html", created_transfer=None, retrieved_transfer=None), 500


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_ENV") == "development")