import os
from pathlib import Path
from functools import wraps
from flask import Flask, jsonify, request, g, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
import pickle as _std_pickle

try:
    import dill as _pickle
except Exception:
    _pickle = _std_pickle

# --- JSON Logging and Metrics Setup ---
import json as _json
from datetime import datetime as _dt

# --- Security Logging Setup ---
import logging
from logging.handlers import RotatingFileHandler
from security_utils import safe_resolve_under_storage, SecurityError as SecError
from security_utils import validate_pdf_file
from werkzeug.utils import secure_filename
import uuid
import time
from collections import defaultdict, deque

logger = logging.getLogger("tatou-security")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
try:
    logs_dir = Path(os.environ.get("LOGS_DIR", "/app/logs"))
    logs_dir.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        str(logs_dir / "security.log"), maxBytes=1_000_000, backupCount=5
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
except Exception:
    # If we cannot write to /app/logs (common in test environments), fall back to stdout
    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    logger.addHandler(sh)


# Structured JSON log file (newline-delimited JSON)
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()
        obj = {
            "timestamp": _dt.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": msg,
        }
        # include exception info if present
        if record.exc_info:
            obj["exc"] = self.formatException(record.exc_info)
        return _json.dumps(obj)


try:
    json_handler = RotatingFileHandler(
        str(Path(os.environ.get("LOGS_DIR", "/app/logs")) / "security.json.log"),
        maxBytes=2_000_000,
        backupCount=3,
    )
    json_handler.setFormatter(JsonFormatter())
    logger.addHandler(json_handler)
except Exception:
    # best-effort: if path unwritable (e.g., in tests), ignore
    pass
# Prometheus metrics (optional)
_METRICS = {}
try:
    from prometheus_client import Counter, generate_latest

    _PROM_AVAILABLE = True
    _EVENT_COUNTER = Counter("tatou_events_total", "Count of tatou events", ["event"])

    def _metrics_increment(ev: str):
        try:
            _EVENT_COUNTER.labels(event=ev).inc()
        except Exception:
            pass

    def _metrics_dump():
        return generate_latest()

except Exception:
    _PROM_AVAILABLE = False

    def _metrics_increment(ev: str):
        _METRICS[ev] = _METRICS.get(ev, 0) + 1

    def _metrics_dump():
        # simple text format
        lines = []
        for k, v in _METRICS.items():
            lines.append(f'tatou_events_total{{event="{k}"}} {v}')
        return "\n".join(lines).encode("utf-8")


def log_event(event, user=None, status="INFO", **extra):
    ip = request.remote_addr if request else "N/A"
    payload = {"event": event, "user": user, "ip": ip, "status": status}
    if extra:
        payload["details"] = extra
    # Human-readable info log
    logger.info(f"{event} user={user} ip={ip} status={status} extra={extra}")
    # Also write structured JSON using the json handler via logger
    try:
        logger.info(_json.dumps(payload))
    except Exception:
        pass

    # Metrics: increment counters if available
    try:
        _metrics_increment(event)
    except Exception:
        pass


def create_app():
    app = Flask(__name__)

    # --- Config ---
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "ehmgr17key")
    app.config["STORAGE_DIR"] = Path(
        os.environ.get("STORAGE_DIR", "./storage")
    ).resolve()
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))

    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "tatou")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")

    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)

    # --- DB engine ---
    def db_url() -> str:
        return (
            f"mysql+pymysql://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}"
            f"@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_NAME']}?charset=utf8mb4&ssl=false"
        )

    def get_engine():
        eng = app.config.get("_ENGINE")
        if eng is None:
            from sqlalchemy import create_engine

            eng = create_engine(
                db_url(),
                pool_pre_ping=True,
                future=True,
                connect_args={"ssl": False},  # 👈 disable SSL properly
            )
            app.config["_ENGINE"] = eng
        return eng

    # --- Auth helper ---
    def _serializer():
        return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

    def _auth_error(msg: str, code: int = 401):
        return jsonify({"error": msg}), code

    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                # Monitoring: log missing/invalid Authorization header
                app.logger.warning(
                    f"Unauthorized request from {request.remote_addr} - missing/invalid Authorization header"
                )
                log_event(
                    "unauthorized-request",
                    user=None,
                    status="FAIL",
                    reason="missing_auth",
                )
                return _auth_error("Missing or invalid Authorization header")
            token = auth.split(" ", 1)[1].strip()
            try:
                data = _serializer().loads(
                    token, max_age=app.config["TOKEN_TTL_SECONDS"]
                )
            except SignatureExpired:
                return _auth_error("Token expired")
            except BadSignature:
                return _auth_error("Invalid token")
            g.user = {
                "id": int(data["uid"]),
                "login": data["login"],
                "email": data.get("email"),
            }
            return f(*args, **kwargs)

        return wrapper

    # --- File access helper for endpoints ---
    def resolve_and_log_file_access(candidate: str, user=None):
        """Resolve a candidate filename under STORAGE_DIR and log attempts.

        Returns the resolved Path on success. Raises SecError on invalid paths.
        """
        # Rate-limit file access by remote IP
        try:
            ip = request.remote_addr or "unknown"
        except Exception:
            ip = "unknown"
        key = f"file:{ip}"
        if not _file_access_limiter.is_allowed(key):
            app.logger.warning(f"Rate limit exceeded for file access from {ip}")
            log_event(
                "file-access-rate-limit", user=(user or None), status="FAIL", ip=ip
            )
            # Deny by raising a security error so callers handle it uniformly
            raise SecError("rate-limited")

        try:
            resolved = safe_resolve_under_storage(app.config["STORAGE_DIR"], candidate)
        except Exception as exc:
            app.logger.warning(
                f"Attempt to access invalid file path '{candidate}' from {request.remote_addr}: {exc}"
            )
            log_event(
                "sensitive-file-access-attempt",
                user=(user or None),
                status="FAIL",
                details=str(exc),
            )
            raise
        app.logger.info(
            f"Resolved file access for user={user} path={resolved} from {request.remote_addr}"
        )
        return resolved

    # --- Simple rate limiter (in-process) ---
    class RateLimiter:
        def __init__(
            self, max_calls: int, period_seconds: int, ban_seconds: int = 3600
        ):
            self.max_calls = max_calls
            self.period = period_seconds
            self.ban = ban_seconds
            self.calls = defaultdict(lambda: deque())
            self.banned_until = {}

        def is_allowed(self, key: str) -> bool:
            now = time.time()
            # check ban
            if key in self.banned_until and now < self.banned_until[key]:
                return False
            dq = self.calls[key]
            # evict old
            while dq and dq[0] <= now - self.period:
                dq.popleft()
            if len(dq) >= self.max_calls:
                # enforce ban
                self.banned_until[key] = now + self.ban
                dq.clear()
                return False
            dq.append(now)
            return True

    # instantiate limiters
    _login_limiter = RateLimiter(max_calls=5, period_seconds=300, ban_seconds=3600)
    _file_access_limiter = RateLimiter(max_calls=20, period_seconds=60, ban_seconds=600)

    # ================= Routes =================

    @app.post("/api/create-user")
    def create_user():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip().lower()
        login = (payload.get("login") or "").strip()
        password = payload.get("password") or ""
        if not email or not login or not password:
            return jsonify({"error": "email, login, and password are required"}), 400

        hpw = generate_password_hash(password)

        try:
            with get_engine().begin() as conn:
                res = conn.execute(
                    text(
                        "INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)"
                    ),
                    {"email": email, "hpw": hpw, "login": login},
                )
                uid = int(res.lastrowid)
        except IntegrityError:
            log_event("user-create-fail", user=login, status="DUPLICATE")
            return jsonify({"error": "email or login already exists"}), 409

        log_event("user-created", user=login, status="OK")
        return jsonify({"id": uid, "email": email, "login": login}), 201

    @app.post("/api/login")
    def login():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""
        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400

        # Simple rate-limit on login attempts per remote IP
        try:
            ip = request.remote_addr or "unknown"
        except Exception:
            ip = "unknown"
        login_key = f"login:{ip}"
        if not _login_limiter.is_allowed(login_key):
            app.logger.warning(f"Rate limit exceeded for login attempts from {ip}")
            log_event("login-rate-limit", user=email, status="FAIL", ip=ip)
            return jsonify({"error": "too many attempts, try later"}), 429

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text(
                        "SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"
                    ),
                    {"email": email},
                ).first()
        except Exception as e:
            # Monitoring: log SQL/database error during login
            app.logger.error(f"SQL error during login for {email}: {e}")
            log_event("login-db-error", user=email, status="ERROR", details=str(e))
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row or not check_password_hash(row.hpassword, password):
            # Monitoring: failed login attempt
            app.logger.warning(
                f"Failed login attempt for user={email} from {request.remote_addr}"
            )
            log_event("login-failed", user=email, status="FAIL")
            return jsonify({"error": "invalid credentials"}), 401

        token = _serializer().dumps(
            {"uid": int(row.id), "login": row.login, "email": row.email}
        )
        log_event("login-success", user=email, status="OK")
        # Include token expiry information to help clients manage refresh
        expires_in = app.config.get("TOKEN_TTL_SECONDS", 86400)
        return (
            jsonify(
                {
                    "token": token,
                    "token_type": "bearer",
                    "expires_in": int(expires_in),
                }
            ),
            200,
        )

    @app.route("/api/delete-document", methods=["DELETE"])
    @require_auth
    def delete_document():
        doc_id = request.args.get("id")
        if not doc_id or not doc_id.isdigit():
            # Monitoring: invalid document id provided
            app.logger.warning(
                f"Delete document: invalid id provided by user={g.user['login']} from {request.remote_addr}: id={doc_id}"
            )
            log_event("delete-document-invalid-id", user=g.user["login"], status="FAIL")
            return jsonify({"error": "invalid document id"}), 400

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("DELETE FROM Documents WHERE id = :id AND ownerid = :uid"),
                    {"id": int(doc_id), "uid": g.user["id"]},
                )
        except Exception as e:
            # Monitoring: SQL/database error during delete
            app.logger.error(
                f"SQL error or possible injection attempt during delete by user={g.user['login']}: {e}"
            )
            log_event(
                "delete-document-db-error",
                user=g.user["login"],
                status="ERROR",
                details=str(e),
            )
            return jsonify({"error": f"database error: {str(e)}"}), 503

        # Monitoring: successful sensitive action
        log_event("delete-document", user=g.user["login"], status="OK", id=doc_id)
        app.logger.info(f"User {g.user['login']} deleted document ID={doc_id}")
        return jsonify({"deleted": True, "id": doc_id}), 200

    # -------- Document endpoints (upload/list/get/version) --------
    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
        # Accept multipart form: file (pdf) and name
        if "file" not in request.files:
            return jsonify({"error": "file is required"}), 400
        file = request.files["file"]
        name = (request.form.get("name") or file.filename or "").strip()
        if not name:
            return jsonify({"error": "name is required"}), 400

        # Sanitize filename and generate server-side storage name
        filename = secure_filename(file.filename or f"upload-{uuid.uuid4().hex}.pdf")
        storage_name = f"{uuid.uuid4().hex}-{filename}"
        try:
            dest = resolve_and_log_file_access(storage_name, user=g.user["login"])
        except Exception:
            return jsonify({"error": "invalid file path"}), 400

        # Save to storage and validate
        try:
            file.save(dest)
            validate_pdf_file(dest)
            size = dest.stat().st_size
            import hashlib

            # Compute raw 32-byte digest for storage (BINARY(32) column)
            with dest.open("rb") as fh:
                body = fh.read()
                sha_raw = hashlib.sha256(body).digest()
                sha_hex = hashlib.sha256(body).hexdigest()
        except Exception as e:
            # cleanup if something went wrong
            try:
                dest.unlink(missing_ok=True)
            except Exception:
                pass
            app.logger.error(f"Upload failed for user={g.user['login']}: {e}")
            return jsonify({"error": f"upload failed: {e}"}), 400

        # Register in DB
        try:
            with get_engine().begin() as conn:
                res = conn.execute(
                    text(
                        "INSERT INTO Documents (name, path, ownerid, sha256, size) VALUES (:name, :path, :uid, :sha, :size)"
                    ),
                    {
                        "name": name,
                        "path": str(dest),
                        "uid": g.user["id"],
                        "sha": sha_raw,
                        "size": int(size),
                    },
                )
                doc_id = int(res.lastrowid)
        except Exception as e:
            app.logger.error(f"DB error registering upload: {e}")
            return jsonify({"error": "database error"}), 500

        log_event("upload-document", user=g.user["login"], status="OK", id=doc_id)
        # Return hex string to clients (more convenient than raw bytes)
        return (
            jsonify({"id": doc_id, "name": name, "sha256": sha_hex, "size": int(size)}),
            201,
        )

    @app.get("/api/list-documents")
    @require_auth
    def list_documents():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text(
                        "SELECT id, name, creation, sha256, size FROM Documents WHERE ownerid = :uid ORDER BY id DESC"
                    ),
                    {"uid": g.user["id"]},
                ).all()
            docs = [
                {
                    "id": int(r.id),
                    "name": r.name,
                    "creation": r.creation,
                    "sha256": r.sha256,
                    "size": int(r.size),
                }
                for r in rows
            ]
            return jsonify({"documents": docs}), 200
        except Exception as e:
            app.logger.error(
                f"DB error listing documents for user={g.user['login']}: {e}"
            )
            return jsonify({"error": "database error"}), 503

    @app.get("/api/get-document/<int:document_id>")
    @require_auth
    def get_document(document_id: int):
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT path, ownerid FROM Documents WHERE id = :id LIMIT 1"),
                    {"id": int(document_id)},
                ).first()
        except Exception as e:
            app.logger.error(f"DB error fetching document {document_id}: {e}")
            return jsonify({"error": "database error"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404
        if int(row.ownerid) != g.user["id"]:
            app.logger.warning(
                f"Unauthorized document access by user={g.user['login']} for doc={document_id}"
            )
            log_event(
                "unauthorized-document-access",
                user=g.user["login"],
                status="FAIL",
                id=document_id,
            )
            return jsonify({"error": "forbidden"}), 403

        # Resolve path under storage
        try:
            resolved = resolve_and_log_file_access(str(row.path), user=g.user["login"])
        except Exception:
            return jsonify({"error": "invalid file path"}), 400

        try:
            from flask import send_file

            return send_file(
                resolved,
                mimetype="application/pdf",
                as_attachment=True,
                download_name=os.path.basename(resolved),
            )
        except Exception as e:
            app.logger.error(f"Failed to send document {document_id}: {e}")
            return jsonify({"error": "could not send file"}), 500

    @app.get("/api/list-versions/<int:document_id>")
    @require_auth
    def list_versions(document_id: int):
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text(
                        "SELECT id, documentid, link, intended_for, method FROM Versions WHERE documentid = :did"
                    ),
                    {"did": int(document_id)},
                ).all()
            versions = [
                {
                    "id": int(r.id),
                    "documentid": int(r.documentid),
                    "link": r.link,
                    "intended_for": r.intended_for,
                    "method": r.method,
                }
                for r in rows
            ]
            return jsonify({"versions": versions}), 200
        except Exception as e:
            app.logger.error(f"DB error listing versions for doc={document_id}: {e}")
            return jsonify({"error": "database error"}), 503

    @app.get("/api/get-version/<path:link>")
    def get_version(link: str):
        # Public endpoint returning a watermarked version by token link
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT path FROM Versions WHERE link = :link LIMIT 1"),
                    {"link": link},
                ).first()
        except Exception as e:
            app.logger.error(f"DB error fetching version link={link}: {e}")
            return jsonify({"error": "database error"}), 503

        if not row:
            return jsonify({"error": "not found"}), 404

        # Resolve and serve the file (no auth: versions are public by design)
        try:
            resolved = resolve_and_log_file_access(str(row.path), user=None)
        except Exception:
            return jsonify({"error": "invalid file path"}), 400

        try:
            from flask import send_file

            return send_file(
                resolved,
                mimetype="application/pdf",
                as_attachment=True,
                download_name=os.path.basename(resolved),
            )
        except Exception as e:
            app.logger.error(f"Failed to send version for link={link}: {e}")
            return jsonify({"error": "could not send file"}), 500

    @app.get("/healthz")
    def healthz():
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        return (
            jsonify(
                {"message": "The server is up and running.", "db_connected": db_ok}
            ),
            200,
        )

    @app.get("/metrics")
    def metrics():
        try:
            data = _metrics_dump()
            return (data, 200, {"Content-Type": "text/plain; version=0.0.4"})
        except Exception as e:
            return (str(e), 500)

    @app.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        """Return a list of available watermarking method identifiers.

        This is a minimal implementation returning the well-known
        methods provided in the repository. For a dynamic system this
        could introspect modules that subclass WatermarkingMethod.
        """
        methods = [
            "add-after-eof",
            "whitespace-steganography",
            "base64-invisible-comment",
            "pdf-object-stream-embedder",
        ]
        return jsonify({"count": len(methods), "methods": methods}), 200

    # Serve the bundled static UI at the root for convenience
    @app.get("/")
    def root_index():
        # redirect to the static index page shipped in the repository
        return redirect("/static/index.html")

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
