import os
import io
import hashlib
import datetime as dt
from pathlib import Path
from functools import wraps
from flask import Flask, jsonify, request, g, send_file, url_for, abort
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
import pickle as _std_pickle

try:
    import dill as _pickle
except Exception:
    _pickle = _std_pickle

import watermarking_utils as WMUtils
from watermarking_method import WatermarkingMethod
import time
from rmap.identity_manager import IdentityManager
from rmap.rmap import RMAP

# --- Security Logging Setup ---
import logging
import json as _json
from datetime import datetime as _dt
from logging.handlers import RotatingFileHandler
from security_utils import safe_resolve_under_storage, SecurityError as SecError
from security_utils import validate_pdf_file
import uuid
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
    app.config["STORAGE_DIR"] = Path(os.environ.get("STORAGE_DIR", "./storage")).resolve()
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))

    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "tatou")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")

    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)

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

    # --- DB engine only (no Table metadata) ---
    def db_url() -> str:
        return (
            f"mysql+pymysql://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}"
            f"@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_NAME']}?charset=utf8mb4"
        )

    def get_engine():
        eng = app.config.get("_ENGINE")
        if eng is None:
            eng = create_engine(db_url(), pool_pre_ping=True, future=True)
            app.config["_ENGINE"] = eng
        return eng

    # --- Helpers ---
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
                data = _serializer().loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
            except SignatureExpired:
                return _auth_error("Token expired")
            except BadSignature:
                return _auth_error("Invalid token")
            g.user = {"id": int(data["uid"]), "login": data["login"], "email": data.get("email")}
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
            raise SecError(f"invalid path: {exc}")
        app.logger.info(
            f"Resolved file access for user={user} path={resolved} from {request.remote_addr}"
        )
        return resolved

    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    # --- Routes ---

    @app.route("/<path:filename>")
    def static_files(filename):
        return app.send_static_file(filename)

    @app.route("/")
    def home():
        return app.send_static_file("index.html")

    @app.get("/healthz")
    def healthz():
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify({"message": "The server is up and running.", "db_connected": db_ok}), 200

    @app.get("/metrics")
    def metrics():
        try:
            data = _metrics_dump()
            return (data, 200, {"Content-Type": "text/plain; version=0.0.4"})
        except Exception as e:
            return (str(e), 500)

    # POST /api/create-user {email, login, password}
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
                    text("INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)"),
                    {"email": email, "hpw": hpw, "login": login},
                )
                uid = int(res.lastrowid)
                row = conn.execute(
                    text("SELECT id, email, login FROM Users WHERE id = :id"),
                    {"id": uid},
                ).one()
        except IntegrityError:
            log_event("user-create-fail", user=login, status="DUPLICATE")
            return jsonify({"error": "email or login already exists"}), 409
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        log_event("user-created", user=login, status="OK")
        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    # POST /api/login {login, password}
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
                    text("SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"),
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

        token = _serializer().dumps({"uid": int(row.id), "login": row.login, "email": row.email})
        log_event("login-success", user=email, status="OK")
        # Include token expiry information to help clients manage refresh
        expires_in = app.config.get("TOKEN_TTL_SECONDS", 86400)
        return jsonify({"token": token, "token_type": "bearer", "expires_in": int(expires_in)}), 200

    # POST /api/upload-document  (multipart form: file + name)
    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
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
        except SecError as e:
            app.logger.warning(f"File access denied for user={g.user['login']}: {e}")
            return jsonify({"error": "invalid file path"}), 400
        except Exception as e:
            app.logger.error(f"Unexpected error resolving path for user={g.user['login']}: {e}")
            return jsonify({"error": "invalid file path"}), 400

        # Save to storage and validate
        try:
            file.save(dest)
            validate_pdf_file(dest)
            size = dest.stat().st_size
            # Compute SHA256 as hex string
            sha_hex = _sha256_file(dest)
        except Exception as e:
            # cleanup if something went wrong
            try:
                dest.unlink(missing_ok=True)
            except Exception:
                pass
            app.logger.error(f"Upload failed for user={g.user['login']}: {e}")
            return jsonify({"error": f"upload failed: {e}"}), 400

        # Register in DB using UNHEX to store as binary
        try:
            with get_engine().begin() as conn:
                res = conn.execute(
                    text("""
                        INSERT INTO Documents (name, path, ownerid, sha256, size)
                        VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
                    """),
                    {
                        "name": name,
                        "path": str(dest),
                        "ownerid": int(g.user["id"]),
                        "sha256hex": sha_hex,
                        "size": int(size),
                    },
                )
                doc_id = int(res.lastrowid)
                # Fetch back with HEX conversion
                row = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id
                    """),
                    {"id": doc_id},
                ).one()
        except Exception as e:
            app.logger.error(f"DB error registering upload: {e}")
            return jsonify({"error": "database error"}), 500

        log_event("upload-document", user=g.user["login"], status="OK", id=doc_id)
        return jsonify({
            "id": int(row.id),
            "name": row.name,
            "creation": row.creation.isoformat() if hasattr(row.creation, "isoformat") else str(row.creation),
            "sha256": row.sha256_hex,
            "size": int(row.size),
        }), 201

    # GET /api/list-documents (authenticated)
    @app.get("/api/list-documents")
    @require_auth
    def list_documents():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE ownerid = :uid
                        ORDER BY creation DESC
                    """),
                    {"uid": int(g.user["id"])},
                ).all()
        except Exception as e:
            app.logger.error(
                f"DB error listing documents for user={g.user['login']}: {e}"
            )
            return jsonify({"error": "database error"}), 503

        docs = [{
            "id": int(r.id),
            "name": r.name,
            "creation": r.creation.isoformat() if hasattr(r.creation, "isoformat") else str(r.creation),
            "sha256": r.sha256_hex,
            "size": int(r.size),
        } for r in rows]
        return jsonify({"documents": docs}), 200

    # GET /api/get-document/<int:document_id>
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
        except SecError as e:
            app.logger.warning(f"File access denied for user={g.user['login']}: {e}")
            return jsonify({"error": "invalid file path"}), 400
        except Exception as e:
            app.logger.error(f"Unexpected error resolving path: {e}")
            return jsonify({"error": "invalid file path"}), 400

        try:
            return send_file(
                resolved,
                mimetype="application/pdf",
                as_attachment=True,
                download_name=os.path.basename(resolved),
            )
        except Exception as e:
            app.logger.error(f"Failed to send document {document_id}: {e}")
            return jsonify({"error": "could not send file"}), 500

    # DELETE /api/delete-document  (and variants)
    @app.route("/api/delete-document", methods=["DELETE", "POST"])
    @app.route("/api/delete-document/<document_id>", methods=["DELETE"])
    @require_auth
    def delete_document(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if not document_id:
            document_id = (
                    request.args.get("id")
                    or request.args.get("documentid")
                    or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        if not document_id or not str(document_id).isdigit():
            # Monitoring: invalid document id provided
            app.logger.warning(
                f"Delete document: invalid id provided by user={g.user['login']} from {request.remote_addr}: id={document_id}"
            )
            log_event("delete-document-invalid-id", user=g.user["login"], status="FAIL")
            return jsonify({"error": "invalid document id"}), 400

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("DELETE FROM Documents WHERE id = :id AND ownerid = :uid"),
                    {"id": int(document_id), "uid": g.user["id"]},
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
        log_event("delete-document", user=g.user["login"], status="OK", id=document_id)
        app.logger.info(f"User {g.user['login']} deleted document ID={document_id}")
        return jsonify({"deleted": True, "id": document_id}), 200

    # GET /api/list-versions/<int:document_id>
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

    # GET /api/get-version/<path:link>
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
        except SecError as e:
            app.logger.warning(f"File access denied for version link={link}: {e}")
            return jsonify({"error": "invalid file path"}), 400
        except Exception as e:
            app.logger.error(f"Unexpected error resolving path for version: {e}")
            return jsonify({"error": "invalid file path"}), 400

        try:
            return send_file(
                resolved,
                mimetype="application/pdf",
                as_attachment=True,
                download_name=os.path.basename(resolved),
            )
        except Exception as e:
            app.logger.error(f"Failed to send version for link={link}: {e}")
            return jsonify({"error": "could not send file"}), 500

    # GET /api/list-all-versions
    @app.get("/api/list-all-versions")
    @require_auth
    def list_all_versions():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.method 
                        FROM Versions v
                        JOIN Documents d ON v.documentid = d.id
                        WHERE d.ownerid = :uid
                        ORDER BY v.id DESC
                    """),
                    {"uid": g.user["id"]},
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
            app.logger.error(f"DB error listing all versions for user={g.user['login']}: {e}")
            return jsonify({"error": "database error"}), 503

    # POST /api/create-watermark
    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<int:document_id>")
    @require_auth
    def create_watermark(document_id: int | None = None):
        if not document_id:
            document_id = (
                    request.args.get("id")
                    or request.args.get("documentid")
                    or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = int(document_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400

        payload = request.get_json(silent=True) or {}
        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")
        secret = payload.get("secret")
        intended_for = payload.get("intended_for") or ""

        if not method or not isinstance(key, str) or not secret:
            return jsonify({"error": "method, key, and secret are required"}), 400

        # Lookup the document and enforce ownership
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, name, path, ownerid FROM Documents WHERE id = :id LIMIT 1"),
                    {"id": doc_id},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404
        if int(row.ownerid) != g.user["id"]:
            return jsonify({"error": "forbidden"}), 403

        storage_root = Path(app.config["STORAGE_DIR"])
        try:
            orig_path = _safe_resolve_under_storage(row.path, storage_root)
        except Exception:
            return jsonify({"error": "invalid file path"}), 400

        # Check if watermarking is applicable
        if not WMUtils.is_watermarking_applicable(method, str(orig_path), position):
            return jsonify({"error": "watermarking not applicable for this document/method"}), 400

        # Create watermark
        link = str(uuid.uuid4())
        wm_filename = f"{link}.pdf"
        wm_dir = storage_root / "watermarks"
        wm_dir.mkdir(parents=True, exist_ok=True)
        wm_path = wm_dir / wm_filename

        try:
            wm_bytes = WMUtils.apply_watermark(
                pdf=str(orig_path),
                secret=secret,
                key=key,
                method=method,
                position=position
            )
            with wm_path.open("wb") as f:
                f.write(wm_bytes)
            wm_size = wm_path.stat().st_size
        except Exception as e:
            return jsonify({"error": f"Error when attempting to create watermark: {e}"}), 400

        # Save to database
        try:
            with get_engine().begin() as conn:
                res = conn.execute(
                    text("""
                        INSERT INTO Versions 
                        (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": doc_id,
                        "link": link,
                        "intended_for": intended_for,
                        "secret": secret,
                        "method": method,
                        "position": position or "",
                        "path": str(wm_path)
                    }
                )
                version_id = int(res.lastrowid)
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        return jsonify({
            "id": version_id,
            "documentid": doc_id,
            "link": link,
            "intended_for": intended_for,
            "method": method,
            "position": position or "",
            "filename": wm_filename,
            "size": int(wm_size)
        }), 201

    # GET /api/get-watermarking-methods
    @app.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        methods = []
        for m in WMUtils.METHODS:
            methods.append({"name": m, "description": WMUtils.get_method(m).get_usage()})
        return jsonify({"methods": methods, "count": len(methods)}), 200

    # POST /api/read-watermark
    @app.post("/api/read-watermark")
    @app.post("/api/read-watermark/<int:document_id>")
    @require_auth
    def read_watermark(document_id: int | None = None):
        if not document_id:
            document_id = (
                    request.args.get("id")
                    or request.args.get("documentid")
                    or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = int(document_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400

        payload = request.get_json(silent=True) or {}
        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")

        if not method or not isinstance(key, str):
            return jsonify({"error": "method and key are required"}), 400

        # Lookup the document and enforce ownership
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, name, path, ownerid FROM Documents WHERE id = :id LIMIT 1"),
                    {"id": doc_id},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404
        if int(row.ownerid) != g.user["id"]:
            return jsonify({"error": "forbidden"}), 403

        storage_root = Path(app.config["STORAGE_DIR"])
        try:
            orig_path = _safe_resolve_under_storage(row.path, storage_root)
        except Exception:
            return jsonify({"error": "invalid file path"}), 400

        # Read watermark
        try:
            secret = WMUtils.read_watermark(
                pdf=str(orig_path),
                key=key,
                method=method,
                position=position
            )
        except Exception as e:
            return jsonify({"error": f"Error when attempting to read watermark: {e}"}), 400

        return jsonify({
            "documentid": doc_id,
            "secret": secret,
            "method": method,
            "position": position
        }), 200

    # ====================== RMAP: setup + endpoints ======================

    # Configuration
    app.config.setdefault("RMAP_BASE_PDF", os.environ.get("RMAP_BASE_PDF", "/app/group_17_rmap.pdf"))
    app.config.setdefault("RMAP_LINK_TTL", int(os.environ.get("RMAP_LINK_TTL", "600")))
    app.config.setdefault("RMAP_TOKENS", {})

    # Key paths
    SERVER_DIR = Path(__file__).resolve().parents[1]
    DEFAULT_KEYS_DIR = SERVER_DIR / "keys"
    rmap_keys_dir = Path(os.environ.get("RMAP_KEYS_DIR", str(DEFAULT_KEYS_DIR))).resolve()
    clients_dir = rmap_keys_dir / "clients"
    server_pub = rmap_keys_dir / "server_public.asc"
    server_priv = rmap_keys_dir / "server_private.asc"

    # Initialize RMAP
    missing = [p for p in (clients_dir, server_pub, server_priv) if not p.exists()]
    if missing:
        app.logger.error("RMAP key path(s) missing: %s", ", ".join(map(str, missing)))
        app.config["RMAP"] = None
    else:
        try:
            im = IdentityManager(
                client_keys_dir=clients_dir,
                server_public_key_path=server_pub,
                server_private_key_path=server_priv,
            )
            app.config["RMAP"] = RMAP(im)
            app.logger.info("RMAP initialized (clients dir: %s)", clients_dir)
        except Exception as e:
            app.logger.exception("Failed to initialize RMAP: %s", e)
            app.config["RMAP"] = None

    # Initialize RMAP Base PDF in Database on Startup
    def init_rmap_base_pdf():
        """Ensure RMAP base PDF exists in the database."""
        base_pdf = Path(app.config["RMAP_BASE_PDF"])
        if not base_pdf.exists():
            app.logger.warning(f"RMAP base PDF not found: {base_pdf}")
            return

        try:
            with get_engine().begin() as conn:
                # Check if already exists
                existing = conn.execute(
                    text("SELECT id FROM Documents WHERE name = :name"),
                    {"name": "RMAP Base Document"}
                ).first()

                if existing:
                    app.logger.info("RMAP base document already exists in database")
                    return

                # Create system user if needed
                system_user = conn.execute(
                    text("SELECT id FROM Users WHERE email = :email"),
                    {"email": "system@tatou.internal"}
                ).first()

                if not system_user:
                    hpw = generate_password_hash("system-internal")
                    res = conn.execute(
                        text("INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)"),
                        {"email": "system@tatou.internal", "hpw": hpw, "login": "system"}
                    )
                    system_uid = int(res.lastrowid)
                else:
                    system_uid = int(system_user.id)

                # Register RMAP base PDF
                with base_pdf.open("rb") as f:
                    body = f.read()
                    sha_raw = hashlib.sha256(body).digest()
                    size = len(body)

                conn.execute(
                    text("""
                        INSERT INTO Documents (name, path, ownerid, sha256, size)
                        VALUES (:name, :path, :uid, :sha, :size)
                    """),
                    {
                        "name": "RMAP Base Document",
                        "path": str(base_pdf),
                        "uid": system_uid,
                        "sha": sha_raw,
                        "size": size
                    }
                )
                app.logger.info("RMAP base PDF registered in database")

        except Exception as e:
            app.logger.error(f"Failed to initialize RMAP base PDF: {e}")

    def _create_watermarked_pdf(identity: str, result_hex: str) -> Path:
        """Create a watermarked PDF for RMAP."""
        base_pdf = Path(app.config["RMAP_BASE_PDF"])
        if not base_pdf.exists():
            raise FileNotFoundError(f"Base PDF not found: {base_pdf}")

        wm_dir = app.config["STORAGE_DIR"] / "watermarks" / "rmap"
        wm_dir.mkdir(parents=True, exist_ok=True)
        wm_path = wm_dir / f"rmap_{result_hex}.pdf"

        if wm_path.exists():
            app.logger.info(f"Reusing existing watermark for {identity}")
            return wm_path

        secret = f"RMAP:{identity}:{result_hex}:{int(time.time())}"
        key = app.config["SECRET_KEY"]
        method = "whitespace-stego"

        app.logger.info(f"Creating watermark for {identity} with method {method}")

        try:
            wm_bytes = WMUtils.apply_watermark(
                pdf=str(base_pdf),
                secret=secret,
                key=key,
                method=method,
                position=None
            )

            with wm_path.open("wb") as f:
                f.write(wm_bytes)

            app.logger.info(f"Watermark created: {wm_path} ({len(wm_bytes)} bytes)")
            return wm_path

        except Exception as e:
            app.logger.error(f"Watermarking failed for {identity}: {e}")
            raise

    def _rmap_make_link(result_hex: str, identity: str) -> dict:
        """Create watermarked PDF and Version record."""
        token = result_hex.lower()

        try:
            # Create watermarked PDF
            pdf_path = _create_watermarked_pdf(identity, result_hex)

            # Store in database
            with get_engine().begin() as conn:
                # Find RMAP base document
                doc_row = conn.execute(
                    text("SELECT id FROM Documents WHERE name = :name"),
                    {"name": "RMAP Base Document"}
                ).first()

                if not doc_row:
                    raise RuntimeError("RMAP base document not found in database")

                # Create Version record
                conn.execute(
                    text("""
                        INSERT INTO Versions 
                        (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": doc_row.id,
                        "link": token,
                        "intended_for": identity,
                        "secret": f"RMAP:{identity}:{token}:{int(time.time())}",
                        "method": "whitespace-stego",
                        "position": "",
                        "path": str(pdf_path)
                    }
                )

                app.logger.info(f"Created Version record with link={token} for {identity}")

            return {"token": token}

        except Exception as e:
            app.logger.error(f"Failed to create watermark: {e}")
            raise

    # Message 1 -> Response 1
    @app.post("/api/rmap-initiate")
    def rmap_initiate():
        """Handle RMAP Message 1"""
        rmap = app.config.get("RMAP")
        if rmap is None:
            return jsonify({"error": "RMAP not initialized"}), 503

        body = request.get_json(silent=True) or {}
        if "payload" not in body:
            return jsonify({"error": "payload is required"}), 400

        try:
            out = rmap.handle_message1(body)

            if "payload" in out:
                app.logger.info("RMAP initiate: success")
                return jsonify(out), 200
            else:
                app.logger.warning(f"RMAP initiate: {out.get('error', 'unknown error')}")
                return jsonify(out), 400

        except Exception as e:
            app.logger.exception("rmap-initiate failed: %s", e)
            return jsonify({"error": "server error"}), 500

    @app.post("/api/rmap-get-link")
    def rmap_get_link():
        """Handle RMAP Message 2 and create watermarked PDF"""
        rmap = app.config.get("RMAP")
        if rmap is None:
            return jsonify({"error": "RMAP not initialized"}), 503

        body = request.get_json(silent=True) or {}
        if "payload" not in body:
            return jsonify({"error": "payload is required"}), 400

        try:
            out = rmap.handle_message2(body)

            if "result" not in out:
                app.logger.warning(f"RMAP get-link: {out.get('error', 'unknown error')}")
                return jsonify(out), 400

            result_hex = out["result"]

            # Get identity from RMAP's internal nonces dictionary
            identity = "Unknown"
            if hasattr(rmap, 'nonces') and rmap.nonces:
                identity = list(rmap.nonces.keys())[0]
                rmap.nonces.clear()

            app.logger.info(f"RMAP get-link: creating link for {identity} with result {result_hex}")

            _rmap_make_link(result_hex, identity)

            return jsonify({"result": result_hex}), 200

        except Exception as e:
            app.logger.exception("rmap-get-link failed: %s", e)
            return jsonify({"error": "server error"}), 500

    # ====================== end RMAP section ======================

    with app.app_context():
        try:
            init_rmap_base_pdf()
        except Exception as e:
            app.logger.error(f"Failed to initialize RMAP base PDF: {e}")

    return app


# WSGI entrypoint
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)