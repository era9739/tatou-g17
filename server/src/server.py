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
    import dill as _pickle  # allows loading classes not importable by module path
except Exception:  # dill is optional
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
                log_event("unauthorized-request", user=None, status="FAIL", reason="missing_auth")
                return _auth_error("Missing or invalid Authorization header")
            token = auth.split(" ", 1)[1].strip()
            try:
                data = _serializer().loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
            except SignatureExpired:
                log_event("token-expired", user=None, status="FAIL")
                return _auth_error("Token expired")
            except BadSignature:
                log_event("invalid-token", user=None, status="FAIL")
                return _auth_error("Invalid token")
            g.user = {"id": int(data["uid"]), "login": data["login"], "email": data.get("email")}
            app.logger.debug(f"User authenticated: {g.user['login']}")
            return f(*args, **kwargs)

        return wrapper

    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    # --- Routes ---

    @app.route("/<path:filename>")
    def static_files(filename):
        app.logger.debug(f"Serving static file: {filename}")
        return app.send_static_file(filename)

    @app.route("/")
    def home():
        app.logger.debug("Serving home page")
        return app.send_static_file("index.html")

    @app.get("/healthz")
    def healthz():
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
            app.logger.info("Health check: database connection successful")
        except Exception as e:
            db_ok = False
            app.logger.warning(f"Health check: database connection failed - {e}")
        return jsonify({"message": "The server is up and running.", "db_connected": db_ok}), 200

    @app.get("/metrics")
    def metrics():
        try:
            data = _metrics_dump()
            app.logger.debug("Metrics retrieved successfully")
            return (data, 200, {"Content-Type": "text/plain; version=0.0.4"})
        except Exception as e:
            app.logger.error(f"Metrics retrieval failed: {e}")
            return (str(e), 500)

    # POST /api/create-user {email, login, password}
    @app.post("/api/create-user")
    def create_user():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip().lower()
        login = (payload.get("login") or "").strip()
        password = payload.get("password") or ""

        app.logger.info(f"Create user request: email={email}, login={login}")

        if not email or not login or not password:
            app.logger.warning(
                f"Create user validation failed: missing fields (email={bool(email)}, login={bool(login)}, password={bool(password)})")
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
        except IntegrityError as e:
            app.logger.warning(f"Create user failed: duplicate email or login - {login}/{email}")
            log_event("user-create-fail", user=login, status="DUPLICATE")
            return jsonify({"error": "email or login already exists"}), 409
        except Exception as e:
            app.logger.error(f"Create user database error: {e}")
            return jsonify({"error": f"database error: {str(e)}"}), 503

        log_event("user-created", user=login, status="OK")
        app.logger.info(f"User created successfully: id={uid}, login={login}")
        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    # POST /api/login {login, password}
    @app.post("/api/login")
    def login():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""

        app.logger.info(f"Login attempt: email={email}")

        if not email or not password:
            app.logger.debug(f"Login validation failed: email={bool(email)}, password={bool(password)}")
            return jsonify({"error": "email and password are required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"),
                    {"email": email},
                ).first()
        except Exception as e:
            app.logger.error(f"Login database error for {email}: {e}")
            log_event("login-db-error", user=email, status="ERROR", details=str(e))
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row or not check_password_hash(row.hpassword, password):
            app.logger.warning(f"Login failed: invalid credentials for {email}")
            log_event("login-failed", user=email, status="FAIL")
            return jsonify({"error": "invalid credentials"}), 401

        token = _serializer().dumps({"uid": int(row.id), "login": row.login, "email": row.email})
        log_event("login-success", user=email, status="OK")
        app.logger.info(f"Login successful: user={row.login} (id={row.id})")
        return jsonify({"token": token, "token_type": "bearer", "expires_in": app.config["TOKEN_TTL_SECONDS"]}), 200

    # POST /api/upload-document  (multipart/form-data)
    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
        app.logger.info(f"Upload document requested by user={g.user['login']}")

        if "file" not in request.files:
            app.logger.warning(f"Upload failed: no file in request from {g.user['login']}")
            return jsonify({"error": "file is required (multipart/form-data)"}), 400
        file = request.files["file"]
        if not file or file.filename == "":
            app.logger.warning(f"Upload failed: empty filename from {g.user['login']}")
            return jsonify({"error": "empty filename"}), 400

        fname = file.filename
        app.logger.debug(f"Processing upload: filename={fname}, user={g.user['login']}")

        user_dir = app.config["STORAGE_DIR"] / "files" / g.user["login"]
        user_dir.mkdir(parents=True, exist_ok=True)

        ts = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S%fZ")
        final_name = request.form.get("name") or fname
        stored_name = f"{ts}__{fname}"
        stored_path = user_dir / stored_name
        file.save(stored_path)
        app.logger.debug(f"File saved to disk: {stored_path}")

        sha_hex = _sha256_file(stored_path)
        size = stored_path.stat().st_size
        app.logger.debug(f"File hash calculated: sha256={sha_hex}, size={size}")

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Documents (name, path, ownerid, sha256, size)
                        VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
                    """),
                    {
                        "name": final_name,
                        "path": str(stored_path),
                        "ownerid": int(g.user["id"]),
                        "sha256hex": sha_hex,
                        "size": int(size),
                    },
                )
                did = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
                row = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id
                    """),
                    {"id": did},
                ).one()
        except Exception as e:
            app.logger.error(f"Upload database error for user={g.user['login']}: {e}")
            return jsonify({"error": f"database error: {str(e)}"}), 503

        log_event("upload-document", user=g.user["login"], status="OK", id=did)
        app.logger.info(
            f"Document uploaded successfully: id={did}, name={final_name}, user={g.user['login']}, size={size}")
        return jsonify({
            "id": int(row.id),
            "name": row.name,
            "creation": row.creation.isoformat() if hasattr(row.creation, "isoformat") else str(row.creation),
            "sha256": row.sha256_hex,
            "size": int(row.size),
        }), 201

    # GET /api/list-documents
    @app.get("/api/list-documents")
    @require_auth
    def list_documents():
        app.logger.info(f"List documents requested by user={g.user['login']}")
        log_event("list documents", user=g.user["login"], status="OK")
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
            app.logger.error(f"List documents database error for user={g.user['login']}: {e}")
            return jsonify({"error": f"database error: {str(e)}"}), 503

        docs = [{
            "id": int(r.id),
            "name": r.name,
            "creation": r.creation.isoformat() if hasattr(r.creation, "isoformat") else str(r.creation),
            "sha256": r.sha256_hex,
            "size": int(r.size),
        } for r in rows]
        app.logger.debug(f"List documents: returning {len(docs)} documents for user={g.user['login']}")
        return jsonify({"documents": docs}), 200

    # GET /api/list-versions
    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<int:document_id>")
    @require_auth
    def list_versions(document_id: int | None = None):
        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                app.logger.warning(f"List versions: invalid document_id from user={g.user['login']}")
                return jsonify({"error": "document id required"}), 400

        app.logger.info(f"List versions requested: doc_id={document_id}, user={g.user['login']}")

        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.secret, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.login = :glogin AND d.id = :did
                    """),
                    {"glogin": str(g.user["login"]), "did": document_id},
                ).all()
        except Exception as e:
            app.logger.error(f"List versions database error: {e}")
            return jsonify({"error": f"database error: {str(e)}"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "secret": r.secret,
            "method": r.method,
        } for r in rows]
        app.logger.debug(f"List versions: returning {len(versions)} versions for doc_id={document_id}")
        return jsonify({"versions": versions}), 200

    # GET /api/list-all-versions
    @app.get("/api/list-all-versions")
    @require_auth
    def list_all_versions():
        app.logger.info(f"List all versions requested by user={g.user['login']}")
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.login = :glogin
                    """),
                    {"glogin": str(g.user["login"])},
                ).all()
        except Exception as e:
            app.logger.error(f"List all versions database error for user={g.user['login']}: {e}")
            return jsonify({"error": f"database error: {str(e)}"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "method": r.method,
        } for r in rows]
        app.logger.debug(f"List all versions: returning {len(versions)} versions for user={g.user['login']}")
        return jsonify({"versions": versions}), 200

    # GET /api/get-document or /api/get-document/<id>  → returns the PDF (inline)
    @app.get("/api/get-document")
    @app.get("/api/get-document/<int:document_id>")
    @require_auth
    def get_document(document_id: int | None = None):

        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                app.logger.warning(f"Get document: invalid document_id from user={g.user['login']}")
                return jsonify({"error": "document id required"}), 400

        app.logger.info(f"Get document requested: doc_id={document_id}, user={g.user['login']}")

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": document_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            app.logger.error(f"Get document database error: {e}")
            return jsonify({"error": f"database error: {str(e)}"}), 503

        # Don't leak whether a doc exists for another user
        if not row:
            app.logger.warning(f"Get document not found or unauthorized: doc_id={document_id}, user={g.user['login']}")
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            # Path looks suspicious or outside storage
            app.logger.error(f"Get document path safety check failed: doc_id={document_id}")
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            app.logger.error(f"Get document file missing on disk: {file_path}")
            return jsonify({"error": "file missing on disk"}), 410

        app.logger.debug(f"Serving document: {file_path}, user={g.user['login']}")

        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.name if row.name.lower().endswith(".pdf") else f"{row.name}.pdf",
            conditional=True,  # enables 304 if If-Modified-Since/Range handling
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )
        # Strong validator
        if isinstance(row.sha256_hex, str) and row.sha256_hex:
            resp.set_etag(row.sha256_hex.lower())

        resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        return resp

    # GET /api/get-version/<link>  → returns the watermarked PDF (inline)
    @app.get("/api/get-version/<link>")
    def get_version(link: str):
        app.logger.info(f"Get version requested: link={link}")

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT *
                        FROM Versions
                        WHERE link = :link
                        LIMIT 1
                    """),
                    {"link": link},
                ).first()
        except Exception as e:
            app.logger.error(f"Get version database error: {e}")
            return jsonify({"error": f"database error: {str(e)}"}), 503

        # Don't leak whether a doc exists for another user
        if not row:
            app.logger.warning(f"Get version not found: link={link}")
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            # Path looks suspicious or outside storage
            app.logger.error(f"Get version path safety check failed: link={link}")
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            app.logger.error(f"Get version file missing on disk: {file_path}")
            return jsonify({"error": "file missing on disk"}), 410

        app.logger.debug(f"Serving version: {file_path}, link={link}")

        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.link if row.link.lower().endswith(".pdf") else f"{row.link}.pdf",
            conditional=True,  # enables 304 if If-Modified-Since/Range handling
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )

        resp.headers["Cache-Control"] = "private, max-age=0"
        return resp

    # Helper: resolve path safely under STORAGE_DIR (handles absolute/relative)
    def _safe_resolve_under_storage(p: str, storage_root: Path) -> Path:
        storage_root = storage_root.resolve()
        fp = Path(p)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()
        # Python 3.12 has is_relative_to on Path
        if hasattr(fp, "is_relative_to"):
            if not fp.is_relative_to(storage_root):
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        else:
            try:
                fp.relative_to(storage_root)
            except ValueError:
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        return fp

    # DELETE /api/delete-document  (and variants)
    @app.route("/api/delete-document", methods=["DELETE", "POST"])  # POST supported for convenience
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
        try:
            doc_id = int(document_id)
        except (TypeError, ValueError):
            app.logger.warning(f"Delete document: invalid document_id from user={g.user['login']}")
            log_event("delete-document-invalid-id", user=g.user["login"], status="FAIL")
            return jsonify({"error": "document id required"}), 400

        app.logger.info(f"Delete document requested: doc_id={doc_id}, user={g.user['login']}")

        # Fetch the document (enforce ownership)
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, path, ownerid FROM Documents WHERE id = :id"),
                    {"id": doc_id}
                ).first()
        except Exception as e:
            app.logger.error(f"Delete document database error: {e}")
            log_event("delete-document-db-error", user=g.user["login"], status="ERROR", details=str(e))
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row or row.ownerid != g.user["id"]:
            app.logger.warning(f"Delete document not found or unauthorized: doc_id={doc_id}, user={g.user['login']}")
            return jsonify({"error": "document not found"}), 404

        # Resolve and delete file (best effort)
        storage_root = Path(app.config["STORAGE_DIR"])
        file_deleted = False
        file_missing = False
        delete_error = None
        try:
            fp = _safe_resolve_under_storage(row.path, storage_root)
            if fp.exists():
                try:
                    fp.unlink()
                    file_deleted = True
                    app.logger.debug(f"File deleted: {fp}")
                except Exception as e:
                    delete_error = f"failed to delete file: {e}"
                    app.logger.warning("Failed to delete file %s for doc id=%s: %s", fp, row.id, e)
            else:
                file_missing = True
                app.logger.warning(f"File missing for deletion: {fp}")
        except RuntimeError as e:
            # Path escapes storage root; refuse to touch the file
            delete_error = str(e)
            app.logger.error("Path safety check failed for doc id=%s: %s", row.id, e)

        # Delete DB row (will cascade to Version if FK has ON DELETE CASCADE)
        try:
            with get_engine().begin() as conn:
                conn.execute(text("DELETE FROM Documents WHERE id = :id"), {"id": doc_id})
                app.logger.debug(f"Document deleted from database: doc_id={doc_id}")
        except Exception as e:
            app.logger.error(f"Delete document database error during deletion: {e}")
            return jsonify({"error": f"database error during delete: {str(e)}"}), 503

        log_event("delete-document", user=g.user["login"], status="OK", id=doc_id)
        app.logger.info(
            f"Document deleted successfully: doc_id={doc_id}, user={g.user['login']}, file_deleted={file_deleted}")
        return jsonify({
            "deleted": True,
            "id": doc_id,
            "file_deleted": file_deleted,
            "file_missing": file_missing,
            "note": delete_error,  # null/omitted if everything was fine
        }), 200

    # POST /api/create-watermark or /api/create-watermark/<id>  → create watermarked pdf and returns metadata
    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<int:document_id>")
    @require_auth
    def create_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if not document_id:
            document_id = (
                    request.args.get("id")
                    or request.args.get("documentid")
                    or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = int(document_id)
        except (TypeError, ValueError):
            app.logger.warning(f"Create watermark: invalid document_id from user={g.user['login']}")
            return jsonify({"error": "document id required"}), 400

        payload = request.get_json(silent=True) or {}
        # allow a couple of aliases for convenience
        method = payload.get("method")
        intended_for = payload.get("intended_for")
        position = payload.get("position") or None
        secret = payload.get("secret")
        key = payload.get("key")

        app.logger.info(
            f"Create watermark requested: doc_id={doc_id}, method={method}, intended_for={intended_for}, user={g.user['login']}")

        # validate input
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            app.logger.warning(f"Create watermark: invalid document_id value {document_id}")
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not intended_for or not isinstance(secret, str) or not isinstance(key, str):
            app.logger.warning(f"Create watermark: missing required fields for doc_id={doc_id}")
            return jsonify({"error": "method, intended_for, secret, and key are required"}), 400

        # lookup the document; enforce ownership
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path, ownerid
                        FROM Documents
                        WHERE id = :id
                        LIMIT 1
                    """),
                    {"id": doc_id},
                ).first()
        except Exception as e:
            app.logger.error(f"Create watermark database error: {e}")
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row or row.ownerid != g.user["id"]:
            app.logger.warning(f"Create watermark not found or unauthorized: doc_id={doc_id}, user={g.user['login']}")
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            app.logger.error(f"Create watermark path safety check failed: doc_id={doc_id}")
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            app.logger.error(f"Create watermark file missing on disk: {file_path}")
            return jsonify({"error": "file missing on disk"}), 410

        # check watermark applicability
        try:
            app.logger.debug(f"Checking watermark applicability: method={method}, position={position}")
            applicable = WMUtils.is_watermarking_applicable(
                method=method,
                pdf=str(file_path),
                position=position
            )
            if applicable is False:
                app.logger.warning(f"Watermarking not applicable: method={method}, doc_id={doc_id}")
                return jsonify({"error": "watermarking method not applicable"}), 400
        except Exception as e:
            app.logger.error(f"Watermark applicability check failed: {e}")
            return jsonify({"error": f"watermark applicability check failed: {e}"}), 400

        # apply watermark → bytes
        try:
            app.logger.debug(f"Applying watermark: method={method}, secret_len={len(secret)}, key_len={len(key)}")
            wm_bytes: bytes = WMUtils.apply_watermark(
                pdf=str(file_path),
                secret=secret,
                key=key,
                method=method,
                position=position
            )
            if not isinstance(wm_bytes, (bytes, bytearray)) or len(wm_bytes) == 0:
                app.logger.error(f"Watermarking produced no output for doc_id={doc_id}")
                return jsonify({"error": "watermarking produced no output"}), 500
            app.logger.debug(f"Watermark applied successfully: size={len(wm_bytes)} bytes")
        except Exception as e:
            app.logger.error(f"Watermarking failed: {e}")
            return jsonify({"error": f"watermarking failed: {e}"}), 500

        # build destination file name: "<original_name>__<intended_to>.pdf"
        base_name = Path(row.name or file_path.name).stem
        intended_slug = secure_filename(intended_for)
        dest_dir = file_path.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)

        candidate = f"{base_name}__{intended_slug}_{int(time.time())}.pdf"
        dest_path = dest_dir / candidate

        # write bytes
        try:
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
            app.logger.debug(f"Watermarked file written: {dest_path}")
        except Exception as e:
            app.logger.error(f"Failed to write watermarked file: {e}")
            return jsonify({"error": f"failed to write watermarked file: {e}"}), 500

        # link token = sha1(watermarked_file_name)
        link_token = hashlib.sha1(candidate.encode("utf-8")).hexdigest()
        app.logger.debug(f"Generated link token: {link_token}")

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": doc_id,
                        "link": link_token,
                        "intended_for": intended_for,
                        "secret": secret,
                        "method": method,
                        "position": position or "",
                        "path": str(dest_path)
                    },
                )
                vid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
                app.logger.debug(f"Version record created: vid={vid}")
        except Exception as e:
            # best-effort cleanup if DB insert fails
            try:
                dest_path.unlink(missing_ok=True)
                app.logger.debug(f"Cleanup: removed watermarked file after DB error")
            except Exception:
                pass
            app.logger.error(f"Database error during version insert: {e}")
            return jsonify({"error": f"database error during version insert: {e}"}), 503

        log_event("create-watermark", user=g.user["login"], status="OK", doc_id=doc_id, version_id=vid)
        app.logger.info(
            f"Watermark created successfully: doc_id={doc_id}, version_id={vid}, method={method}, user={g.user['login']}")
        return jsonify({
            "id": vid,
            "documentid": doc_id,
            "link": link_token,
            "intended_for": intended_for,
            "method": method,
            "position": position,
            "filename": candidate,
            "size": len(wm_bytes),
        }), 201

    # GET /api/get-watermarking-methods
    @app.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        app.logger.info("Get watermarking methods requested")
        methods = []

        for m in WMUtils.METHODS:
            methods.append({"name": m, "description": WMUtils.get_method(m).get_usage()})

        app.logger.debug(f"Returning {len(methods)} watermarking methods")
        return jsonify({"methods": methods, "count": len(methods)}), 200

    # POST /api/read-watermark
    @app.post("/api/read-watermark")
    @app.post("/api/read-watermark/<int:document_id>")
    @require_auth
    def read_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if not document_id:
            document_id = (
                    request.args.get("id")
                    or request.args.get("documentid")
                    or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = int(document_id)
        except (TypeError, ValueError):
            app.logger.warning(f"Read watermark: invalid document_id from user={g.user['login']}")
            return jsonify({"error": "document id required"}), 400

        payload = request.get_json(silent=True) or {}
        # allow a couple of aliases for convenience
        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")

        app.logger.info(f"Read watermark requested: doc_id={doc_id}, method={method}, user={g.user['login']}")

        # validate input
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            app.logger.warning(f"Read watermark: invalid document_id value {document_id}")
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not isinstance(key, str):
            app.logger.warning(f"Read watermark: missing method or key for doc_id={doc_id}")
            return jsonify({"error": "method, and key are required"}), 400

        # lookup the document; enforce ownership
        try:
            with get_engine().connect() as conn:
                # original document row
                row_ori = conn.execute(
                    text("""
                        SELECT id, name, path, ownerid
                        FROM Documents
                        WHERE id = :id
                        LIMIT 1
                    """),
                    {"id": doc_id},
                ).first()

                # NEW: latest watermarked version for this document (if any)
                row_ver = conn.execute(
                    text("""
                        SELECT path
                        FROM Versions
                        WHERE documentid = :id 
                        AND method = :method 
                        ORDER BY id DESC
                        LIMIT 1
                    """),
                    {"id": doc_id, "method": method},
                ).first()
        except Exception as e:
            app.logger.error(f"Read watermark database error: {e}")
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row_ori or row_ori.ownerid != g.user["id"]:
            app.logger.warning(
                f"Read watermark document not found or unauthorized: doc_id={doc_id}, user={g.user['login']}")
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        # get the version
        file_path = Path(row_ver.path) if row_ver else Path(row_ori.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            app.logger.error(f"Read watermark path safety check failed: doc_id={doc_id}")
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            app.logger.error(f"Read watermark file missing on disk: {file_path}")
            return jsonify({"error": "file missing on disk"}), 410

        app.logger.debug(f"Reading watermark from: {file_path}")
        secret = None
        try:
            secret = WMUtils.read_watermark(
                method=method,
                pdf=str(file_path),
                key=key
            )
            app.logger.info(
                f"Watermark read successfully: doc_id={doc_id}, method={method}, secret_len={len(secret) if secret else 0}")
        except Exception as e:
            app.logger.error(f"Error reading watermark: {e}")
            return jsonify({"error": f"Error when attempting to read watermark: {e}"}), 400
        return jsonify({
            "documentid": doc_id,
            "secret": secret,
            "method": method,
            "position": position
        }), 201

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

    app.logger.info(f"RMAP configuration: keys_dir={rmap_keys_dir}, base_pdf={app.config['RMAP_BASE_PDF']}")

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
            app.logger.info("RMAP initialized successfully (clients dir: %s)", clients_dir)
        except Exception as e:
            app.logger.exception("Failed to initialize RMAP: %s", e)
            app.config["RMAP"] = None

    def init_rmap_base_pdf():
        """Ensure RMAP base PDF exists in the database."""
        base_pdf_path = Path(app.config["RMAP_BASE_PDF"])
        app.logger.info(f"Initializing RMAP base PDF: {base_pdf_path}")

        if not base_pdf_path.exists():
            app.logger.warning(f"RMAP base PDF not found: {base_pdf_path}")
            return

        try:
            with get_engine().begin() as conn:
                # Check if already exists
                existing = conn.execute(
                    text("SELECT id FROM Documents WHERE path = :path"),
                    {"path": str(base_pdf_path)}
                ).first()

                if existing:
                    app.logger.info(f"RMAP base PDF already in database (id={existing.id})")
                    return

                # Create system user if needed
                conn.execute(text("""
                    INSERT INTO Users (id, email, hpassword, login)
                    VALUES (10000, 'system@tatou.local', '', 'system')
                    ON DUPLICATE KEY UPDATE id=id
                """))
                app.logger.debug("System user ensured in database")

                # Create document record
                sha_hex = _sha256_file(base_pdf_path)
                size = base_pdf_path.stat().st_size

                conn.execute(text("""
                    INSERT INTO Documents (name, path, ownerid, sha256, size)
                    VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
                """), {
                    "name": "RMAP Base Document",
                    "path": str(base_pdf_path),
                    "ownerid": 10000,
                    "sha256hex": sha_hex,
                    "size": size,
                })

                app.logger.info(
                    f"✓ Created RMAP base document in database (size={size} bytes, sha256={sha_hex[:16]}...)")

        except Exception as e:
            app.logger.error(f"Failed to initialize RMAP base PDF: {e}")

    def _create_watermarked_pdf(identity: str, result_hex: str) -> Path:
        """Create a watermarked PDF for the given identity."""
        base_pdf = Path(app.config["RMAP_BASE_PDF"])
        if not base_pdf.exists():
            app.logger.error(f"Base PDF not found: {base_pdf}")
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

        app.logger.info(f"Creating RMAP watermark for identity={identity}, method={method}")

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

            app.logger.info(f"RMAP watermark created successfully: {wm_path} ({len(wm_bytes)} bytes)")
            return wm_path

        except Exception as e:
            app.logger.error(f"RMAP watermarking failed for {identity}: {e}")
            raise

    def _rmap_make_link(result_hex: str, identity: str) -> dict:
        """Create watermarked PDF and Version record."""
        token = result_hex.lower()
        app.logger.info(f"Creating RMAP link for identity={identity}, token={token}")

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
                    app.logger.error("RMAP base document not found in database")
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

                app.logger.info(f"RMAP Version record created: token={token}, identity={identity}")

            return {"token": token}

        except Exception as e:
            app.logger.error(f"Failed to create RMAP link: {e}")
            raise

    # Message 1 -> Response 1
    @app.post("/api/rmap-initiate")
    def rmap_initiate():
        """Handle RMAP Message 1"""
        rmap = app.config.get("RMAP")
        if rmap is None:
            app.logger.warning("RMAP initiate: RMAP not initialized")
            return jsonify({"error": "RMAP not initialized"}), 503

        body = request.get_json(silent=True) or {}
        if "payload" not in body:
            app.logger.warning("RMAP initiate: missing payload")
            return jsonify({"error": "payload is required"}), 400

        try:
            app.logger.debug("RMAP initiate: processing message 1")
            out = rmap.handle_message1(body)

            if "payload" in out:
                app.logger.info("RMAP initiate: success")
                return jsonify(out), 200
            else:
                app.logger.warning(f"RMAP initiate failed: {out.get('error', 'unknown error')}")
                return jsonify(out), 400

        except Exception as e:
            app.logger.exception("rmap-initiate failed: %s", e)
            return jsonify({"error": "server error"}), 500

    @app.post("/api/rmap-get-link")
    def rmap_get_link():
        """Handle RMAP Message 2 and create watermarked PDF"""
        rmap = app.config.get("RMAP")
        if rmap is None:
            app.logger.warning("RMAP get-link: RMAP not initialized")
            return jsonify({"error": "RMAP not initialized"}), 503

        body = request.get_json(silent=True) or {}
        if "payload" not in body:
            app.logger.warning("RMAP get-link: missing payload")
            return jsonify({"error": "payload is required"}), 400

        try:
            app.logger.debug("RMAP get-link: processing message 2")
            out = rmap.handle_message2(body)

            if "result" not in out:
                app.logger.warning(f"RMAP get-link: {out.get('error', 'unknown error')}")
                return jsonify(out), 400

            result_hex = out["result"]

            # Get identity from RMAP's internal nonces dictionary
            identity = "Unknown"
            if hasattr(rmap, 'nonces') and rmap.nonces:
                # Get the identity (typically only one active session)
                identity = list(rmap.nonces.keys())[0]
                # Clean up the nonce after use
                rmap.nonces.clear()

            app.logger.info(f"RMAP get-link: creating link for identity={identity}, result={result_hex}")

            _rmap_make_link(result_hex, identity)

            app.logger.info(f"RMAP get-link: success for identity={identity}")
            return jsonify({"result": result_hex}), 200

        except Exception as e:
            app.logger.exception("rmap-get-link failed: %s", e)
            return jsonify({"error": "server error"}), 500

    # ====================== end RMAP section ======================

    with app.app_context():
        try:
            init_rmap_base_pdf()
        except Exception as e:
            app.logger.error(f"Failed to initialize RMAP base PDF on startup: {e}")

    return app


# WSGI entrypoint
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.logger.info(f"Starting Tatou server on port {port}")
    app.run(host="0.0.0.0", port=port)