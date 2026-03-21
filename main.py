import json
import os
import re
import socket
import sys
import threading
import uuid
import webbrowser
import hashlib
import hmac
import secrets
import time
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from http.cookies import SimpleCookie
from socket import error as SocketError


HOST = "127.0.0.1"
PORT = 8000
UPLOAD_DIR = "uploads"
STATE_FILE = "app_state.json"
AUTH_FILE = "auth.json"
SESSION_COOKIE = "fibula_session"
SESSION_MAX_AGE = 60 * 60 * 12

DEFAULT_CENIK_VALUES = {
    "individualna": 50,
    "semi2": 40,
    "semi3": 35,
    "semi4": 30,
    "semi5": 25,
    "terapevtska": 25,
    "skupina": 30,
}

DEFAULT_CUSTOMERS = [
    {"name": "Ana Štefančič", "email": "", "kraj": "", "racun": "", "popust": "0", "datoteke": [], "komentar": ""},
    {"name": "Matjaž Štefančič", "email": "", "kraj": "", "racun": "", "popust": "0", "datoteke": [], "komentar": ""},
    {"name": "Jana Hladnik Tratnik", "email": "", "kraj": "", "racun": "", "popust": "0", "datoteke": [], "komentar": ""},
    {"name": "Aljoša", "email": "", "kraj": "", "racun": "", "popust": "0", "datoteke": [], "komentar": ""},
    {"name": "Marko", "email": "", "kraj": "", "racun": "", "popust": "0", "datoteke": [], "komentar": ""},
    {"name": "Tamara Vidmar", "email": "", "kraj": "", "racun": "", "popust": "0", "datoteke": [], "komentar": ""},
    {"name": "Tomaž", "email": "", "kraj": "", "racun": "", "popust": "0", "datoteke": [], "komentar": ""},
    {"name": "Ana Curk", "email": "", "kraj": "", "racun": "", "popust": "0", "datoteke": [], "komentar": ""},
    {"name": "Beočanin žena", "email": "", "kraj": "", "racun": "", "popust": "0", "datoteke": [], "komentar": ""},
]
for customer in DEFAULT_CUSTOMERS:
    customer["telefon"] = customer.get("telefon", "")
    customer["statusi"] = customer.get("statusi", [])

DEFAULT_STATE = {
    "customers": DEFAULT_CUSTOMERS,
    "treningi": [],
    "cenik": {
        "Ajdovščina": {**DEFAULT_CENIK_VALUES},
        "Idrija": {**DEFAULT_CENIK_VALUES},
    },
}


class AuthStore:
    def __init__(self, root_dir: Path) -> None:
        self.auth_path = root_dir / AUTH_FILE
        self._lock = threading.Lock()
        self._sessions: dict[str, dict[str, float | str]] = {}

    def has_user(self) -> bool:
        return len(self._load_users()) > 0

    def _build_user_record(self, username: str, password: str) -> dict:
        salt = secrets.token_hex(16)
        password_hash = self._hash_password(password, salt)
        return {
            "username": username,
            "salt": salt,
            "password_hash": password_hash,
            "iterations": 200_000,
        }

    @staticmethod
    def _hash_password(password: str, salt: str, iterations: int = 200_000) -> str:
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        ).hex()

    def _load_auth(self) -> dict:
        if not self.auth_path.exists():
            return {"users": []}

        raw = json.loads(self.auth_path.read_text(encoding="utf-8"))
        if isinstance(raw, dict) and isinstance(raw.get("users"), list):
            return {
                "users": [
                    {
                        "username": str(user.get("username", "")).strip(),
                        "salt": str(user.get("salt", "")).strip(),
                        "password_hash": str(user.get("password_hash", "")).strip(),
                        "iterations": int(user.get("iterations", 200_000) or 200_000),
                    }
                    for user in raw["users"]
                    if isinstance(user, dict) and str(user.get("username", "")).strip()
                ]
            }

        legacy_username = str(raw.get("username", "admin")).strip() or "admin"
        return {
            "users": [{
                "username": legacy_username,
                "salt": str(raw.get("salt", "")).strip(),
                "password_hash": str(raw.get("password_hash", "")).strip(),
                "iterations": int(raw.get("iterations", 200_000) or 200_000),
            }]
        }

    def _load_users(self) -> list[dict]:
        return self._load_auth()["users"]

    def _save_users(self, users: list[dict]) -> None:
        self.auth_path.write_text(json.dumps({"users": users}, ensure_ascii=False, indent=2), encoding="utf-8")

    def authenticate(self, username: str, password: str) -> str | None:
        if not self.has_user():
            return None
        user = next((item for item in self._load_users() if item["username"] == username), None)
        if not user:
            return None
        expected_hash = self._hash_password(password, user["salt"], int(user["iterations"]))
        if not hmac.compare_digest(expected_hash, user["password_hash"]):
            return None

        session_id = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[session_id] = {
                "username": user["username"],
                "expires_at": time.time() + SESSION_MAX_AGE,
            }
        return session_id

    def get_session_user(self, session_id: str | None) -> str | None:
        if not session_id:
            return None

        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            if float(session["expires_at"]) < time.time():
                self._sessions.pop(session_id, None)
                return None
            session["expires_at"] = time.time() + SESSION_MAX_AGE
            return str(session["username"])

    def clear_session(self, session_id: str | None) -> None:
        if not session_id:
            return
        with self._lock:
            self._sessions.pop(session_id, None)

    def update_password(self, username: str, current_password: str, new_password: str) -> bool:
        if len(new_password) < 8:
            raise ValueError("Novo geslo mora imeti vsaj 8 znakov.")

        users = self._load_users()
        user = next((item for item in users if item["username"] == username), None)
        if not user:
            return False
        current_hash = self._hash_password(current_password, user["salt"], int(user["iterations"]))
        if not hmac.compare_digest(current_hash, user["password_hash"]):
            return False

        updated = self._build_user_record(username, new_password)
        updated_users = [updated if item["username"] == username else item for item in users]
        self._save_users(updated_users)
        return True

    def register(self, username: str, password: str) -> bool:
        if len(username.strip()) < 3:
            raise ValueError("Uporabniško ime mora imeti vsaj 3 znake.")
        if len(password) < 8:
            raise ValueError("Geslo mora imeti vsaj 8 znakov.")

        clean_username = username.strip()
        users = self._load_users()
        if any(item["username"].lower() == clean_username.lower() for item in users):
            raise ValueError("To uporabniško ime že obstaja.")

        users.append(self._build_user_record(clean_username, password))
        self._save_users(users)
        return True


class StateStore:
    def __init__(self, root_dir: Path) -> None:
        self.root_dir = root_dir
        self.state_path = root_dir / STATE_FILE
        self._lock = threading.Lock()
        self._ensure_state_file()

    def _ensure_state_file(self) -> None:
        if not self.state_path.exists():
            self.save(DEFAULT_STATE)

    def load(self) -> dict:
        with self._lock:
            try:
                raw = json.loads(self.state_path.read_text(encoding="utf-8"))
            except (FileNotFoundError, json.JSONDecodeError):
                raw = DEFAULT_STATE
                self.state_path.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
            return self._normalize_state(raw)

    def save(self, state: dict) -> dict:
        normalized = self._normalize_state(state)
        with self._lock:
            self.state_path.write_text(json.dumps(normalized, ensure_ascii=False, indent=2), encoding="utf-8")
        return normalized

    def _normalize_state(self, state: dict) -> dict:
        if not isinstance(state, dict):
            state = {}

        raw_customers = state.get("customers", DEFAULT_CUSTOMERS)
        raw_treningi = state.get("treningi", [])
        raw_cenik = state.get("cenik", {})

        customers = []
        if isinstance(raw_customers, list):
            for customer in raw_customers:
                if not isinstance(customer, dict):
                    continue
                name = str(customer.get("name", "")).strip()
                if not name:
                    continue
                datoteke = customer.get("datoteke", [])
                normalized_files = []
                if isinstance(datoteke, list):
                    for item in datoteke:
                        if isinstance(item, dict):
                            item_name = str(item.get("name", "")).strip()
                            item_url = str(item.get("url", "")).strip()
                            if item_name and item_url:
                                normalized_files.append({"name": item_name, "url": item_url})
                customers.append(
                    {
                        "name": name,
                        "email": str(customer.get("email", "")).strip(),
                        "telefon": str(customer.get("telefon", "")).strip(),
                        "kraj": str(customer.get("kraj", "")).strip(),
                        "racun": str(customer.get("racun", "")).strip(),
                        "popust": str(customer.get("popust", "0")).strip() or "0",
                        "statusi": [str(item).strip() for item in customer.get("statusi", []) if str(item).strip()],
                        "datoteke": normalized_files,
                        "komentar": str(customer.get("komentar", "")).strip(),
                    }
                )

        treningi = []
        if isinstance(raw_treningi, list):
            for trening in raw_treningi:
                if not isinstance(trening, dict):
                    continue
                treningi.append(
                    {
                        "id": str(trening.get("id", f"trening_{uuid.uuid4().hex}")),
                        "imeStranke": str(trening.get("imeStranke", "")).strip(),
                        "datum": str(trening.get("datum", "")).strip(),
                        "datumPrikaz": str(trening.get("datumPrikaz", "")).strip(),
                        "ura": str(trening.get("ura", "")).strip(),
                        "trajanje": int(trening.get("trajanje", 60) or 60),
                        "seriesId": str(trening.get("seriesId", "")).strip(),
                        "recurring": bool(trening.get("recurring", False)),
                        "kraj": str(trening.get("kraj", "")).strip(),
                        "vrstaVadbe": str(trening.get("vrstaVadbe", "")).strip(),
                        "cena": float(trening.get("cena", 0) or 0),
                    }
                )

        cenik = {}
        for kraj in ("Ajdovščina", "Idrija"):
            merged = {**DEFAULT_CENIK_VALUES}
            source = raw_cenik.get(kraj, {}) if isinstance(raw_cenik, dict) else {}
            if isinstance(source, dict):
                for key, value in source.items():
                    merged[str(key)] = float(value or 0)
            cenik[kraj] = merged

        return {"customers": customers, "treningi": treningi, "cenik": cenik}


class NoCacheHandler(SimpleHTTPRequestHandler):
    store: StateStore | None = None
    auth_store: AuthStore | None = None
    app_data_dir: Path | None = None

    def __init__(self, *args, directory: str | None = None, **kwargs) -> None:
        super().__init__(*args, directory=directory, **kwargs)

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def handle(self) -> None:
        try:
            super().handle()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, SocketError):
            pass

    def finish(self) -> None:
        try:
            super().finish()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, SocketError):
            pass

    def log_error(self, format: str, *args) -> None:
        message = format % args if args else format
        if "Broken pipe" in message or "Connection reset" in message:
            return
        super().log_error(format, *args)

    def do_GET(self) -> None:
        if self.path == "/api/session":
            username = self._get_authenticated_username()
            self._send_json({
                "authenticated": bool(username),
                "username": username or "",
                "registrationAvailable": True,
            })
            return

        if self.path == "/api/state":
            if not self._require_auth():
                return
            self._send_json(self._require_store().load())
            return

        if self.path.startswith(f"/{UPLOAD_DIR}/") and not self._require_auth():
            return

        super().do_GET()

    def do_POST(self) -> None:
        if self.path == "/api/login":
            self._handle_login()
            return

        if self.path == "/api/register":
            self._handle_register()
            return

        if self.path == "/api/logout":
            session_id = self._get_session_id()
            self._require_auth_store().clear_session(session_id)
            self._send_json({"ok": True}, clear_session_cookie=True)
            return

        if self.path == "/api/change-password":
            if not self._require_auth():
                return
            self._handle_change_password()
            return

        if self.path == "/api/upload":
            if not self._require_auth():
                return
            try:
                uploaded_files = self._handle_upload()
            except ValueError as error:
                self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
            except Exception as error:
                self.log_error("Upload failed: %s", error)
                self._send_json({"error": "Upload failed"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
                return

            self._send_json({"files": uploaded_files})
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Unknown endpoint")

    def do_PUT(self) -> None:
        if self.path != "/api/state":
            self.send_error(HTTPStatus.NOT_FOUND, "Unknown endpoint")
            return

        if not self._require_auth():
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length) if content_length else b"{}"

        try:
            payload = json.loads(body.decode("utf-8"))
            state = self._require_store().save(payload)
        except ValueError as error:
            self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
            return
        except Exception as error:
            self.log_error("State save failed: %s", error)
            self._send_json({"error": "State save failed"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        self._send_json(state)

    def do_DELETE(self) -> None:
        if self.path != "/api/delete-file":
            self.send_error(HTTPStatus.NOT_FOUND, "Unknown endpoint")
            return

        if not self._require_auth():
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length) if content_length else b"{}"

        try:
            payload = json.loads(body.decode("utf-8"))
            url = payload.get("url", "")
            self._delete_uploaded_file(url)
        except ValueError as error:
            self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
            return
        except Exception as error:
            self.log_error("Delete failed: %s", error)
            self._send_json({"error": "Delete failed"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        self._send_json({"ok": True})

    def _require_store(self) -> StateStore:
        if self.store is None:
            raise RuntimeError("State store is not configured")
        return self.store

    def _require_auth_store(self) -> AuthStore:
        if self.auth_store is None:
            raise RuntimeError("Auth store is not configured")
        return self.auth_store

    def _get_session_id(self) -> str | None:
        cookie_header = self.headers.get("Cookie", "")
        if not cookie_header:
            return None
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        morsel = cookie.get(SESSION_COOKIE)
        return morsel.value if morsel else None

    def _get_authenticated_username(self) -> str | None:
        return self._require_auth_store().get_session_user(self._get_session_id())

    def _require_auth(self) -> bool:
        if self._get_authenticated_username():
            return True
        self._send_json({"error": "Authentication required"}, status=HTTPStatus.UNAUTHORIZED)
        return False

    def _handle_login(self) -> None:
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length) if content_length else b"{}"

        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid login payload"}, status=HTTPStatus.BAD_REQUEST)
            return

        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        session_id = self._require_auth_store().authenticate(username, password)

        if not session_id:
            self._send_json({"error": "Nepravilno uporabniško ime ali geslo."}, status=HTTPStatus.UNAUTHORIZED)
            return

        self._send_json({"ok": True, "username": username}, session_id=session_id)

    def _handle_register(self) -> None:
        if self._require_auth_store().has_user():
            self._send_json({"error": "Račun že obstaja. Uporabi prijavo."}, status=HTTPStatus.CONFLICT)
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length) if content_length else b"{}"

        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid registration payload"}, status=HTTPStatus.BAD_REQUEST)
            return

        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))

        try:
            created = self._require_auth_store().register(username, password)
        except ValueError as error:
            self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
            return

        if not created:
            self._send_json({"error": "Registracija ni na voljo."}, status=HTTPStatus.CONFLICT)
            return

        session_id = self._require_auth_store().authenticate(username, password)
        self._send_json({"ok": True, "username": username}, session_id=session_id)

    def _handle_register(self) -> None:
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length) if content_length else b"{}"

        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid registration payload"}, status=HTTPStatus.BAD_REQUEST)
            return

        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))

        try:
            self._require_auth_store().register(username, password)
        except ValueError as error:
            self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
            return

        session_id = self._require_auth_store().authenticate(username, password)
        self._send_json({"ok": True, "username": username}, session_id=session_id)

    def _handle_change_password(self) -> None:
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length) if content_length else b"{}"

        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid password payload"}, status=HTTPStatus.BAD_REQUEST)
            return

        username = self._get_authenticated_username()
        current_password = str(payload.get("currentPassword", ""))
        new_password = str(payload.get("newPassword", ""))

        try:
            updated = self._require_auth_store().update_password(username or "", current_password, new_password)
        except ValueError as error:
            self._send_json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
            return

        if not updated:
            self._send_json({"error": "Trenutno geslo ni pravilno."}, status=HTTPStatus.UNAUTHORIZED)
            return

        self._send_json({"ok": True})

    def _handle_upload(self) -> list[dict[str, str]]:
        content_type = self.headers.get("Content-Type", "")

        if "multipart/form-data" not in content_type:
            raise ValueError("Content-Type must be multipart/form-data")

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)
        message = BytesParser(policy=policy.default).parsebytes(
            f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + body
        )

        upload_root = self._get_app_data_dir() / UPLOAD_DIR
        upload_root.mkdir(parents=True, exist_ok=True)
        uploaded_files: list[dict[str, str]] = []

        for part in message.iter_parts():
            if part.get_content_disposition() != "form-data":
                continue

            if part.get_param("name", header="content-disposition") != "files":
                continue

            original_filename = part.get_filename()
            if not original_filename:
                continue

            original_name = Path(original_filename).name
            safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", original_name)
            target_name = f"{uuid.uuid4().hex}_{safe_name}"
            target_path = upload_root / target_name
            data = part.get_payload(decode=True) or b""
            target_path.write_bytes(data)
            uploaded_files.append({"name": original_name, "url": f"/{UPLOAD_DIR}/{target_name}"})

        return uploaded_files

    def _send_json(
        self,
        payload: dict,
        status: HTTPStatus = HTTPStatus.OK,
        session_id: str | None = None,
        clear_session_cookie: bool = False,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if session_id:
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE}={session_id}; Max-Age={SESSION_MAX_AGE}; HttpOnly; SameSite=Strict; Path=/",
            )
        elif clear_session_cookie:
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE}=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/",
            )
        self.end_headers()
        self.wfile.write(body)

    def _delete_uploaded_file(self, url: str) -> None:
        if not url.startswith(f"/{UPLOAD_DIR}/"):
            raise ValueError("Invalid file url")

        file_name = Path(url).name
        target_path = (self._get_app_data_dir() / UPLOAD_DIR / file_name).resolve()
        upload_root = (self._get_app_data_dir() / UPLOAD_DIR).resolve()

        if upload_root not in target_path.parents:
            raise ValueError("Invalid file path")

        if target_path.exists():
            target_path.unlink()

    def _get_app_data_dir(self) -> Path:
        if self.app_data_dir is not None:
            return self.app_data_dir
        return Path(self.directory or Path.cwd())


def get_runtime_paths() -> tuple[Path, Path]:
    if getattr(sys, "frozen", False):
        resource_dir = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
        data_dir = Path(sys.executable).resolve().parent
        return resource_dir, data_dir

    project_dir = Path(__file__).resolve().parent
    return project_dir, project_dir


def create_server(handler) -> tuple[ThreadingHTTPServer, int]:
    for port in range(PORT, PORT + 20):
        try:
            server = ThreadingHTTPServer((HOST, port), handler)
            return server, port
        except OSError as error:
            bind_errors = {13, 48, 98, 10013, 10048}
            if error.errno not in bind_errors and getattr(error, "winerror", None) not in bind_errors:
                raise

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((HOST, 0))
        fallback_port = probe.getsockname()[1]

    server = ThreadingHTTPServer((HOST, fallback_port), handler)
    return server, fallback_port


def main() -> None:
    resource_dir, data_dir = get_runtime_paths()
    index_file = resource_dir / "index.html"

    if not index_file.exists():
        raise FileNotFoundError(f"Missing page file: {index_file}")

    store = StateStore(data_dir)
    auth_store = AuthStore(data_dir)

    def handler(*args, **kwargs):
        NoCacheHandler.store = store
        NoCacheHandler.auth_store = auth_store
        NoCacheHandler.app_data_dir = data_dir
        NoCacheHandler(*args, directory=str(resource_dir), **kwargs)

    server, active_port = create_server(handler)
    app_url = f"http://127.0.0.1:{active_port}"

    print(f"Serving {index_file.name} at {app_url}")
    if active_port != PORT:
        print(f"Port {PORT} is unavailable, using {active_port} instead.")
    print("Press Ctrl+C to stop the server.")

    if getattr(sys, "frozen", False):
        threading.Timer(1.0, lambda: webbrowser.open(app_url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
