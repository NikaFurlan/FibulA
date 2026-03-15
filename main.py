import json
import re
import uuid
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socket import error as SocketError


HOST = "127.0.0.1"
PORT = 8000
UPLOAD_DIR = "uploads"


class NoCacheHandler(SimpleHTTPRequestHandler):
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

    def do_POST(self) -> None:
        if self.path != "/api/upload":
            self.send_error(HTTPStatus.NOT_FOUND, "Unknown endpoint")
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

    def do_DELETE(self) -> None:
        if self.path != "/api/delete-file":
            self.send_error(HTTPStatus.NOT_FOUND, "Unknown endpoint")
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

    def _handle_upload(self) -> list[dict[str, str]]:
        content_type = self.headers.get("Content-Type", "")

        if "multipart/form-data" not in content_type:
            raise ValueError("Content-Type must be multipart/form-data")

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)
        message = BytesParser(policy=policy.default).parsebytes(
            f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + body
        )

        upload_root = Path(self.directory or Path.cwd()) / UPLOAD_DIR
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
            uploaded_files.append(
                {
                    "name": original_name,
                    "url": f"/{UPLOAD_DIR}/{target_name}",
                }
            )

        return uploaded_files

    def _send_json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _delete_uploaded_file(self, url: str) -> None:
        if not url.startswith(f"/{UPLOAD_DIR}/"):
            raise ValueError("Invalid file url")

        file_name = Path(url).name
        target_path = (Path(self.directory or Path.cwd()) / UPLOAD_DIR / file_name).resolve()
        upload_root = (Path(self.directory or Path.cwd()) / UPLOAD_DIR).resolve()

        if upload_root not in target_path.parents:
            raise ValueError("Invalid file path")

        if target_path.exists():
            target_path.unlink()


def main() -> None:
    project_dir = Path(__file__).resolve().parent
    index_file = project_dir / "index.html"

    if not index_file.exists():
        raise FileNotFoundError(f"Missing page file: {index_file}")

    def handler(*args, **kwargs):
        NoCacheHandler(*args, directory=str(project_dir), **kwargs)

    server = ThreadingHTTPServer((HOST, PORT), handler)

    print(f"Serving {index_file.name} at http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop the server.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
