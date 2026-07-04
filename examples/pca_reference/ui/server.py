from __future__ import annotations

import json
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
STATIC_ROOT = Path(__file__).resolve().parent / "static"
CLI = ROOT / "pca_cli.py"

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
}


def build_cli(action: str, payload: dict[str, object]) -> list[str]:
    namespace = str(payload.get("namespace", ""))
    command = [sys.executable, str(CLI)]
    source = source_args(payload)

    if action == "init":
        return command + ["init"]
    if action == "derive-node":
        return command + [
            "derive-node",
            *source,
            "--namespace",
            namespace,
            "--path",
            str(payload.get("path", "")),
            "--length",
            str(payload.get("length", 64)),
        ]
    if action == "identity":
        return command + [
            "identity",
            *source,
            "--namespace",
            namespace,
            "--path",
            str(payload.get("path", "")),
        ]
    if action == "generation":
        return command + [
            "generation",
            *source,
            "--namespace",
            namespace,
            "--path",
            str(payload.get("path", "")),
            "--length",
            str(payload.get("length", 32)),
        ]
    if action == "bip32-seed":
        return command + [
            "bip32-seed",
            *source,
            "--namespace",
            namespace,
            "--network",
            str(payload.get("network", "Mainnet")),
        ]
    if action == "vault-permission":
        return command + [
            "vault-permission",
            *source,
            "--namespace",
            namespace,
            "--permission-path",
            str(payload.get("permission_path", "")),
        ]
    if action == "vault-file-key":
        result = command + [
            "vault-file-key",
            *source,
            "--namespace",
            namespace,
            "--permission-path",
            str(payload.get("permission_path", "")),
        ]
        file_id = payload.get("file_id")
        if file_id:
            result += ["--file-id", str(file_id)]
        return result
    raise ValueError(f"unknown action: {action}")


def source_args(payload: dict[str, object]) -> list[str]:
    parent_key = payload.get("parent_key_hex")
    parent_path = payload.get("parent_path")
    if parent_key or parent_path:
        return ["--parent-key-hex", str(parent_key or ""), "--parent-path", str(parent_path or "")]
    return ["--master-hex", str(payload.get("master_hex", ""))]


def parse_stdout(stdout: str) -> object:
    text = stdout.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


class PCAUIHandler(BaseHTTPRequestHandler):
    server_version = "PCAReferenceUI/1.0"

    def do_GET(self) -> None:
        if self.path == "/":
            self._serve_file(STATIC_ROOT / "index.html")
            return
        if self.path == "/api/health":
            self._json({"ok": True})
            return
        path = unquote(self.path.split("?", 1)[0]).lstrip("/")
        candidate = (STATIC_ROOT / path).resolve()
        if STATIC_ROOT.resolve() not in candidate.parents and candidate != STATIC_ROOT.resolve():
            self.send_error(403)
            return
        if not candidate.is_file():
            self.send_error(404)
            return
        self._serve_file(candidate)

    def do_POST(self) -> None:
        if self.path != "/api/cli":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length).decode("utf-8"))
            action = str(request.get("action", ""))
            payload = request.get("payload", {})
            if not isinstance(payload, dict):
                raise ValueError("payload must be an object")
            command = build_cli(action, payload)
            completed = subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                text=True,
                shell=False,
                timeout=15,
            )
            self._json(
                {
                    "command": subprocess.list2cmdline(command),
                    "ok": completed.returncode == 0,
                    "returncode": completed.returncode,
                    "stdout": completed.stdout,
                    "stderr": completed.stderr,
                    "data": parse_stdout(completed.stdout),
                }
            )
        except Exception as exc:
            self._json({"ok": False, "error": str(exc)}, status=400)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _serve_file(self, path: Path) -> None:
        content = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", CONTENT_TYPES.get(path.suffix, "application/octet-stream"))
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _json(self, value: object, status: int = 200) -> None:
        data = json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    server = ThreadingHTTPServer(("127.0.0.1", port), PCAUIHandler)
    print(f"PCA reference UI: http://127.0.0.1:{port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
