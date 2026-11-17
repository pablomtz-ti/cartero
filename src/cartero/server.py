"""Servidor web local (solo escucha en 127.0.0.1) con la API y la interfaz."""

from __future__ import annotations

import json
import logging
import mimetypes
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .engine import Engine
from .knowledge import Knowledge

log = logging.getLogger(__name__)
WEB_DIR = Path(__file__).parent / "web"
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}


class App:
    """Lo que necesita el servidor: el motor y cómo listar dispositivos."""

    def __init__(self, engine: Engine, kb: Knowledge, devices) -> None:
        self.engine = engine
        self.kb = kb
        self.devices = devices  # callable(deep: bool) -> list[Device]
        self._wifi_lock = threading.Lock()


def make_handler(app: App) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "Cartero"
        sys_version = ""

        def log_message(self, fmt: str, *args) -> None:  # silenciamos el log por petición
            log.debug("%s - %s", self.address_string(), fmt % args)

        # --- seguridad ------------------------------------------------
        def _host_ok(self) -> bool:
            """Protección contra DNS rebinding: solo aceptamos peticiones dirigidas a localhost."""
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
            return host in ALLOWED_HOSTS

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
                "connect-src 'self'; frame-ancestors 'none'",
            )
            self.end_headers()
            self.wfile.write(body)

        def _json(self, data, status: int = 200) -> None:
            self._send(status, json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

        # --- rutas ----------------------------------------------------
        def do_GET(self) -> None:  # noqa: N802
            if not self._host_ok():
                return self._json({"error": "host no permitido"}, HTTPStatus.FORBIDDEN)
            url = urlparse(self.path)
            q = parse_qs(url.query)
            path = url.path
            if path == "/api/live":
                return self._json(app.engine.live(hide_noise=q.get("all", ["0"])[0] != "1"))
            if path == "/api/scan":
                return self._json(app.engine.scan_status())
            if path == "/api/card":
                card = app.engine.find_card(q.get("id", [""])[0])
                return self._json(card.to_dict() if card else {"error": "no encontrado"}, 200 if card else 404)
            if path == "/api/wifi":
                deep = q.get("deep", ["0"])[0] == "1"
                with app._wifi_lock:
                    devices = app.devices(deep)
                return self._json({"devices": [d.to_dict() for d in devices]})
            if path == "/api/glossary":
                return self._json(app.kb.glossary)
            if path == "/api/status":
                live = app.engine.live()
                return self._json({k: live[k] for k in ("mode", "capture", "limited")})
            return self._static(path)

        def do_POST(self) -> None:  # noqa: N802
            if not self._host_ok():
                return self._json({"error": "host no permitido"}, HTTPStatus.FORBIDDEN)
            if urlparse(self.path).path == "/api/scan":
                return self._json(app.engine.start_scan())
            return self._json({"error": "no encontrado"}, HTTPStatus.NOT_FOUND)

        def _static(self, path: str) -> None:
            rel = "index.html" if path in ("/", "") else path.lstrip("/")
            target = (WEB_DIR / rel).resolve()
            if WEB_DIR.resolve() not in target.parents or not target.is_file():
                return self._send(HTTPStatus.NOT_FOUND, b"No encontrado", "text/plain; charset=utf-8")
            ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
                ctype += "; charset=utf-8"
            self._send(HTTPStatus.OK, target.read_bytes(), ctype)

    return Handler


def serve(app: App, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    httpd.daemon_threads = True
    return httpd
