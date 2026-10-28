"""Local web server and JSON API (Python standard library only).

The server binds to 127.0.0.1 and refuses to bind anywhere else. Because any
website open in the same browser could try to talk to a localhost service,
it also checks the Host header (DNS-rebinding defence), the Origin /
Sec-Fetch-Site headers on state-changing requests (CSRF defence) and requires
a JSON content type.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import mimetypes
import re
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from . import __version__
from .config import WEB_DIR, ScanLimits, Settings
from .engine import Scanner
from .jobs import QueueFull, ScanQueue
from .plans import FREE_BETA, FairUse
from .security import EgressPolicy, UnsafeUrlError, validate_url
from .storage import ReportStore, new_scan_id, valid_id

log = logging.getLogger("adleak.server")

STATIC_FILES = {"/": "index.html", "/index.html": "index.html", "/styles.css": "styles.css", "/app.js": "app.js", "/favicon.svg": "favicon.svg"}
MAX_BODY = 8 * 1024
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; "
                               "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
}
_SCREENSHOT_ROUTE = re.compile(r"^/api/scans/([0-9a-f]{32})/screenshots/([a-z\-]+\.png)$")
_SCAN_ROUTE = re.compile(r"^/api/scans/([0-9a-f]{32})$")


class App:
    def __init__(self, settings: Settings, policy: EgressPolicy | None = None, limits: ScanLimits | None = None):
        self.settings = settings
        self.policy = policy or EgressPolicy()
        self.limits = limits or ScanLimits(max_links=FREE_BETA.max_links)
        self.store = ReportStore(settings.data_dir, settings.max_stored_reports)
        recovered = self.store.recover_interrupted()
        if recovered:
            log.info("marked %d interrupted scans as failed", recovered)
        self.fair_use = FairUse(FREE_BETA)
        self.fair_use.seed(r["created_at"] for r in self.store.list(limit=100_000) if r.get("created_at"))
        self.queue = ScanQueue(
            self.store,
            lambda: Scanner(self.policy, self.limits, screenshot_root=self.store.shots_dir),
            workers=settings.max_concurrent_scans,
            max_queued=settings.max_queued_scans,
        )
        self.port = settings.port

    def allowed_hosts(self) -> set[str]:
        return {f"127.0.0.1:{self.port}", f"localhost:{self.port}", f"[::1]:{self.port}"}

    def allowed_origins(self) -> set[str]:
        return {f"http://{h}" for h in self.allowed_hosts()}

    # -- API operations ----------------------------------------------------
    def create_scan(self, body: dict) -> tuple[int, dict]:
        if not isinstance(body, dict):
            return 400, {"error": "The request body must be a JSON object."}
        try:
            target = validate_url(body.get("url"), self.policy)
        except UnsafeUrlError as exc:
            return 400, {"error": exc.message, "code": exc.code}
        expected_raw = body.get("expected_tags") or {}
        if not isinstance(expected_raw, dict):
            return 400, {"error": "expected_tags must be an object."}
        expected = {k: bool(expected_raw.get(k)) for k in ("meta", "ga4", "gtm")}
        options = {"expected_tags": expected, "screenshots": body.get("screenshots", True) is not False}
        ok, message = self.fair_use.try_consume()
        if not ok:
            return 429, {"error": message, "usage": self.fair_use.status()}
        scan_id = new_scan_id()
        now = time.time()
        record = {
            "id": scan_id, "workspace": "local", "plan": FREE_BETA.key, "submitted_url": target.url,
            "state": "queued", "created_at": now, "options": options,
            "progress": [{"at": now, "message": "Queued: waiting for a free scanner slot"}],
        }
        self.store.save(record)
        try:
            self.queue.submit(scan_id, target.url, options)
        except QueueFull as exc:
            self.store.delete(scan_id)
            return 503, {"error": str(exc)}
        return 202, {"id": scan_id, "state": "queued"}


class Handler(BaseHTTPRequestHandler):
    server_version = "AdLeak"
    sys_version = ""
    app: App  # set on the subclass created by make_server

    # -- plumbing ------------------------------------------------------------
    def log_message(self, fmt, *args):
        log.info("%s %s", self.address_string(), fmt % args)

    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def _host_ok(self) -> bool:
        return (self.headers.get("Host") or "").lower() in self.app.allowed_hosts()

    def _same_origin_write(self) -> bool:
        origin = self.headers.get("Origin")
        if origin is not None and origin not in self.app.allowed_origins():
            return False
        site = self.headers.get("Sec-Fetch-Site")
        if site is not None and site not in ("same-origin", "none"):
            return False
        return True

    def _read_json(self):
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            raise ValueError("Content-Type must be application/json.")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ValueError("Invalid Content-Length.")
        if length <= 0 or length > MAX_BODY:
            raise ValueError("The request body is empty or too large.")
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("The request body is not valid JSON.")

    # -- verbs ---------------------------------------------------------------
    def do_GET(self):
        if not self._host_ok():
            return self._error(421, "Unexpected Host header. Open AdLeak at http://127.0.0.1:%d/" % self.app.port)
        path = urlsplit(self.path).path
        if path in STATIC_FILES:
            return self._static(STATIC_FILES[path])
        if path == "/api/health":
            return self._json(200, {"ok": True, "version": __version__})
        if path == "/api/usage":
            usage = self.app.fair_use.status()
            usage.update(queued_or_running=self.app.queue.pending(), max_concurrent=self.app.settings.max_concurrent_scans,
                         max_links=self.app.limits.max_links)
            return self._json(200, usage)
        if path == "/api/scans":
            return self._json(200, {"scans": self.app.store.list()})
        m = _SCAN_ROUTE.match(path)
        if m:
            record = self.app.store.load(m.group(1))
            return self._json(200, record) if record else self._error(404, "Report not found.")
        m = _SCREENSHOT_ROUTE.match(path)
        if m:
            file = self.app.store.screenshot_path(m.group(1), m.group(2))
            if not file:
                return self._error(404, "Screenshot not found.")
            return self._send(200, file.read_bytes(), "image/png", {"Content-Disposition": "inline"})
        return self._error(404, "Not found.")

    do_HEAD = do_GET

    def do_POST(self):
        if not self._host_ok():
            return self._error(421, "Unexpected Host header.")
        if not self._same_origin_write():
            return self._error(403, "Cross-site requests are not allowed.")
        if urlsplit(self.path).path != "/api/scans":
            return self._error(404, "Not found.")
        try:
            body = self._read_json()
        except ValueError as exc:
            return self._error(400, str(exc))
        status, payload = self.app.create_scan(body)
        self._json(status, payload)

    def do_DELETE(self):
        if not self._host_ok():
            return self._error(421, "Unexpected Host header.")
        if not self._same_origin_write():
            return self._error(403, "Cross-site requests are not allowed.")
        m = _SCAN_ROUTE.match(urlsplit(self.path).path)
        if not m:
            return self._error(404, "Not found.")
        record = self.app.store.load(m.group(1))
        if record and record.get("state") in ("queued", "scanning"):
            return self._error(409, "This scan is still running. Delete it after it finishes.")
        if not self.app.store.delete(m.group(1)):
            return self._error(404, "Report not found.")
        self._json(200, {"deleted": True})

    def _static(self, name: str) -> None:
        file = WEB_DIR / name
        if not file.is_file():
            return self._error(404, "Not found.")
        ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
            ctype += "; charset=utf-8"
        self._send(200, file.read_bytes(), ctype)


def make_server(app: App, host: str = "127.0.0.1") -> ThreadingHTTPServer:
    if not ipaddress.ip_address(host).is_loopback:
        raise SystemExit("AdLeak Detector only runs on 127.0.0.1 during the local beta. Public hosting needs isolated workers first.")
    handler = type("BoundHandler", (Handler,), {"app": app})
    server = ThreadingHTTPServer((host, app.settings.port), handler)
    server.daemon_threads = True
    app.port = server.server_address[1]
    return server
