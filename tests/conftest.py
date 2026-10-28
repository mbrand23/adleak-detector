"""Shared fixtures: a controlled local website, and a scanner allowed to reach it.

The scanner's normal policy refuses 127.0.0.1. Tests build an EgressPolicy
that allows exactly the fixture server's (ip, port) and maps the Meta/Google
tag hostnames to it, so tracking detection can be tested without contacting
Meta or Google. Production code never sets these test-only fields.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(ROOT / ".browsers"))

from adleak.config import ScanLimits  # noqa: E402
from adleak.engine import Scanner  # noqa: E402
from adleak.security import EgressPolicy  # noqa: E402

SITE = Path(__file__).parent / "fixtures" / "site"
TAG_HOSTS = ("connect.facebook.net", "www.facebook.com", "www.googletagmanager.com", "region1.google-analytics.com")


class FixtureHandler(SimpleHTTPRequestHandler):
    stop_event: threading.Event
    hits: dict

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(SITE), **kwargs)

    def log_message(self, *args):
        pass

    def _redirect(self, status, location):
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _status(self, code):
        body = f"<html><body><h1>Error {code}</h1></body></html>".encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parts = urlsplit(self.path)
        path, query = parts.path, parts.query
        type(self).hits[path] = type(self).hits.get(path, 0) + 1
        if path == "/redirect/keep":
            return self._redirect(301, "/good.html" + (f"?{query}" if query else ""))
        if path == "/redirect/drop":
            return self._redirect(302, "/good.html")
        if path == "/redirect/two":
            return self._redirect(301, "/redirect/keep" + (f"?{query}" if query else ""))
        if path == "/redirect/private":
            return self._redirect(302, "http://10.255.255.1/admin")
        if path == "/redirect/loop":
            return self._redirect(302, "/redirect/loop")
        if path.startswith("/status/"):
            return self._status(int(path.rsplit("/", 1)[1]))
        if path == "/flaky":
            if type(self).hits[path] == 1:
                return self._status(503)
            return self._serve_file("good.html")
        if path == "/slow":
            self.stop_event.wait(15)
            return self._status(200)
        if path == "/checkout":
            return self._serve_text("<html><body><h1>Checkout</h1></body></html>")
        # Tag stand-ins (served when the proxy maps tag hostnames here)
        if path == "/en_US/fbevents.js":
            return self._serve_file("stub-fbevents.js", "application/javascript")
        if path == "/gtm.js":
            return self._serve_file("stub-gtm.js", "application/javascript")
        if path == "/gtag/js":
            return self._serve_file("stub-gtag.js", "application/javascript")
        return super().do_GET()

    def _serve_text(self, text, ctype="text/html"):
        body = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _serve_file(self, name, ctype="text/html"):
        return self._serve_text((SITE / name).read_text(encoding="utf-8"), ctype)


@pytest.fixture(scope="session")
def fixture_site():
    stop = threading.Event()
    handler = type("H", (FixtureHandler,), {"stop_event": stop, "hits": {}})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    yield {"base": f"http://127.0.0.1:{port}", "port": port, "hits": handler.hits}
    stop.set()
    server.shutdown()


@pytest.fixture(scope="session")
def test_policy(fixture_site):
    port = fixture_site["port"]
    return EgressPolicy(
        test_allow=frozenset({("127.0.0.1", port)}),
        test_resolve={host: ("127.0.0.1", port) for host in TAG_HOSTS},
    )


@pytest.fixture(scope="session")
def fast_limits():
    return ScanLimits(navigation_timeout_ms=6_000, load_wait_ms=4_000, settle_ms=1_500, scan_deadline_s=90,
                      max_links=15, link_timeout_s=4, link_workers=4)


def serve_tag_stubs(ctx):
    """Chromium forces HTTPS for HSTS-preloaded hosts such as connect.facebook.net,
    which the plain-HTTP fixture server can't answer, so the Meta stand-in script
    is fulfilled inside the browser instead. Beacons to www.facebook.com/tr are
    still observed and blocked by the scanner's own route."""
    stub = (SITE / "stub-fbevents.js").read_text(encoding="utf-8")
    ctx.route("**://connect.facebook.net/**/fbevents.js",
              lambda route: route.fulfill(status=200, content_type="application/javascript", body=stub))


@pytest.fixture(scope="session")
def scanner(test_policy, fast_limits, tmp_path_factory):
    return Scanner(test_policy, fast_limits, screenshot_root=tmp_path_factory.mktemp("shots"), context_hook=serve_tag_stubs)


def by_check(report, check, device=None):
    return [f for f in report["findings"] if f["check"] == check
            and (device is None or f["device"] == "all" or device in f["device"].split(" + "))]


def titles(report):
    return [f"{f['status']}:{f['title']}" for f in report["findings"]]
