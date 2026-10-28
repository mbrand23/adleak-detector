"""API, local-server hardening, report persistence (plan item 11) and the
front end's handling of unexpected input (plan item 12)."""

import json
import threading
import time
import urllib.error
import urllib.request

import pytest

from adleak.config import Settings
from adleak.plans import Plan
from adleak.server import App, make_server

NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


@pytest.fixture(scope="module")
def app_server(tmp_path_factory, test_policy, fast_limits):
    settings = Settings(port=0, data_dir=tmp_path_factory.mktemp("data"), max_concurrent_scans=1)
    app = App(settings, policy=test_policy, limits=fast_limits)
    server = make_server(app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield app, f"http://127.0.0.1:{app.port}"
    server.shutdown()
    server.server_close()


def call(base, path, method="GET", body=None, headers=None, raw=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    hdrs = {"Content-Type": "application/json"} if data is not None else {}
    hdrs.update(headers or {})
    req = urllib.request.Request(base + path, data=data, method=method, headers=hdrs)
    try:
        with NO_PROXY.open(req, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def wait_done(base, scan_id, timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        _, _, body = call(base, f"/api/scans/{scan_id}")
        record = json.loads(body)
        if record["state"] not in ("queued", "scanning"):
            return record
        time.sleep(1)
    raise AssertionError("scan did not finish")


def test_static_page_and_security_headers(app_server):
    _, base = app_server
    status, headers, body = call(base, "/")
    assert status == 200 and b"AdLeak Detector" in body
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"


def test_host_header_is_checked(app_server):
    _, base = app_server
    status, _, _ = call(base, "/api/health", headers={"Host": "evil.example.com"})
    assert status == 421


@pytest.mark.parametrize("kwargs, expected", [
    ({"body": {"url": "https://a.com"}, "headers": {"Origin": "https://evil.example.com"}}, 403),
    ({"body": {"url": "https://a.com"}, "headers": {"Sec-Fetch-Site": "cross-site"}}, 403),
    ({"raw": b'{"url": "https://a.com"}', "headers": {"Content-Type": "text/plain"}}, 400),
    ({"raw": b"{not json"}, 400),
    ({"raw": b'{"url": "' + b"a" * 9000 + b'"}'}, 400),
    ({"body": ["not", "an", "object"]}, 400),
    ({"body": {"url": "javascript:alert(1)"}}, 400),
    ({"body": {"url": "http://localhost:8765/api/scans"}}, 400),
    ({"body": {"url": "http://169.254.169.254/latest/meta-data/"}}, 400),
    ({"body": {"url": "http://user:pw@example.com/"}}, 400),
    ({"body": {"url": "https://example.com", "expected_tags": "yes"}}, 400),
])
def test_bad_scan_requests_rejected(app_server, kwargs, expected):
    _, base = app_server
    status, _, body = call(base, "/api/scans", method="POST", **kwargs)
    assert status == expected
    assert "error" in json.loads(body)


def test_unknown_and_traversal_paths(app_server):
    _, base = app_server
    for path in ("/api/scans/../../adleak/server.py", "/api/scans/" + "0" * 32, "/../run.py", "/web/app.js",
                 f"/api/scans/{'0' * 32}/screenshots/..%2f..%2frun.py"):
        assert call(base, path)[0] == 404, path


def test_scan_saved_retrieved_listed_and_deleted(app_server, fixture_site):
    _, base = app_server
    status, _, body = call(base, "/api/scans", method="POST",
                           body={"url": fixture_site["base"] + "/notags.html?utm_source=test", "expected_tags": {"meta": True}})
    assert status == 202
    scan_id = json.loads(body)["id"]
    record = wait_done(base, scan_id)
    assert record["state"] == "completed", record.get("error")
    report = record["report"]
    assert report["findings"] and report["summary"]["PASSED"] > 0
    assert any(f["check"] == "meta_pixel" and f["status"] == "WARNING" for f in report["findings"])
    messages = [p["message"] for p in record["progress"]]
    assert messages[0].startswith("Queued") and "Scan finished" in messages[-1]

    shot = report["devices"][0]["screenshots"][0]["name"]
    status, headers, png = call(base, f"/api/scans/{scan_id}/screenshots/{shot}")
    assert status == 200 and headers["Content-Type"] == "image/png" and png[:4] == b"\x89PNG"

    _, _, body = call(base, "/api/scans")
    assert any(s["id"] == scan_id for s in json.loads(body)["scans"])

    assert call(base, f"/api/scans/{scan_id}", method="DELETE", headers={"Origin": "https://evil.example.com"})[0] == 403
    assert call(base, f"/api/scans/{scan_id}", method="DELETE")[0] == 200
    assert call(base, f"/api/scans/{scan_id}")[0] == 404
    assert call(base, f"/api/scans/{scan_id}/screenshots/{shot}")[0] == 404


def test_fair_use_limit_returns_429(app_server):
    app, base = app_server
    original = app.fair_use.plan
    app.fair_use.plan = Plan("t", "Test", scans_per_hour=0, scans_per_day=0, max_links=1)
    try:
        status, _, body = call(base, "/api/scans", method="POST", body={"url": "https://example.com/"})
        assert status == 429 and "Fair-use limit" in json.loads(body)["error"]
    finally:
        app.fair_use.plan = original


def test_refuses_non_loopback_bind(tmp_path):
    app = App(Settings(port=0, data_dir=tmp_path))
    with pytest.raises(SystemExit):
        make_server(app, host="0.0.0.0")


@pytest.mark.browser
def test_frontend_handles_unexpected_input(app_server, fixture_site):
    from playwright.sync_api import sync_playwright

    _, base = app_server
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page()
        dialogs = []
        page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
        page.goto(base + "/#/")
        error = page.locator("#form-error")

        page.click("#scan-button")
        assert error.inner_text() == "Enter a website address to scan."
        page.fill("#url-input", "javascript:alert(1)")
        page.click("#scan-button")
        assert "Only http" in error.inner_text()
        page.fill("#url-input", "http://localhost/admin")
        page.click("#scan-button")
        error.filter(has_text="cannot be scanned").wait_for(timeout=5000)
        page.fill("#url-input", "has spaces .com")
        page.click("#scan-button")
        assert "spaces" in error.inner_text()
        assert "#/scan/" not in page.url

        # A real scan of a page whose link text contains HTML must render it as text.
        page.fill("#url-input", fixture_site["base"] + "/broken.html")
        page.click("#scan-button")
        page.wait_for_url("**/#/scan/*", timeout=10_000)
        page.get_by_role("heading", name="Scan report").wait_for(timeout=120_000)
        page.click("text=All (")
        assert page.locator(".finding").count() > 5
        page.locator("details.evidence").first.wait_for()
        for d in page.locator("details.evidence").all():
            d.evaluate("el => el.open = true")
        assert "onerror" in page.locator("main").inner_text()        # shown as text...
        assert page.evaluate("window.__xss") is None                   # ...never executed
        assert page.locator("main img[src='x']").count() == 0
        assert page.locator(".shots img").count() >= 1

        page.goto(base + "/#/history")
        page.locator(".history-item").first.wait_for()
        page.goto(base + "/#/scan/" + "f" * 32)
        page.get_by_role("heading", name="Report not found").wait_for()
        assert not dialogs
        browser.close()


@pytest.mark.browser
def test_empty_history_state(tmp_path, test_policy, fast_limits):
    from playwright.sync_api import sync_playwright

    app = App(Settings(port=0, data_dir=tmp_path), policy=test_policy, limits=fast_limits)
    server = make_server(app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page()
            page.goto(f"http://127.0.0.1:{app.port}/#/history")
            page.get_by_role("heading", name="No scans yet").wait_for()
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
