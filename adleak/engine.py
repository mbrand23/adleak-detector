"""Scan orchestration: drives Chromium through the egress proxy and runs every check.

One scan = one proxy + one browser. The page is loaded on a desktop and a
mobile profile in separate, throwaway browser contexts. The scanner reads the
page and its network traffic; it never clicks, types, submits forms, accepts
cookie banners or follows popups.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeout
from playwright.sync_api import sync_playwright

from . import __version__, campaign, pagechecks, tracking
from .config import ScanLimits
from .findings import FAILED, HIGH, INCONCLUSIVE, INFO, LOW, MEDIUM, PASSED, WARNING, Finding, summarise
from .links import check_links
from .proxy import EgressProxy
from .security import EgressPolicy, validate_url

PROBE_JS = (Path(__file__).parent / "probe.js").read_text(encoding="utf-8")
UA_TOKEN = f"AdLeakDetector/{__version__}"

DEVICES = {
    "desktop": {
        "viewport": {"width": 1366, "height": 900}, "device_scale_factor": 1, "is_mobile": False, "has_touch": False,
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36 " + UA_TOKEN,
        "label": "Desktop (1366x900)",
    },
    "mobile": {
        "viewport": {"width": 390, "height": 844}, "device_scale_factor": 2, "is_mobile": True, "has_touch": True,
        "ua": "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Mobile Safari/537.36 " + UA_TOKEN,
        "label": "Mobile (390x844, touch)",
    },
}

LIMITATIONS = [
    "Only what a browser can observe from outside is checked. AdLeak cannot see your ad accounts, server-side tracking or analytics settings.",
    "Nothing on the page is clicked or submitted, so problems that appear only after an interaction (checkout steps, form errors) are not tested.",
    "Tracking beacons are recorded and then blocked inside the scanner so your analytics are not affected; delivery to Meta/Google is not confirmed.",
    "Timings are single measurements from this computer's internet connection, without throttling.",
    "Sites with bot protection may show the scanner a challenge page; those results are marked inconclusive.",
]

RETRYABLE = {"timeout", "connection", "server_error"}


class ScanAborted(Exception):
    pass


def _net_error_kind(message: str) -> str:
    m = message.upper()
    if "ERR_NAME_NOT_RESOLVED" in m or "ERR_NAME_RESOLUTION_FAILED" in m:
        return "dns"
    if "ERR_CERT" in m or "ERR_SSL" in m or "SSL_PROTOCOL" in m:
        return "tls"
    if "ERR_TOO_MANY_REDIRECTS" in m:
        return "redirect_loop"
    if "ERR_TIMED_OUT" in m or "TIMEOUT" in m:
        return "timeout"
    if "ERR_TUNNEL_CONNECTION_FAILED" in m:
        return "tunnel"
    if "ERR_ABORTED" in m:
        return "aborted"
    if "ERR_BLOCKED_BY_CLIENT" in m:
        return "blocked_by_policy"
    return "connection"


class Scanner:
    def __init__(self, policy: EgressPolicy | None = None, limits: ScanLimits | None = None,
                 screenshot_root: Path | None = None, headless: bool = True,
                 context_hook: Callable | None = None):
        self.policy = policy or EgressPolicy()
        self.limits = limits or ScanLimits()
        self.screenshot_root = Path(screenshot_root) if screenshot_root else None
        self.headless = headless
        # Test-only: lets the test suite serve stand-in tag scripts for HSTS-preloaded
        # hosts (e.g. connect.facebook.net) that a plain-HTTP fixture can't serve.
        self.context_hook = context_hook

    # ------------------------------------------------------------------ public
    def scan(self, url: str, scan_id: str, options: dict | None = None,
             progress: Callable[[str], None] | None = None) -> dict:
        options = options or {}
        say = progress or (lambda _msg: None)
        started = time.monotonic()
        deadline = started + self.limits.scan_deadline_s
        target = validate_url(url, self.policy)
        expected = options.get("expected_tags") or {}
        capture = options.get("screenshots", True) and self.screenshot_root is not None
        shot_dir = (self.screenshot_root / scan_id) if capture else None
        if shot_dir:
            shot_dir.mkdir(parents=True, exist_ok=True)

        findings: list[Finding] = []
        devices: list[dict] = []
        report = {
            "submitted_url": target.url, "final_url": None, "devices": devices, "redirect_chain": [],
            "platforms": [], "findings": [], "limitations": LIMITATIONS, "engine_version": __version__,
        }

        with EgressProxy(self.policy, max_bytes=self.limits.max_bytes) as proxy:
            say("Starting an isolated Chromium browser (all traffic goes through the safety proxy)")
            with sync_playwright() as pw:
                browser, browser_name = self._launch(pw, proxy)
                report["browser"] = browser_name
                major = (browser.version or "120").split(".")[0]
                try:
                    desktop = self._run_device(browser, "desktop", target.url, major, proxy, deadline, shot_dir, say)
                    devices.append(desktop["summary"])
                    report["final_url"] = desktop.get("final_url") or target.url
                    report["redirect_chain"] = desktop.get("chain", [])
                    findings += self._access_findings(desktop)
                    if desktop["usable"]:
                        report["platforms"] = desktop["probe"].get("platforms", [])
                        findings += self._page_findings(desktop, "desktop")
                        findings += campaign.analyse(target.url, desktop["chain"], desktop["final_url"], desktop.get("client_redirect"))
                        say("Checking tracking signals observed during page load")
                        findings += tracking.build_findings(
                            desktop["signals"], desktop["failed_scripts"], desktop["probe"]["globals"], expected, desktop["probe"].get("consent"))
                        findings += self._link_findings(desktop, proxy, deadline, say)
                    else:
                        findings.append(Finding(
                            "access", "Other checks were not run", INCONCLUSIVE, INFO,
                            "Links, sales actions, tracking and layout can only be checked once the page loads, so they were skipped.",
                            "Fix the loading problem above (or try again later) and rescan.", check="skipped"))

                    if desktop["usable"] or desktop["outcome"] in RETRYABLE:
                        if time.monotonic() > deadline - 25:
                            findings.append(Finding(
                                "mobile", "Mobile test skipped (scan time limit)", INCONCLUSIVE, INFO,
                                f"The scan reached its {self.limits.scan_deadline_s}s limit before the mobile pass could run.",
                                "Rescan; if it keeps happening the page is very slow to load.", check="mobile_skipped"))
                        else:
                            mobile = self._run_device(browser, "mobile", target.url, major, proxy, deadline, shot_dir, say)
                            devices.append(mobile["summary"])
                            if mobile["usable"]:
                                findings += self._page_findings(mobile, "mobile")
                                findings += self._compare_devices(desktop, mobile)
                            elif desktop["usable"]:
                                findings += [f for f in self._access_findings(mobile) if f.status != PASSED]
                finally:
                    browser.close()

            say("Writing report")
            findings += self._proxy_findings(proxy)
            report["network"] = {
                "bytes_transferred": proxy.bytes_transferred,
                "blocked_requests": proxy.blocked[:50],
                "budget_exceeded": proxy.budget_exceeded,
            }

        ordered = sorted(_merge_devices(f.to_dict() for f in findings), key=_sort_key)
        report["findings"] = ordered
        report["summary"] = summarise(ordered)
        report["duration_s"] = round(time.monotonic() - started, 1)
        first = devices[0] if devices else {}
        report["outcome"] = "inconclusive" if first.get("outcome") in ("timeout", "challenge", "blocked_by_policy", "connection") and not first.get("usable") else "completed"
        return report

    # ---------------------------------------------------------------- browser
    def _launch(self, pw, proxy: EgressProxy):
        args = [
            f"--proxy-server={proxy.url}",
            "--proxy-bypass-list=<-loopback>",   # send even loopback traffic through the proxy, where it is refused
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            "--webrtc-ip-handling-policy=disable_non_proxied_udp",
            "--disable-background-networking",
            "--disable-component-update",
            "--dns-prefetch-disable",
            "--no-first-run",
        ]
        errors = []
        for channel in (None, "msedge", "chrome"):
            try:
                kwargs = {"headless": self.headless, "args": args}
                if channel:
                    kwargs["channel"] = channel
                browser = pw.chromium.launch(**kwargs)
                return browser, f"{channel or 'chromium'} {browser.version}"
            except PlaywrightError as exc:
                errors.append(f"{channel or 'bundled chromium'}: {str(exc).splitlines()[0]}")
        raise RuntimeError("Could not start a browser. Run 'python -m playwright install chromium'. " + " | ".join(errors))

    def _run_device(self, browser, device, url, major, proxy, deadline, shot_dir, say) -> dict:
        profile = DEVICES[device]
        attempts = []
        result = None
        for attempt in (1, 2):
            say(f"Loading the page on {profile['label']}" + (" (retry to confirm the failure)" if attempt == 2 else ""))
            result = self._attempt(browser, device, url, major, proxy, deadline, shot_dir, say)
            attempts.append({"attempt": attempt, "outcome": result["outcome"], "status": result.get("status"), "detail": result.get("detail", "")})
            if result["outcome"] not in RETRYABLE or not self.limits.retry_failed_navigation:
                break
            if time.monotonic() > deadline - 40:
                break
            time.sleep(2)
        result["attempts"] = attempts
        result["summary"] = {
            "device": device, "label": profile["label"], "viewport": profile["viewport"],
            "user_agent": profile["ua"].format(major=major), "outcome": result["outcome"], "status": result.get("status"),
            "final_url": result.get("final_url"), "usable": result["usable"], "attempts": attempts,
            "timing": (result.get("probe") or {}).get("timing"), "screenshots": result.get("screenshots", []),
            "load_event": result.get("load_event", None),
        }
        if result["usable"]:
            say(f"{device.capitalize()} page loaded: HTTP {result.get('status')} at {result.get('final_url')}")
        else:
            say(f"{device.capitalize()} page could not be assessed: {result['outcome']} {result.get('detail', '')}".strip())
        return result

    def _attempt(self, browser, device, url, major, proxy, deadline, shot_dir, say) -> dict:
        profile = DEVICES[device]
        ctx = browser.new_context(
            viewport=profile["viewport"], device_scale_factor=profile["device_scale_factor"],
            is_mobile=profile["is_mobile"], has_touch=profile["has_touch"],
            user_agent=profile["ua"].format(major=major), service_workers="block",
            accept_downloads=False, locale="en-US", ignore_https_errors=False,
        )
        if self.context_hook:
            self.context_hook(ctx)
        out = {"device": device, "outcome": "", "usable": False, "signals": [], "failed_scripts": [],
               "failed_resources": [], "error_responses": [], "page_errors": [], "chain": [], "screenshots": []}
        aborted: set[str] = set()

        def on_beacon(route):
            req = route.request
            sig = tracking.classify(req.url, req.post_data)
            if sig:
                out["signals"].append(sig)
            aborted.add(req.url)
            route.abort("blockedbyclient")

        def on_request(req):
            sig = tracking.classify(req.url)
            if sig and sig["kind"] == "script" and len(out["signals"]) < 500:
                out["signals"].append(sig)

        def on_failed(req):
            if req.url in aborted or req.url.startswith("data:"):
                return
            error = req.failure or "failed"
            kind = _net_error_kind(error)
            if kind == "aborted":
                return
            if kind == "tunnel":
                info = proxy.failure_for(urlsplit(req.url).hostname or "")
                kind, error = (info["kind"], info["detail"]) if info else ("connection", error)
            item = {"url": req.url, "type": req.resource_type, "error": error, "kind": kind}
            if len(out["failed_resources"]) < 300:
                out["failed_resources"].append(item)
            sig = tracking.classify(req.url)
            if sig and sig["kind"] == "script":
                out["failed_scripts"].append(item)

        def on_response(resp):
            if resp.status < 400 or len(out["error_responses"]) >= 300:
                return
            headers = resp.headers
            if headers.get("x-adleak-proxy"):
                kind = "blocked_by_policy" if resp.status == 403 else ("dns" if "DNS" in (resp.status_text or "") else "connection")
                out["failed_resources"].append({"url": resp.url, "type": resp.request.resource_type, "error": resp.status_text, "kind": kind})
                return
            out["error_responses"].append({"url": resp.url, "status": resp.status, "type": resp.request.resource_type})
            sig = tracking.classify(resp.url)
            if sig and sig["kind"] == "script":
                out["failed_scripts"].append({"url": resp.url, "error": f"HTTP {resp.status}"})

        def on_page_error(exc):
            if len(out["page_errors"]) < 20:
                out["page_errors"].append(str(exc)[:300])

        try:
            page = ctx.new_page()
            ctx.on("page", lambda p: p.close() if p != page else None)
            page.on("dialog", lambda d: d.dismiss())
            page.on("request", on_request)
            page.on("requestfailed", on_failed)
            page.on("response", on_response)
            page.on("pageerror", on_page_error)
            page.route(tracking.is_tracking_beacon, on_beacon)
            page.set_default_timeout(15_000)

            started = time.monotonic()
            remaining_ms = max(5_000, int((deadline - started) * 1000) - 20_000)
            try:
                resp = page.goto(url, wait_until="domcontentloaded", timeout=min(self.limits.navigation_timeout_ms, remaining_ms))
            except PlaywrightTimeout:
                out.update(outcome="timeout", detail=f"No usable response within {self.limits.navigation_timeout_ms // 1000}s")
                return out
            except PlaywrightError as exc:
                message = str(exc).splitlines()[0]
                kind = _net_error_kind(message)
                if kind == "tunnel":
                    info = proxy.failure_for(urlsplit(url).hostname or "") or proxy.failure_for(_last_blocked_host(proxy))
                    kind, message = (info["kind"], info["detail"]) if info else ("connection", message)
                if kind == "aborted":
                    kind, message = "connection", "Navigation was aborted (the address may trigger a file download)"
                out.update(outcome=kind, detail=message)
                return out
            if resp is None:
                out.update(outcome="connection", detail="The browser received no response")
                return out

            out["chain"] = _redirect_chain(resp)
            out["status"] = resp.status
            out["headers"] = resp.headers
            out["final_url"] = resp.url
            out["response_ms"] = round((time.monotonic() - started) * 1000)
            if resp.headers.get("x-adleak-proxy"):
                host = urlsplit(resp.url).hostname or ""
                info = proxy.failure_for(host) or {"kind": "blocked_by_policy" if resp.status == 403 else "connection", "detail": resp.status_text}
                out.update(outcome=info["kind"], detail=f"{info['detail']} ({host})")
                return out

            try:
                page.wait_for_load_state("load", timeout=self.limits.load_wait_ms)
                out["load_event"] = True
            except PlaywrightTimeout:
                out["load_event"] = False
            try:
                page.wait_for_load_state("networkidle", timeout=self.limits.settle_ms)
            except PlaywrightTimeout:
                pass
            page.wait_for_timeout(1_500)

            current = page.url
            if _strip_fragment(current) != _strip_fragment(resp.url):
                out["client_redirect"] = current
                out["final_url"] = current
                try:
                    page.wait_for_load_state("load", timeout=5_000)
                except PlaywrightTimeout:
                    pass

            say(f"Inspecting the {device} page: sales actions, links, images and layout")
            try:
                probe = page.evaluate(PROBE_JS)
            except PlaywrightError as exc:
                out.update(outcome="probe_failed", detail=f"Could not inspect the page: {str(exc).splitlines()[0]}")
                return out
            out["probe"] = probe

            challenge = pagechecks.detect_challenge(resp.status, probe.get("title", ""), probe.get("text_sample", ""), resp.headers)
            if challenge:
                out.update(outcome="challenge", detail=challenge)
            elif resp.status >= 500:
                out.update(outcome="server_error", detail=f"HTTP {resp.status}")
            elif resp.status >= 400:
                out.update(outcome="http_error", detail=f"HTTP {resp.status}")
            else:
                out.update(outcome="ok", usable=True)

            if shot_dir is not None:
                out["screenshots"] = self._screenshots(page, device, shot_dir, probe)
            return out
        finally:
            try:
                ctx.close()
            except PlaywrightError:
                pass

    def _screenshots(self, page, device, shot_dir: Path, probe: dict) -> list[dict]:
        shots = []
        try:
            page.screenshot(path=str(shot_dir / f"{device}.png"), timeout=15_000, animations="disabled", scale="css")
            shots.append({"name": f"{device}.png", "label": f"{device.capitalize()} - first screen"})
            height = min(int(probe.get("scroll_height") or 0), self.limits.screenshot_max_height)
            if height > probe["viewport"][1] + 50:
                page.screenshot(path=str(shot_dir / f"{device}-full.png"), full_page=True, timeout=20_000, animations="disabled",
                                scale="css", clip={"x": 0, "y": 0, "width": probe["viewport"][0], "height": height})
                cropped = " (cropped)" if probe["scroll_height"] > height else ""
                shots.append({"name": f"{device}-full.png", "label": f"{device.capitalize()} - full page{cropped}"})
        except PlaywrightError:
            pass
        return shots

    # --------------------------------------------------------------- findings
    def _access_findings(self, r: dict) -> list[Finding]:
        device = r["device"]
        tries = r.get("attempts", [])
        tries_text = [f"Attempt {a['attempt']}: {a['outcome']} {a['status'] or ''} {a['detail']}".strip() for a in tries]
        chain = [f"{h['status']} {h['url']}" for h in r.get("chain", [])]
        outcome = r["outcome"]
        f = None
        if outcome == "ok":
            evidence = [f"Final URL: {r['final_url']}", f"HTTP {r['status']}", f"First response + DOM ready in {r.get('response_ms')} ms"] + chain
            f = Finding("access", f"Page loaded (HTTP {r['status']})", PASSED, INFO,
                        f"The page responded and rendered on {device}.", evidence=evidence, device=device, check="reachability")
            out = [f]
            if len(tries) > 1:
                out.append(Finding("access", "Page failed once, then loaded", WARNING, MEDIUM,
                                   "The first attempt failed and the retry worked. Intermittent failures lose ad clicks at random.",
                                   "Check hosting uptime and server error logs.", tries_text, device=device, check="intermittent"))
            if r.get("load_event") is False:
                out.append(Finding("access", "Page kept loading for over 10 seconds", WARNING, LOW,
                                   "The browser's load event did not fire within 10s of the page appearing. Something on the page (often a large "
                                   "image, video or slow third-party script) keeps it loading.",
                                   "Check the slowest requests in your browser's Network tab.", device=device, check="load_event"))
            return out
        if outcome == "http_error":
            f = Finding("access", f"Page returned an error (HTTP {r['status']})", FAILED, HIGH,
                        "The server answered with an error instead of the page. Every ad click to this address lands on an error page.",
                        "Check the URL in your ads, restore the page, or redirect it to a working page.", tries_text + chain, device, "reachability")
        elif outcome == "server_error":
            f = Finding("access", f"Server error (HTTP {r['status']}) on every attempt", FAILED, HIGH,
                        "The website's server failed to produce the page, and still failed when AdLeak retried.",
                        "Check your hosting status and error logs, or contact your host.", tries_text + chain, device, "reachability")
        elif outcome == "dns":
            f = Finding("access", "Domain does not resolve", FAILED, HIGH,
                        "The domain name could not be looked up, so no visitor can reach the site.",
                        "Check the domain's registration and DNS records with your registrar.", tries_text, device, "reachability")
        elif outcome == "tls":
            f = Finding("access", "SSL/TLS certificate problem", FAILED, HIGH,
                        "The browser refused the secure connection (expired, mismatched or untrusted certificate). Visitors see a full-page security warning.",
                        "Renew or reinstall the SSL certificate for this exact domain.", tries_text, device, "reachability")
        elif outcome == "redirect_loop":
            f = Finding("access", "Redirect loop", FAILED, HIGH,
                        "The address keeps redirecting and never reaches a page.",
                        "Check redirect rules (for example HTTP/HTTPS or www/non-www rules that send visitors back and forth).", tries_text, device, "reachability")
        elif outcome == "timeout":
            f = Finding("access", "Page did not load in time", INCONCLUSIVE, HIGH,
                        f"No usable page arrived within {self.limits.navigation_timeout_ms // 1000}s on any attempt. The site may be very slow or "
                        "down, or the connection from this computer may be the problem, so this is not treated as proof the site is broken.",
                        "Open the page yourself; if it's slow for you too, look at hosting performance.", tries_text, device, "reachability")
        elif outcome == "challenge":
            f = Finding("access", "The site blocked the automated browser", INCONCLUSIVE, MEDIUM,
                        "The page served a bot-protection or CAPTCHA challenge instead of its content. AdLeak does not try to get around "
                        "these, so the page itself wasn't checked. Real visitors may see the page normally.",
                        "If this is your site, you can allow the AdLeakDetector user agent in your firewall/bot-protection settings and rescan.",
                        tries_text + [r.get("detail", "")], device, "reachability")
        elif outcome == "blocked_by_policy":
            f = Finding("safety", "Scanner refused to follow the site to a restricted address", INCONCLUSIVE, HIGH,
                        "Loading this page required contacting a private, internal or otherwise restricted address, which the scanner never does. "
                        "Public visitors usually can't reach such addresses either.",
                        "Check redirects and DNS for this domain.", tries_text, device, "reachability")
        else:
            f = Finding("access", "Page could not be loaded", FAILED if outcome == "connection" else INCONCLUSIVE, HIGH,
                        "The browser could not get the page after retrying (connection refused, reset or closed).",
                        "Check that the web server is running and reachable from the internet.", tries_text, device, "reachability")
        return [f]

    def _page_findings(self, r: dict, device: str) -> list[Finding]:
        probe = r["probe"]
        out = pagechecks.sales_findings(probe, device)
        out += pagechecks.layout_findings(probe, device)
        failed_images = [x for x in r["failed_resources"] if x["type"] == "image"]
        out += pagechecks.image_findings(probe, failed_images, device)
        out += self._resource_findings(r, device)
        out += self._timing_findings(probe, device)
        if r["page_errors"]:
            out.append(Finding("resources", "JavaScript errors on the page", WARNING, LOW,
                               "Uncaught script errors happened while the page loaded. They can stop buttons, forms or tracking tags from working.",
                               "Open the browser console on this page to find the failing script.", r["page_errors"][:8], device, "js_errors"))
        return out

    def _resource_findings(self, r: dict, device: str) -> list[Finding]:
        out = []
        important = ("script", "stylesheet")
        failed = [x for x in r["failed_resources"] if x["kind"] not in ("blocked_by_policy",)]
        errors = r["error_responses"]
        crit = [f"{x['url']} -> {x['error']}" for x in failed if x["type"] in important] + \
               [f"{x['url']} -> HTTP {x['status']}" for x in errors if x["type"] in important]
        minor = [f"{x['url']} -> {x['error']}" for x in failed if x["type"] in ("image", "font", "media")] + \
                [f"{x['url']} -> HTTP {x['status']}" for x in errors if x["type"] in ("image", "font", "media")]
        if crit:
            out.append(Finding("resources", f"{len(crit)} script/stylesheet request{'s' if len(crit) != 1 else ''} failed", FAILED, MEDIUM,
                               "Scripts or stylesheets the page asked for failed to load. Missing scripts can break buttons, carts and tracking; "
                               "missing stylesheets break the layout.",
                               "Fix or remove the references. If a file belongs to a plugin or app, update or reinstall it.", _dedupe(crit)[:15], device, "failed_resources"))
        if minor:
            out.append(Finding("resources", f"{len(minor)} image/font/media request{'s' if len(minor) != 1 else ''} failed", WARNING, LOW,
                               "Some images, fonts or media files the page requested failed to load.",
                               "Fix the file paths or re-upload the files.", _dedupe(minor)[:15], device, "failed_resources"))
        if not crit and not minor and r["outcome"] == "ok":
            out.append(Finding("resources", "Page resources loaded", PASSED, INFO,
                               "No script, stylesheet, image, font or media request failed during the page load.", device=device, check="failed_resources"))
        return out

    def _timing_findings(self, probe: dict, device: str) -> list[Finding]:
        t = probe.get("timing") or {}
        if not t.get("dom_content_loaded_ms"):
            return []
        evidence = [f"Time to first byte: {t['ttfb_ms']} ms", f"DOM ready: {t['dom_content_loaded_ms']} ms",
                    f"Load event: {t['load_ms'] or 'not reached'} ms"]
        load = t.get("load_ms") or 0
        if load > 10_000 or t["dom_content_loaded_ms"] > 6_000:
            return [Finding("access", "Slow page load", WARNING, MEDIUM,
                            "The page took a long time to load in this test. Slow landing pages lose visitors who clicked an ad, "
                            "especially on mobile data. This is one measurement from this computer, without throttling.",
                            "Compress images, remove unused apps/plugins and defer non-essential scripts.", evidence, device, "speed")]
        return [Finding("access", "Load time measured", PASSED, INFO,
                        "Single measurement from this computer's connection, without network throttling.", evidence=evidence, device=device, check="speed")]

    def _link_findings(self, desktop: dict, proxy: EgressProxy, deadline: float, say) -> list[Finding]:
        probe = desktop["probe"]
        out, urls = pagechecks.link_inventory(probe, desktop["final_url"])
        cta_urls = {a["abs_href"].split("#")[0] for a in probe.get("actions", []) if a.get("abs_href", "") and a["abs_href"].startswith("http")}
        page_host = urlsplit(desktop["final_url"]).hostname
        # Sales destinations first, then same-site links, then external links.
        urls.sort(key=lambda u: (u not in cta_urls, urlsplit(u).hostname != page_host))
        selected = urls[: self.limits.max_links]
        if not selected:
            return out
        say(f"Testing {len(selected)} of {len(urls)} links (limit {self.limits.max_links} per scan)")
        results = check_links(proxy.url, selected, self.limits.link_timeout_s, self.limits.max_link_redirects,
                              self.limits.link_workers, deadline - 15)
        return out + pagechecks.link_result_findings(results, len(urls), self.limits.max_links, cta_urls)

    def _compare_devices(self, desktop: dict, mobile: dict) -> list[Finding]:
        d_visible = {(a["kind"], a["text"]) for a in desktop["probe"]["actions"] if a["visible"] and a["kind"] in ("buy", "add_to_cart", "checkout", "whatsapp", "call")}
        m_visible = {(a["kind"], a["text"]) for a in mobile["probe"]["actions"] if a["visible"]}
        missing = sorted(d_visible - m_visible)
        if not missing:
            return []
        return [Finding("mobile", "Sales action visible on desktop but not on mobile", WARNING, HIGH,
                        "These sales actions are visible on desktop but hidden or missing on mobile, where most ad traffic arrives.",
                        "Check your theme's mobile settings and any CSS that hides these elements on small screens.",
                        [f"'{text}' [{kind}]" for kind, text in missing[:10]], "mobile", "mobile_cta")]

    def _proxy_findings(self, proxy: EgressProxy) -> list[Finding]:
        out = []
        if proxy.blocked:
            out.append(Finding("safety", "Requests to private or internal addresses were blocked", WARNING, MEDIUM,
                               "The page tried to load something from localhost, a private network or another restricted address. AdLeak blocked it. "
                               "Real visitors can't load these either; they're usually leftovers from a development or staging site.",
                               "Replace these references with public URLs.",
                               _dedupe([f"{b['target']} ({b['reason']})" for b in proxy.blocked])[:12], check="egress_blocked"))
        if proxy.budget_exceeded:
            out.append(Finding("safety", "Scan data limit reached", INCONCLUSIVE, LOW,
                               f"The page transferred more than {self.limits.max_bytes // (1024 * 1024)} MB, so the scanner stopped loading more. "
                               "Later results may be incomplete. A landing page this heavy is slow on mobile data.",
                               "Reduce page weight (video, images, scripts).", check="byte_budget"))
        return out


def _redirect_chain(resp) -> list[dict]:
    chain = []
    req = resp.request
    while req is not None:
        chain.append(req)
        req = req.redirected_from
    chain.reverse()
    out = []
    for req in chain:
        r = resp if req is resp.request else req.response()
        out.append({"url": req.url, "status": r.status if r else None})
    return out


def _strip_fragment(url: str) -> str:
    return url.split("#", 1)[0]


def _last_blocked_host(proxy: EgressProxy) -> str:
    return proxy.blocked[-1]["host"] if proxy.blocked else ""


def _dedupe(items: list[str]) -> list[str]:
    seen, out = set(), []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _merge_devices(findings) -> list[dict]:
    """Collapse a finding reported identically on desktop and mobile into one entry."""
    merged: list[dict] = []
    index: dict[tuple, dict] = {}
    for f in findings:
        key = (f["check"], f["title"], f["status"], tuple(f["evidence"]))
        if f["device"] in ("desktop", "mobile") and key in index:
            index[key]["device"] = "desktop + mobile"
            continue
        index[key] = f
        merged.append(f)
    return merged


def _sort_key(f: dict):
    status_rank = {FAILED: 0, WARNING: 1, INCONCLUSIVE: 2, PASSED: 3}
    severity_rank = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}
    return (status_rank.get(f["status"], 9), severity_rank.get(f["severity"], 9))
