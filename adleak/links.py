"""HTTP link checks, routed through the egress proxy.

Links are requested with HEAD (falling back to a small GET) and redirects are
followed manually so every hop is recorded. Results that cannot be trusted
(bot protection, rate limits, timeouts) are labelled inconclusive rather than
broken, and server errors and timeouts are retried once before reporting.
"""

from __future__ import annotations

import socket
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlsplit

USER_AGENT = "Mozilla/5.0 (compatible; AdLeakDetector/0.1; local beta link check)"

PLACEHOLDER_HREFS = ("#", "", "javascript:void(0)", "javascript:void(0);", "javascript:;", "javascript:", "#!", "/#")
PLACEHOLDER_MARKERS = ("example.com", "yourdomain", "your-domain", "yoursite", "{{", "%7b%7b", "undefined", "null", "lorem", "placeholder", "todo")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_opener(proxy_url: str) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}),
        _NoRedirect(),
    )


def placeholder_reason(raw_href: str | None) -> str | None:
    href = (raw_href or "").strip()
    lowered = href.lower()
    if lowered in PLACEHOLDER_HREFS:
        return "empty or '#' link"
    if lowered.startswith("javascript:"):
        return "javascript: link"
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return "placeholder text in the address"
    return None


def _request_once(opener, url: str, method: str, timeout: float) -> tuple[int | None, dict, str]:
    req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    if method == "GET":
        req.add_header("Range", "bytes=0-2047")
    try:
        with opener.open(req, timeout=timeout) as resp:
            if method == "GET":
                resp.read(2048)
            return resp.status, dict(resp.headers), ""
    except urllib.error.HTTPError as exc:
        headers = dict(exc.headers or {})
        exc.close()
        return exc.code, headers, ""
    except urllib.error.URLError as exc:
        return None, {}, str(exc.reason)
    except (socket.timeout, TimeoutError):
        return None, {}, "timed out"
    except (OSError, ValueError) as exc:
        return None, {}, str(exc)


def _classify_error(error: str) -> str:
    text = error.lower()
    if "blocked by adleak" in text or "403 blocked" in text:
        return "blocked_by_policy"
    if "dns" in text or "getaddrinfo" in text or "name or service" in text:
        return "dns"
    if "timed out" in text or "504" in text:
        return "timeout"
    if "ssl" in text or "certificate" in text:
        return "tls"
    return "connection"


def check_link(opener, url: str, timeout: float = 10.0, max_redirects: int = 5, retry: bool = True) -> dict:
    result = {"url": url, "status": None, "final_url": url, "hops": [], "outcome": "", "detail": "", "attempts": 0}
    current = url
    for _ in range(max_redirects + 1):
        status, headers, error = _request_once(opener, current, "HEAD", timeout)
        result["attempts"] += 1
        if status in (400, 403, 405, 501) or (status is None and "timed out" not in error):
            # Many servers mishandle HEAD; confirm with a tiny GET.
            g_status, g_headers, g_error = _request_once(opener, current, "GET", timeout)
            result["attempts"] += 1
            if g_status is not None or status is None:
                status, headers, error = g_status, g_headers, g_error
        if status is None and retry and _classify_error(error) in ("timeout", "connection"):
            time.sleep(1.0)
            status, headers, error = _request_once(opener, current, "GET", timeout)
            result["attempts"] += 1
        if status is None:
            if "Tunnel connection failed: 403" in error:
                error = "Blocked by AdLeak safety policy"
            elif "Tunnel connection failed: 502" in error:
                error = "DNS lookup failed" if "DNS" in error else error
            result.update(outcome=_classify_error(error), detail=error)
            return result
        if 300 <= status < 400:
            location = headers.get("Location") or headers.get("location")
            result["hops"].append(f"{status} {current}")
            if not location:
                result.update(status=status, outcome="broken", detail="Redirect without a Location header")
                return result
            nxt = urljoin(current, location)
            if urlsplit(nxt).scheme not in ("http", "https"):
                result.update(status=status, final_url=nxt, outcome="ok", detail="Redirects to a non-web address")
                return result
            current = nxt
            continue
        result["status"] = status
        result["final_url"] = current
        if headers.get("X-AdLeak-Blocked"):
            result.update(outcome="blocked_by_policy", detail=headers["X-AdLeak-Blocked"])
        elif 200 <= status < 300:
            result["outcome"] = "ok"
        elif status in (404, 410):
            result["outcome"] = "broken"
        elif status in (401, 403, 429, 999):
            result["outcome"] = "restricted"
        elif status >= 500:
            if retry:
                time.sleep(1.0)
                again = check_link(opener, url, timeout, max_redirects, retry=False)
                again["attempts"] += result["attempts"]
                if again["outcome"] != "server_error":
                    again["detail"] = f"First attempt returned {status}; retry gave {again['status'] or again['detail']}"
                    again["intermittent"] = True
                return again
            result["outcome"] = "server_error"
        else:
            result["outcome"] = "broken"
        return result
    result.update(outcome="redirect_loop", detail=f"More than {max_redirects} redirects")
    return result


def check_links(proxy_url: str, urls: list[str], timeout: float, max_redirects: int, workers: int, deadline: float) -> list[dict]:
    opener = build_opener(proxy_url)

    def run(u):
        if time.monotonic() > deadline:
            return {"url": u, "status": None, "final_url": u, "hops": [], "outcome": "skipped", "detail": "scan time limit reached", "attempts": 0}
        return check_link(opener, u, timeout, max_redirects)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return list(pool.map(run, urls))
