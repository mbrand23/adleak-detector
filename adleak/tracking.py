"""Detection of observable Meta Pixel, Google Analytics 4 and Google Tag Manager signals.

The scanner records the beacons these tags send, then aborts them inside the
browser so a scan does not add fake page views to the site owner's analytics.
A beacon being observed means the tag tried to send it; it does not prove
Meta or Google accepted it.
"""

from __future__ import annotations

from collections import Counter
from urllib.parse import parse_qs, urlsplit

from .findings import FAILED, INCONCLUSIVE, INFO, LOW, MEDIUM, PASSED, WARNING, Finding

TRACKING_CAVEAT = (
    "Only browser-side signals can be observed. Cookie-consent settings, ad blockers, browser "
    "privacy features and server-side tracking (Conversions API, server-side GTM) can all change "
    "what is visible here, so a missing signal is a lead to investigate, not proof that tracking is broken."
)


def _host_path(url: str) -> tuple[str, str]:
    parts = urlsplit(url)
    return (parts.hostname or "").lower(), parts.path


def is_tracking_beacon(url: str) -> bool:
    """True for requests that would record an event in someone's analytics."""
    host, path = _host_path(url)
    if host in ("www.facebook.com", "facebook.com", "web.facebook.com") and path.rstrip("/") == "/tr":
        return True
    if (host.endswith("google-analytics.com") or host.endswith("analytics.google.com")) and path.endswith("/collect"):
        return True
    if host.endswith("googletagmanager.com") and path == "/g/collect":
        return True
    if host in ("www.googleadservices.com", "googleads.g.doubleclick.net") and "/pagead/" in path:
        return True
    return False


def classify(url: str, post_data: str | None = None) -> dict | None:
    """Classify a request URL as a tracking signal, or return None."""
    host, path = _host_path(url)
    query = parse_qs(urlsplit(url).query)

    def q(name):
        values = query.get(name)
        return values[0] if values else ""

    if host == "connect.facebook.net" and (path.endswith("/fbevents.js") or "/signals/config/" in path):
        return {"tag": "meta", "kind": "script", "url": url}
    if host in ("www.facebook.com", "facebook.com", "web.facebook.com") and path.rstrip("/") == "/tr":
        return {"tag": "meta", "kind": "event", "event": q("ev") or "unknown", "id": q("id"), "url": url}
    if host.endswith("googletagmanager.com") and path == "/gtm.js":
        return {"tag": "gtm", "kind": "script", "id": q("id"), "url": url}
    if host.endswith("googletagmanager.com") and path == "/gtag/js":
        tag_id = q("id")
        tag = "ga4" if tag_id.startswith(("G-", "GT-")) else "google_ads" if tag_id.startswith("AW-") else "gtag"
        return {"tag": tag, "kind": "script", "id": tag_id, "url": url}
    if (host.endswith("google-analytics.com") or host.endswith("analytics.google.com") or host.endswith("googletagmanager.com")) and path.endswith("/g/collect"):
        events = [q("en")] if q("en") else []
        if post_data:
            for line in post_data.splitlines():
                body = parse_qs(line)
                if body.get("en"):
                    events.append(body["en"][0])
        return {"tag": "ga4", "kind": "event", "event": ",".join(e for e in events if e) or "unknown", "id": q("tid"), "url": url}
    if host.endswith("google-analytics.com") and path.endswith("/collect"):
        return {"tag": "ua", "kind": "event", "event": q("t") or "unknown", "id": q("tid"), "url": url}
    return None


def build_findings(signals: list[dict], failed_scripts: list[dict], globals_seen: dict,
                   expected: dict, consent_banner: str | None) -> list[Finding]:
    findings: list[Finding] = []
    consent_note = (
        f" A cookie-consent banner was visible ({consent_banner}); tags that wait for consent will not fire "
        "until a visitor accepts, and AdLeak never clicks consent buttons." if consent_banner else ""
    )

    def by(tag, kind):
        return [s for s in signals if s["tag"] == tag and s["kind"] == kind]

    def failed_for(tag):
        return [f for f in failed_scripts if (classify(f["url"]) or {}).get("tag") == tag]

    # Meta Pixel ------------------------------------------------------------
    scripts, events, failures = by("meta", "script"), by("meta", "event"), failed_for("meta")
    pixel_ids = sorted({e["id"] for e in events if e.get("id")})
    if failures:
        findings.append(Finding(
            "tracking", "Meta Pixel script failed to load", FAILED, MEDIUM,
            "The browser requested the Meta Pixel library but the request failed, so the pixel could not run in this session." + consent_note,
            "Check that the pixel snippet URL is correct and not blocked by a Content-Security-Policy on your site.",
            [f"{f['url']} -> {f['error']}" for f in failures], check="meta_pixel"))
    elif events:
        counts = Counter((e.get("id"), e.get("event")) for e in events)
        evidence = [f"Pixel {pid or '(no id)'}: {ev} x{n}" for (pid, ev), n in counts.items()]
        findings.append(Finding(
            "tracking", "Meta Pixel events observed", PASSED, INFO,
            "The page sent Meta Pixel events from the browser. AdLeak blocked the beacons after recording them so your Meta data is not affected. "
            "Whether Meta accepted and attributed them cannot be confirmed from outside your ad account.",
            "Use Meta Events Manager > Test Events to confirm the events arrive.", evidence, check="meta_pixel"))
        dupes = [(pid, n) for (pid, ev), n in counts.items() if ev == "PageView" and n > 1]
        if dupes:
            findings.append(Finding(
                "tracking", "Meta PageView fired more than once", WARNING, MEDIUM,
                "The same pixel sent PageView more than once during a single page load. This often comes from the pixel being installed twice "
                "(for example a theme snippet plus an app or plugin) and can inflate reported page views.",
                "Search your theme, tag manager and plugins for duplicate pixel installs and keep one.",
                [f"Pixel {pid}: PageView x{n}" for pid, n in dupes], check="meta_pixel_duplicate"))
        if len(pixel_ids) > 1:
            findings.append(Finding(
                "tracking", "Multiple Meta Pixel IDs on the page", WARNING, LOW,
                "More than one pixel ID sent events. This can be intentional (agency + owner pixels) but is also a common leftover from old setups.",
                "Confirm every pixel ID belongs to an ad account you use.", [f"Pixel IDs: {', '.join(pixel_ids)}"], check="meta_pixel_multiple"))
    elif scripts or globals_seen.get("fbq"):
        findings.append(Finding(
            "tracking", "Meta Pixel loaded but no event was observed", WARNING, MEDIUM,
            "The Meta Pixel library loaded but no PageView or other event was sent while AdLeak watched the page." + consent_note,
            "Check that fbq('init', ...) and fbq('track', 'PageView') run after the library loads.",
            [s["url"] for s in scripts][:3] or ["window.fbq is defined"], check="meta_pixel"))
    else:
        findings.append(_not_observed("Meta Pixel", "meta_pixel", expected.get("meta"), consent_note))

    # Google Analytics 4 ------------------------------------------------------
    scripts, events, failures = by("ga4", "script"), by("ga4", "event"), failed_for("ga4")
    if failures:
        findings.append(Finding(
            "tracking", "Google tag (gtag.js) failed to load", FAILED, MEDIUM,
            "The browser requested gtag.js but the request failed." + consent_note,
            "Check the measurement ID in the snippet and any Content-Security-Policy on your site.",
            [f"{f['url']} -> {f['error']}" for f in failures], check="ga4"))
    elif events:
        counts = Counter((e.get("id"), e.get("event")) for e in events)
        findings.append(Finding(
            "tracking", "Google Analytics 4 hits observed", PASSED, INFO,
            "The page sent GA4 measurement hits from the browser. AdLeak blocked them after recording them so your reports are not affected.",
            "Use GA4 DebugView or Tag Assistant to confirm hits arrive in the right property.",
            [f"{tid or '(no id)'}: {ev} x{n}" for (tid, ev), n in counts.items()], check="ga4"))
        dupes = [(tid, n) for (tid, ev), n in counts.items() if "page_view" in (ev or "").split(",") and n > 1]
        if dupes:
            findings.append(Finding(
                "tracking", "GA4 page_view sent more than once", WARNING, MEDIUM,
                "The same measurement ID sent page_view more than once on one load, which usually means GA4 is installed twice (hard-coded tag plus GTM, or two plugins).",
                "Remove the duplicate install and keep GA4 in one place.",
                [f"{tid}: page_view x{n}" for tid, n in dupes], check="ga4_duplicate"))
    elif scripts or globals_seen.get("gtag"):
        findings.append(Finding(
            "tracking", "Google tag loaded but no GA4 hit was observed", WARNING, MEDIUM,
            "gtag.js loaded but no GA4 collect request was seen while AdLeak watched the page." + consent_note,
            "Check the gtag('config', 'G-...') call and Google Consent Mode settings.",
            [s["url"] for s in scripts][:3] or ["window.gtag is defined"], check="ga4"))
    else:
        findings.append(_not_observed("Google Analytics 4", "ga4", expected.get("ga4"), consent_note))

    # Google Tag Manager -----------------------------------------------------
    scripts, failures = by("gtm", "script"), failed_for("gtm")
    containers = sorted(set(globals_seen.get("gtm_containers") or []) | {s["id"] for s in scripts if s.get("id")})
    if failures:
        findings.append(Finding(
            "tracking", "Google Tag Manager container failed to load", FAILED, HIGH,
            "gtm.js was requested but failed, so none of the tags inside the container could run in this session.",
            "Check the container ID and that the container is published.",
            [f"{f['url']} -> {f['error']}" for f in failures], check="gtm"))
    elif scripts or containers:
        findings.append(Finding(
            "tracking", "Google Tag Manager container loaded", PASSED, INFO,
            "A GTM container loaded. Which tags it fires depends on its triggers and consent settings, which AdLeak cannot see.",
            "Use GTM Preview mode to check that your conversion tags fire on the right triggers.",
            [f"Container: {c}" for c in containers] or [s["url"] for s in scripts][:3], check="gtm"))
    else:
        findings.append(_not_observed("Google Tag Manager", "gtm", expected.get("gtm"), consent_note))

    return findings


def _not_observed(name: str, check: str, expected: bool | None, consent_note: str) -> Finding:
    if expected:
        return Finding(
            "tracking", f"{name} expected but not observed", WARNING, MEDIUM,
            f"You said this page should run {name}, but no {name} script or event was observed in the browser." + consent_note
            + " " + TRACKING_CAVEAT,
            f"Open the page with your browser's developer tools (Network tab) or the vendor's debugging tool and confirm {name} loads.",
            check=check)
    return Finding(
        "tracking", f"{name} not observed", INCONCLUSIVE, INFO,
        f"No {name} script or event was observed. If you don't use {name} on this page, ignore this." + consent_note,
        f"If you do rely on {name}, tick it under 'Tags I expect' and rescan.", check=check)
