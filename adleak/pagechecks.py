"""Turn in-page probe data into findings (sales actions, layout, images, links)."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

from .findings import FAILED, HIGH, INCONCLUSIVE, INFO, LOW, MEDIUM, PASSED, WARNING, Finding
from .links import placeholder_reason

CHALLENGE_PATTERNS = re.compile(
    r"just a moment|attention required|verify you are (a )?human|are you a robot|captcha|access denied|"
    r"pardon our interruption|unusual traffic|request unsuccessful|checking your browser|enable javascript and cookies",
    re.IGNORECASE,
)


def detect_challenge(status: int | None, title: str, text: str, headers: dict) -> str | None:
    """Return a description if the response looks like bot protection rather than the real page."""
    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    if lowered.get("cf-mitigated") == "challenge":
        return "Cloudflare challenge (cf-mitigated: challenge)"
    sample = f"{title}\n{text[:1500]}"
    if CHALLENGE_PATTERNS.search(sample) and (status in (403, 429, 503) or len(text) < 1500):
        return f"Bot-protection page detected (title: '{title[:80]}')"
    return None


def sales_findings(probe: dict, device: str) -> list[Finding]:
    findings: list[Finding] = []
    actions = probe.get("actions") or []
    forms = probe.get("forms") or []
    lead_forms = [f for f in forms if f["lead"] and f["visible"]]
    if not actions and not lead_forms:
        findings.append(Finding(
            "sales", "No recognisable sales or contact action found", WARNING, MEDIUM,
            "AdLeak looked for buttons and links such as Buy Now, Order Now, Add to Cart, WhatsApp, Call or Contact, and for lead forms, "
            "and found none. If this is an ad landing page, visitors may not know what to do next. Buttons drawn as images or "
            "with unusual wording can be missed by this check.",
            "Add a clear, visible call to action near the top of the page.", device=device, check="sales_presence"))
        return findings

    visible = [a for a in actions if a["visible"]]
    disabled = [a for a in visible if a["disabled"]]
    placeholder = [a for a in visible if a["tag"] == "a" and placeholder_reason(a["href"]) and a["kind"] not in ("whatsapp",)]
    covered = [a for a in visible if a["covered_by"] and a["above_fold"]]
    above = [a for a in visible if a["above_fold"] and not a["disabled"]]

    def ev(a):
        dest = a["abs_href"] or a["form_action"] or "(no link)"
        return f"'{a['text'] or a['selector']}' [{a['kind']}] {a['selector']} -> {dest}"

    findings.append(Finding(
        "sales", f"{len(visible)} visible sales/contact action{'s' if len(visible) != 1 else ''} found", PASSED if visible else WARNING,
        INFO if visible else MEDIUM,
        "These are the buttons and links AdLeak recognised. Their destinations were inspected and, where they are web links, tested; "
        "nothing was clicked or submitted.",
        "" if visible else "Make sure your main call to action is visible on this device.",
        [ev(a) for a in visible[:15]] or [ev(a) for a in actions[:10]], device=device, check="sales_presence"))

    hidden = [a for a in actions if not a["visible"] and a["kind"] in ("buy", "add_to_cart", "checkout", "whatsapp")]
    if hidden and not visible:
        findings.append(Finding(
            "sales", "Sales buttons exist but are hidden", FAILED, HIGH,
            f"Sales buttons are in the page but none are visible at this {device} size.",
            "Check the CSS and theme settings that hide these buttons on this screen size.",
            [ev(a) for a in hidden[:10]], device=device, check="sales_hidden"))

    if visible and not above:
        findings.append(Finding(
            "sales", "No usable call to action above the fold", WARNING, LOW,
            f"Nothing recognised as a sales action is visible in the first screen ({probe['viewport'][0]}x{probe['viewport'][1]}px). "
            "Ad visitors who don't scroll won't see one.",
            "Move a primary button into the first screen of the page.",
            [f"First action at {visible[0]['top']}px: {ev(visible[0])}"], device=device, check="sales_above_fold"))

    if disabled:
        findings.append(Finding(
            "sales", "Disabled sales button", WARNING, HIGH,
            "A sales button is visible but disabled, so visitors can't use it. Sometimes this is correct (sold out, or the button "
            "waits for a variant choice) but on an ad landing page it often means lost orders.",
            "Check stock, variant defaults and any script that enables the button.",
            [ev(a) for a in disabled[:10]], device=device, check="sales_disabled"))

    if placeholder:
        findings.append(Finding(
            "sales", "Sales link goes nowhere (placeholder link)", WARNING, HIGH,
            "These sales links point to '#', 'javascript:' or placeholder text. Some themes attach a script to such links, which "
            "AdLeak cannot verify without clicking; if no script is attached, the button does nothing.",
            "Click the button yourself to confirm it works, and give it a real destination URL where possible.",
            [f"{ev(a)} (href: {a['href']!r})" for a in placeholder[:10]], device=device, check="sales_placeholder"))

    if covered:
        findings.append(Finding(
            "sales", "Sales button covered by another element", WARNING, MEDIUM,
            "The centre of a sales button above the fold is covered by another element (often a popup, chat widget or cookie banner), "
            "so a tap may hit the overlay instead.",
            "Check popups and sticky widgets on this screen size.",
            [f"{ev(a)} covered by {a['covered_by']}" for a in covered[:10]], device=device, check="sales_covered"))

    for a in actions:
        if a["kind"] != "whatsapp" or not a["abs_href"]:
            continue
        problem = whatsapp_problem(a["abs_href"])
        if problem:
            findings.append(Finding(
                "sales", "WhatsApp order link looks wrong", FAILED, HIGH,
                f"{problem}. Visitors tapping it won't reach your WhatsApp chat. AdLeak inspected the link only; no message was sent.",
                "Use the format https://wa.me/<country code><number>, digits only, e.g. https://wa.me/2348012345678.",
                [ev(a)], device=device, check="whatsapp_link"))

    small = [a for a in visible if device == "mobile" and (a["size"][1] < 32 or a["size"][0] < 32)]
    if small:
        findings.append(Finding(
            "sales", "Small tap target for a sales action", WARNING, LOW,
            "On mobile these sales actions are smaller than 32px in at least one direction, which makes them easy to miss with a thumb.",
            "Make primary buttons at least 44x44px on mobile.",
            [f"{ev(a)} size {a['size'][0]}x{a['size'][1]}px" for a in small[:8]], device=device, check="tap_target"))
    return findings


def whatsapp_problem(url: str) -> str | None:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme == "whatsapp":
        phone = parse_qs(parts.query).get("phone", [""])[0]
    elif host in ("wa.me", "www.wa.me"):
        phone = parts.path.strip("/").split("/")[0]
    elif host.endswith("whatsapp.com"):
        if parts.path.startswith(("/channel", "/catalog")) or host == "chat.whatsapp.com":
            return None
        phone = parse_qs(parts.query).get("phone", [""])[0]
    else:
        return None
    if host in ("wa.me", "www.wa.me") and phone.startswith(("message", "c", "p", "qr")) and not phone.isdigit():
        return None
    digits = re.sub(r"\D", "", phone)
    if not phone:
        return "The WhatsApp link has no phone number"
    if phone != digits and not phone.lstrip("+").isdigit():
        return f"The phone number '{phone}' contains characters other than digits"
    if phone.startswith(("+", "0")) and host in ("wa.me", "www.wa.me"):
        return f"The number '{phone}' starts with '+' or '0'; wa.me needs the full international number with no '+' or leading 0"
    if not 7 <= len(digits) <= 15:
        return f"The number '{phone}' has {len(digits)} digits; international numbers have 7 to 15"
    return None


def layout_findings(probe: dict, device: str) -> list[Finding]:
    findings: list[Finding] = []
    vw = probe["viewport"][0]
    overflow = probe["scroll_width"] - vw
    if device == "mobile" and not probe.get("viewport_meta"):
        pass  # the page is laid out at desktop width and zoomed out; the viewport finding below covers it
    elif overflow > 4:
        findings.append(Finding(
            "mobile", "Page is wider than the screen (horizontal scrolling)", FAILED if device == "mobile" else WARNING,
            HIGH if device == "mobile" else LOW,
            f"At {vw}px wide the page measures {probe['scroll_width']}px, so visitors can scroll or zoom sideways and content is cut off.",
            "Find the elements below and give them max-width: 100% (images, tables, embeds) or fix their fixed widths.",
            [f"{o['selector']} extends to {o['right']}px (width {o['width']}px)" for o in probe["overflow_offenders"]]
            or [f"Document scroll width {probe['scroll_width']}px vs viewport {vw}px"], device=device, check="overflow"))
    else:
        findings.append(Finding(
            "mobile", "No horizontal overflow", PASSED, INFO,
            f"The page fits the {vw}px viewport.", evidence=[f"scrollWidth {probe['scroll_width']}px, viewport {vw}px"],
            device=device, check="overflow"))

    if device == "mobile":
        meta = probe.get("viewport_meta")
        if not meta:
            findings.append(Finding(
                "mobile", "Missing mobile viewport tag", FAILED, HIGH,
                "The page has no <meta name=\"viewport\">, so phones render it as a shrunken desktop page.",
                "Add <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> to the <head>.",
                device=device, check="viewport_meta"))
        elif "width=device-width" not in meta.replace(" ", "").lower():
            findings.append(Finding(
                "mobile", "Viewport tag doesn't use device width", WARNING, MEDIUM,
                "The viewport tag exists but doesn't set width=device-width.",
                "Use content=\"width=device-width, initial-scale=1\".", [f"content=\"{meta}\""], device=device, check="viewport_meta"))
        if meta and re.search(r"user-scalable\s*=\s*(no|0)|maximum-scale\s*=\s*1(\.0)?\b", meta, re.IGNORECASE):
            findings.append(Finding(
                "mobile", "Pinch-zoom is disabled", WARNING, LOW,
                "The viewport tag stops visitors zooming, which is an accessibility problem for people with low vision.",
                "Remove user-scalable=no and maximum-scale=1.", [f"content=\"{meta}\""], device=device, check="viewport_zoom"))
    return findings


def image_findings(probe: dict, failed_images: list[dict], device: str) -> list[Finding]:
    broken = [i for i in probe.get("images", []) if i["complete"] and i["natural_width"] == 0 and i["src"] and not i["src"].startswith("data:")]
    pending = [i for i in probe.get("images", []) if not i["complete"] and i["in_viewport"] and i["visible"] and not i["lazy"]]
    findings: list[Finding] = []
    if broken:
        findings.append(Finding(
            "resources", f"{len(broken)} broken image{'s' if len(broken) != 1 else ''}", FAILED, MEDIUM,
            "These images finished loading but have no image data (missing file, wrong URL, or an error response). Visitors see an empty box or a broken-image icon.",
            "Re-upload the images or fix their URLs.",
            [f"{i['src']} ({i['selector']})" for i in broken[:12]], device=device, check="images"))
    if pending:
        findings.append(Finding(
            "resources", "Images in the first screen hadn't finished loading", WARNING, LOW,
            "When AdLeak finished waiting, these visible, non-lazy images in the first screen were still loading. Slow hero images delay what ad visitors see.",
            "Compress large images and serve them in WebP/AVIF at the size they are shown.",
            [i["src"] for i in pending[:10]], device=device, check="images_slow"))
    if not broken and not pending and probe.get("images"):
        findings.append(Finding(
            "resources", "Images loaded", PASSED, INFO,
            f"{len(probe['images'])} image elements checked; none broken.", device=device, check="images"))
    return findings


def link_inventory(probe: dict, page_url: str) -> tuple[list[Finding], list[str]]:
    """Return findings for placeholder/anchor links and the list of http(s) links to test."""
    findings: list[Finding] = []
    placeholders, missing_anchors, testable = [], [], []
    page = urlsplit(page_url)
    for link in probe.get("links", []):
        raw = link["raw"] or ""
        reason = placeholder_reason(raw)
        if reason and link["visible"]:
            placeholders.append(f"'{link['text'] or link['selector']}' href={raw!r} ({reason})")
            continue
        if link["anchor_ok"] is False and link["visible"]:
            missing_anchors.append(f"'{link['text'] or link['selector']}' -> {raw} (no element with that id)")
            continue
        abs_url = link["abs"] or ""
        parts = urlsplit(abs_url)
        if parts.scheme not in ("http", "https"):
            continue
        if parts.hostname in ("wa.me", "api.whatsapp.com", "web.whatsapp.com"):
            continue  # inspected by the WhatsApp check, never opened
        base = parts._replace(fragment="").geturl()
        if base == page._replace(fragment="").geturl():
            continue
        testable.append(base)
    if placeholders:
        findings.append(Finding(
            "links", f"{len(placeholders)} placeholder link{'s' if len(placeholders) != 1 else ''}", WARNING, LOW,
            "These visible links have no real destination ('#', 'javascript:' or placeholder text). Menus and toggles often use this on "
            "purpose; links that look like navigation or offers should be fixed.",
            "Give each link a real URL, or use a <button> for things that aren't links.", placeholders[:15], check="placeholder_links"))
    if missing_anchors:
        findings.append(Finding(
            "links", "Links to page sections that don't exist", WARNING, LOW,
            "These in-page links point to an id that isn't on the page, so clicking them does nothing.",
            "Fix the section ids or the link targets.", missing_anchors[:15], check="anchor_links"))
    seen, unique = set(), []
    for url in testable:
        if url not in seen:
            seen.add(url)
            unique.append(url)
    return findings, unique


def link_result_findings(results: list[dict], total_found: int, tested_limit: int, cta_urls: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    def line(r):
        hops = f" via {' -> '.join(r['hops'])}" if r["hops"] else ""
        status = r["status"] if r["status"] is not None else r["detail"]
        return f"{r['url']} -> {status}{hops}"

    broken = [r for r in results if r["outcome"] in ("broken", "dns", "redirect_loop", "tls")]
    server = [r for r in results if r["outcome"] == "server_error"]
    unclear = [r for r in results if r["outcome"] in ("restricted", "timeout", "connection", "skipped")]
    blocked = [r for r in results if r["outcome"] == "blocked_by_policy"]
    intermittent = [r for r in results if r.get("intermittent")]
    cta_broken = [r for r in broken + server if r["url"] in cta_urls]

    if cta_broken:
        findings.append(Finding(
            "sales", "Sales button links to a broken page", FAILED, HIGH,
            "A recognised sales or contact action points to a page that returned an error. Visitors who click it hit a dead end.",
            "Update the button's link to a working page.", [line(r) for r in cta_broken], check="cta_destination"))
    if broken:
        findings.append(Finding(
            "links", f"{len(broken)} broken link{'s' if len(broken) != 1 else ''}", FAILED, MEDIUM if not cta_broken else HIGH,
            "These links returned 404/410, don't resolve, have certificate errors or redirect in a loop.",
            "Fix or remove the links, or redirect old URLs to their replacements.", [line(r) for r in broken[:20]], check="broken_links"))
    if server:
        findings.append(Finding(
            "links", "Links returning server errors", WARNING, MEDIUM,
            "These links returned a 5xx error twice in a row (AdLeak retried after a second). The target server is failing, at least right now.",
            "Check the target pages; if they're yours, check your hosting error logs.", [line(r) for r in server[:15]], check="server_error_links"))
    if intermittent:
        findings.append(Finding(
            "links", "Links that failed once, then worked", WARNING, LOW,
            "These links returned a server error on the first try and worked on the retry. That points to an unstable server.",
            "Keep an eye on hosting stability.", [f"{r['url']}: {r['detail']}" for r in intermittent[:10]], check="intermittent_links"))
    if unclear:
        findings.append(Finding(
            "links", "Links that couldn't be verified", INCONCLUSIVE, INFO,
            "These links refused automated checks (401/403/429 or bot protection), timed out, or weren't tested before the time limit. "
            "They may work fine for real visitors.",
            "Open them in your own browser to confirm.", [line(r) for r in unclear[:15]], check="unverified_links"))
    if blocked:
        findings.append(Finding(
            "safety", "Links to private or internal addresses", WARNING, MEDIUM,
            "These links lead to localhost, a private network or another address the scanner never contacts. Real visitors can't reach them "
            "either; they're usually left over from a staging or development site.",
            "Replace them with public URLs.", [line(r) for r in blocked[:10]], check="private_links"))
    ok = [r for r in results if r["outcome"] == "ok"]
    note = f" (of {total_found} found; this scan tests up to {tested_limit})" if total_found > len(results) else ""
    if results and not broken and not server:
        findings.append(Finding(
            "links", f"{len(ok)} of {len(results)} tested links work{note}", PASSED, INFO,
            "The tested links returned a successful response, following redirects where needed.", check="links_ok"))
    return findings
