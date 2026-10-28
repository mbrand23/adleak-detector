"""Ad destination URL checks: tracking parameters and redirect behaviour."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from .findings import FAILED, HIGH, INCONCLUSIVE, INFO, LOW, MEDIUM, PASSED, WARNING, Finding

TRACKING_PARAMS = (
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
    "gclid", "gbraid", "wbraid", "dclid", "fbclid", "msclkid", "ttclid", "twclid", "li_fat_id",
)
_MACRO = re.compile(r"\{\{.*?\}\}|\{[a-z_.]+\}|%7B%7B|%7B[a-z_.]+%7D", re.IGNORECASE)


def tracking_params(url: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for key, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if key.lower() in TRACKING_PARAMS and key.lower() not in found:
            found[key.lower()] = value
    return found


def _registrable(host: str) -> str:
    """Rough registrable domain (last two labels, three for common ccTLD second levels)."""
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and labels[-2] in ("co", "com", "org", "net", "gov", "ac", "edu") and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def analyse(submitted_url: str, chain: list[dict], final_url: str, client_redirect: str | None = None) -> list[Finding]:
    """``chain`` is the browser's redirect chain: [{url, status}], first hop first,
    ending with the document that was finally served."""
    findings: list[Finding] = []
    original = tracking_params(submitted_url)

    # Redirect behaviour ----------------------------------------------------
    hops = [h for h in chain if 300 <= (h.get("status") or 0) < 400]
    hop_evidence = [f"{h['status']} {h['url']}" for h in chain]
    if client_redirect:
        hop_evidence.append(f"Script/meta redirect -> {client_redirect}")

    if hops:
        status = WARNING if len(hops) >= 3 else PASSED
        findings.append(Finding(
            "campaign", f"{len(hops)} redirect{'s' if len(hops) != 1 else ''} before the page loaded", status,
            LOW if status == WARNING else INFO,
            "Each redirect adds a round trip before the visitor sees anything. Three or more on an ad click is worth reducing."
            if status == WARNING else "The redirect chain is short.",
            "Point the ad straight at the final URL." if status == WARNING else "",
            hop_evidence, check="redirect_chain"))

    start_host = urlsplit(submitted_url).hostname or ""
    end_host = urlsplit(final_url).hostname or ""
    if start_host and end_host and _registrable(start_host) != _registrable(end_host):
        findings.append(Finding(
            "campaign", "Destination moved to a different domain", WARNING, MEDIUM,
            f"The submitted address on {start_host} ended up on {end_host}. Ad platforms compare the display/destination domain with the "
            "landing page, and an unexpected domain change can get ads disapproved or break cookie-based attribution.",
            "Confirm the redirect is intentional, and use the final domain as the ad destination.",
            hop_evidence, check="domain_change"))

    if urlsplit(submitted_url).scheme == "https" and urlsplit(final_url).scheme == "http":
        findings.append(Finding(
            "campaign", "Redirect downgraded HTTPS to HTTP", FAILED, MEDIUM,
            "The visitor started on a secure page and was sent to an insecure one. Browsers show 'Not secure' and some tracking cookies are dropped.",
            "Fix the redirect so it targets the https:// version.", hop_evidence, check="https_downgrade"))
    elif urlsplit(final_url).scheme == "http":
        findings.append(Finding(
            "campaign", "Final page is not served over HTTPS", WARNING, MEDIUM,
            "The landing page loads over plain HTTP. Browsers label it 'Not secure', which hurts trust on a sales page.",
            "Install an SSL certificate and redirect HTTP to HTTPS.", [final_url], check="https"))

    if client_redirect:
        findings.append(Finding(
            "campaign", "Page redirected itself with JavaScript or meta refresh", WARNING, LOW,
            "After the page loaded it sent the browser somewhere else. Client-side redirects are slower than server redirects and can "
            "fire tags on the first page before leaving it.",
            "Replace it with a server-side 301/302 redirect, or link the ad to the final page.", hop_evidence, check="client_redirect"))

    # Tracking parameters -----------------------------------------------------
    if not original:
        findings.append(Finding(
            "campaign", "No campaign parameters to test", INCONCLUSIVE, INFO,
            "The submitted address has no UTM or click-ID parameters, so parameter preservation was not tested.",
            "Paste the full destination URL from your ad (including ?utm_source=...) to check that tracking parameters survive redirects.",
            check="utm_preservation"))
        return findings

    final = tracking_params(final_url)
    lost = [k for k in original if k not in final]
    changed = [k for k in original if k in final and final[k] != original[k]]
    if lost:
        culprit = _first_hop_dropping(chain, client_redirect, lost[0])
        evidence = [f"Lost: {', '.join(lost)}", f"Submitted: {submitted_url}", f"Final: {final_url}"]
        if culprit:
            evidence.append(f"First dropped by: {culprit}")
        findings.append(Finding(
            "campaign", "Tracking parameters were dropped", FAILED, HIGH,
            "Some UTM or click-ID parameters in the ad URL did not reach the final page. Analytics then records these visits without "
            "the campaign (often as direct or referral traffic), and click IDs such as gclid/fbclid are needed for conversion attribution.",
            "Make the redirect keep the query string (for example, in a 301 rule pass $query_string or use 'preserve query'), "
            "or point the ad directly at the final URL.",
            evidence + hop_evidence, check="utm_preservation"))
    elif changed:
        findings.append(Finding(
            "campaign", "Tracking parameter values changed during redirect", WARNING, MEDIUM,
            "Parameters arrived at the final page with different values than the ad sent.",
            "Check redirect rules and URL rewriting plugins.",
            [f"{k}: '{original[k]}' -> '{final[k]}'" for k in changed], check="utm_preservation"))
    else:
        findings.append(Finding(
            "campaign", "Tracking parameters preserved", PASSED, INFO,
            "Every UTM and click-ID parameter in the submitted URL reached the final page unchanged.",
            evidence=[f"{k}={v}" for k, v in original.items()] + ([f"Final: {final_url}"] if final_url != submitted_url else []),
            check="utm_preservation"))

    macros = [f"{k}={v}" for k, v in original.items() if _MACRO.search(v)]
    if macros:
        findings.append(Finding(
            "campaign", "Parameters contain unreplaced ad-platform macros", WARNING, LOW,
            "Values such as {{campaign.name}} or {campaignid} are placeholders the ad platform fills in on a real click. If you copied the "
            "URL from an ad template that's expected; if this URL is used anywhere as-is, analytics will record the placeholder text.",
            "Check the macro spelling for your platform, or test with a real ad click URL.", macros, check="utm_macros"))

    utm = {k for k in original if k.startswith("utm_")}
    missing = [k for k in ("utm_source", "utm_medium", "utm_campaign") if utm and k not in utm]
    empty = [k for k, v in original.items() if k.startswith("utm_") and not v.strip()]
    if missing or empty:
        findings.append(Finding(
            "campaign", "UTM tagging is incomplete", WARNING, LOW,
            "GA4 attributes traffic using utm_source, utm_medium and utm_campaign. Missing or empty values put visits in '(not set)'.",
            "Add the missing parameters to the ad's URL template.",
            ([f"Missing: {', '.join(missing)}"] if missing else []) + ([f"Empty: {', '.join(empty)}"] if empty else []),
            check="utm_complete"))
    return findings


def _first_hop_dropping(chain: list[dict], client_redirect: str | None, param: str) -> str | None:
    urls = [h["url"] for h in chain] + ([client_redirect] if client_redirect else [])
    for prev, nxt in zip(urls, urls[1:]):
        if param in tracking_params(prev) and param not in tracking_params(nxt):
            status = next((h.get("status") for h in chain if h["url"] == prev), None)
            return f"{status or ''} {prev} -> {nxt}".strip()
    return None
