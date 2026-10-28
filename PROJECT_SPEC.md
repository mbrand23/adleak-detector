# AdLeak Detector: Product specification

## Purpose

AdLeak Detector finds observable technical problems that waste paid traffic: pages that don't load, sales buttons that do nothing, broken links, tracking parameters lost in redirects, tags that never fire and layouts that break on phones. Anyone can paste a URL and get a report with evidence and suggested fixes. No plugin, store app or ad-account connection is needed.

Audience: individuals, Shopify store owners, WordPress/WooCommerce users, Elementor and Thrive Architect users, freelancers, digital marketers, agencies, and businesses with custom sites. All use the same scanning engine.

## Principles

1. **Real checks only.** Every finding comes from something the scanner measured in this scan. No sample data, simulated progress or invented statistics.
2. **Evidence with every finding.** URLs, status codes, selectors, measurements or request details are attached.
3. **Honest uncertainty.** "Couldn't verify" is `INCONCLUSIVE`, never `FAILED`. A missing tracking signal is never presented as proof that conversion tracking is broken. The scanner never estimates money lost.
4. **Do no harm.** No clicks, form submissions, orders, payments, WhatsApp messages or consent acceptance. Analytics beacons are blocked so scans don't add fake traffic. No CAPTCHA or bot-protection bypass.
5. **Safe by default.** Only public websites can be scanned (see ARCHITECTURE.md).

## Statuses

| Status | Meaning |
|---|---|
| PASSED | The check ran and found no problem. |
| FAILED | The check ran and found a problem visitors will hit, with evidence. |
| WARNING | Likely problem or risk that needs a human look (it can be intentional). |
| INCONCLUSIVE | The check couldn't produce a trustworthy answer (timeout, bot protection, not applicable, not tested). |

Severity (`high`, `medium`, `low`, `info`) ranks how much the problem could affect ad performance.

## Checks (v0.1.0)

| Area | Checks |
|---|---|
| Accessibility | HTTP status, DNS failure, TLS errors, connection refused, timeouts (retried), redirect loops, final URL, intermittent failures, load event, load timing |
| Links | Up to 40 links per scan (sales destinations first): 404/410, DNS, TLS, loops, 5xx (retried), restricted (401/403/429 = inconclusive), placeholder links, missing in-page anchors, links to private addresses |
| Sales actions | Order/Buy/Add to cart/Checkout/WhatsApp/Call/Contact/lead forms: presence, visibility, disabled state, placeholder destinations, above-the-fold, covered by overlays, broken destinations, WhatsApp number format, mobile tap-target size, visible on desktop but hidden on mobile |
| Tracking | Meta Pixel script and events (with pixel IDs, duplicate PageView, multiple pixels), GA4 script and hits (duplicate page_view), GTM container; failed tag scripts; consent-banner caveat; user-declared expected tags |
| Campaign URL | UTM and click-ID (gclid, fbclid, msclkid, ttclid...) preservation through each redirect hop with the hop that dropped them, changed values, unreplaced macros, incomplete UTM sets, domain changes, HTTPS downgrade, plain HTTP, JavaScript/meta redirects, redirect count |
| Mobile and layout | Horizontal overflow with the elements causing it (desktop and mobile), viewport tag, disabled zoom |
| Resources | Broken images, failed scripts/stylesheets/fonts/media, slow above-the-fold images, uncaught JavaScript errors |
| Safety | Requests the page made to private/internal addresses (blocked), data budget reached |

Screenshots: first screen and full page (cropped at 5000 px) for desktop and mobile, stored locally with the report.

## Interface

- **Home:** product summary, URL field, Scan Website button, options (expected tags, screenshots), features, how it works, limitations, fair-use usage.
- **Scanning:** Queued/Scanning state and the scanner's real step log, polled every 1.5 s.
- **Report:** website URL, final URL, date/time, devices tested and their outcome, detected platform, counts by status, findings grouped by area with severity, evidence and fix, filters, screenshots, redirect chain, limitations, Scan again, Print/Save PDF.
- **Report history:** all stored reports with status and counts, open and delete, empty state.

## Free beta limits

20 scans per hour, 100 per day, 40 links per scan, 2 scans at once, 6 queued, 180 s per scan, 80 MB of network data per scan, 200 stored reports.

## Out of scope for the local beta

Hosting, domains, accounts, billing, scheduled monitoring, email, interaction tests (planned as owner-verified, opt-in), ad-platform APIs.
