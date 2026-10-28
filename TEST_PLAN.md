# Test plan

## How to run

```bash
.venv\Scripts\python.exe -m pytest
```

Unit tests only (no browser): `-m "not browser"`. The browser tests start a fixture website on `127.0.0.1` (`tests/fixtures/site/`) and scan it with real Chromium. To reach it, they use an `EgressPolicy` that allows exactly that one `(ip, port)` and maps the Meta/Google tag hostnames to it. The production policy has neither, so the real app still refuses 127.0.0.1.

`connect.facebook.net` is on Chromium's HSTS preload list, so the browser forces HTTPS for it, which the plain-HTTP fixture can't serve. The tests therefore supply the stand-in `fbevents.js` through a test-only context hook. The Meta beacon it sends is still observed and blocked by the scanner's own code.

## Coverage against the required scenarios

| # | Scenario | Tests |
|---|---|---|
| 1 | Working sales page | `test_engine::test_working_sales_page` (no FAILED findings; sales, links, overflow, Meta/GA4/GTM all PASSED; screenshots saved) |
| 2 | Deliberately broken page | `test_engine::test_deliberately_broken_page` |
| 3 | Broken and placeholder links | broken page: 404 FAILED, 500 retried then WARNING, placeholder and missing-anchor WARNINGs; `test_proxy::test_link_checker_classifies_results` (ok, 404, 403 restricted, 500, loop, redirect hops, private address) |
| 4 | Disabled sales buttons | broken page: disabled Add to cart, `javascript:void(0)` Buy now, bad WhatsApp number |
| 5 | Missing expected browser tags | `test_engine::test_missing_expected_tags` (WARNING when expected, INCONCLUSIVE when not; never FAILED), `test_campaign_tracking::test_missing_expected_tag_is_warning_never_failed` |
| 6 | UTM parameter preservation | `test_utm_preserved_across_two_redirects` (301, 301, 200), `test_utm_dropped_by_redirect` (names the 302 hop), unit tests for domain change, HTTPS downgrade, macros, incomplete UTM |
| 7 | Mobile layout issues | `test_mobile_horizontal_overflow` (offending element named), `test_missing_viewport_tag`, CTA visible on desktop but hidden on mobile |
| 8 | Failed image and script resources | broken page: `/missing.png` broken image, `/missing.js` failed script, uncaught JS error |
| 9 | Blocked or timed-out scans | `test_timeout_is_inconclusive_and_retried` (2 attempts, INCONCLUSIVE), `test_redirect_to_private_address_is_refused`, `test_redirect_loop`, `test_http_error_page`, `test_intermittent_failure_is_corroborated` (503 then 200 gives WARNING) |
| 10 | Unsafe URL rejection | `test_security` (40 rejected inputs: schemes, credentials, loopback incl. `127.1`/hex/decimal forms, private, CGNAT, metadata, IPv6-embedded, internal names, ports, DNS rebinding with mixed records), `test_proxy` (CONNECT/GET to private targets refused, byte budget), `test_private_resources_and_links_are_blocked` |
| 11 | Report saving and retrieval | `test_storage` (save/load/list/delete, traversal-proof ids and screenshot names, corrupt files, retention, restart recovery, fair use), `test_server::test_scan_saved_retrieved_listed_and_deleted` (full API round trip incl. screenshot download and delete) |
| 12 | Frontend handling of unexpected input | `test_server::test_frontend_handles_unexpected_input` (empty, `javascript:`, localhost, spaces; HTML in scanned link text shown as text and never executed; unknown report id), `test_empty_history_state`, bad JSON/content type/size/origin/Host header tests |

Also covered: tracking beacons never reach the fixture (`/tr` and `/g/collect` hit counts stay 0), the server refuses to bind to `0.0.0.0`, and security headers are present.

## Latest results

Run on 28 October 2026, Windows 11 Pro, Python 3.14.0, Playwright 1.64.1, Chromium 156.0.8078.4:

```
105 passed in 139.00s
```

Manual checks the same day:

- `start-windows.bat` run in a clean copy of the app with no `.venv`: it created the venv, installed the packages, found Chromium, and the server answered `/api/health` in about 36 s.
- Real-internet scan of `https://example.com/?utm_source=facebook&utm_medium=paid&utm_campaign=beta_check` through the interface: completed in 26 s, desktop and mobile HTTP 200, UTM parameters preserved, screenshots saved, report and history displayed, no browser console errors.
- Interface rendered at 1280 px and 375 px wide with no horizontal scrolling.

## Not yet verified

- **Real WordPress, WooCommerce, Shopify, Elementor and Thrive sites.** No authorised sites were available, so sales-action detection, platform detection and tracking detection on live themes are unverified. This is the first task of Milestone 2 (ROADMAP.md).
- **Real Meta Pixel / GA4 / GTM scripts.** Detection was tested with stand-in scripts that use the real hostnames and URL formats. Live tags (which batch, delay and consent-gate events) haven't been scanned yet.
- **Bot-protection pages.** Detection is unit-tested on sample text and headers only, not against a live Cloudflare challenge.
- **IPv6-only sites, very large pages and long-running pages** under the 80 MB and 180 s limits.
- **Security beyond the listed cases.** The SSRF controls have not had an independent review or penetration test.

## Real-site test log

Add one row per authorised real site scanned:

| Date | Site type | URL (or anonymised) | Expected problems | Found correctly | False positives | Missed | Notes |
|---|---|---|---|---|---|---|---|
| 2026-10-28 | Static | example.com | none | n/a | 0 | 0 | "No sales action" WARNING is correct for this page |
