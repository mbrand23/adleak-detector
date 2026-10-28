"""End-to-end scans of the controlled fixture site with a real Chromium browser.

Covers test plan items 1-9: working page, broken page, broken/placeholder
links, disabled buttons, missing tags, UTM preservation, mobile layout,
failed resources, and blocked / timed-out scans.
"""

import pytest

from conftest import by_check, titles

pytestmark = pytest.mark.browser
_cache = {}


def scan(scanner, url, **options):
    key = (url, tuple(sorted(options.items())))
    if key not in _cache:
        _cache[key] = scanner.scan(url, f"{len(_cache):032x}", {"expected_tags": options} if options else {})
    return _cache[key]


def statuses(report, check, device=None):
    return sorted({f["status"] for f in by_check(report, check, device)})


def test_working_sales_page(scanner, fixture_site):
    r = scan(scanner, fixture_site["base"] + "/good.html")
    assert r["outcome"] == "completed"
    assert [f for f in r["findings"] if f["status"] == "FAILED"] == [], titles(r)
    assert statuses(r, "reachability") == ["PASSED"]
    assert statuses(r, "sales_presence", "desktop") == ["PASSED"]
    assert statuses(r, "links_ok") == ["PASSED"]
    assert statuses(r, "overflow", "mobile") == ["PASSED"]
    assert statuses(r, "meta_pixel") == ["PASSED"]
    assert statuses(r, "ga4") == ["PASSED"]
    assert statuses(r, "gtm") == ["PASSED"]
    assert statuses(r, "utm_preservation") == ["INCONCLUSIVE"]  # no params submitted -> not tested
    assert {d["device"] for d in r["devices"]} == {"desktop", "mobile"}
    assert any(s["name"] == "mobile.png" for d in r["devices"] for s in d["screenshots"])
    evidence = " ".join(by_check(r, "meta_pixel")[0]["evidence"])
    assert "111222333" in evidence and "PageView" in evidence


def test_tracking_beacons_are_blocked_not_delivered(scanner, fixture_site):
    r = scan(scanner, fixture_site["base"] + "/good.html")
    # The scanner saw the events (see test above) but the beacons never left the browser.
    assert by_check(r, "meta_pixel")[0]["status"] == "PASSED"
    assert fixture_site["hits"].get("/tr", 0) == 0
    assert fixture_site["hits"].get("/g/collect", 0) == 0
    assert fixture_site["hits"].get("/gtag/js", 0) >= 1  # the tag script itself was loaded


def test_deliberately_broken_page(scanner, fixture_site):
    r = scan(scanner, fixture_site["base"] + "/broken.html")
    assert r["outcome"] == "completed"
    broken = by_check(r, "broken_links")
    assert broken and broken[0]["status"] == "FAILED"
    assert any("/status/404" in e for e in broken[0]["evidence"])
    assert statuses(r, "server_error_links") == ["WARNING"]
    assert statuses(r, "placeholder_links") == ["WARNING"]
    assert statuses(r, "anchor_links") == ["WARNING"]
    assert "WARNING" in statuses(r, "sales_disabled")
    assert "WARNING" in statuses(r, "sales_placeholder")
    assert "FAILED" in statuses(r, "whatsapp_link")
    assert "FAILED" in statuses(r, "images")
    assert "FAILED" in statuses(r, "failed_resources")
    assert any("missing.js" in e for f in by_check(r, "failed_resources") for e in f["evidence"])
    assert "WARNING" in statuses(r, "js_errors")


def test_mobile_horizontal_overflow(scanner, fixture_site):
    r = scan(scanner, fixture_site["base"] + "/overflow.html")
    overflow = [f for f in by_check(r, "overflow") if f["device"] == "mobile"][0]
    assert overflow["status"] == "FAILED"
    assert any("table.wide" in e for e in overflow["evidence"])
    assert [f["status"] for f in by_check(r, "overflow") if f["device"] == "desktop"] == ["PASSED"]
    mobile_cta = by_check(r, "mobile_cta")
    assert mobile_cta and any("Order now" in e for e in mobile_cta[0]["evidence"])


def test_missing_viewport_tag(scanner, fixture_site):
    r = scan(scanner, fixture_site["base"] + "/broken.html")
    # No viewport tag: phones lay the page out at desktop width and zoom out, so the fix is the tag itself.
    assert statuses(r, "viewport_meta", "mobile") == ["FAILED"]
    assert not [f for f in by_check(r, "overflow") if f["device"] == "mobile"]


def test_private_resources_and_links_are_blocked(scanner, fixture_site):
    r = scan(scanner, fixture_site["base"] + "/broken.html")
    blocked = by_check(r, "egress_blocked")
    assert blocked and any("192.168.1.20" in e for e in blocked[0]["evidence"])
    assert by_check(r, "private_links")
    assert any(b["host"] == "192.168.1.20" for b in r["network"]["blocked_requests"])


def test_utm_preserved_across_two_redirects(scanner, fixture_site):
    url = fixture_site["base"] + "/redirect/two?utm_source=facebook&utm_medium=paid&utm_campaign=spring&fbclid=abc"
    r = scan(scanner, url)
    assert statuses(r, "utm_preservation") == ["PASSED"]
    assert [h["status"] for h in r["redirect_chain"]] == [301, 301, 200]
    assert r["final_url"].endswith("/good.html?utm_source=facebook&utm_medium=paid&utm_campaign=spring&fbclid=abc")


def test_utm_dropped_by_redirect(scanner, fixture_site):
    r = scan(scanner, fixture_site["base"] + "/redirect/drop?utm_source=google&utm_medium=cpc&utm_campaign=x&gclid=123")
    lost = by_check(r, "utm_preservation")[0]
    assert lost["status"] == "FAILED"
    assert any("gclid" in e for e in lost["evidence"])
    assert any("First dropped by: 302" in e for e in lost["evidence"])


def test_missing_expected_tags(scanner, fixture_site):
    r = scan(scanner, fixture_site["base"] + "/notags.html", meta=True, ga4=True)
    assert statuses(r, "meta_pixel") == ["WARNING"]
    assert statuses(r, "ga4") == ["WARNING"]
    assert statuses(r, "gtm") == ["INCONCLUSIVE"]   # not expected -> informational only
    assert [f for f in r["findings"] if f["status"] == "FAILED"] == [], titles(r)


def test_http_error_page(scanner, fixture_site):
    r = scan(scanner, fixture_site["base"] + "/status/404")
    assert statuses(r, "reachability", "desktop") == ["FAILED"]
    assert "404" in by_check(r, "reachability")[0]["title"]
    assert by_check(r, "skipped")


def test_timeout_is_inconclusive_and_retried(scanner, fixture_site):
    r = scan(scanner, fixture_site["base"] + "/slow")
    assert r["outcome"] == "inconclusive"
    access = by_check(r, "reachability", "desktop")[0]
    assert access["status"] == "INCONCLUSIVE"
    assert len(r["devices"][0]["attempts"]) == 2


def test_redirect_to_private_address_is_refused(scanner, fixture_site):
    r = scan(scanner, fixture_site["base"] + "/redirect/private")
    assert r["outcome"] == "inconclusive"
    refused = [f for f in r["findings"] if f["category"] == "safety"]
    assert refused and refused[0]["status"] in ("INCONCLUSIVE", "WARNING")
    assert any(b["host"] == "10.255.255.1" for b in r["network"]["blocked_requests"])


def test_redirect_loop(scanner, fixture_site):
    r = scan(scanner, fixture_site["base"] + "/redirect/loop")
    assert statuses(r, "reachability", "desktop") == ["FAILED"]
    assert "loop" in by_check(r, "reachability")[0]["title"].lower()


def test_intermittent_failure_is_corroborated(scanner, fixture_site):
    r = scan(scanner, fixture_site["base"] + "/flaky")
    assert statuses(r, "intermittent", "desktop") == ["WARNING"]
    assert r["devices"][0]["attempts"][0]["status"] == 503
