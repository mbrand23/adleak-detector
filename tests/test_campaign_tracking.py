"""Unit tests for campaign-URL analysis and tracking-signal classification."""

from adleak import campaign, tracking
from adleak.pagechecks import detect_challenge, whatsapp_problem


def statuses(findings, check):
    return [f.status for f in findings if f.check == check]


def test_utm_preserved_through_redirect():
    chain = [{"url": "https://a.com/go?utm_source=fb&utm_medium=cpc&utm_campaign=x", "status": 301},
             {"url": "https://a.com/offer?utm_source=fb&utm_medium=cpc&utm_campaign=x", "status": 200}]
    out = campaign.analyse(chain[0]["url"], chain, chain[-1]["url"])
    assert statuses(out, "utm_preservation") == ["PASSED"]


def test_utm_dropped_names_the_hop():
    chain = [{"url": "https://a.com/go?utm_source=fb&gclid=abc", "status": 302}, {"url": "https://a.com/offer", "status": 200}]
    out = campaign.analyse(chain[0]["url"], chain, chain[-1]["url"])
    lost = [f for f in out if f.check == "utm_preservation"][0]
    assert lost.status == "FAILED"
    assert any("First dropped by: 302 https://a.com/go" in e for e in lost.evidence)


def test_no_params_is_inconclusive_not_failed():
    out = campaign.analyse("https://a.com/", [{"url": "https://a.com/", "status": 200}], "https://a.com/")
    assert statuses(out, "utm_preservation") == ["INCONCLUSIVE"]


def test_domain_change_and_https_downgrade():
    chain = [{"url": "https://a.com/?utm_source=x", "status": 301}, {"url": "http://b.net/?utm_source=x", "status": 200}]
    out = campaign.analyse(chain[0]["url"], chain, chain[-1]["url"])
    assert statuses(out, "domain_change") == ["WARNING"]
    assert statuses(out, "https_downgrade") == ["FAILED"]


def test_macros_and_incomplete_utm():
    url = "https://a.com/?utm_source={{site_source_name}}&utm_campaign="
    out = campaign.analyse(url, [{"url": url, "status": 200}], url)
    assert statuses(out, "utm_macros") == ["WARNING"]
    assert statuses(out, "utm_complete") == ["WARNING"]


def test_tracking_classification():
    assert tracking.classify("https://connect.facebook.net/en_US/fbevents.js")["tag"] == "meta"
    ev = tracking.classify("https://www.facebook.com/tr/?id=123&ev=Purchase")
    assert ev["kind"] == "event" and ev["event"] == "Purchase" and ev["id"] == "123"
    assert tracking.classify("https://www.googletagmanager.com/gtm.js?id=GTM-ABC")["tag"] == "gtm"
    assert tracking.classify("https://www.googletagmanager.com/gtag/js?id=G-XYZ")["tag"] == "ga4"
    hit = tracking.classify("https://region1.google-analytics.com/g/collect?v=2&tid=G-XYZ", "en=page_view\nen=scroll")
    assert hit["event"] == "page_view,scroll"
    assert tracking.is_tracking_beacon("https://www.facebook.com/tr?id=1&ev=PageView")
    assert not tracking.is_tracking_beacon("https://www.facebook.com/mypage")
    assert tracking.classify("https://example.com/app.js") is None


def test_missing_expected_tag_is_warning_never_failed():
    out = tracking.build_findings([], [], {}, {"meta": True}, None)
    meta = [f for f in out if f.check == "meta_pixel"][0]
    assert meta.status == "WARNING" and "not proof" in meta.explanation
    out = tracking.build_findings([], [], {}, {}, None)
    assert all(f.status == "INCONCLUSIVE" for f in out)


def test_duplicate_pageview_detected():
    signals = [{"tag": "meta", "kind": "event", "event": "PageView", "id": "1", "url": "u"}] * 2
    out = tracking.build_findings(signals, [], {}, {}, None)
    assert any(f.check == "meta_pixel_duplicate" for f in out)


def test_whatsapp_link_validation():
    assert whatsapp_problem("https://wa.me/2348012345678") is None
    assert whatsapp_problem("https://wa.me/message/ABC123") is None
    assert "no phone number" in whatsapp_problem("https://wa.me/")
    assert "leading 0" in whatsapp_problem("https://wa.me/08012345678")
    assert whatsapp_problem("https://api.whatsapp.com/send?phone=2348012345678") is None
    assert whatsapp_problem("https://api.whatsapp.com/send?phone=") is not None


def test_challenge_detection():
    assert detect_challenge(403, "Just a moment...", "Checking your browser", {"server": "cloudflare"})
    assert detect_challenge(200, "x", "", {"cf-mitigated": "challenge"})
    assert detect_challenge(200, "Face cream", "Buy our face cream. " * 200, {}) is None
