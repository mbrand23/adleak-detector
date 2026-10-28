// Read-only inspection of the loaded page. Runs inside the scanned page via
// page.evaluate(). It never clicks, types or submits anything.
() => {
  // Mobile Chrome zooms an overflowing page out to fit, which inflates
  // innerWidth, so the device's own width is the reference.
  const vw = Math.min(window.innerWidth, screen.width || window.innerWidth);
  const vh = Math.min(window.innerHeight, screen.height || window.innerHeight);
  const clip = (s, n) => (s || "").replace(/\s+/g, " ").trim().slice(0, n);

  const sel = (el) => {
    if (!el || !el.tagName) return "";
    let s = el.tagName.toLowerCase();
    if (el.id) s += "#" + el.id.slice(0, 40);
    const cls = (typeof el.className === "string" ? el.className : "").trim().split(/\s+/).filter(Boolean).slice(0, 2);
    if (cls.length) s += "." + cls.join(".");
    return s.slice(0, 90);
  };

  const visible = (el) => {
    const r = el.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) return false;
    for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
      const cs = getComputedStyle(n);
      if (cs.display === "none" || cs.visibility === "hidden" || parseFloat(cs.opacity) === 0) return false;
    }
    return true;
  };

  const covering = (el) => {
    const r = el.getBoundingClientRect();
    const x = r.left + r.width / 2, y = r.top + r.height / 2;
    if (x < 0 || y < 0 || x > vw || y > vh) return null;
    const hit = document.elementFromPoint(x, y);
    if (!hit || hit === el || el.contains(hit) || hit.contains(el)) return null;
    return sel(hit);
  };

  // ---- Sales actions -----------------------------------------------------
  const CTA = /\b(order now|order|buy now|buy it now|buy|add to cart|add to bag|add to basket|checkout|check out|shop now|purchase|book now|book a call|get started|sign up|subscribe|contact us|contact|get a quote|request a quote|enquire|inquire|call now|call us|whatsapp|chat with us|claim|get offer|pre-order)\b/i;
  const kindOf = (text, href, el) => {
    const h = (href || "").toLowerCase();
    if (/wa\.me|whatsapp\.com|^whatsapp:/.test(h) || /whatsapp/i.test(text)) return "whatsapp";
    if (h.startsWith("tel:") || /call (now|us)/i.test(text)) return "call";
    if (h.startsWith("mailto:")) return "email";
    if (/add to (cart|bag|basket)/i.test(text) || (el.form && /\/cart\/add/.test(el.form.getAttribute("action") || ""))) return "add_to_cart";
    if (/checkout|check out/i.test(text)) return "checkout";
    if (/order|buy|purchase|shop now|pre-order|claim|get offer/i.test(text)) return "buy";
    if (/contact|quote|enquire|inquire|chat/i.test(text)) return "contact";
    if (/sign up|subscribe|get started|book/i.test(text)) return "lead";
    return "other";
  };

  const ctaEls = Array.from(document.querySelectorAll("a, button, input[type=submit], input[type=button], [role=button]")).slice(0, 4000);
  const actions = [];
  for (const el of ctaEls) {
    const text = clip(el.innerText || el.value || el.getAttribute("aria-label") || el.title, 80);
    const href = el.tagName === "A" ? el.getAttribute("href") : null;
    const inCartForm = el.form && /\/cart\/add/.test(el.form.getAttribute("action") || "");
    const hrefHit = href && /wa\.me|whatsapp\.com|^whatsapp:|^tel:|\/cart|\/checkout/i.test(href);
    if (!CTA.test(text) && !hrefHit && !inCartForm) continue;
    const r = el.getBoundingClientRect();
    const isVisible = visible(el);
    actions.push({
      text, selector: sel(el), tag: el.tagName.toLowerCase(), kind: kindOf(text, href, el),
      href, abs_href: el.tagName === "A" ? el.href : null,
      form_action: el.form ? el.form.action : null,
      disabled: !!(el.disabled || el.getAttribute("aria-disabled") === "true" || /(^|\s)(disabled|sold-?out)(\s|$)/i.test(el.className || "")),
      visible: isVisible,
      above_fold: isVisible && r.top < vh && r.bottom > 0,
      top: Math.round(r.top + window.scrollY),
      covered_by: isVisible ? covering(el) : null,
      size: [Math.round(r.width), Math.round(r.height)],
    });
    if (actions.length >= 60) break;
  }

  const forms = Array.from(document.forms).slice(0, 30).map((f) => ({
    selector: sel(f),
    action: f.getAttribute("action"),
    abs_action: f.action,
    method: (f.getAttribute("method") || "get").toLowerCase(),
    lead: !!f.querySelector("input[type=email], input[type=tel], input[name*=email i], input[name*=phone i], textarea"),
    cart: /\/cart\/add/.test(f.getAttribute("action") || ""),
    visible: visible(f),
    fields: f.querySelectorAll("input:not([type=hidden]), select, textarea").length,
  }));

  // ---- Links ---------------------------------------------------------------
  const links = Array.from(document.querySelectorAll("a[href]")).slice(0, 800).map((a) => {
    const raw = a.getAttribute("href");
    let anchor_ok = null;
    if (raw && raw.length > 1 && raw.startsWith("#") && !raw.startsWith("#!")) {
      let id = raw.slice(1);
      try { id = decodeURIComponent(id); } catch (e) {}
      anchor_ok = !!(document.getElementById(id) || document.getElementsByName(id).length);
    }
    return { raw, abs: a.href, text: clip(a.innerText || a.getAttribute("aria-label") || a.title, 60), visible: visible(a), selector: sel(a), anchor_ok };
  });

  // ---- Images --------------------------------------------------------------
  const images = Array.from(document.images).slice(0, 600).map((img) => {
    const r = img.getBoundingClientRect();
    return {
      src: (img.currentSrc || img.src || "").slice(0, 400),
      complete: img.complete, natural_width: img.naturalWidth,
      lazy: img.loading === "lazy", visible: visible(img),
      in_viewport: r.top < vh && r.bottom > 0, selector: sel(img),
      rendered_width: Math.round(r.width),
    };
  });

  // ---- Layout --------------------------------------------------------------
  const docEl = document.documentElement;
  const scrollWidth = Math.max(docEl.scrollWidth, document.body ? document.body.scrollWidth : 0);
  const offenders = [];
  if (scrollWidth > vw + 1) {
    const clipped = (el) => {
      for (let n = el.parentElement; n && n !== document.body && n !== docEl; n = n.parentElement) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === "hidden" || ox === "auto" || ox === "scroll" || ox === "clip") return true;
      }
      return false;
    };
    const all = Array.from(document.body ? document.body.querySelectorAll("*") : []).slice(0, 5000);
    for (const el of all) {
      const r = el.getBoundingClientRect();
      if (r.right <= vw + 1 || r.width < 1) continue;
      const parent = el.parentElement;
      if (parent && parent !== document.body && parent.getBoundingClientRect().right > vw + 1 && !clipped(el)) continue;
      if (clipped(el) || !visible(el)) continue;
      offenders.push({ selector: sel(el), right: Math.round(r.right), width: Math.round(r.width) });
    }
    offenders.sort((a, b) => b.right - a.right);
  }
  const vpMeta = document.querySelector('meta[name="viewport" i]');

  // ---- Consent banner ------------------------------------------------------
  const CONSENT = ["#onetrust-banner-sdk", "#CybotCookiebotDialog", "#cookiebanner", ".cc-window", "#cookie-law-info-bar",
    ".cky-consent-container", "#usercentrics-root", "#truste-consent-track", ".fc-consent-root", "#didomi-host",
    "#cmplz-cookiebanner-container", ".cmplz-cookiebanner", "#moove_gdpr_cookie_info_bar", "#shopify-pc__banner",
    "[id*=cookie-banner i]", "[class*=cookie-banner i]", "[id*=cookie-consent i]", "[class*=cookie-consent i]", "[aria-label*=cookie i]"];
  let consent = null;
  for (const s of CONSENT) {
    let el = null;
    try { el = document.querySelector(s); } catch (e) {}
    if (el && visible(el)) { consent = s; break; }
  }

  // ---- Platform hints ------------------------------------------------------
  const html = docEl.outerHTML.slice(0, 400000);
  const gen = (document.querySelector('meta[name="generator" i]') || {}).content || "";
  const platforms = [];
  if (window.Shopify || /cdn\.shopify\.com/.test(html)) platforms.push("Shopify");
  if (/wordpress/i.test(gen) || /\/wp-content\//.test(html)) platforms.push("WordPress");
  if (/woocommerce/i.test(gen) || (document.body && /\bwoocommerce\b/.test(document.body.className))) platforms.push("WooCommerce");
  if (/elementor/i.test(gen) || /elementor-/.test(html)) platforms.push("Elementor");
  if (/thrive|tve_|tcb-/i.test(html.slice(0, 200000))) platforms.push("Thrive Architect");

  // ---- Tracking globals ----------------------------------------------------
  const gtm = window.google_tag_manager ? Object.keys(window.google_tag_manager).filter((k) => /^(GTM|G|GT|AW)-/.test(k)) : [];

  // ---- Timing --------------------------------------------------------------
  const nav = performance.getEntriesByType("navigation")[0];
  const timing = nav ? {
    ttfb_ms: Math.round(nav.responseStart), dom_content_loaded_ms: Math.round(nav.domContentLoadedEventEnd),
    load_ms: Math.round(nav.loadEventEnd), transfer_bytes: nav.transferSize || null,
  } : null;

  return {
    title: clip(document.title, 200),
    text_sample: clip(document.body ? document.body.innerText : "", 3000),
    viewport: [vw, vh],
    scroll_width: scrollWidth,
    scroll_height: Math.max(docEl.scrollHeight, document.body ? document.body.scrollHeight : 0),
    overflow_offenders: offenders.slice(0, 6),
    viewport_meta: vpMeta ? vpMeta.getAttribute("content") : null,
    actions, forms, links, images, consent, platforms, timing,
    globals: { fbq: typeof window.fbq === "function", gtag: typeof window.gtag === "function",
      data_layer: Array.isArray(window.dataLayer) ? window.dataLayer.length : null, gtm_containers: gtm },
    meta_refresh: (document.querySelector('meta[http-equiv="refresh" i]') || {}).content || null,
  };
}
