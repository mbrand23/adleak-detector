# Roadmap

The business model is **free to scan, pay to monitor**. The local beta proves the scanner first; hosting and billing come after it has been tested on real customer sites.

## Done: Milestone 1, local scanning beta (v0.1.0)

- Scanning engine: accessibility, redirects, broken and placeholder links, sales actions, WhatsApp links, Meta Pixel / GA4 / GTM signals, UTM and click-ID preservation, desktop and mobile layout, failed resources, JS errors, load timing, screenshots.
- Retries before reporting navigation failures; inconclusive results kept separate from failures.
- Egress proxy with SSRF policy, DNS pinning, byte budget; hardened localhost server.
- Interface: home, live scan progress, report with filters/evidence/screenshots, report history, print to PDF.
- Local JSON persistence, retention, interrupted-scan recovery, fair-use limits.
- Automated test suite against a controlled fixture site.

## Next: Milestone 2, real-site validation and report quality

1. Scan 20-30 authorised real sites (Shopify, WooCommerce, Elementor, Thrive, custom) and record false positives / missed problems in TEST_PLAN.md.
2. Tune sales-action detection from those results (icon-only buttons, non-English labels, Shopify variant pickers).
3. Owner-verified advanced checks (opt-in, non-destructive): open the WhatsApp/checkout destination without sending, click "Add to cart" on a verified site and confirm the cart count changes, then empty it.
4. Exportable PDF/HTML client report and a "share with my developer" summary.
5. Lighthouse-style performance metrics (LCP, CLS) from the browser's PerformanceObserver.
6. Consent-aware tracking check: a second, owner-approved pass that records which tags fire after consent is given.

## Milestone 3: monitoring (first paid feature)

- Saved websites and scheduled rescans (hourly/daily).
- Change detection: alert when a finding appears or a passed check starts failing.
- Email notifications (SMTP provider, opt-in).
- History charts per site.

## Milestone 4: accounts and agencies

- Authentication (email + password with hashing, or a hosted identity provider).
- Workspaces with strict per-workspace data separation (every query filtered by workspace id; tested).
- Account types: individual, online store, marketer, agency. Agency client workspaces, team roles (owner, editor, viewer).
- Admin dashboard: usage, failed scans, abuse reports.

## Milestone 5: public deployment (prerequisites)

Must be done before the scanner is reachable by anyone other than its owner:

- Scans in isolated, disposable workers (container/VM per scan or per small batch), no secrets inside.
- Network-level egress restrictions on workers: deny RFC 1918, loopback, link-local, CGNAT, metadata endpoints and IPv6 equivalents at the firewall, not only in code.
- Job queue and database instead of local files; object storage for screenshots with expiry.
- Abuse controls: per-account and per-IP rate limits, target-domain throttling, robots/opt-out handling, reporting channel.
- TLS, CSRF tokens and session security for the hosted interface; dependency and container image updates; external penetration test.
- Privacy policy and terms; screenshot retention policy.

## Milestone 6: billing

- Plans from `adleak/plans.py` (Monitor, Agency) attached to accounts.
- Payment provider checkout and webhooks; usage metering for scheduled scans.
- Core one-off scanning stays free.
