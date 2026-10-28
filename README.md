# AdLeak Detector (local beta)

AdLeak Detector checks a website or ad landing page for technical problems that waste paid traffic. Paste a URL, click **Scan website**, and a real Chromium browser loads the page as a desktop and as a phone. The report lists what passed, what failed, what needs a look and what couldn't be verified, with evidence and a suggested fix for each.

It runs entirely on your Windows computer at `http://127.0.0.1:8765/`. No hosting, domain, account, plugin or ad-platform login is needed, and nothing is published.

## Start it on Windows

1. Install **Python 3.10 or newer** from <https://www.python.org/downloads/windows/>. During setup, tick **"Add python.exe to PATH"**.
2. Open the `AdLeak_Detector` folder and double-click **`start-windows.bat`**.
   - The first run creates `.venv`, installs the Python packages and downloads Chromium into `.browsers` (about 400 MB, all inside this folder). Later runs start in a few seconds.
3. Your browser opens at <http://127.0.0.1:8765/>. Keep the black window open while you use the app; close it (or press Ctrl+C) to stop.

Running it from a terminal instead:

```bash
.venv\Scripts\python.exe run.py
```

Options: `--port 8766` to use another port, `--no-browser` to stop the browser opening. Reports are stored in `data\` (set `ADLEAK_DATA_DIR` to move them).

### Use it from your phone

Install Tailscale on this PC and your phone, then start AdLeak with **`start-with-tailscale.bat`**. Your phone opens it at a private `https://<your-pc>.<tailnet>.ts.net/` address that only your own devices can reach. Step-by-step setup is in [PHONE_ACCESS.md](PHONE_ACCESS.md). Never use `tailscale funnel` with AdLeak: that would make it public.

## What a scan checks

| Area | Examples |
|---|---|
| Page access | HTTP status, redirects and final URL, DNS/SSL failures, timeouts (retried once), redirect loops, load time |
| Links | Up to 40 links per scan, sales buttons first: 404s, dead domains, server errors (retried), placeholder `#` links, missing page anchors, links to localhost/private addresses |
| Sales actions | Order Now, Buy Now, Add to Cart, Checkout, WhatsApp, Call, Contact, lead forms: found, visible, enabled, not covered, pointing somewhere real; WhatsApp number format; hidden on mobile |
| Tracking | Meta Pixel, Google Analytics 4 and Google Tag Manager scripts and events seen in the browser, duplicate installs, tags you said should be there |
| Ad campaign URL | Whether UTM and click-ID parameters (gclid, fbclid...) survive every redirect, and which hop drops them; domain changes; HTTPS downgrade; script redirects |
| Mobile and layout | Horizontal overflow and the elements causing it, viewport tag, zoom disabled, small tap targets |
| Resources | Broken images, failed scripts and stylesheets, JavaScript errors |

Results are **PASSED**, **FAILED**, **WARNING** or **INCONCLUSIVE**. Inconclusive means the scanner couldn't get a trustworthy answer (bot protection, timeout, not applicable); it is never counted as a failure.

## What it won't do

- Click buttons, submit forms, place orders, pay, send WhatsApp messages or accept cookie banners.
- Get around CAPTCHAs or bot protection. Those scans are reported as inconclusive.
- Claim to know how much ad money was lost, or that tracking is broken because a browser signal was missing. Consent settings, ad blockers and server-side tracking can all hide signals.
- Send fake analytics: Meta and Google beacons are recorded and then blocked inside the scanner.
- Scan localhost, private networks, cloud metadata addresses or non-web ports.

## Known limitations

- Tested against a controlled fixture site and example.com only. Real Shopify, WordPress/WooCommerce, Elementor and Thrive pages haven't been scanned yet, so expect some missed or mislabelled sales buttons on unusual themes.
- Sales buttons are recognised by their wording (English) and link targets. Icon-only or image buttons can be missed.
- Tracking checks see only what the browser sends in the first few seconds without consent. Events fired on scroll, click or purchase are not tested.
- One measurement per scan: timings depend on this computer's connection.
- Single-user and local: no accounts, scheduling, alerts or email yet.

## Run the tests

```bash
.venv\Scripts\python.exe -m pytest
```

The browser tests start a small fixture website on 127.0.0.1 and scan it. Skip them with `-m "not browser"`. See TEST_PLAN.md for what each test covers and the latest results.

## Project layout

```
run.py, start-windows.bat   start the app
adleak/server.py            local web server + JSON API (127.0.0.1 only)
adleak/jobs.py              scan queue and worker threads
adleak/engine.py            runs a scan in Chromium (desktop + mobile)
adleak/probe.js             read-only inspection inside the page
adleak/pagechecks.py        sales, layout, image and link findings
adleak/tracking.py          Meta Pixel / GA4 / GTM detection
adleak/campaign.py          UTM and redirect analysis
adleak/links.py             link checking
adleak/security.py          URL and destination safety policy
adleak/proxy.py             filtering proxy every scan connection goes through
adleak/storage.py           JSON reports and screenshots in data/
adleak/plans.py             free-beta fair-use limits (no billing)
web/                        interface (HTML, CSS, JavaScript)
tests/                      automated tests and fixture site
```

More detail: PROJECT_SPEC.md (what it does), ARCHITECTURE.md (how it works and the security model), ROADMAP.md (what's next), TEST_PLAN.md (testing).

## Security status

The safety controls are application-level and have been tested only against the cases in `tests/`. They are suitable for one person running the app on their own computer. **They are not production-ready for a public service.** Before the scanner is offered to anyone else it needs isolated scan workers and network-level egress restrictions (see ARCHITECTURE.md and ROADMAP.md). Don't expose port 8765 to your network or the internet; the server refuses to bind to anything except 127.0.0.1.
