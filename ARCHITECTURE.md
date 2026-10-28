# Architecture

AdLeak Detector is a small Python application with no web framework. One process serves the interface and the JSON API, keeps a scan queue, and drives Chromium through Playwright. Reports are JSON files on disk.

```
 Browser tab (web/)                 run.py
 index.html, app.js  ──HTTP──▶  adleak/server.py   127.0.0.1 only; Host/Origin checks
                                     │
                                     ├── adleak/plans.py     fair-use limits (free beta)
                                     ├── adleak/storage.py   data/scans/<id>.json, data/screenshots/<id>/
                                     └── adleak/jobs.py      queue + N worker threads (concurrency limit)
                                              │
                                              ▼
                                     adleak/engine.py  (one scan)
                                       ├── adleak/security.py   URL + destination policy
                                       ├── adleak/proxy.py      filtering egress proxy (per scan)
                                       ├── Chromium ── all traffic ──▶ proxy ──▶ public internet
                                       │     └── probe.js       read-only DOM inspection
                                       ├── adleak/links.py      link checks (also via the proxy)
                                       ├── adleak/pagechecks.py sales, layout, images, link findings
                                       ├── adleak/tracking.py   Meta / GA4 / GTM signals
                                       └── adleak/campaign.py   UTM + redirect analysis
```

## Scan lifecycle

1. `POST /api/scans` validates the URL (`security.validate_url`), checks fair use, writes a `queued` record and puts the job on the queue. The response is `202` with the scan id.
2. A worker thread marks the record `scanning` and calls `Scanner.scan`. Each real step appends a progress message to the record; the interface polls `GET /api/scans/<id>` and shows those messages. There is no simulated progress.
3. The scanner starts a fresh `EgressProxy` on a random loopback port and launches Chromium with `--proxy-server` pointing at it and `--proxy-bypass-list=<-loopback>`, so even loopback traffic goes through the proxy, where it is refused.
4. **Desktop pass** (1366x900) in a new browser context: navigate, wait for `load` and a short network-idle period, run `probe.js`, take screenshots, close the context. Timeouts, connection errors and 5xx responses are retried once, so a single failure isn't reported as fact.
5. If the page loaded: campaign analysis on the browser's redirect chain, tracking analysis on the requests the page made, and link checks (sales destinations first, at most `max_links`).
6. **Mobile pass** (390x844, touch, mobile user agent) repeats the page checks, and desktop and mobile sales actions are compared.
7. The report (findings sorted by status and severity, devices, redirect chain, blocked requests, limitations) is saved, the record becomes `completed`, `inconclusive` or `failed`, and old reports beyond the retention limit are removed.

States: `queued`, `scanning`, `completed`, `inconclusive` (the page couldn't be assessed: timeout, bot challenge, restricted address), `failed` (the scanner itself failed, or the app was closed mid-scan). Finding statuses: `PASSED`, `FAILED`, `WARNING`, `INCONCLUSIVE`.

## Network safety model

| Layer | What it does |
|---|---|
| `validate_url` | http/https only, no credentials in the URL, length and character checks, blocked hostnames and suffixes (`localhost`, `*.internal`, `*.local`, metadata names...), legacy IPv4 forms (`127.1`, `0x7f000001`, `2130706433`) expanded, allowed ports 80/443/8080/8443, DNS resolved and every address checked. |
| `ip_block_reason` | Refuses loopback, private, link-local, CGNAT, multicast, reserved, unspecified and cloud-metadata addresses, including IPv4 addresses embedded in IPv6 (mapped, 6to4, Teredo, NAT64). |
| `EgressProxy` | Applies the same policy to every browser and link-check connection, including each redirect hop and every sub-resource. It resolves DNS once and connects to the address it validated, so a DNS answer can't change between check and use. HTTPS is tunnelled (CONNECT), never decrypted. Byte budget, connection cap, idle timeouts. |
| Browser context | Fresh context per pass, service workers blocked, downloads refused, dialogs dismissed, popups closed, WebRTC limited to proxied traffic, no clicks or form input. |
| Tracking beacons | Requests to Meta `/tr`, GA4 `/g/collect` and Google Ads conversion endpoints are recorded and then aborted inside the browser, so scans don't pollute the site owner's analytics. |

These are application-level controls in one process. They are **not** enough for a public service: a bug in the proxy, Chromium or Playwright could still reach the local network. Before any public deployment, scans must run in isolated, disposable workers (container or VM) whose network egress is restricted by the network itself (firewall/egress gateway denying private ranges and metadata endpoints), with no credentials in the worker.

## Local server hardening

- Binds to `127.0.0.1` and refuses any non-loopback address.
- `Host` header must be `127.0.0.1:<port>`, `localhost:<port>` or `[::1]:<port>` (stops DNS-rebinding attacks from other websites). With `--tailscale`, this PC's private Tailscale name is also accepted, and only with an `https://` origin, because `tailscale serve` forwards that name to 127.0.0.1 over HTTPS (see PHONE_ACCESS.md). Extra names must be plain hostnames; wildcards, schemes and ports are rejected.
- State-changing requests (`POST`, `DELETE`) must be same-origin (`Origin` and `Sec-Fetch-Site` checks) and `application/json`, so other sites open in the browser can't start or delete scans.
- 8 KB request body limit; static files come from a fixed allow-list; scan IDs are 32-hex and screenshot names come from a fixed set, so no user input becomes a file path.
- Strict CSP (`script-src 'self'`, no inline script), `nosniff`, `X-Frame-Options: DENY`, `no-referrer`, `no-store`.
- The front end inserts scanned content with `textContent` only; only `http(s)` URLs become links, with `rel="noopener noreferrer nofollow"`.

## Data

`data/scans/<id>.json` holds one record:

```json
{ "id": "...", "workspace": "local", "plan": "free_beta", "submitted_url": "...", "state": "completed",
  "created_at": 0, "started_at": 0, "completed_at": 0, "options": {"expected_tags": {}, "screenshots": true},
  "progress": [{"at": 0, "message": "..."}],
  "report": { "final_url": "...", "devices": [], "redirect_chain": [], "findings": [], "summary": {},
              "network": {}, "limitations": [], "browser": "...", "engine_version": "0.1.0" } }
```

Writes are atomic (temp file + `os.replace`). Screenshots are only served through `/api/scans/<id>/screenshots/<name>` and are deleted with their report. Scans interrupted by closing the app are marked `failed` at the next start.

## Built for later growth

- **Accounts and workspaces:** every record has `workspace`. Moving to SQLite/Postgres means replacing `ReportStore` with a class of the same shape and filtering every query by workspace id.
- **Plans:** limits come from `plans.Plan`; `FUTURE_PLANS` lists the inactive Monitor and Agency tiers. There is no billing code.
- **Workers:** `ScanQueue` hands a URL and options to a `Scanner` and receives a report dict. A hosted version can swap the in-process queue for a job queue and run `Scanner` in isolated workers without changing the checks.
- **Monitoring:** a scheduler only needs to call `App.create_scan` on a timetable and compare `summary`/findings between reports.
