// AdLeak Detector front end. Everything that comes from a scanned website is
// inserted with textContent (never innerHTML), so page titles, link text and
// URLs can't inject markup into this interface.
"use strict";

const view = document.getElementById("view");
const CATEGORY_ORDER = [
  ["access", "Website accessibility"], ["campaign", "Ad campaign URL"], ["sales", "Sales actions"],
  ["links", "Links"], ["tracking", "Advertising tracking"], ["mobile", "Mobile and layout"],
  ["resources", "Page resources"], ["safety", "Scanner safety"],
];
const STATUS_ORDER = ["FAILED", "WARNING", "INCONCLUSIVE", "PASSED"];
const STATE_LABEL = { queued: "Queued", scanning: "Scanning", completed: "Completed", failed: "Failed", inconclusive: "Inconclusive" };
let pollTimer = null;

// ---------- helpers ----------
function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

// Only http(s) links from scan data become clickable, and they open in a new tab.
function extLink(url) {
  let parsed;
  try { parsed = new URL(url); } catch (e) { return el("span", { class: "mono", text: url || "" }); }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return el("span", { class: "mono", text: url });
  return el("a", { href: parsed.href, target: "_blank", rel: "noopener noreferrer nofollow", class: "mono", text: url });
}

async function api(path, options = {}) {
  const init = { method: options.method || "GET", headers: {} };
  if (options.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }
  let resp;
  try {
    resp = await fetch(path, init);
  } catch (e) {
    throw new Error("Can't reach the AdLeak server. Is the AdLeak window (start-windows.bat) still running?");
  }
  let data = null;
  try { data = await resp.json(); } catch (e) { /* non-JSON error */ }
  if (!resp.ok) throw new Error((data && data.error) || `Request failed (HTTP ${resp.status}).`);
  return data;
}

function fmtDate(seconds) {
  if (!seconds) return "";
  return new Date(seconds * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
function fmtTime(seconds) {
  return new Date(seconds * 1000).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
function statePill(state) {
  const busy = state === "queued" || state === "scanning";
  return el("span", { class: `pill st-${state}` }, busy && state === "scanning" ? el("span", { class: "spinner", "aria-hidden": "true" }) : null, STATE_LABEL[state] || state);
}
function setNav(name) {
  document.querySelectorAll("[data-nav]").forEach((a) => {
    if (a.dataset.nav === name) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
}
function stopPolling() { if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; } }

// Client-side check for obviously wrong input. The server does the real validation.
function precheckUrl(raw) {
  const value = raw.trim();
  if (!value) return "Enter a website address to scan.";
  if (value.length > 2048) return "That address is too long (over 2048 characters).";
  if (/\s/.test(value)) return "The address can't contain spaces.";
  if (/^[a-z][a-z0-9+.-]*:(?!\d)/i.test(value) && !/^https?:\/\//i.test(value)) return "Only http:// and https:// addresses can be scanned.";
  return null;
}

// ---------- home ----------
function renderHome(prefill) {
  stopPolling();
  setNav("home");
  view.replaceChildren(document.getElementById("home-template").content.cloneNode(true));
  const form = document.getElementById("scan-form");
  const input = document.getElementById("url-input");
  const errorBox = document.getElementById("form-error");
  const button = document.getElementById("scan-button");
  if (prefill) input.value = prefill;

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorBox.hidden = true;
    const problem = precheckUrl(input.value);
    if (problem) { errorBox.textContent = problem; errorBox.hidden = false; input.focus(); return; }
    button.disabled = true;
    button.textContent = "Checking address...";
    try {
      const body = {
        url: input.value.trim(),
        expected_tags: { meta: form.meta.checked, ga4: form.ga4.checked, gtm: form.gtm.checked },
        screenshots: form.screenshots.checked,
      };
      const result = await api("/api/scans", { method: "POST", body });
      location.hash = `#/scan/${result.id}`;
    } catch (e) {
      errorBox.textContent = e.message;
      errorBox.hidden = false;
      button.disabled = false;
      button.textContent = "Scan website";
    }
  });
  input.focus();
  api("/api/usage").then((u) => {
    const line = document.getElementById("usage-line");
    if (line) line.textContent = `${u.plan}: ${u.scans_last_hour} of ${u.limit_per_hour} scans used this hour. Up to ${u.max_links} links tested per scan.`;
  }).catch(() => {});
}

// ---------- scan / report ----------
async function renderScan(id) {
  stopPolling();
  setNav("");
  view.replaceChildren(el("p", { class: "muted", text: "Loading report..." }));
  let record;
  try {
    record = await api(`/api/scans/${id}`);
  } catch (e) {
    view.replaceChildren(el("div", { class: "empty" }, el("h2", { text: "Report not found" }), el("p", { text: e.message }),
      el("a", { class: "btn", href: "#/history", text: "Back to report history" })));
    return;
  }
  if (record.state === "queued" || record.state === "scanning") {
    renderProgress(record);
    pollTimer = setTimeout(() => { if (location.hash === `#/scan/${id}`) renderScan(id); }, 1500);
    return;
  }
  renderReport(record);
}

function renderProgress(record) {
  const items = (record.progress || []).map((p) => el("li", {}, el("time", { text: fmtTime(p.at) }), el("span", { text: p.message })));
  const elapsed = Math.max(0, Math.round(Date.now() / 1000 - (record.started_at || record.created_at)));
  view.replaceChildren(
    el("div", { class: "page-head" },
      el("div", {}, el("h1", { text: record.state === "queued" ? "Waiting to scan" : "Scanning" }),
        el("p", { class: "muted" }, extLink(record.submitted_url))),
      statePill(record.state)),
    el("div", { class: "panel", "aria-live": "polite" },
      el("p", { class: "muted", text: `Each line below is a step the scanner has actually started. Elapsed: ${elapsed}s. Most scans take 20-90 seconds.` }),
      el("ol", { class: "progress-list" }, items)));
}

function renderReport(record) {
  const report = record.report || {};
  const findings = report.findings || [];
  const summary = report.summary || {};

  const head = el("div", { class: "page-head" },
    el("div", {}, el("h1", { text: "Scan report" }), el("p", { class: "muted", text: fmtDate(record.completed_at || record.created_at) })),
    el("div", { class: "actions" },
      statePill(record.state),
      el("button", { class: "btn small", type: "button", onclick: () => rescan(record), text: "Scan again" }),
      el("button", { class: "btn small", type: "button", onclick: () => window.print(), text: "Print / save PDF" })));

  if (record.state === "failed") {
    view.replaceChildren(head, el("div", { class: "panel" },
      el("dl", { class: "meta-grid" }, el("dt", { text: "Website URL" }), el("dd", {}, extLink(record.submitted_url))),
      el("p", { class: "error-box", text: record.error || "The scan failed." }),
      el("p", { class: "muted", text: "No findings were produced, so nothing about the website should be concluded from this scan." })));
    return;
  }

  const devices = (report.devices || []).map((d) => `${d.label}: ${d.outcome === "ok" ? `loaded (HTTP ${d.status})` : d.outcome}`);
  const meta = el("dl", { class: "meta-grid" },
    el("dt", { text: "Website URL" }), el("dd", {}, extLink(report.submitted_url || record.submitted_url)),
    el("dt", { text: "Final destination" }), el("dd", {}, report.final_url ? extLink(report.final_url) : el("span", { class: "muted", text: "Not reached" })),
    el("dt", { text: "Date and time" }), el("dd", { text: fmtDate(record.completed_at) }),
    el("dt", { text: "Devices tested" }), el("dd", {}, devices.length ? el("span", { text: devices.join(" | ") }) : "None"),
    report.platforms && report.platforms.length ? [el("dt", { text: "Platform detected" }), el("dd", { text: report.platforms.join(", ") })] : null,
    el("dt", { text: "Scan details" }), el("dd", { class: "muted", text: `${report.duration_s ?? "?"}s, ${report.browser || ""}, engine ${report.engine_version || ""}` }));

  const counts = el("div", { class: "counts" }, STATUS_ORDER.map((s) =>
    el("div", { class: `count s-${s}` }, el("b", { text: summary[s] || 0 }), el("span", { text: s }))));

  const banner = record.state === "inconclusive"
    ? el("p", { class: "notice", text: "The page could not be fully assessed (see the first findings). This is not proof that the website is broken." })
    : null;

  const filterBar = el("div", { class: "filters", role: "group", "aria-label": "Filter findings" });
  const list = el("div", {});
  const filters = ["ALL", ...STATUS_ORDER];
  let active = (summary.FAILED || summary.WARNING) ? "ISSUES" : "ALL";
  filters.splice(1, 0, "ISSUES");
  const draw = () => {
    filterBar.replaceChildren(...filters.map((f) => el("button", {
      type: "button", "aria-pressed": String(f === active),
      onclick: () => { active = f; draw(); },
      text: f === "ALL" ? `All (${findings.length})` : f === "ISSUES" ? `Issues (${(summary.FAILED || 0) + (summary.WARNING || 0)})` : `${f[0]}${f.slice(1).toLowerCase()} (${summary[f] || 0})`,
    })));
    const shown = findings.filter((f) => active === "ALL" || (active === "ISSUES" ? (f.status === "FAILED" || f.status === "WARNING") : f.status === active));
    const groups = CATEGORY_ORDER.map(([key, label]) => {
      const items = shown.filter((f) => f.category === key);
      if (!items.length) return null;
      return [el("h3", { class: "category", text: label }), items.map(renderFinding)];
    }).filter(Boolean);
    list.replaceChildren(...(groups.length ? groups.flat(2) : [el("p", { class: "empty", text: "No findings match this filter." })]));
  };
  draw();

  const shots = [];
  for (const d of report.devices || []) {
    for (const s of d.screenshots || []) {
      const src = `/api/scans/${record.id}/screenshots/${encodeURIComponent(s.name)}`;
      shots.push(el("figure", {}, el("a", { href: src, target: "_blank", rel: "noopener" }, el("img", { src, alt: s.label, loading: "lazy" })),
        el("figcaption", { text: s.label })));
    }
  }

  const chain = report.redirect_chain || [];
  const chainTable = chain.length > 1 ? el("div", { class: "panel" }, el("h2", { text: "Redirect chain" }),
    el("table", {}, el("thead", {}, el("tr", {}, el("th", { text: "#" }), el("th", { text: "Status" }), el("th", { text: "URL" }))),
      el("tbody", {}, chain.map((h, i) => el("tr", {}, el("td", { text: i + 1 }), el("td", { text: h.status ?? "" }), el("td", {}, el("span", { class: "mono", text: h.url }))))))) : null;

  view.replaceChildren(...[
    head,
    el("div", { class: "panel" }, meta, counts),
    banner,
    el("h2", { text: "Findings" }), filterBar, list,
    shots.length ? el("div", { class: "panel" }, el("h2", { text: "Screenshots" }), el("div", { class: "shots" }, shots)) : null,
    chainTable,
    el("div", { class: "panel" }, el("h2", { text: "Limitations of this scan" }),
      el("ul", { class: "muted" }, (report.limitations || []).map((l) => el("li", { text: l })))),
  ].filter(Boolean));
}

function renderFinding(f) {
  const evidence = (f.evidence || []).length
    ? el("details", { class: "evidence" }, el("summary", { text: `Evidence (${f.evidence.length})` }), el("ul", {}, f.evidence.map((e) => el("li", { text: e }))))
    : null;
  return el("article", { class: `finding b-${f.status}` },
    el("div", { class: "finding-head" },
      el("span", { class: `pill s-${f.status}`, text: f.status }),
      el("h4", { text: f.title }),
      f.severity && f.severity !== "info" ? el("span", { class: "sev", text: `${f.severity} severity` }) : null,
      f.device && f.device !== "all" ? el("span", { class: "tag", text: f.device }) : null),
    el("p", { text: f.explanation }),
    f.recommendation ? el("p", { class: "fix" }, el("b", { text: "How to fix: " }), f.recommendation) : null,
    evidence);
}

async function rescan(record) {
  try {
    const result = await api("/api/scans", { method: "POST", body: { url: record.submitted_url, ...(record.options || {}) } });
    location.hash = `#/scan/${result.id}`;
  } catch (e) {
    alert(e.message);
  }
}

// ---------- history ----------
async function renderHistory() {
  stopPolling();
  setNav("history");
  view.replaceChildren(el("p", { class: "muted", text: "Loading report history..." }));
  let data;
  try {
    data = await api("/api/scans");
  } catch (e) {
    view.replaceChildren(el("p", { class: "error-box", text: e.message }));
    return;
  }
  const scans = data.scans || [];
  const head = el("div", { class: "page-head" }, el("h1", { text: "Report history" }), el("a", { class: "btn primary", href: "#/", text: "New scan" }));
  if (!scans.length) {
    view.replaceChildren(head, el("div", { class: "empty panel" }, el("h2", { text: "No scans yet" }),
      el("p", { text: "Reports you run are saved on this computer and will appear here." }),
      el("a", { class: "btn primary", href: "#/", text: "Scan your first website" })));
    return;
  }
  const rows = scans.map((s) => {
    const counts = s.summary ? el("span", { class: "mini-counts" }, STATUS_ORDER.filter((k) => s.summary[k]).map((k) =>
      el("span", { class: `pill s-${k}`, title: k, text: `${s.summary[k]} ${k.toLowerCase()}` }))) : null;
    return el("div", { class: "panel history-item" },
      el("div", {},
        el("a", { class: "url", href: `#/scan/${s.id}`, text: s.submitted_url }),
        el("div", { class: "sub" }, statePill(s.state), el("span", { text: fmtDate(s.created_at) }), counts)),
      el("div", { class: "actions" },
        el("a", { class: "btn small", href: `#/scan/${s.id}`, text: "Open" }),
        s.state === "queued" || s.state === "scanning" ? null : el("button", {
          class: "btn small danger", type: "button", text: "Delete",
          onclick: async () => {
            if (!confirm("Delete this report and its screenshots?")) return;
            try { await api(`/api/scans/${s.id}`, { method: "DELETE" }); renderHistory(); } catch (e) { alert(e.message); }
          },
        })));
  });
  view.replaceChildren(head, el("p", { class: "muted", text: `${scans.length} report${scans.length === 1 ? "" : "s"} stored on this computer (oldest are removed after 200).` }), ...rows);
}

// ---------- router ----------
function route() {
  const hash = location.hash || "#/";
  const scan = hash.match(/^#\/scan\/([0-9a-f]{32})$/);
  if (scan) return renderScan(scan[1]);
  if (hash === "#/history") return renderHistory();
  return renderHome();
}
window.addEventListener("hashchange", () => { route(); view.focus({ preventScroll: true }); window.scrollTo(0, 0); });
route();
