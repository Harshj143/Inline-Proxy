"use strict";
const $ = (id) => document.getElementById(id);

// event -> [cssClass, tagText, tool, whyText]. cssClass doubles as filter category.
const SPEC = {
  tool_call_allowed:      (e) => [e.action === "redact" ? "redact" : "allow",
                                  (e.action || "allow").toUpperCase(), e.tool, e.reason || ""],
  tool_result_redacted:   (e) => ["redact", "REDACTED", e.tool,
                                  "stripped " + fmt(e.redactions)],
  tool_call_rewritten:    (e) => ["rewrite", "REWRITE", e.tool,
                                  "args rewritten: " + fmt(e.rewrites)],
  tool_call_quarantined:  (e) => ["quarantine", "QUARANTINE", e.tool, e.reason || "result withheld"],
  tool_result_quarantined:(e) => ["quarantine", "QUARANTINED", e.tool, "result withheld from model"],
  approval_requested:     (e) => ["approval", e.approved ? "APPROVED" : "DENIED",
                                  e.tool, e.reason || ""],
  tool_call_blocked:      (e) => ["block", "BLOCKED", e.tool, e.reason || ""],
  tool_call_blocked_by_sequence: (e) => ["block", "BLOCKED", e.tool, e.reason || ""],
  tool_call_denied_session_suspended: (e) => ["block", "DENIED", e.tool,
                                  "session suspended (score " + e.session_score + ")"],
  session_tainted:        (e) => ["block", "TAINTED", e.tool, e.note || ""],
  session_suspended:      (e) => ["block", "SUSPENDED", "", "risk " + e.session_score + " ≥ 80"],
  anomaly_detected:       (e) => ["anomaly", "ANOMALY " + up(e.severity), e.tool, e.rationale || ""],
  gateway_start:          (e) => ["info", "SESSION UP", "",
                                  "role=" + (e.role || "-") + " · anomaly=" + (e.anomaly_backend || "off")
                                  + " · " + short(e.upstream)],
  gateway_stop:           (e) => ["info", "SESSION DOWN", "", ""],
};
const fmt = (o) => { try { return JSON.stringify(o); } catch { return ""; } };
const up = (s) => (s || "").toUpperCase();
const short = (s) => { s = s || ""; const p = s.split(" "); return p[p.length - 1] || s; };

// ---- state
let viewMode = "live";
let paused = false;
let filterType = "all";
let filterText = "";
const live = freshState();
let liveRecords = [];
const pending = new Map();   // approval id -> element
let activePolicyRaw = null;

function freshState() {
  return { score: 0, level: "NORMAL", tainted: false, redactions: 0, blocked: 0, points: [] };
}

// ---- metrics
function applyState(s) {
  $("m-score").firstChild.nodeValue = s.score + " ";
  const lvl = $("m-level"); lvl.textContent = s.level; lvl.className = "badge lvl-" + s.level;
  const g = $("m-gauge"); g.style.width = Math.min(s.score, 100) + "%";
  g.style.background = s.score >= 80 ? "#c0392f" : s.score >= 50 ? "#b45309" : "#15803d";
  const t = $("m-taint");
  t.textContent = s.tainted ? "TAINTED" : "CLEAN";
  t.className = "badge " + (s.tainted ? "taint-tainted" : "taint-clean");
  $("m-redactions").textContent = s.redactions;
  $("m-blocked").textContent = s.blocked;
}
function applyPendingCount() { $("m-approvals").textContent = pending.size; }

// ---- fold an audit record into a state object
function fold(s, e) {
  if (e.event === "gateway_start") { Object.assign(s, freshState()); }
  if (typeof e.session_score === "number") s.score = e.session_score;
  if (e.session_level) s.level = e.session_level;
  if (e.event === "session_tainted") s.tainted = true;
  if (e.event === "tool_result_redacted") s.redactions += e.total || 0;
  if (["tool_call_blocked", "tool_call_blocked_by_sequence",
       "tool_call_denied_session_suspended"].includes(e.event)) s.blocked += 1;
  // chart point whenever risk is known, plus a baseline at session start
  if (e.event === "gateway_start") s.points.push({ score: 0, cls: "info" });
  if (typeof e.session_score === "number") {
    const spec = SPEC[e.event]; const cls = spec ? spec(e)[0] : "info";
    s.points.push({ score: e.session_score, cls });
  }
}

// ---- feed
function rowEl(e, animate) {
  const spec = SPEC[e.event]; if (!spec) return null;
  const [cls, tag, tool, why] = spec(e);
  const row = document.createElement("div");
  row.className = "row";
  if (!animate) row.style.animation = "none";
  row.dataset.cat = cls;
  row.dataset.text = ((tool || "") + " " + (why || "")).toLowerCase();
  const ts = (e.ts || "").split("T")[1] || (e.ts || "");
  row.innerHTML =
    `<span class="tag t-${cls}">${tag}</span>` +
    (tool ? `<span class="tool">${esc(tool)}</span>` : `<span class="tool"></span>`) +
    `<span class="why">${esc((why || "").slice(0, 200))}</span>` +
    `<span class="ts">${esc(ts)}</span>`;
  return row;
}
function esc(s) { return String(s).replace(/[<>&]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c])); }
function passesFilter(cat, text) {
  if (filterType !== "all" && cat !== filterType) return false;
  if (filterText && !text.includes(filterText)) return false;
  return true;
}
function appendLive(e) {
  if (paused) return;
  const row = rowEl(e, true); if (!row) return;
  if (!passesFilter(row.dataset.cat, row.dataset.text)) { hideEmpty(); return; }
  const feed = $("feed"); feed.insertBefore(row, feed.firstChild);
  while (feed.children.length > 400) feed.removeChild(feed.lastChild);
  hideEmpty();
}
function rebuildFeed(records) {
  const feed = $("feed"); feed.innerHTML = "";
  for (const e of records) {
    const row = rowEl(e, false); if (!row) continue;
    if (!passesFilter(row.dataset.cat, row.dataset.text)) continue;
    feed.insertBefore(row, feed.firstChild);
  }
  hideEmpty();
}
function hideEmpty() { $("feed-empty").hidden = $("feed").children.length > 0; }

// ---- chart
let shownPoints = [];
function drawChart(points) {
  shownPoints = points;
  const c = $("chart"), wrap = c.parentElement;
  const dpr = window.devicePixelRatio || 1;
  const w = wrap.clientWidth - 36, h = 150;
  c.width = w * dpr; c.height = h * dpr;
  c.style.width = w + "px"; c.style.height = h + "px";
  const g = c.getContext("2d"); g.scale(dpr, dpr);
  g.clearRect(0, 0, w, h);
  const pad = 6, x0 = pad, x1 = w - pad, y0 = pad, y1 = h - pad;
  const Y = (s) => y1 - (Math.min(s, 100) / 100) * (y1 - y0);

  // threshold guides (elevated 50, suspend 80)
  g.setLineDash([4, 4]); g.lineWidth = 1;
  for (const [v, col] of [[50, "#e0b44b"], [80, "#e08a80"]]) {
    g.strokeStyle = col; g.beginPath(); g.moveTo(x0, Y(v)); g.lineTo(x1, Y(v)); g.stroke();
  }
  g.setLineDash([]);
  $("chart-note").textContent = points.length < 2
    ? "waiting for activity"
    : "peak " + Math.max(...points.map((p) => p.score)) + " over " + points.length + " points";
  if (points.length < 2) return;

  const X = (i) => x0 + (i / (points.length - 1)) * (x1 - x0);
  // area
  g.beginPath(); g.moveTo(X(0), y1);
  points.forEach((p, i) => g.lineTo(X(i), Y(p.score)));
  g.lineTo(X(points.length - 1), y1); g.closePath();
  g.fillStyle = "#eff4ff"; g.fill();
  // line
  g.beginPath();
  points.forEach((p, i) => (i ? g.lineTo(X(i), Y(p.score)) : g.moveTo(X(i), Y(p.score))));
  g.strokeStyle = "#2563eb"; g.lineWidth = 2; g.lineJoin = "round"; g.stroke();
  // markers on block/anomaly points
  points.forEach((p, i) => {
    if (p.cls === "block" || p.cls === "anomaly") {
      g.beginPath(); g.arc(X(i), Y(p.score), 3.5, 0, 7); g.fillStyle = "#c0392f"; g.fill();
      g.strokeStyle = "#fff"; g.lineWidth = 1.5; g.stroke();
    }
  });
}

// ---- approvals
function addPending(m) {
  if (pending.has(m.id)) return;
  const el = document.createElement("div");
  el.className = "approval-item";
  el.innerHTML =
    `<div class="approval-main">
       <div class="approval-tool">${esc(m.tool || "")}</div>
       <div class="approval-reason">${esc(m.reason || "")}</div>
       <div class="approval-args">${esc(fmt(m.arguments).slice(0, 160))}</div>
     </div>
     <div class="approval-actions">
       <button class="btn btn-approve">Approve</button>
       <button class="btn btn-deny">Deny</button>
     </div>`;
  el.querySelector(".btn-approve").onclick = () => decide(m.id, true);
  el.querySelector(".btn-deny").onclick = () => decide(m.id, false);
  $("approvals").appendChild(el);
  pending.set(m.id, el);
  $("approvals-card").hidden = false;
  applyPendingCount();
}
function removePending(id) {
  const el = pending.get(id);
  if (el) { el.remove(); pending.delete(id); }
  if (pending.size === 0) $("approvals-card").hidden = true;
  applyPendingCount();
}
function decide(id, approved) {
  const el = pending.get(id);
  if (el) el.querySelectorAll("button").forEach((b) => (b.disabled = true));
  fetch(`/api/approvals/${id}/decide`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ approved, approver: "operator" }),
  }).catch(() => {});
}

// ---- SSE
function connect() {
  const es = new EventSource("/api/stream");
  es.onopen = () => setConn("live");
  es.onerror = () => setConn("down");
  es.onmessage = (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.kind === "audit") {
      const e = m.record;
      fold(live, e);
      liveRecords.push(e);
      if (liveRecords.length > 800) liveRecords.shift();
      if (viewMode === "live") {
        applyState(live);
        drawChart(live.points);
        appendLive(e);
      }
    } else if (m.kind === "approval_pending") {
      if (viewMode === "live") addPending(m);
    } else if (m.kind === "approval_resolved") {
      removePending(m.id);
    }
  };
}
function setConn(state) {
  const c = $("conn"); c.className = "conn " + state;
  $("conn-text").textContent = state === "live" ? "live" : "reconnecting";
}

// ---- sessions
async function loadSessions() {
  const list = await fetch("/api/sessions").then((r) => r.json()).catch(() => []);
  const box = $("sessions"); box.innerHTML = "";
  if (!list.length) { box.innerHTML = `<div class="feed-empty">No sessions recorded yet.</div>`; return; }
  for (const s of list) {
    const el = document.createElement("div");
    el.className = "session";
    const started = (s.started || "").replace("T", " ").slice(0, 19);
    el.innerHTML =
      `<div>
         <div class="sid">${esc(s.id)}</div>
         <div class="meta">${esc(started)} · ${esc(short(s.upstream))} · role ${esc(s.role || "-")}</div>
       </div>
       <div class="tags">
         <span class="pill">${s.events} events</span>
         <span class="pill">${s.redactions} redactions</span>
         <span class="pill">${s.blocks} blocked</span>
         ${s.tainted ? `<span class="badge taint-tainted">TAINTED</span>` : ``}
         ${!s.ended ? `<span class="pill live-pill">live</span>` : ``}
       </div>
       <div style="text-align:right">
         <div class="num">${s.score}</div>
         <span class="badge lvl-${s.level}">${s.level}</span>
       </div>`;
    el.onclick = () => enterReplay(s.id, started);
    box.appendChild(el);
  }
}
async function enterReplay(sid, started) {
  const recs = await fetch(`/api/sessions/${sid}`).then((r) => r.json()).catch(() => []);
  viewMode = "replay";
  showView("live");
  $("approvals-card").hidden = true;
  $("replay-banner").hidden = false;
  $("replay-text").textContent = `Replaying session ${sid} · ${started}`;
  _replayRecs = recs;
  const s = freshState();
  for (const e of recs) fold(s, e);
  applyState(s); drawChart(s.points); rebuildFeed(recs);
}
function exitReplay() {
  viewMode = "live";
  $("replay-banner").hidden = true;
  applyState(live); drawChart(live.points); rebuildFeed(liveRecords);
  if (pending.size) $("approvals-card").hidden = false;
}

// ---- view + controls
function showView(name) {
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.view === name));
  $("view-live").hidden = name !== "live";
  $("view-sessions").hidden = name !== "sessions";
  $("view-policy").hidden = name !== "policy";
}
function initChips() {
  const cats = [["all", "All"], ["allow", "Allowed"], ["block", "Blocked"],
    ["redact", "Redact"], ["rewrite", "Rewrite"], ["quarantine", "Quarantine"],
    ["approval", "Approval"], ["anomaly", "Anomaly"]];
  const box = $("chips");
  for (const [cat, label] of cats) {
    const b = document.createElement("button");
    b.className = "chip" + (cat === "all" ? " on" : "");
    b.textContent = label; b.dataset.cat = cat;
    b.onclick = () => {
      filterType = cat;
      document.querySelectorAll(".chip").forEach((c) => c.classList.toggle("on", c === b));
      rebuildFeed(viewMode === "live" ? liveRecords : currentReplay());
    };
    box.appendChild(b);
  }
}
let _replayRecs = [];
function currentReplay() { return _replayRecs; }

document.querySelectorAll(".tab").forEach((t) => {
  t.onclick = () => {
    showView(t.dataset.view);
    if (t.dataset.view === "sessions") loadSessions();
    if (t.dataset.view === "policy") loadPolicy();
  };
});
$("search").addEventListener("input", (e) => {
  filterText = e.target.value.trim().toLowerCase();
  rebuildFeed(viewMode === "live" ? liveRecords : currentReplay());
});
$("pause").onclick = function () {
  paused = !paused; this.classList.toggle("on", paused);
  this.textContent = paused ? "Resume" : "Pause";
  if (!paused && viewMode === "live") rebuildFeed(liveRecords);
};
$("exit-replay").onclick = exitReplay;
$("refresh-sessions").onclick = loadSessions;
$("refresh-policy").onclick = loadPolicy;
window.addEventListener("resize", () => drawChart(shownPoints));

initChips();
connect();

// ---- policy viewer
async function loadPolicy() {
  const p = await fetch("/api/policy").then((r) => r.json()).catch((e) => ({ ok: false, error: String(e) }));
  if (!p.ok) {
    $("policy-title").textContent = "Policy unavailable";
    $("policy-path").textContent = p.error || "Could not load policy.";
    $("policy-summary").innerHTML = "";
    $("policy-stateful").innerHTML = "";
    $("policy-tools").innerHTML = `<div class="feed-empty">No policy loaded.</div>`;
    $("policy-tool-count").textContent = "0 tools";
    return;
  }
  $("policy-title").textContent = `Default ${up(p.default_action)}`;
  $("policy-path").textContent = p.path;
  activePolicyRaw = p.raw || null;
  if (!$("backtest-policy").value.trim() && activePolicyRaw) {
    $("backtest-policy").value = JSON.stringify(activePolicyRaw, null, 2);
  }
  $("policy-summary").innerHTML = [
    statCard("Default action", p.default_action, "Anything not explicitly listed"),
    statCard("Redaction entities", String(p.redact_entities.length), (p.redact_entities || []).join(", ") || "none"),
    statCard("Explicit tools", String(p.tools.length), "Tool-level rules"),
  ].join("");
  $("policy-stateful").innerHTML = [
    statCard("Taint sources", String(p.taint_sources.length), chips(p.taint_sources)),
    statCard("Taint sinks", String(p.taint_sinks.length), chips(p.taint_sinks)),
    statCard("Sequence rules", String(p.sequence_rules.length), sequenceText(p.sequence_rules)),
  ].join("");
  $("policy-tool-count").textContent = `${p.tools.length} tools`;
  renderToolRules(p.tools);
}

function statCard(label, value, detail) {
  return `<div class="policy-stat">
    <div class="policy-label">${esc(label)}</div>
    <div class="policy-num">${esc(value)}</div>
    <div class="policy-detail">${detail}</div>
  </div>`;
}

function chips(items) {
  if (!items || !items.length) return `<span class="muted">none</span>`;
  return items.map((x) => `<span class="mini-chip">${esc(x)}</span>`).join("");
}

function sequenceText(rules) {
  if (!rules || !rules.length) return `<span class="muted">none</span>`;
  return rules.map((r) => `<span class="seq">${esc(r.after)} → ${esc(r.forbid)}</span>`).join("");
}

function renderToolRules(tools) {
  const box = $("policy-tools");
  if (!tools.length) { box.innerHTML = `<div class="feed-empty">No explicit tool rules.</div>`; return; }
  box.innerHTML = tools.map((t) => {
    const roleText = t.roles && t.roles.length
      ? t.roles.map((r) => `<span class="role-chip">${esc(r.role)}: ${esc(r.action)}</span>`).join("")
      : `<span class="muted">same for all roles</span>`;
    const detail = [
      t.reason ? `<div>${esc(t.reason)}</div>` : "",
      t.constraints && t.constraints.length ? `<div><b>Constraints</b> ${esc(fmt(t.constraints))}</div>` : "",
      t.rewrites && t.rewrites.length ? `<div><b>Rewrites</b> ${esc(fmt(t.rewrites))}</div>` : "",
      t.approval && Object.keys(t.approval).length ? `<div><b>Approval</b> ${esc(fmt(t.approval))}</div>` : "",
    ].filter(Boolean).join("");
    return `<div class="policy-row">
      <div>
        <div class="policy-tool mono">${esc(t.name)}</div>
        <div class="policy-reason">${detail || `<span class="muted">no extra details</span>`}</div>
      </div>
      <div><span class="tag t-${actionClass(t.action)}">${esc(up(t.action))}</span></div>
      <div class="policy-roles">${roleText}</div>
    </div>`;
  }).join("");
}

function actionClass(action) {
  if (action === "block") return "block";
  if (action === "redact") return "redact";
  if (action === "rewrite") return "rewrite";
  if (action === "quarantine") return "quarantine";
  if (action === "require_approval") return "approval";
  return "allow";
}

async function runBacktest() {
  const status = $("backtest-status");
  status.textContent = "Running replay...";
  $("backtest-summary").hidden = true;
  $("backtest-results").innerHTML = "";
  const policy = $("backtest-policy").value;
  const r = await fetch("/api/backtest", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ policy }),
  }).then((x) => x.json()).catch((e) => ({ ok: false, error: String(e) }));
  if (!r.ok) {
    status.textContent = r.error || "Backtest failed.";
    return;
  }
  status.textContent = r.note || "Backtest complete.";
  renderBacktest(r);
}

function renderBacktest(report) {
  const s = report.summary || {};
  $("backtest-summary").hidden = false;
  $("backtest-summary").innerHTML = [
    btStat("Calls replayed", s.total || 0),
    btStat("Changed", s.changed || 0),
    btStat("Newly blocked", s.newly_blocked || 0),
    btStat("Newly allowed", s.newly_allowed || 0),
    btStat("New redactions", s.new_redactions || 0),
    btStat("Approval changes", s.approval_changes || 0),
    btStat("Partial", s.partial || 0),
  ].join("");

  const rows = (report.rows || []).filter((r) => r.changed || r.confidence === "partial");
  if (!rows.length) {
    $("backtest-results").innerHTML = `<div class="feed-empty">No behavior changes found in the current audit history.</div>`;
    return;
  }
  $("backtest-results").innerHTML = rows.map((r) => {
    const warn = r.warnings && r.warnings.length
      ? `<div class="bt-warn">${esc(r.warnings.join("; "))}</div>` : "";
    return `<div class="bt-row ${r.changed ? "changed" : ""}">
      <div>
        <div class="policy-tool mono">${esc(r.tool || "")}</div>
        <div class="policy-reason">${esc(r.new_reason || "")}${warn}</div>
      </div>
      <div class="bt-actions">
        <span class="tag t-${actionClass(r.old_action)}">${esc(up(r.old_action))}</span>
        <span class="arrow">→</span>
        <span class="tag t-${actionClass(r.new_action)}">${esc(up(r.new_action))}</span>
      </div>
      <div class="bt-meta">${esc(r.confidence || "exact")} · ${esc((r.ts || "").replace("T", " ").slice(0, 19))}</div>
    </div>`;
  }).join("");
}

function btStat(label, value) {
  return `<div class="bt-stat"><div class="policy-label">${esc(label)}</div><div class="policy-num">${esc(value)}</div></div>`;
}

$("run-backtest").onclick = runBacktest;
$("reset-backtest-policy").onclick = () => {
  if (activePolicyRaw) $("backtest-policy").value = JSON.stringify(activePolicyRaw, null, 2);
  $("backtest-status").textContent = "Reset to active policy.";
};
