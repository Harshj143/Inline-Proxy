/* Security Ops Console — vanilla JS SPA (no framework, minimal-dependency ethos).
 *
 * Talks only to the console's own REST + SSE API. Auth is the cookie the login
 * POST sets, so every fetch just needs credentials: 'same-origin' (default for
 * same-origin) — we never handle a token in JS. Approve controls are hidden for
 * the viewer role; the server enforces it regardless (defense in depth). */
"use strict";

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};
const api = (path, opts) => fetch(path, Object.assign({ headers: { "Content-Type": "application/json" } }, opts));

let me = null;        // {username, role}
let feedSource = null; // EventSource

// ------------------------------------------------------------------- auth
async function boot() {
  const r = await api("/api/me");
  if (r.ok) { me = await r.json(); showApp(); }
  else showLogin();
}

function showLogin() {
  $("#app").classList.add("hidden");
  $("#login").classList.remove("hidden");
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const r = await api("/api/login", {
    method: "POST",
    body: JSON.stringify({ username: f.username.value, password: f.password.value }),
  });
  const errBox = $("#login-error");
  if (r.ok) { me = await r.json(); errBox.classList.add("hidden"); showApp(); }
  else { errBox.textContent = "Invalid credentials."; errBox.classList.remove("hidden"); }
});

$("#logout").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST" });
  if (feedSource) feedSource.close();
  me = null;
  showLogin();
});

function showApp() {
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  $("#whoami").textContent = `${me.username} · ${me.role}`;
  selectTab("feed");
  startFeed();
  pollPending();
}

// ------------------------------------------------------------------- tabs
$("#tabs").addEventListener("click", (e) => {
  if (e.target.dataset.tab) selectTab(e.target.dataset.tab);
});

function selectTab(name) {
  document.querySelectorAll("#tabs button").forEach((b) =>
    b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll("main section").forEach((s) =>
    s.classList.toggle("hidden", s.dataset.panel !== name));
  if (name === "sessions") loadSessions();
  if (name === "approvals") loadApprovals();
  if (name === "policy") loadPolicy();
}

// -------------------------------------------------------------- live feed
const evClass = (name) => {
  if (name === "tool_call_allowed") return "ev-allowed";
  if (name === "tool_call_blocked" || name === "tool_call_denied_session_suspended"
      || name === "session_suspended") return "ev-blocked";
  if (name === "session_tainted" || name === "tool_result_redacted") return "ev-tainted";
  if (name === "approval_requested") return "ev-approval";
  return "";
};

function feedRow(ev) {
  const tr = el("tr");
  tr.appendChild(el("td", "ts", (ev.ts || "").replace("T", " ").slice(0, 19)));
  tr.appendChild(el("td", "ev " + evClass(ev.event), ev.event));
  tr.appendChild(el("td", null, ev.tool || ""));
  const meta = [];
  if (ev.action) meta.push(ev.action);
  if (ev.reason) meta.push(ev.reason);
  if (ev.session_id) meta.push("· " + ev.session_id);
  tr.appendChild(el("td", "muted", meta.join(" ")));
  return tr;
}

function startFeed() {
  if (feedSource) feedSource.close();
  // EventSource handles Last-Event-ID resume natively on reconnect.
  feedSource = new EventSource("/api/stream");
  const rows = $("#feed-rows");
  feedSource.onopen = () => { $("#feed-status").textContent = "live"; };
  feedSource.onerror = () => { $("#feed-status").textContent = "reconnecting…"; };
  feedSource.onmessage = (m) => {
    let ev; try { ev = JSON.parse(m.data); } catch { return; }
    rows.insertBefore(feedRow(ev), rows.firstChild);
    while (rows.children.length > 300) rows.removeChild(rows.lastChild);
    if (ev.event === "approval_requested") pollPending();
  };
}

$("#feed-clear").addEventListener("click", () => { $("#feed-rows").innerHTML = ""; });

// --------------------------------------------------------------- sessions
async function loadSessions() {
  const r = await api("/api/sessions");
  if (!r.ok) return;
  const { sessions } = await r.json();
  const body = $("#sessions-rows");
  body.innerHTML = "";
  for (const s of sessions) {
    const tr = el("tr", "clickable");
    tr.appendChild(el("td", null, s.session_id));
    tr.appendChild(el("td", null, String(s.event_count)));
    tr.appendChild(el("td", "tag-allowed", String(s.allowed_count)));
    tr.appendChild(el("td", "tag-blocked", String(s.blocked_count)));
    tr.appendChild(el("td", null, `${s.risk_score} (${s.risk_level})`));
    const flags = [];
    if (s.tainted) flags.push("tainted");
    if (s.suspended) flags.push("suspended");
    tr.appendChild(el("td", "ev-tainted", flags.join(", ")));
    tr.addEventListener("click", () => loadSessionDetail(s.session_id));
    body.appendChild(tr);
  }
}

async function loadSessionDetail(sid) {
  const r = await api(`/api/sessions/${encodeURIComponent(sid)}`);
  const box = $("#session-detail");
  if (!r.ok) { box.textContent = "Could not load session."; return; }
  const d = await r.json();
  box.classList.remove("muted");
  box.innerHTML = "";
  box.appendChild(el("h3", null, `Session ${d.session_id}`));
  const tbl = el("table");
  const tb = el("tbody");
  for (const ev of d.events) {
    const tr = el("tr");
    tr.appendChild(el("td", "ts", (ev.ts || "").slice(11, 19)));
    tr.appendChild(el("td", "ev " + evClass(ev.event), ev.event));
    tr.appendChild(el("td", null, ev.tool || ev.reason || ""));
    tb.appendChild(tr);
  }
  tbl.appendChild(tb);
  box.appendChild(tbl);
}

// -------------------------------------------------------------- approvals
async function pollPending() {
  const r = await api("/api/approvals/pending");
  if (!r.ok) return;
  const { pending } = await r.json();
  const badge = $("#pending-badge");
  badge.textContent = String(pending.length);
  badge.classList.toggle("hidden", pending.length === 0);
  if (!$('section[data-panel="approvals"]').classList.contains("hidden")) {
    renderApprovals(pending);
  }
}

async function loadApprovals() {
  const r = await api("/api/approvals/pending");
  if (r.ok) renderApprovals((await r.json()).pending);
}

function renderApprovals(pending) {
  const list = $("#approvals-list");
  list.innerHTML = "";
  if (pending.length === 0) { list.appendChild(el("p", "muted", "Nothing waiting.")); return; }
  const canApprove = me && me.role === "approver";
  for (const p of pending) {
    const card = el("div", "approval");
    card.appendChild(el("span", "tool", p.tool));
    card.appendChild(el("span", "muted", `  · ${p.principal || "?"} · session ${p.session_id || "?"}`));
    if (p.reason) card.appendChild(el("div", "muted", p.reason));
    card.appendChild(el("pre", null, JSON.stringify(p.arguments || {}, null, 2)));
    if (canApprove) {
      const row = el("div", "row");
      const note = el("input"); note.placeholder = "note (optional)";
      const ok = el("button", "approve", "Approve");
      const no = el("button", "deny", "Deny");
      ok.addEventListener("click", () => resolve(p.approval_id, true, note.value));
      no.addEventListener("click", () => resolve(p.approval_id, false, note.value));
      row.append(note, ok, no);
      card.appendChild(row);
    } else {
      card.appendChild(el("div", "muted", "Viewer role — cannot resolve."));
    }
    list.appendChild(card);
  }
}

async function resolve(id, approved, note) {
  await api(`/api/approvals/${id}/resolve`, {
    method: "POST",
    body: JSON.stringify({ approved, note: note || "" }),
  });
  pollPending();
}

// ----------------------------------------------------------------- policy
async function loadPolicy() {
  const box = $("#policy-view");
  const r = await api("/api/policy");
  if (r.status === 404) { box.textContent = "No policy loaded on this console."; return; }
  if (!r.ok) { box.textContent = "Could not load policy."; return; }
  const p = await r.json();
  box.classList.remove("muted");
  box.innerHTML = "";
  box.appendChild(el("p", null, `Layers: ${p.layers.join(" + ")} · default: ${p.default_action}`));
  const tbl = el("table");
  tbl.innerHTML = "<thead><tr><th>tool</th><th>action</th><th>notes</th></tr></thead>";
  const tb = el("tbody");
  for (const rule of p.rules) {
    const tr = el("tr");
    tr.appendChild(el("td", null, rule.pattern));
    tr.appendChild(el("td", "tag-" + rule.action, rule.action));
    const notes = [];
    if (rule.constraints) notes.push(`${rule.constraints.length} constraint(s)`);
    if (rule.rewrites) notes.push(`${rule.rewrites.length} rewrite(s)`);
    if (rule.then) notes.push(`then=${rule.then}`);
    if (rule.roles) notes.push("roles: " + Object.keys(rule.roles).join(", "));
    tr.appendChild(el("td", "muted", notes.join("; ")));
    tb.appendChild(tr);
  }
  tbl.appendChild(tb);
  box.appendChild(tbl);
}

// --------------------------------------------------------------- backtest
$("#backtest-run").addEventListener("click", async () => {
  const box = $("#backtest-result");
  let policy;
  try { policy = JSON.parse($("#backtest-input").value); }
  catch { box.innerHTML = '<p class="error">Input is not valid JSON.</p>'; return; }
  const r = await api("/api/backtest", { method: "POST", body: JSON.stringify({ policy }) });
  if (!r.ok) {
    const e = await r.json().catch(() => ({}));
    box.innerHTML = `<p class="error">${e.detail || "backtest failed"}</p>`;
    return;
  }
  const rep = await r.json();
  box.innerHTML = "";
  const s = rep.summary;
  box.appendChild(el("p", null,
    `Examined ${rep.calls_examined} call(s), ${rep.distinct_calls} distinct.`));
  const chips = el("p");
  chips.innerHTML =
    `<span class="chip tag-blocked">${s.newly_blocked} newly blocked</span>` +
    `<span class="chip tag-allowed">${s.newly_allowed} newly allowed</span>` +
    `<span class="chip tag-redact">${s.action_changed} action changed</span>` +
    `<span class="chip">${s.unchanged} unchanged</span>`;
  box.appendChild(chips);
  if (rep.changed.length) {
    const tbl = el("table");
    tbl.innerHTML = "<thead><tr><th>change</th><th>tool</th><th>role</th><th>diff</th><th>count</th></tr></thead>";
    const tb = el("tbody");
    for (const c of rep.changed) {
      const tr = el("tr");
      tr.appendChild(el("td", "tag-" + (c.change_kind === "newly_blocked" ? "blocked" : "allowed"), c.change_kind));
      tr.appendChild(el("td", null, c.tool));
      tr.appendChild(el("td", "muted", c.role || ""));
      tr.appendChild(el("td", null, `${c.old_action || c.old_outcome} → ${c.new_action}`));
      tr.appendChild(el("td", null, String(c.count)));
      tb.appendChild(tr);
    }
    tbl.appendChild(tb);
    box.appendChild(tbl);
  }
  box.appendChild(el("p", "muted", rep.note));
});

boot();
