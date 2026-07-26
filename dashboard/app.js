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

// ---- Attack Lab: a plain-language replay of the real Jac demo policies.
const ATTACK_SCENARIOS = {
  github: {
    title: "GitHub supply-chain attack",
    severity: "HIGH",
    service: "GitHub MCP",
    icon: "GH",
    final: "Supply-chain attack contained",
    steps: [
      {
        session: "Compromised agent session",
        phase: "Prevention · Before the attack",
        title: "Dangerous capabilities disappear",
        subtitle: "Shrink the attack surface",
        tool: "tools/list",
        outcome: "3 dangerous tools removed",
        explainer: "Before the model plans anything, Jac removes repository deletion, workflow execution, and release publication from the tool menu.",
        why: "An injected instruction cannot easily choose powers the agent cannot see.",
        gate: "policy", decision: "hide", action: "TOOLS HIDDEN", flow: "transform",
        policy: "Capability minimization",
        rule: "tools/list → hide deny-only and unapproved tools",
        reason: "Only capabilities this identity can safely use are shown.",
        risk: 0, level: "Normal", tainted: false, upstream: true,
        evidence: "GitHub’s list is fetched, then delete_repository, run_workflow, and create_release are removed before the model sees it.",
        policyCount: 3
      },
      {
        phase: "Initial access · Prompt injection",
        title: "A poisoned pull request enters context",
        subtitle: "Untrusted content read",
        tool: "get_pull_request(#418)",
        outcome: "Read allowed · session tainted",
        explainer: "An external contributor hides instructions inside a normal-looking pull request. The agent can read it, but Jac marks everything that follows as potentially compromised.",
        why: "Jac does not need to perfectly detect the hidden instruction. It remembers that the session consumed attacker-controlled content.",
        gate: "action", decision: "redact", action: "TAINT + REDACT", flow: "transform",
        policy: "Untrusted-content taint",
        rule: "get_pull_request ∈ taint_sources",
        reason: "Pull-request text is attacker-controlled and may contain secrets or instructions.",
        risk: 0, level: "Normal", tainted: true, upstream: true,
        evidence: "The Session node records tainted=true and origin=get_pull_request.",
        policyCount: 2
      },
      {
        phase: "Discovery · Credential theft",
        title: "CI secrets are found, then removed",
        subtitle: "Sensitive log response",
        tool: "get_job_logs(run 99184)",
        outcome: "6 sensitive values redacted",
        explainer: "The poisoned agent reads deployment logs. GitHub returns real-looking credentials, but Jac scans the complete response before the model receives it.",
        why: "The task can continue with useful build context, while credentials never enter the model’s usable context.",
        gate: "response", decision: "redact", action: "REDACTED", flow: "transform",
        policy: "Strict response DLP",
        rule: "get_job_logs → redact(strict)",
        reason: "CI logs routinely contain credentials and personal data.",
        risk: 10, level: "Normal", tainted: true, upstream: true,
        evidence: "Counts only: email 1, GitHub PAT 1, AWS keys 2, JWT 1, labeled secret 1.",
        policyCount: 2,
        payload: {
          before: "GITHUB_TOKEN=ghp_••• · AWS_ACCESS_KEY_ID=AKIA••• · OIDC=eyJ•••",
          after: "GITHUB_TOKEN=[REDACTED] · AWS_ACCESS_KEY_ID=[REDACTED] · OIDC=[REDACTED]"
        }
      },
      {
        phase: "Impact · Protected branch mutation",
        title: "Direct workflow push to main is stopped",
        subtitle: "Argument violates branch policy",
        tool: "push_files(branch=main)",
        outcome: "Blocked before GitHub",
        explainer: "The attacker tells the agent to replace a deployment workflow directly on the protected branch. Jac inspects the arguments and refuses the call.",
        why: "Allowing a tool does not mean allowing every use of it. The branch and repository still have to satisfy policy.",
        gate: "constraint", decision: "block", action: "BLOCKED", flow: "block",
        policy: "Protected-branch constraint",
        rule: "branch must_not_match main|master|release|production",
        reason: "Direct writes to protected branches are forbidden.",
        risk: 30, level: "Elevated", tainted: true, upstream: false,
        evidence: "push_files is absent from the upstream-call log for this request.",
        policyCount: 3
      },
      {
        phase: "Evasion · Alternate branch",
        title: "Changing branches does not bypass taint",
        subtitle: "Second path attempted",
        tool: "push_files(branch=agent/checkout-fix)",
        outcome: "Blocked by session history",
        explainer: "The agent switches to a normally permitted branch. The arguments now pass, but Jac remembers the poisoned pull request and blocks the write at the sequence gate.",
        why: "Attackers often retry with a policy-compliant-looking path. Stateful controls connect earlier reads to later mutations.",
        gate: "sequence", decision: "block", action: "BLOCKED", flow: "block",
        policy: "Taint sink gate",
        rule: "tainted session + push_files sink → block",
        reason: "A compromised session may read, but it may not mutate source or CI.",
        risk: 60, level: "Elevated", tainted: true, upstream: false,
        evidence: "First-deny-wins stops traversal at Sequence + taint; GitHub is never contacted.",
        policyCount: 3
      },
      {
        phase: "Containment · Useful access retained",
        title: "Safe investigation still works",
        subtitle: "Least-privilege continuity",
        tool: "search_code(checkout timeout)",
        outcome: "Read-only search delivered",
        explainer: "Even at elevated risk, the agent can search code to understand the issue. Jac contains dangerous movement without causing a blanket outage.",
        why: "A useful security control preserves safe work instead of simply turning the agent off after one warning.",
        gate: "action", decision: "allow", action: "ALLOWED", flow: "allow",
        policy: "Read-only allow rule",
        rule: "search_code → allow",
        reason: "Read-only discovery is permitted in approved repositories.",
        risk: 60, level: "Elevated", tainted: true, upstream: true,
        evidence: "Search reached GitHub and returned file names; no sensitive payload was logged.",
        policyCount: 2
      },
      {
        session: "Clean comparison session",
        phase: "Recovery · Safe change path",
        title: "A clean change is forced into draft review",
        subtitle: "Arguments made safer",
        tool: "create_pull_request(draft=false)",
        outcome: "Rewritten to draft=true",
        explainer: "A separate clean session proposes a legitimate fix. Jac does not block it; it transforms the pull request into a draft that requires review.",
        why: "The weakest effective control is better than a blanket denial. The developer keeps moving while a human remains in the loop.",
        gate: "action", decision: "rewrite", action: "REWRITTEN", flow: "transform",
        policy: "Safe pull-request rewrite",
        rule: "create_pull_request → set draft=true",
        reason: "Agent-authored changes must begin as drafts.",
        risk: 0, level: "Normal", tainted: false, upstream: true,
        evidence: "The upstream mock received draft=true, even though the agent requested false.",
        policyCount: 3,
        payload: { before: "draft=false", after: "draft=true" }
      },
      {
        phase: "Release boundary · Human decision",
        title: "Publishing a release needs a person",
        subtitle: "High-impact action gated",
        tool: "create_release(v9.9.9)",
        outcome: "Denied without approval",
        explainer: "Publishing would affect downstream users. Jac asks for human approval and fails closed because no approver is configured for the demo.",
        why: "A release is a supply-chain boundary. Automation should prepare it, not silently publish it.",
        gate: "action", decision: "approval", action: "APPROVAL REQUIRED", flow: "block",
        policy: "Human approval boundary",
        rule: "create_release → require_approval → allow",
        reason: "Release publication requires an accountable human decision.",
        risk: 25, level: "Normal", tainted: false, upstream: false,
        evidence: "No approval means no release; create_release never reaches GitHub.",
        policyCount: 2
      },
      {
        phase: "Defense in depth · Sequence policy",
        title: "CI read followed by workflow run is blocked",
        subtitle: "Independent final barrier",
        tool: "run_workflow(deploy.yml)",
        outcome: "Blocked by tool sequence",
        explainer: "After CI logs were read, the same clean-review session tries to execute a deployment workflow. A separate sequence rule stops it before the approval layer.",
        why: "Multiple independent controls prevent one configuration mistake from becoming a supply-chain incident.",
        gate: "sequence", decision: "block", action: "BLOCKED", flow: "block",
        policy: "Secret-adjacent sequence rule",
        rule: "after get_job_logs → forbid run_workflow",
        reason: "No workflow execution after reading secret-adjacent CI logs.",
        risk: 65, level: "Elevated", tainted: false, upstream: false,
        evidence: "The walker disengages at the sequence gate; workflow dispatch is absent upstream.",
        policyCount: 3
      }
    ]
  },
  slack: {
    title: "Slack data-exfiltration attack",
    severity: "CRITICAL",
    service: "Slack MCP",
    icon: "SL",
    final: "Every exfiltration route stopped",
    steps: [
      {
        session: "Compromised support-agent session",
        phase: "Prevention · Before the attack",
        title: "Outbound capabilities are hidden",
        subtitle: "Shrink the attack surface",
        tool: "tools/list",
        outcome: "5 egress tools removed",
        explainer: "Before the model sees Slack, Jac removes messages, drafts, new conversations, and canvas writes that cannot run without approval.",
        why: "The poisoned model cannot plan around outbound tools it was never offered.",
        gate: "policy", decision: "hide", action: "TOOLS HIDDEN", flow: "transform",
        policy: "Capability minimization",
        rule: "tools/list → filter approval-only tools",
        reason: "No approver is available, so approval-only tools are not advertised.",
        risk: 0, level: "Normal", tainted: false, upstream: true,
        evidence: "Slack’s list is fetched, then send_message, draft_message, create_conversation, create_canvas, and update_canvas are hidden.",
        policyCount: 5
      },
      {
        phase: "Initial access · Poisoned support message",
        title: "A guest message compromises session trust",
        subtitle: "Slack Connect content read",
        tool: "read_channel(#customer-support)",
        outcome: "Read allowed · session tainted",
        explainer: "A Slack Connect guest embeds instructions to search private messages, download credentials, and create an external DM.",
        why: "Free-form messages are untrusted input. Jac marks the session without relying on a brittle prompt-injection classifier.",
        gate: "action", decision: "redact", action: "TAINT + REDACT", flow: "transform",
        policy: "Untrusted-message taint",
        rule: "read_channel ∈ taint_sources",
        reason: "External and free-form channel content can steer an agent.",
        risk: 0, level: "Normal", tainted: true, upstream: true,
        evidence: "The Session node records tainted=true with the channel read as origin.",
        policyCount: 2
      },
      {
        phase: "Discovery · Workspace-wide search",
        title: "Customer data and tokens are scrubbed",
        subtitle: "Sensitive results found",
        tool: "search_messages(incident token)",
        outcome: "5 sensitive values redacted",
        explainer: "The attacker’s instruction triggers a broad message search. Slack returns customer identity data and credentials, but Jac replaces each sensitive value.",
        why: "The agent can still see that relevant messages exist without receiving reusable secrets or personal identifiers.",
        gate: "response", decision: "redact", action: "REDACTED", flow: "transform",
        policy: "Strict workspace DLP",
        rule: "search_messages → redact(strict)",
        reason: "Workspace-wide search crosses channel boundaries and must be scrubbed.",
        risk: 5, level: "Normal", tainted: true, upstream: true,
        evidence: "Counts only: email 1, SSN 1, Slack token 1, JWT 1, API key 1.",
        policyCount: 2,
        payload: {
          before: "ada.verne@example.com · SSN 544-21-1290 · xoxb-••• · eyJ•••",
          after: "[REDACTED_EMAIL] · ****1290 · [REDACTED_SLACK_TOKEN] · [REDACTED_JWT]"
        }
      },
      {
        phase: "Business continuity · Low-risk action",
        title: "A reaction remains safe to use",
        subtitle: "Proportional access",
        tool: "add_reaction(:eyes:)",
        outcome: "Reaction delivered",
        explainer: "The compromised session can add a small acknowledgment reaction. This action cannot carry meaningful stolen data.",
        why: "Jac chooses the least restrictive action that works; not every capability becomes dangerous after taint.",
        gate: "action", decision: "allow", action: "ALLOWED", flow: "allow",
        policy: "Low-bandwidth allow rule",
        rule: "add_reaction → allow",
        reason: "Reaction bandwidth is too low to justify blocking normal support work.",
        risk: 5, level: "Normal", tainted: true, upstream: true,
        evidence: "The reaction reaches Slack while message and conversation sinks stay protected.",
        policyCount: 2
      },
      {
        phase: "Collection · Credentials file",
        title: "An opaque file is quarantined",
        subtitle: "Unsafe result withheld",
        tool: "read_file(production.env)",
        outcome: "Entire file withheld",
        explainer: "The attacker asks for a production environment file. Rather than guessing which fragments are safe, Jac quarantines the complete response.",
        why: "Some content is too risky to reduce safely. Withholding it is more reliable than partial redaction.",
        gate: "response", decision: "quarantine", action: "QUARANTINED", flow: "transform",
        policy: "Opaque-file quarantine",
        rule: "read_file → quarantine",
        reason: "Arbitrary files cannot always be reduced to a safe, useful partial view.",
        risk: 5, level: "Normal", tainted: true, upstream: true,
        evidence: "Slack was contacted, but the model received only a quarantine notice.",
        policyCount: 2,
        payload: { before: "production.env: SLACK_TOKEN=••• · api_key=•••", after: "[QUARANTINED] result withheld for review" }
      },
      {
        phase: "Privilege probe · Sensitive channel",
        title: "Direct access to #exec is denied",
        subtitle: "Scope boundary tested",
        tool: "read_channel(#exec)",
        outcome: "Blocked before Slack",
        explainer: "The compromised agent probes an executive channel. A channel-level constraint rejects it even though read_channel is generally available.",
        why: "Permissions must apply to the target of the action, not only the tool name.",
        gate: "constraint", decision: "block", action: "BLOCKED", flow: "block",
        policy: "Sensitive-channel ACL",
        rule: "channel must_not_match exec|hr|legal|board|payroll|security",
        reason: "The requested channel is outside the support agent’s approved scope.",
        risk: 20, level: "Normal", tainted: true, upstream: false,
        evidence: "The constraint fails before any #exec content is requested from Slack.",
        policyCount: 3
      },
      {
        phase: "Exfiltration · Primary route",
        title: "The external DM never leaves",
        subtitle: "Stolen-data sink attempted",
        tool: "send_message(@external-auditor)",
        outcome: "Blocked by taint",
        explainer: "The attacker tries the direct route: send the collected archive to an external identity. Jac connects the earlier untrusted read to this outbound sink.",
        why: "Each call can look reasonable in isolation. The dangerous meaning appears only when the session history is considered.",
        gate: "sequence", decision: "block", action: "BLOCKED", flow: "block",
        policy: "Taint sink gate",
        rule: "tainted session + send_message sink → block",
        reason: "A compromised session may not send messages or DMs.",
        risk: 45, level: "Elevated", tainted: true, upstream: false,
        evidence: "send_message is absent from the Slack upstream-call log.",
        policyCount: 3
      },
      {
        phase: "Exfiltration · Fallback route",
        title: "A new conversation is blocked too",
        subtitle: "Attacker changes technique",
        tool: "create_conversation(external-auditor)",
        outcome: "Blocked · session suspended",
        explainer: "After the DM fails, the attacker tries to manufacture a new route. Jac blocks the second sink and the accumulated risk crosses the suspension threshold.",
        why: "Attackers retry. Risk scoring turns repeated violations into automatic containment.",
        gate: "sequence", decision: "block", action: "BLOCKED", flow: "block",
        policy: "Multi-route exfiltration defense",
        rule: "tainted session + create_conversation sink → block",
        reason: "A searched or tainted session may not create a new outbound route.",
        risk: 70, level: "Suspended", tainted: true, upstream: false,
        evidence: "Second sink denial raises risk above 60; the Session node is suspended.",
        policyCount: 3
      },
      {
        phase: "Containment · Session lock",
        title: "The compromised session is isolated",
        subtitle: "Safe-looking retry denied",
        tool: "search_channels(engineering)",
        outcome: "Denied at first gate",
        explainer: "The suspended agent tries a normally harmless metadata search. Jac rejects it immediately at the Session gate, before policy matching.",
        why: "Once behavior becomes clearly hostile, continuing to let the agent probe increases exposure.",
        gate: "session", decision: "suspend", action: "SESSION DENIED", flow: "block",
        policy: "Automatic risk suspension",
        rule: "risk_score ≥ 60 → suspend session",
        reason: "The session exceeded the configured critical-risk threshold.",
        risk: 70, level: "Suspended", tainted: true, upstream: false,
        evidence: "Walker trace contains only Session gate; Slack is never contacted.",
        policyCount: 1
      },
      {
        session: "Clean comparison session",
        phase: "Human boundary · Clean outbound call",
        title: "Even a clean message needs approval",
        subtitle: "Baseline control",
        tool: "send_message(#engineering)",
        outcome: "Denied without a human",
        explainer: "A separate clean session attempts a legitimate message. Taint is absent, but outbound communication still requires accountable human approval.",
        why: "The policy protects both compromised and ordinary sessions at the organization’s egress boundary.",
        gate: "action", decision: "approval", action: "APPROVAL REQUIRED", flow: "block",
        policy: "Human approval boundary",
        rule: "send_message → require_approval → allow",
        reason: "Messages and DMs are primary data-exfiltration paths.",
        risk: 20, level: "Normal", tainted: false, upstream: false,
        evidence: "Fail-closed approval prevents delivery when no human is available.",
        policyCount: 2
      }
    ]
  }
};

// ---- state
let viewMode = "live";
let paused = false;
let filterType = "all";
let filterText = "";
const live = freshState();
let liveRecords = [];
const pending = new Map();   // approval id -> element
let activePolicyRaw = null;
let labScenario = "github";
let labStep = -1;
let labTimer = null;
let labPlaying = false;
let labRunId = newLabRunId();

function freshState() {
  return { score: 0, level: "NORMAL", tainted: false, redactions: 0, blocked: 0, points: [] };
}

function normalizeAudit(raw) {
  const decision = raw.decision || {};
  const risk = raw.risk || {};
  const taint = raw.taint || {};
  const report = raw.redactions || {};
  return {
    ...raw,
    action: raw.action || decision.action,
    reason: raw.reason || decision.reason,
    session_score: typeof raw.session_score === "number" ? raw.session_score : risk.score,
    session_level: raw.session_level || risk.level,
    tainted: typeof raw.tainted === "boolean" ? raw.tainted : taint.tainted,
    total: typeof raw.total === "number" ? raw.total : report.total,
    redactions: report.by_entity || raw.redactions,
  };
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
  if (e.event === "session_tainted" || e.tainted === true) s.tainted = true;
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
    if (m.kind === "backlog_session") {
      const summary = m.summary || {};
      Object.assign(live, freshState());
      liveRecords.length = 0;
      $("live-session-name").textContent =
        summary.id || "Security-relevant incident session";
      $("live-session-detail").textContent =
        `${summary.role || "agent"} · ${summary.level || "NORMAL"} · ` +
        `${summary.redactions || 0} redactions · ${summary.blocks || 0} blocked`;
      if (viewMode === "live") {
        applyState(live);
        drawChart(live.points);
        rebuildFeed(liveRecords);
      }
    } else if (m.kind === "audit") {
      const e = normalizeAudit(m.record);
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

// ---- Attack Lab simulation
const GATE_ORDER = ["session", "policy", "constraint", "sequence", "action", "response"];

function labScenarioData() {
  return ATTACK_SCENARIOS[labScenario];
}

function decisionResultClass(step) {
  if (step.flow === "block") return "block";
  if (step.flow === "allow") return "allow";
  return "transform";
}

function newLabRunId() {
  return `RUN-${Date.now().toString(36).slice(-6).toUpperCase()}`;
}

function labPlatformName() {
  return labScenario === "github" ? "GitHub" : "Slack";
}

function detectedScenarioTitle(scenario) {
  if (labStep < 0) return `New ${labPlatformName()} agent session`;
  if (labStep < 1) return `${labPlatformName()} activity under observation`;
  if (labStep < 3) return `Suspicious ${labPlatformName()} agent activity`;
  return scenario.title;
}

function renderLabTimeline() {
  const scenario = labScenarioData();
  let previousSession = "";
  const revealed = scenario.steps.slice(0, labStep + 1);
  const rows = revealed.map((step, index) => {
    let divider = "";
    if (step.session && step.session !== previousSession) {
      previousSession = step.session;
      divider = `<div class="session-divider">${esc(step.session)}</div>`;
    }
    return `${divider}<button class="timeline-step ${index < labStep ? "done" : ""} ${index === labStep ? "active arriving" : ""}"
      data-step="${index}">
      <span class="timeline-number">${index < labStep ? "✓" : index + 1}</span>
      <span class="timeline-copy">
        <b>${esc(step.title)}</b>
        <small>${esc(step.subtitle)}</small>
      </span>
      <span class="timeline-result result-${decisionResultClass(step)}"></span>
    </button>`;
  });
  if (labStep < scenario.steps.length - 1) {
    rows.push(`<div class="timeline-waiting">
      <span class="waiting-pulse"></span>
      <span>${labStep < 0 ? "Waiting for the first tool call…" : "Waiting for the agent’s next action…"}</span>
    </div>`);
  }
  $("lab-timeline").innerHTML = rows.join("");
  document.querySelectorAll(".timeline-step").forEach((button) => {
    button.onclick = () => {
      stopLab();
      labStep = Number(button.dataset.step);
      renderLab();
    };
  });
}

function renderLabGates(step) {
  const activeIndex = GATE_ORDER.indexOf(step.gate);
  document.querySelectorAll("#lab-gates [data-gate]").forEach((gate, index) => {
    gate.className = "";
    if (index < activeIndex) gate.classList.add("passed");
    if (index === activeIndex) {
      gate.classList.add(step.flow === "block" ? "denied" : "active");
    }
  });
  const names = {
    session: "Session gate",
    policy: "Policy match",
    constraint: "Argument constraints",
    sequence: "Sequence + taint",
    action: "Action handler",
    response: "Response DLP"
  };
  $("lab-active-gate").textContent = names[step.gate] || "Policy graph";
}

function animateLabFlow(step) {
  const topology = $("lab-topology");
  topology.classList.remove("flow-allow", "flow-transform", "flow-block");
  void topology.offsetWidth;
  topology.classList.add(`flow-${step.flow}`);
  $("lab-gateway-verdict").textContent =
    step.flow === "block" ? "STOPPED" : step.flow === "allow" ? "PASSED" : "MADE SAFE";
  $("lab-service-state").textContent =
    step.upstream ? "Received controlled call" : "Not contacted";
}

function renderLabIdle() {
  const scenario = labScenarioData();
  $("lab-verdict-label").textContent = "Incident state";
  $("lab-verdict-icon").textContent = "•";
  $("lab-final-outcome").textContent = `Monitoring · ${labRunId}`;
  $("lab-scenario-title").textContent = detectedScenarioTitle(scenario);
  $("lab-severity").textContent = "ANALYZING";
  $("lab-severity").className = "severity severity-analyzing";
  $("lab-service-name").textContent = scenario.service;
  $("lab-service-icon").textContent = scenario.icon;

  $("lab-step-count").textContent = "0 observed";
  $("lab-decision").textContent = "NO ACTIVITY";
  $("lab-decision").className = "decision-pill decision-hide";
  $("lab-trust").textContent = "Clean";
  $("lab-trust").style.color = "#15803d";
  $("lab-risk").textContent = "0 · Normal";
  $("lab-risk-fill").style.width = "0%";
  $("lab-risk-fill").style.background = "#15803d";
  $("lab-upstream").textContent = "Waiting";

  $("lab-stage-overline").textContent = `NEW SESSION · ${labRunId}`;
  $("lab-step-title").textContent = "Waiting for the agent’s first tool call";
  $("lab-explainer").textContent =
    "Nothing has been classified yet. Start the session and watch each action appear only when the agent attempts it.";
  $("lab-tool").textContent = "No request yet";
  $("lab-outcome").textContent = "Jac is standing by";
  $("lab-why").textContent =
    "The incident classification, severity, policies, and outcome will emerge from observed behavior.";
  $("lab-payload").hidden = true;

  $("lab-policy-action").textContent = "WAITING";
  $("lab-policy-action").className = "decision-pill decision-hide";
  $("lab-policy-name").textContent = "No policy invoked yet";
  $("lab-policy-rule").textContent = "CallWalker has not started";
  $("lab-policy-reason").textContent =
    "A policy will appear here when a tool call enters the Jac enforcement graph.";
  $("lab-proof-upstream").textContent = "No activity";
  $("lab-policy-count").textContent = "0";
  $("lab-evidence").textContent = "The audit stream is waiting for the first event.";

  $("lab-prev").disabled = true;
  $("lab-next").disabled = false;
  renderLabTimeline();
  document.querySelectorAll("#lab-gates [data-gate]").forEach((gate) => {
    gate.className = "";
  });
  const topology = $("lab-topology");
  topology.classList.remove("flow-allow", "flow-transform", "flow-block");
  $("lab-active-gate").textContent = "Waiting for activity";
  $("lab-gateway-verdict").textContent = "WATCHING";
  $("lab-service-state").textContent = "Waiting for activity";
}

function renderLab() {
  const scenario = labScenarioData();
  if (labStep < 0) {
    renderLabIdle();
    return;
  }
  const step = scenario.steps[labStep];
  const riskColor =
    step.level === "Suspended" ? "#c0392f" : step.level === "Elevated" ? "#b45309" : "#15803d";
  const finished = labStep === scenario.steps.length - 1;

  $("lab-verdict-label").textContent = finished ? "Final outcome" : "Live classification";
  $("lab-verdict-icon").textContent = finished ? "✓" : "!";
  $("lab-final-outcome").textContent = finished
    ? scenario.final
    : labStep < 1
      ? `Analyzing · ${labRunId}`
      : `Possible ${scenario.title.toLowerCase()}`;
  $("lab-scenario-title").textContent = detectedScenarioTitle(scenario);
  const severity = labStep < 1 ? "ANALYZING" : scenario.severity;
  $("lab-severity").textContent = severity;
  $("lab-severity").className =
    `severity severity-${severity === "ANALYZING" ? "analyzing" : severity.toLowerCase()}`;
  $("lab-service-name").textContent = scenario.service;
  $("lab-service-icon").textContent = scenario.icon;

  $("lab-step-count").textContent = `${labStep + 1} observed`;
  $("lab-decision").textContent = step.action;
  $("lab-decision").className = `decision-pill decision-${step.decision}`;
  $("lab-trust").textContent = step.tainted ? "Tainted · untrusted" : "Clean";
  $("lab-trust").style.color = step.tainted ? "#c0392f" : "#15803d";
  $("lab-risk").textContent = `${step.risk} · ${step.level}`;
  $("lab-risk-fill").style.width = `${Math.min(step.risk, 100)}%`;
  $("lab-risk-fill").style.background = riskColor;
  $("lab-upstream").textContent = step.upstream ? `${scenario.service} reached` : "Not contacted";

  $("lab-stage-overline").textContent = step.phase;
  $("lab-step-title").textContent = step.title;
  $("lab-explainer").textContent = step.explainer;
  $("lab-tool").textContent = step.tool;
  $("lab-outcome").textContent = step.outcome;
  $("lab-why").textContent = step.why;

  const payload = $("lab-payload");
  payload.hidden = !step.payload;
  if (step.payload) {
    $("lab-payload-before").textContent = step.payload.before;
    $("lab-payload-after").textContent = step.payload.after;
  }

  $("lab-policy-action").textContent = step.action;
  $("lab-policy-action").className = `decision-pill decision-${step.decision}`;
  $("lab-policy-name").textContent = step.policy;
  $("lab-policy-rule").textContent = step.rule;
  $("lab-policy-reason").textContent = step.reason;
  $("lab-proof-upstream").textContent = step.upstream ? "Yes — controlled" : "No — stopped first";
  $("lab-policy-count").textContent = String(step.policyCount);
  $("lab-evidence").textContent = step.evidence;

  $("lab-prev").disabled = labStep === 0;
  $("lab-next").disabled = labStep === scenario.steps.length - 1;
  renderLabTimeline();
  renderLabGates(step);
  animateLabFlow(step);

  const active = document.querySelector(".timeline-step.active");
  if (active) active.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

function stopLab() {
  if (labTimer) clearTimeout(labTimer);
  labTimer = null;
  labPlaying = false;
  $("lab-play").textContent =
    labStep < 0
      ? "▶ Start new session"
      : labStep >= labScenarioData().steps.length - 1
        ? "↻ Start new run"
        : "▶ Continue session";
}

function scheduleLab() {
  if (!labPlaying) return;
  const scenario = labScenarioData();
  const delay = Number($("lab-speed").value);
  labTimer = setTimeout(() => {
    if (labStep >= scenario.steps.length - 1) {
      stopLab();
      return;
    }
    labStep += 1;
    renderLab();
    scheduleLab();
  }, delay);
}

function toggleLab() {
  if (labPlaying) {
    stopLab();
    return;
  }
  if (labStep >= labScenarioData().steps.length - 1) {
    labRunId = newLabRunId();
    labStep = -1;
  }
  if (labStep < 0) labStep = 0;
  labPlaying = true;
  $("lab-play").textContent = "Ⅱ Pause stream";
  renderLab();
  scheduleLab();
}

function changeLabScenario(name) {
  stopLab();
  labScenario = name;
  labStep = -1;
  labRunId = newLabRunId();
  document.querySelectorAll(".scenario-choice").forEach((button) => {
    button.classList.toggle("active", button.dataset.scenario === name);
  });
  renderLab();
}

// ---- view + controls
function showView(name) {
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.view === name));
  $("view-lab").hidden = name !== "lab";
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

document.querySelectorAll(".scenario-choice").forEach((button) => {
  button.onclick = () => changeLabScenario(button.dataset.scenario);
});
$("lab-prev").onclick = () => {
  stopLab();
  labStep = Math.max(0, labStep - 1);
  renderLab();
};
$("lab-next").onclick = () => {
  stopLab();
  labStep = Math.min(labScenarioData().steps.length - 1, labStep + 1);
  renderLab();
};
$("lab-restart").onclick = () => {
  stopLab();
  labStep = -1;
  labRunId = newLabRunId();
  renderLab();
};
$("lab-play").onclick = toggleLab;
$("lab-speed").onchange = () => {
  if (labPlaying) {
    if (labTimer) clearTimeout(labTimer);
    scheduleLab();
  }
};
document.addEventListener("keydown", (event) => {
  if (!$("view-lab").hidden && !["INPUT", "TEXTAREA", "SELECT"].includes(event.target.tagName)) {
    if (event.key === "ArrowRight") $("lab-next").click();
    if (event.key === "ArrowLeft") $("lab-prev").click();
    if (event.key === " ") {
      event.preventDefault();
      toggleLab();
    }
  }
});

initChips();
renderLab();
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
