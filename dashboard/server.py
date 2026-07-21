"""Security Ops Console — control plane for the MCP security gateway.

A zero-dependency web app (Python stdlib only) that turns the gateway's JSONL
audit trail into a live operator console. It does three things:

  1. STREAMS every decision to the browser in real time (SSE tail of audit.log).
  2. HOLDS approval requests. A gateway launched with `--approvals http` POSTs
     each `require_approval` call here and blocks; the console shows it with
     Approve / Deny buttons, and the human's click unblocks the gateway. The
     browser IS the human-in-the-loop.
  3. Serves SESSION HISTORY — every past gateway run, grouped by session id,
     with its final risk score, ready to replay.

    python dashboard/server.py --audit audit.log --port 8000
    open http://localhost:8000

Nothing about policy enforcement lives here; the console is a read-only view
plus the approval relay. Enforcement is entirely in the gateway.
"""

from __future__ import annotations

import argparse
import json
import queue
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gateway.policy import ALLOW, BLOCK, REQUIRE_APPROVAL, apply_rewrites
from gateway.sequence import SequencePolicy, SessionState

HERE = Path(__file__).resolve().parent
AUDIT_PATH = Path("audit.log")
POLICY_PATH = Path("policies.json")

# The console holds an approval POST open this long before failing (the gateway
# client waits slightly longer, so it always gets a response, not a reset).
APPROVAL_WAIT = 290.0

SUBS: set[queue.Queue] = set()
SUBS_LOCK = threading.Lock()

PENDING: dict[str, dict] = {}   # approval id -> {event, decision, info}
PENDING_LOCK = threading.Lock()

_CT = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
       ".js": "application/javascript; charset=utf-8"}


def broadcast(obj: dict) -> None:
    line = json.dumps(obj)
    with SUBS_LOCK:
        dead = []
        for q in SUBS:
            try:
                q.put_nowait(line)
            except queue.Full:
                dead.append(q)
        for q in dead:
            SUBS.discard(q)


# --------------------------------------------------------------- audit reading
def read_all_records() -> list[dict]:
    if not AUDIT_PATH.exists():
        return []
    out = []
    for line in AUDIT_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


def group_sessions(records: list[dict]) -> dict[str, list[dict]]:
    """Bucket records into sessions. Every record carries session_id; older
    records without one attach to the most recent gateway_start."""
    sessions: dict[str, list[dict]] = {}
    order: list[str] = []
    current = None
    for rec in records:
        if rec.get("event") == "gateway_start":
            current = rec.get("session_id") or f"legacy-{len(order)}"
        sid = rec.get("session_id") or current or "unknown"
        if sid not in sessions:
            sessions[sid] = []
            order.append(sid)
        sessions[sid].append(rec)
    return {sid: sessions[sid] for sid in order}


def session_summaries() -> list[dict]:
    grouped = group_sessions(read_all_records())
    out = []
    for sid, recs in grouped.items():
        start = next((r for r in recs if r.get("event") == "gateway_start"), {})
        score, level, tainted = 0, "NORMAL", False
        redactions = blocks = approvals = anomalies = 0
        for r in recs:
            if isinstance(r.get("session_score"), int):
                score = r["session_score"]
            if r.get("session_level"):
                level = r["session_level"]
            e = r.get("event")
            if e == "session_tainted":
                tainted = True
            elif e == "tool_result_redacted":
                redactions += r.get("total", 0)
            elif e in ("tool_call_blocked", "tool_call_blocked_by_sequence",
                       "tool_call_denied_session_suspended"):
                blocks += 1
            elif e == "approval_requested":
                approvals += 1
            elif e == "anomaly_detected":
                anomalies += 1
        out.append({
            "id": sid,
            "started": recs[0].get("ts", ""),
            "ended": any(r.get("event") == "gateway_stop" for r in recs),
            "upstream": start.get("upstream", "?"),
            "role": start.get("role"),
            "anomaly_backend": start.get("anomaly_backend", "off"),
            "score": score, "level": level, "tainted": tainted,
            "events": len(recs), "redactions": redactions,
            "blocks": blocks, "approvals": approvals, "anomalies": anomalies,
        })
    out.reverse()  # newest first
    return out


def policy_payload() -> dict:
    if not POLICY_PATH.exists():
        return {"ok": False, "error": f"policy file not found: {POLICY_PATH}"}
    try:
        raw = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": str(exc)}

    tools = []
    for name, rule in sorted(raw.get("tools", {}).items()):
        role_overrides = rule.get("roles", {})
        tools.append({
            "name": name,
            "action": rule.get("action", raw.get("default_action", "block")),
            "reason": rule.get("reason", ""),
            "roles": [
                {"role": role, "action": override.get("action", rule.get("action", "allow")),
                 "reason": override.get("reason", "")}
                for role, override in sorted(role_overrides.items())
            ],
            "constraints": rule.get("constraints", []),
            "rewrites": rule.get("rewrites", []),
            "approval": rule.get("approval", {}),
        })

    return {
        "ok": True,
        "path": str(POLICY_PATH),
        "raw": raw,
        "default_action": raw.get("default_action", "block"),
        "redact_entities": raw.get("redact_entities", []),
        "taint_sources": raw.get("taint_sources", []),
        "taint_sinks": raw.get("taint_sinks", []),
        "sequence_rules": raw.get("sequence_rules", []),
        "tools": tools,
    }


REQUEST_EVENTS = {
    "tool_call_allowed",
    "tool_call_rewritten",
    "tool_call_quarantined",
    "tool_call_blocked",
    "tool_call_blocked_by_sequence",
    "tool_call_denied_session_suspended",
}


def _effective_rule(raw: dict, tool: str, role: str | None) -> dict | None:
    rule = raw.get("tools", {}).get(tool)
    if rule is None:
        return None
    eff = dict(rule)
    override = rule.get("roles", {}).get(role) if role else None
    if override:
        eff.update(override)
    return eff


def _backtest_decision(raw: dict, tool: str, arguments, role: str | None) -> dict:
    rule = _effective_rule(raw, tool, role)
    if rule is None:
        return {
            "action": raw.get("default_action", BLOCK),
            "reason": "tool not on allowlist; default policy applied",
            "confidence": "exact",
        }

    warnings = []
    constraints = rule.get("constraints", [])
    has_args = isinstance(arguments, dict)
    if constraints and not has_args:
        warnings.append("arguments were not logged; constraints could not be replayed")

    action = rule.get("action", raw.get("default_action", BLOCK))
    reason = rule.get("reason", "explicit tool rule")
    if action == REQUIRE_APPROVAL:
        reason = rule.get("reason", "human approval required")

    rewrites = []
    if action == "rewrite":
        if has_args:
            _, rewrites = apply_rewrites(arguments, rule.get("rewrites", []))
        else:
            warnings.append("arguments were not logged; rewrites could not be previewed")

    return {
        "action": action,
        "reason": reason,
        "confidence": "partial" if warnings else "exact",
        "warnings": warnings,
        "rewrites": rewrites,
    }


def _old_action(rec: dict, approvals: dict[tuple[str, object], dict]) -> str:
    key = (rec.get("session_id", ""), rec.get("id"))
    approval = approvals.get(key)
    if approval:
        return REQUIRE_APPROVAL
    event = rec.get("event")
    if event in ("tool_call_blocked", "tool_call_blocked_by_sequence",
                 "tool_call_denied_session_suspended"):
        return BLOCK
    if event == "tool_call_rewritten":
        return "rewrite"
    if event == "tool_call_quarantined":
        return "quarantine"
    return rec.get("action", ALLOW)


def _extract_calls(records: list[dict]) -> list[dict]:
    approvals: dict[tuple[str, object], dict] = {}
    current_sid = ""
    for rec in records:
        if rec.get("event") == "gateway_start":
            current_sid = rec.get("session_id", current_sid)
        if rec.get("event") == "approval_requested":
            approvals[(rec.get("session_id", current_sid), rec.get("id"))] = rec

    calls = []
    seen: set[tuple[str, object]] = set()
    current_role = None
    current_sid = ""
    for rec in records:
        if rec.get("event") == "gateway_start":
            current_role = rec.get("role")
            current_sid = rec.get("session_id", current_sid)
        if rec.get("event") == "approval_requested":
            sid = rec.get("session_id", current_sid)
            key = (sid, rec.get("id"))
            seen.add(key)
            calls.append({
                "session_id": sid,
                "id": rec.get("id"),
                "ts": rec.get("ts"),
                "tool": rec.get("tool"),
                "role": rec.get("role", current_role),
                "arguments": rec.get("arguments"),
                "old_action": REQUIRE_APPROVAL,
                "old_reason": rec.get("reason", ""),
                "old_event": rec.get("event"),
            })
            continue
        if rec.get("event") not in REQUEST_EVENTS or not rec.get("tool"):
            continue
        sid = rec.get("session_id", current_sid)
        key = (sid, rec.get("id"))
        if key in seen:
            continue
        seen.add(key)
        calls.append({
            "session_id": sid,
            "id": rec.get("id"),
            "ts": rec.get("ts"),
            "tool": rec.get("tool"),
            "role": rec.get("role", current_role),
            "arguments": rec.get("arguments"),
            "old_action": _old_action(rec, approvals),
            "old_reason": rec.get("reason", ""),
            "old_event": rec.get("event"),
        })
    return calls


def backtest_payload(candidate: dict, records: list[dict]) -> dict:
    calls = _extract_calls(records)
    seq = SequencePolicy(
        candidate.get("taint_sources", []),
        candidate.get("taint_sinks", []),
        candidate.get("sequence_rules", []),
    )
    states: dict[str, SessionState] = {}
    rows = []
    summary = {
        "total": 0,
        "changed": 0,
        "newly_blocked": 0,
        "newly_allowed": 0,
        "new_redactions": 0,
        "removed_redactions": 0,
        "approval_changes": 0,
        "partial": 0,
    }

    for call in calls:
        sid = call["session_id"] or "unknown"
        state = states.setdefault(sid, SessionState())
        new = _backtest_decision(candidate, call["tool"], call.get("arguments"), call.get("role"))

        if new["action"] != BLOCK:
            seq_reason = seq.check(call["tool"], state)
            if seq_reason:
                new = {**new, "action": BLOCK, "reason": seq_reason}
            else:
                state.record_call(call["tool"])
                if seq.is_taint_source(call["tool"]):
                    state.mark_tainted(call["tool"])

        old = call["old_action"]
        changed = old != new["action"]
        if changed:
            summary["changed"] += 1
        if old != BLOCK and new["action"] == BLOCK:
            summary["newly_blocked"] += 1
        if old == BLOCK and new["action"] != BLOCK:
            summary["newly_allowed"] += 1
        if old != "redact" and new["action"] == "redact":
            summary["new_redactions"] += 1
        if old == "redact" and new["action"] != "redact":
            summary["removed_redactions"] += 1
        if old != REQUIRE_APPROVAL and new["action"] == REQUIRE_APPROVAL:
            summary["approval_changes"] += 1
        if new.get("confidence") == "partial":
            summary["partial"] += 1

        rows.append({
            **call,
            "new_action": new["action"],
            "new_reason": new.get("reason", ""),
            "confidence": new.get("confidence", "exact"),
            "warnings": new.get("warnings", []),
            "rewrites": new.get("rewrites", []),
            "changed": changed,
        })

    summary["total"] = len(rows)
    return {
        "ok": True,
        "summary": summary,
        "rows": rows,
        "note": "Backtesting replays logged tool calls. Argument-level constraints are partial when original arguments were not logged.",
    }


class AuditTailer(threading.Thread):
    """Tails audit.log and broadcasts each new record to all browsers."""
    daemon = True

    def run(self) -> None:
        pos = AUDIT_PATH.stat().st_size if AUDIT_PATH.exists() else 0
        while True:
            try:
                if AUDIT_PATH.exists():
                    size = AUDIT_PATH.stat().st_size
                    if size < pos:
                        pos = 0  # truncated/recreated
                    if size > pos:
                        with AUDIT_PATH.open("r", encoding="utf-8") as f:
                            f.seek(pos)
                            for line in f:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    rec = json.loads(line)
                                except json.JSONDecodeError:
                                    continue
                                broadcast({"kind": "audit", "record": rec})
                            pos = f.tell()
            except OSError:
                pass
            time.sleep(0.25)


# --------------------------------------------------------------------- handler
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    # ---- helpers
    def _json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _static(self, name: str):
        path = HERE / name
        if not path.exists():
            self.send_error(404)
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", _CT.get(path.suffix, "text/plain"))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        n = int(self.headers.get("Content-Length", 0))
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except (ValueError, OSError):
            return {}

    # ---- GET
    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self._static("index.html")
        elif path in ("/styles.css", "/app.js"):
            self._static(path.lstrip("/"))
        elif path == "/api/sessions":
            self._json(session_summaries())
        elif path.startswith("/api/sessions/"):
            sid = path.rsplit("/", 1)[-1]
            grouped = group_sessions(read_all_records())
            self._json(grouped.get(sid, []))
        elif path == "/api/policy":
            self._json(policy_payload())
        elif path == "/api/stream":
            self._stream()
        else:
            self.send_error(404)

    # ---- POST
    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/api/approvals":
            self._approval_request()
        elif path == "/api/backtest":
            self._backtest()
        elif path.startswith("/api/approvals/") and path.endswith("/decide"):
            aid = path.split("/")[3]
            self._approval_decide(aid)
        else:
            self.send_error(404)

    # ---- SSE stream
    def _stream(self):
        q: queue.Queue = queue.Queue(maxsize=2000)
        with SUBS_LOCK:
            SUBS.add(q)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            # Backlog: replay the most recent session so the feed isn't empty.
            grouped = group_sessions(read_all_records())
            if grouped:
                last = list(grouped.values())[-1]
                for rec in last:
                    self._sse({"kind": "audit", "record": rec, "backlog": True})
            # Any approvals currently waiting for a human.
            with PENDING_LOCK:
                for aid, p in PENDING.items():
                    if p["decision"] is None:
                        self._sse({"kind": "approval_pending", "id": aid, **p["info"]})
            while True:
                try:
                    line = q.get(timeout=15)
                    self.wfile.write(f"data: {line}\n\n".encode("utf-8"))
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with SUBS_LOCK:
                SUBS.discard(q)

    def _sse(self, obj):
        self.wfile.write(f"data: {json.dumps(obj)}\n\n".encode("utf-8"))
        self.wfile.flush()

    # ---- approvals
    def _approval_request(self):
        info = self._read_body()
        aid = uuid.uuid4().hex[:12]
        ev = threading.Event()
        entry = {"event": ev, "decision": None,
                 "info": {"tool": info.get("tool"), "arguments": info.get("arguments"),
                          "role": info.get("role"), "reason": info.get("reason"),
                          "session_id": info.get("session_id"),
                          "ts": time.strftime("%H:%M:%S")}}
        with PENDING_LOCK:
            PENDING[aid] = entry
        broadcast({"kind": "approval_pending", "id": aid, **entry["info"]})

        decided = ev.wait(timeout=APPROVAL_WAIT)
        with PENDING_LOCK:
            decision = PENDING.pop(aid, {}).get("decision")
        if not decided or decision is None:
            broadcast({"kind": "approval_resolved", "id": aid, "approved": False,
                       "approver": "timeout"})
            self._json({"approved": False, "approver": "timeout",
                        "note": "no decision within the approval window"})
            return
        self._json(decision)

    def _approval_decide(self, aid: str):
        body = self._read_body()
        approved = bool(body.get("approved"))
        approver = body.get("approver", "operator")
        with PENDING_LOCK:
            entry = PENDING.get(aid)
            if not entry:
                self._json({"ok": False, "error": "unknown or expired"}, code=404)
                return
            entry["decision"] = {"approved": approved, "approver": approver,
                                 "note": "decided in console"}
            entry["event"].set()
        broadcast({"kind": "approval_resolved", "id": aid,
                   "approved": approved, "approver": approver})
        self._json({"ok": True})

    # ---- policy backtesting
    def _backtest(self):
        body = self._read_body()
        raw_text = body.get("policy")
        if not isinstance(raw_text, str) or not raw_text.strip():
            self._json({"ok": False, "error": "policy JSON is required"}, code=400)
            return
        try:
            candidate = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            self._json({"ok": False, "error": f"invalid JSON: {exc}"}, code=400)
            return
        if not isinstance(candidate, dict):
            self._json({"ok": False, "error": "policy must be a JSON object"}, code=400)
            return
        try:
            report = backtest_payload(candidate, read_all_records())
        except Exception as exc:
            self._json({"ok": False, "error": str(exc)}, code=400)
            return
        self._json(report)


def main() -> int:
    parser = argparse.ArgumentParser(description="Security Ops Console")
    parser.add_argument("--audit", default="audit.log")
    parser.add_argument("--policy", default="policies.json")
    parser.add_argument("--port", type=int, default=8000)
    ns = parser.parse_args()

    global AUDIT_PATH, POLICY_PATH
    AUDIT_PATH = Path(ns.audit)
    POLICY_PATH = Path(ns.policy)
    AuditTailer().start()

    srv = ThreadingHTTPServer(("127.0.0.1", ns.port), Handler)
    print(f"Security Ops Console: http://localhost:{ns.port}   (tailing {AUDIT_PATH}, policy {POLICY_PATH})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
