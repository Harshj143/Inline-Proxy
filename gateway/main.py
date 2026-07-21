"""MCP Security Gateway.

A transparent stdio proxy between an MCP client (the AI agent host) and an
MCP server. The client is configured to launch the gateway INSTEAD of the
real server; the gateway launches the real server as a subprocess and sits
in the middle of the JSON-RPC stream.

    agent/client  <-- stdio -->  GATEWAY  <-- stdio -->  real MCP server

Enforcement stages (miniature of a Formal-style pipeline):

  request stage   tools/call intercepted:
                    - BLOCK  -> JSON-RPC error returned to client; the call
                                never reaches the upstream server
                    - REDACT -> PII stripped from arguments before forwarding
  response stage  results of REDACT-ed tools are scrubbed before the LLM
                  ever sees them
  every stage     full JSONL audit trail

Usage:
    python -m gateway.main --policy policies.json --audit audit.log -- \
        python demo/mock_server.py

Everything after `--` is the command that starts the real MCP server.
MCP's stdio transport is newline-delimited JSON-RPC, so we read and write
line by line.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import uuid
from pathlib import Path

from .anomaly import AnomalyDetector
from .approval import ApprovalBroker
from .audit import AuditLog
from .policy import PolicyEngine, apply_rewrites
from .redact import Redactor, RedactionReport
from .risk import SessionRisk
from .sequence import SequencePolicy, SessionState


class Gateway:
    def __init__(
        self,
        server_cmd: list[str],
        policy_path: str,
        audit_path: str,
        role: str | None = None,
        approval: ApprovalBroker | None = None,
        anomaly: AnomalyDetector | None = None,
    ):
        self.policy = PolicyEngine(policy_path)
        self.redactor = Redactor(self.policy.redact_entities)
        self.audit = AuditLog(audit_path)
        self.risk = SessionRisk()
        self.sequence = SequencePolicy(
            self.policy.taint_sources,
            self.policy.taint_sinks,
            self.policy.sequence_rules,
        )
        self.state = SessionState()
        self.server_cmd = server_cmd
        self.role = role
        self.approval = approval or ApprovalBroker(mode="deny")
        self.anomaly = anomaly or AnomalyDetector(mode="off")
        # A short id so the console can group this run's events into one session
        # and correlate approval requests back to it.
        self.session_id = uuid.uuid4().hex[:8]
        self.approval.session_id = self.session_id
        self.audit.default_fields = {"session_id": self.session_id}

        # request id -> (mode, tool), so we know how each response is handled:
        #   mode "redact"     -> scrub PII from the result
        #   mode "quarantine" -> withhold the result from the LLM entirely
        self._pending: dict = {}
        self._lock = threading.Lock()
        self._stdout_lock = threading.Lock()

    # ------------------------------------------------------------- lifecycle
    def run(self) -> int:
        self.audit.write(
            "gateway_start",
            session_id=self.session_id,
            upstream=" ".join(self.server_cmd),
            redaction_backend=self.redactor.backend,
            default_action=self.policy.default_action,
            role=self.role,
            approval_mode=self.approval.mode,
            anomaly_backend=self.anomaly.backend,
        )
        self.proc = subprocess.Popen(
            self.server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
        )
        t = threading.Thread(target=self._pump_upstream_to_client, daemon=True)
        t.start()
        try:
            self._pump_client_to_upstream()
        finally:
            self.proc.terminate()
            self.audit.write("gateway_stop")
            self.audit.close()
        return 0

    # ---------------------------------------------------- client -> upstream
    def _pump_client_to_upstream(self) -> None:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self._forward_upstream(line)  # not ours to judge; pass through
                continue

            if msg.get("method") == "tools/call":
                msg = self._handle_tool_call(msg)
                if msg is None:
                    continue  # blocked; error already sent to client
                self._forward_upstream(json.dumps(msg))
            else:
                self.audit.write(
                    "passthrough_request", method=msg.get("method"), id=msg.get("id")
                )
                self._forward_upstream(json.dumps(msg))

    def _handle_tool_call(self, msg: dict) -> dict | None:
        params = msg.get("params", {}) or {}
        tool = params.get("name", "<unknown>")
        args = params.get("arguments", {})

        # Session-level control: a suspended session gets nothing more,
        # regardless of what the static policy would have allowed.
        if self.risk.suspended:
            self.audit.write(
                "tool_call_denied_session_suspended", tool=tool,
                id=msg.get("id"), session_score=self.risk.score,
            )
            self._deny(msg, tool,
                       f"session suspended (risk score {self.risk.score} >= 80 "
                       f"after repeated policy violations)")
            return None

        decision = self.policy.evaluate(tool, args, role=self.role)

        if decision.blocked:
            self._block(msg, tool,
                        "constraint_violation" if decision.constraint_violation
                        else "blocked_tool",
                        decision.reason)
            self._run_anomaly(tool)
            return None

        # require_approval: pause and ask a human. On approval, continue as the
        # rule's `then` action; on denial, treat as a block (with risk points).
        if decision.needs_approval:
            result = self.approval.request(tool, args, self.role, decision.reason)
            self.audit.write(
                "approval_requested", tool=tool, id=msg.get("id"),
                reason=decision.reason, approved=result.approved,
                approver=result.approver, note=result.note,
            )
            if not result.approved:
                risk = self.risk.record("approval_denied", detail=tool)
                self.audit.write(
                    "tool_call_blocked", tool=tool, id=msg.get("id"),
                    reason=f"human approval denied ({result.note})", **risk,
                )
                if risk["suspended_now"]:
                    self._audit_suspended()
                self._deny(msg, tool, f"human approval denied ({result.note})")
                self._run_anomaly(tool)
                return None
            # Approved: fold in the underlying action and fall through.
            decision.action = decision.then_action

        # Session-state checks: taint sinks and ordered sequence rules. The
        # static policy said "allow", but the SESSION so far may forbid it.
        seq_reason = self.sequence.check(tool, self.state)
        if seq_reason is not None:
            risk = self.risk.record("blocked_tool", detail=tool)
            self.audit.write(
                "tool_call_blocked_by_sequence", tool=tool, id=msg.get("id"),
                reason=seq_reason, tainted=self.state.tainted,
                taint_origin=self.state.taint_origin, **risk,
            )
            if risk["suspended_now"]:
                self._audit_suspended()
            self._deny(msg, tool, seq_reason)
            self._run_anomaly(tool)
            return None

        # The call is going through. Record it in session history and, if it
        # is a taint source, mark the session tainted from here on.
        self.state.record_call(tool)
        if self.sequence.is_taint_source(tool):
            first = self.state.mark_tainted(tool)
            if first:
                self.audit.write(
                    "session_tainted", tool=tool, id=msg.get("id"),
                    note="untrusted content ingested; taint sinks now blocked",
                )

        if decision.needs_rewrite:
            # Rewrite the arguments to a safe form before forwarding, e.g. pin
            # a SQL LIMIT or force read_only=true. Allowed, but not as asked.
            new_args, changes = apply_rewrites(args, decision.rewrites)
            params["arguments"] = new_args
            msg["params"] = params
            self.audit.write(
                "tool_call_rewritten", tool=tool, id=msg.get("id"),
                action="rewrite", rewrites=changes, role=self.role,
            )
        elif decision.needs_redaction:
            report = RedactionReport()
            params["arguments"] = self.redactor.redact_json(args, report)
            msg["params"] = params
            with self._lock:
                self._pending[msg.get("id")] = ("redact", tool)
            self.audit.write(
                "tool_call_allowed", tool=tool, id=msg.get("id"),
                action="redact", args_redactions=report.counts, role=self.role,
            )
        elif decision.is_quarantine:
            # Let the call run upstream, but the result will be withheld from
            # the LLM and flagged for review (handled on the response path).
            with self._lock:
                self._pending[msg.get("id")] = ("quarantine", tool)
            self.audit.write(
                "tool_call_quarantined", tool=tool, id=msg.get("id"),
                action="quarantine", reason=decision.reason, role=self.role,
            )
        else:
            self.audit.write(
                "tool_call_allowed", tool=tool, id=msg.get("id"), action="allow",
                role=self.role,
            )
        self._run_anomaly(tool)
        return msg

    # ------------------------------------------------------- shared helpers
    def _block(self, msg: dict, tool: str, event: str, reason: str) -> None:
        risk = self.risk.record(event, detail=tool)
        self.audit.write(
            "tool_call_blocked", tool=tool, id=msg.get("id"), reason=reason,
            **risk,
        )
        if risk["suspended_now"]:
            self._audit_suspended()
        self._deny(msg, tool, reason)

    def _audit_suspended(self) -> None:
        self.audit.write(
            "session_suspended", session_score=self.risk.score,
            events=self.risk.events,
        )

    def _run_anomaly(self, last_tool: str) -> None:
        """Ask the behavioral monitor to judge the session so far, and let a
        flagged verdict feed the risk engine like any other event."""
        verdict = self.anomaly.assess(
            history=list(self.state.history),
            last_tool=last_tool,
            tainted=self.state.tainted,
            blocked_count=sum(
                1 for e in self.risk.events
                if e["event"] in ("blocked_tool", "constraint_violation",
                                  "approval_denied")
            ),
        )
        if verdict is None or not verdict.anomalous:
            return
        risk = self.risk.record(f"anomaly_{verdict.severity}", detail=last_tool)
        self.audit.write(
            "anomaly_detected", tool=last_tool, severity=verdict.severity,
            rationale=verdict.rationale, backend=self.anomaly.backend, **risk,
        )
        if risk["suspended_now"]:
            self._audit_suspended()

    # ---------------------------------------------------- upstream -> client
    def _pump_upstream_to_client(self) -> None:
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self._send_client(line)
                continue

            with self._lock:
                pending = self._pending.pop(msg.get("id"), None)

            if pending is not None and "result" in msg:
                mode, tool = pending
                if mode == "redact":
                    report = RedactionReport()
                    msg["result"] = self.redactor.redact_json(msg["result"], report)
                    extra = {}
                    if report.total >= 3:
                        # A result stuffed with PII is a signal worth scoring
                        # even though redaction succeeded: the agent is reaching
                        # into unusually sensitive data.
                        extra = self.risk.record("heavy_redaction", detail=tool)
                    self.audit.write(
                        "tool_result_redacted", tool=tool, id=msg.get("id"),
                        redactions=report.counts, total=report.total, **extra,
                    )
                elif mode == "quarantine":
                    # Withhold the real result from the LLM entirely; hand back
                    # a notice instead. The data ran upstream but never enters
                    # the model's context window.
                    msg["result"] = {"content": [{"type": "text", "text": (
                        f"[QUARANTINED by security gateway] The result of "
                        f"'{tool}' was withheld from the model and flagged for "
                        f"human review."
                    )}]}
                    self.audit.write(
                        "tool_result_quarantined", tool=tool, id=msg.get("id"),
                    )
            self._send_client(json.dumps(msg))

    # --------------------------------------------------------------- plumbing
    def _deny(self, msg: dict, tool: str, reason: str) -> None:
        self._send_client(json.dumps({
            "jsonrpc": "2.0",
            "id": msg.get("id"),
            "error": {
                "code": -32001,
                "message": (
                    f"Tool call '{tool}' denied by security gateway policy "
                    f"({reason}). The request never reached the upstream server."
                ),
            },
        }))

    def _forward_upstream(self, line: str) -> None:
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

    def _send_client(self, line: str) -> None:
        with self._stdout_lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()


def main() -> int:
    parser = argparse.ArgumentParser(description="MCP security gateway")
    parser.add_argument("--policy", default="policies.json")
    parser.add_argument("--audit", default="audit.log")
    parser.add_argument("--role", default=None,
                        help="caller identity for role-based policy (e.g. admin, analyst)")
    parser.add_argument("--approvals", default="deny",
                        choices=["deny", "allow", "http"],
                        help="how require_approval calls are resolved "
                             "(deny = fail closed; allow = auto-approve, dev only; "
                             "http = ask the console, block until a human clicks)")
    parser.add_argument("--approvals-url", default="http://localhost:8000",
                        help="console base URL for --approvals http")
    parser.add_argument("--anomaly", default="off",
                        choices=["off", "heuristic", "claude"],
                        help="LLM behavioral anomaly detection backend")
    parser.add_argument("server_cmd", nargs=argparse.REMAINDER,
                        help="-- command to launch the real MCP server")
    ns = parser.parse_args()

    cmd = ns.server_cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        parser.error("provide the upstream server command after --")
    if not Path(ns.policy).exists():
        parser.error(f"policy file not found: {ns.policy}")

    broker = (ApprovalBroker(mode="http", url=ns.approvals_url)
              if ns.approvals == "http" else ApprovalBroker(mode=ns.approvals))
    return Gateway(
        cmd, ns.policy, ns.audit,
        role=ns.role,
        approval=broker,
        anomaly=AnomalyDetector(mode=ns.anomaly),
    ).run()


if __name__ == "__main__":
    raise SystemExit(main())
