"""The gateway orchestrator: routes wire traffic, runs the pipeline, audits.

Transport-agnostic by design — it never touches stdin/stdout/sockets. A
transport feeds it decoded lines via `on_client_line` / `on_upstream_line`
and provides `send_client` / `send_upstream`; that seam is what lets the
Streamable HTTP transport (Phase 5) reuse this file unchanged.

Routing rules (docs/ARCHITECTURE.md §2):
  * unparseable line        -> forward opaquely, audit (not ours to judge)
  * tools/call request      -> enforcement pipeline
  * everything else client  -> audited passthrough
  * upstream response to a  -> correlate to the pending call, audit result
    forwarded tools/call       (redact/quarantine hook here in later phases)
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from typing import Any, Protocol

from mcp_gateway.anomaly import AnomalyMonitor, SessionTrace
from mcp_gateway.audit import events
from mcp_gateway.audit.recorder import AuditRecorder
from mcp_gateway.core.context import CallContext, Principal
from mcp_gateway.core.failure import FailMode, FailurePosture
from mcp_gateway.core.pipeline import RequestPipeline
from mcp_gateway.policy.engine import PolicyEngine
from mcp_gateway.protocol import mcp
from mcp_gateway.protocol.jsonrpc import decode_line, denied_response, encode
from mcp_gateway.redaction.service import RedactionService
from mcp_gateway.risk.scoring import (
    APPROVAL_DENIED,
    BLOCKED_TOOL,
    CONSTRAINT_VIOLATION,
    HEAVY_REDACTION,
    SEQUENCE_VIOLATION,
    RiskEngine,
)
from mcp_gateway.sequence.policy import SequencePolicy
from mcp_gateway.state import MemorySessionStore, SessionStore

QUARANTINE_NOTICE = (
    "[QUARANTINED by security gateway] The result of '{tool}' was withheld "
    "from the model and flagged for human review."
)
REDACTION_FAILED_NOTICE = (
    "[WITHHELD by security gateway] The result of '{tool}' could not be safely "
    "redacted and was withheld from the model (fail-closed)."
)


class Transport(Protocol):
    async def send_client(self, line: str) -> None: ...
    async def send_upstream(self, line: str) -> None: ...


class SecurityGateway:
    def __init__(
        self,
        *,
        pipeline: RequestPipeline,
        audit: AuditRecorder,
        principal: Principal | None = None,
        policy: PolicyEngine | None = None,
        redaction: RedactionService | None = None,
        store: SessionStore | None = None,
        anomaly: AnomalyMonitor | None = None,
    ):
        self.pipeline = pipeline
        self.audit = audit
        self.principal = principal or Principal()
        # Applies result-stage redaction for calls the redact action marked.
        self.redaction = redaction
        # Optional but recommended: with the engine present, tools/list
        # responses are filtered so tools whose action can only deny are
        # invisible to the model (smaller prompt-injection surface, no agent
        # turns wasted on doomed calls).
        self.policy = policy
        # Risk scoring + taint marking. Built from policy when present; a no-op
        # default (empty config) otherwise so the gateway works policy-less.
        self.risk = policy.build_risk_engine() if policy else RiskEngine()
        self.sequence = policy.build_sequence_policy() if policy else SequencePolicy()
        # Failure posture (fail-closed default). Governs unexpected runtime
        # errors only — never policy denials or config errors.
        self.posture = policy.posture if policy else FailurePosture()
        self.store = store or MemorySessionStore()
        # Behavioral monitor (off by default); its verdicts feed the risk engine.
        self.anomaly = anomaly
        self.session = self.store.get_or_create(uuid.uuid4().hex[:8])
        # Every event from this gateway carries the session id; the console
        # and SIEM group on it.
        self.audit.default_fields.setdefault("session_id", self.session.id)
        self._transport: Transport | None = None
        # Request ids of in-flight tools/list calls awaiting filtered responses.
        self._pending_tools_list: set[Any] = set()

    def bind_transport(self, transport: Transport) -> None:
        self._transport = transport

    @property
    def transport(self) -> Transport:
        if self._transport is None:
            raise RuntimeError("gateway used before bind_transport()")
        return self._transport

    # ------------------------------------------------------------- lifecycle
    async def on_start(self, upstream_cmd: list[str]) -> None:
        await self.audit.emit(
            events.GATEWAY_START,
            upstream=" ".join(upstream_cmd),
            principal=self.principal.id,
            roles=list(self.principal.roles),
            failure_posture=self.posture.describe(),
        )
        # A fail-open posture is a security-relevant choice; make it impossible
        # to enable silently — a distinct audit event and a stderr banner.
        if self.posture.any_open:
            categories = ", ".join(self.posture.open_categories())
            await self.audit.emit(events.FAIL_OPEN_ENABLED, categories=categories)
            print(
                f"mcp-gateway: WARNING — FAIL-OPEN enabled for [{categories}]. "
                f"On error, affected calls are ALLOWED/RELEASED, not blocked. "
                f"This trades security for availability at your own risk.",
                file=sys.stderr,
            )

    async def on_upstream_exit(self, returncode: int | None) -> None:
        await self.audit.emit(events.UPSTREAM_EXIT, returncode=returncode)

    async def on_stop(self) -> None:
        await self.audit.emit(events.GATEWAY_STOP)
        await self.audit.close()

    # ------------------------------------------------------ client -> upstream
    async def on_client_line(self, line: str) -> None:
        msg = decode_line(line)
        if msg is None:
            await self.audit.emit(
                events.PASSTHROUGH_OPAQUE,
                direction="client_to_upstream",
                bytes=len(line.encode("utf-8")),
            )
            await self.transport.send_upstream(line)
            return

        if mcp.is_tool_call(msg):
            await self._handle_tool_call(msg)
            return

        if msg.method == mcp.METHOD_TOOLS_LIST and msg.is_request and self.policy:
            self._pending_tools_list.add(msg.id)

        await self.audit.emit(
            events.PASSTHROUGH_REQUEST, method=msg.method, id=msg.id
        )
        await self.transport.send_upstream(encode(msg.raw))

    async def _handle_denial(self, msg, tool, ctx, outcome, decision) -> None:
        """Audit a denied call, score it, and send the JSON-RPC error."""
        # Fail-open (opt-in): an UNEXPECTED stage crash — never a policy denial —
        # forwards the original call unmodified instead of blocking.
        if outcome.internal_error and self.posture.pipeline is FailMode.OPEN:
            await self.audit.emit(
                events.STAGE_ERROR_FAIL_OPEN,
                tool=tool, id=msg.id, stage=outcome.stage, reason=outcome.reason,
            )
            self.session.track_pending(msg.id, tool, "fail_open")
            await self.transport.send_upstream(encode(msg.raw))
            return

        if outcome.stage == "session_gate":
            # Already suspended: refuse without adding more risk (don't punish
            # a cut-off session repeatedly).
            await self.audit.emit(
                events.TOOL_CALL_DENIED_SESSION_SUSPENDED,
                tool=tool, id=msg.id, reason=outcome.reason,
                session_score=self.session.risk_score,
            )
        else:
            fields: dict[str, Any] = {
                "tool": tool, "id": msg.id, "reason": outcome.reason,
                "stage": outcome.stage,
                "rule": decision.rule if decision else None,
                "stage_timings_ms": ctx.timings_ms,
            }
            if outcome.risk_event:
                update = self.risk.record(self.session, outcome.risk_event, detail=tool)
                fields.update(update.audit_fields())
                if outcome.stage == "sequence":
                    fields["tainted"] = self.session.tainted
                    fields["taint_origin"] = self.session.taint_origin
            await self.audit.emit(events.TOOL_CALL_BLOCKED, **fields)
            if outcome.risk_event and update.suspended_now:
                await self._audit_suspended()

        await self.transport.send_client(
            encode(denied_response(msg.id, tool, outcome.reason))
        )
        # A block is one of the moments most worth a behavioral look — force it.
        await self._run_anomaly(tool, force=True)

    async def _run_anomaly(self, last_tool: str, force: bool) -> None:
        """Ask the behavioral monitor to judge the session; a flagged verdict
        feeds the risk engine like any other event."""
        if self.anomaly is None:
            return
        trace = SessionTrace(
            history=list(self.session.history),
            last_tool=last_tool,
            tainted=self.session.tainted,
            blocked_count=self._blocked_count(),
        )
        verdict = await self.anomaly.observe(trace, force=force)
        if verdict is None or not verdict.anomalous:
            return
        update = self.risk.record(self.session, f"anomaly_{verdict.severity}", detail=last_tool)
        await self.audit.emit(
            events.ANOMALY_DETECTED,
            tool=last_tool, severity=verdict.severity, rationale=verdict.rationale,
            backend=self.anomaly.backend_name, **update.audit_fields(),
        )
        if update.suspended_now:
            await self._audit_suspended()

    def _blocked_count(self) -> int:
        denials = {BLOCKED_TOOL, CONSTRAINT_VIOLATION, SEQUENCE_VIOLATION, APPROVAL_DENIED}
        return sum(1 for e in self.session.risk_events if e["event"] in denials)

    async def _audit_suspended(self) -> None:
        await self.audit.emit(
            events.SESSION_SUSPENDED,
            session_score=self.session.risk_score,
            events=self.session.risk_events,
        )

    async def _handle_tool_call(self, msg) -> None:
        tool, arguments = mcp.tool_call_parts(msg)
        ctx = CallContext(
            session=self.session,
            message=msg,
            tool=tool,
            arguments=arguments,
            principal=self.principal,
        )
        outcome = await self.pipeline.run(ctx)

        # A require_approval rule asked a human; record the decision either way.
        if ctx.approval is not None:
            await self.audit.emit(
                events.APPROVAL_REQUESTED,
                tool=tool, id=msg.id,
                approved=ctx.approval.approved,
                approver=ctx.approval.approver,
                note=ctx.approval.note,
            )

        decision = ctx.decision
        if outcome.denied:
            await self._handle_denial(msg, tool, ctx, outcome, decision)
            return

        assert decision is not None, "pipeline allowed a call without a decision"
        self.session.record_call(tool)
        # A taint source ingests untrusted content: from here on, sinks are
        # blocked (the sequence gate enforces it). Marked only AFTER the call
        # passed every gate — a blocked source call must not taint the session.
        if self.sequence.is_taint_source(tool) and self.session.mark_tainted(tool):
            await self.audit.emit(
                events.SESSION_TAINTED, tool=tool, id=msg.id,
                note="untrusted content ingested; taint sinks now blocked",
            )
        self.session.track_pending(
            msg.id, tool, decision.action, ctx.disposition, ctx.redaction_spec
        )

        allowed_fields: dict[str, Any] = {
            "tool": tool,
            "id": msg.id,
            "action": decision.action,
            "rule": decision.rule,
            "stage_timings_ms": ctx.timings_ms,
        }
        if decision.role is not None:
            allowed_fields["role"] = decision.role
        if ctx.argument_changes:
            allowed_fields["rewrites"] = ctx.argument_changes
        if ctx.argument_redactions:
            allowed_fields["arg_redactions"] = ctx.argument_redactions
        if ctx.disposition != "none":
            allowed_fields["disposition"] = ctx.disposition
        await self.audit.emit(events.TOOL_CALL_ALLOWED, **allowed_fields)

        outbound = msg.raw
        if ctx.effective_arguments is not None:
            # Forward the rewritten arguments, never the originals.
            outbound = {
                **msg.raw,
                "params": {**msg.params, "arguments": ctx.effective_arguments},
            }
        await self.transport.send_upstream(encode(outbound))
        await self._run_anomaly(tool, force=False)

    # ------------------------------------------------------ upstream -> client
    async def on_upstream_line(self, line: str) -> None:
        msg = decode_line(line)
        if msg is None:
            await self.audit.emit(
                events.PASSTHROUGH_OPAQUE,
                direction="upstream_to_client",
                bytes=len(line.encode("utf-8")),
            )
            await self.transport.send_client(line)
            return

        if msg.is_response:
            pending = self.session.resolve_pending(msg.id)
            if pending is not None:
                await self._deliver_tool_result(msg, pending)
                return
            if msg.id in self._pending_tools_list:
                self._pending_tools_list.discard(msg.id)
                outbound, hidden, total = self._filter_tools_list(msg.raw)
                if hidden:
                    await self.audit.emit(
                        events.TOOLS_LIST_FILTERED,
                        id=msg.id,
                        total=total,
                        shown=total - len(hidden),
                        hidden=hidden,
                    )
                await self.transport.send_client(encode(outbound))
                return
        elif msg.method is not None and msg.is_request:
            # Server-initiated request (sampling, roots, …): passes through,
            # but its existence is on the record.
            await self.audit.emit(events.UPSTREAM_REQUEST, method=msg.method, id=msg.id)

        await self.transport.send_client(encode(msg.raw))

    async def _deliver_tool_result(self, msg, pending) -> None:
        """Apply the pending disposition to a correlated tool result."""
        result_bytes = mcp.result_size_bytes(msg.raw)
        is_error = mcp.result_is_error(msg.raw)

        # Error results carry no data to protect; deliver them as-is regardless
        # of disposition so the client sees the real failure.
        if not is_error and pending.disposition == "quarantine":
            await self._deliver_quarantined(msg, pending, result_bytes)
            return
        if not is_error and pending.disposition == "redact":
            await self._deliver_redacted(msg, pending, result_bytes)
            return

        await self.audit.emit(
            events.TOOL_RESULT,
            tool=pending.tool,
            id=msg.id,
            action=pending.action,
            duration_ms=round(pending.elapsed_ms(), 1),
            is_error=is_error,
            result_bytes=result_bytes,
        )
        await self.transport.send_client(encode(msg.raw))

    async def _deliver_quarantined(self, msg, pending, result_bytes: int) -> None:
        # The data ran upstream but never enters the model's context window;
        # audit records size only, never content.
        outbound = {**msg.raw, "result": {"content": [{
            "type": "text", "text": QUARANTINE_NOTICE.format(tool=pending.tool),
        }]}}
        await self.audit.emit(
            events.TOOL_RESULT_QUARANTINED,
            tool=pending.tool, id=msg.id,
            duration_ms=round(pending.elapsed_ms(), 1),
            withheld_bytes=result_bytes,
        )
        await self.transport.send_client(encode(outbound))

    async def _deliver_redacted(self, msg, pending, result_bytes: int) -> None:
        """Scrub the result before it reaches the model; fail closed on error.

        A detector crash or missing service must never release unscanned data,
        so any failure here withholds the result (quarantine) rather than
        delivering it — the same safe direction as every other control.
        """
        spec = pending.redaction
        if self.redaction is None or spec is None:
            await self._withhold_unredactable(msg, pending, result_bytes,
                                               "redaction service unavailable")
            return
        try:
            # Redaction (especially the NER tier) is CPU-bound; run it in a
            # worker thread so a slow scan never stalls the event loop and
            # other in-flight calls.
            redacted, report = await asyncio.to_thread(
                self.redaction.redact, msg.raw.get("result"), spec
            )
        except Exception as exc:  # noqa: BLE001
            # Fail-closed (default): withhold the unscanned result. Fail-open
            # (opt-in): release the RAW result and audit it loudly.
            if self.posture.redaction is FailMode.OPEN:
                await self.audit.emit(
                    events.REDACTION_ERROR_FAIL_OPEN,
                    tool=pending.tool, id=msg.id, reason=str(exc),
                    result_bytes=result_bytes,
                )
                await self.transport.send_client(encode(msg.raw))
            else:
                await self._withhold_unredactable(msg, pending, result_bytes, str(exc))
            return

        outbound = {**msg.raw, "result": redacted}
        fields: dict[str, Any] = {
            "tool": pending.tool, "id": msg.id,
            "duration_ms": round(pending.elapsed_ms(), 1),
            "result_bytes": result_bytes,
            "profile": spec.profile,
            "redactions": report.summary(),
        }
        # A result stuffed with PII is a signal worth scoring even though
        # redaction succeeded: the agent is reaching into unusually sensitive
        # data. (Threshold mirrors the prototype: 3+ entities.)
        if report.total >= 3:
            update = self.risk.record(self.session, HEAVY_REDACTION, detail=pending.tool)
            fields.update(update.audit_fields())
            if update.suspended_now:
                await self._audit_suspended()
        await self.audit.emit(events.TOOL_RESULT_REDACTED, **fields)
        await self.transport.send_client(encode(outbound))

    async def _withhold_unredactable(self, msg, pending, result_bytes, reason) -> None:
        outbound = {**msg.raw, "result": {"content": [{
            "type": "text", "text": REDACTION_FAILED_NOTICE.format(tool=pending.tool),
        }]}}
        await self.audit.emit(
            events.TOOL_RESULT_REDACTION_FAILED,
            tool=pending.tool, id=msg.id,
            duration_ms=round(pending.elapsed_ms(), 1),
            withheld_bytes=result_bytes,
            reason=reason,
        )
        await self.transport.send_client(encode(outbound))

    def _filter_tools_list(
        self, raw: dict[str, Any]
    ) -> tuple[dict[str, Any], list[str], int]:
        """Drop tools whose action can only deny from a tools/list result.

        Returns (outbound_message, hidden_tool_names, total_tools).
        """
        assert self.policy is not None
        result = raw.get("result")
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list):
            return raw, [], 0  # error response or unexpected shape: pass through

        role = self.principal.roles[0] if self.principal.roles else None
        # Visibility reflects the pipeline's ACTUAL handlers: a redact/approval
        # tool is visible when its service-backed handler can succeed.
        denying = self.pipeline.denying_actions()
        shown: list[Any] = []
        hidden: list[str] = []
        for entry in tools:
            name = entry.get("name") if isinstance(entry, dict) else None
            if isinstance(name, str) and not self.policy.is_visible(
                name, role=role, denying=denying
            ):
                hidden.append(name)
            else:
                shown.append(entry)

        if hidden:
            return {**raw, "result": {**result, "tools": shown}}, hidden, len(tools)
        return raw, [], len(tools)

    # ---------------------------------------------------------------- helpers
    def annotate(self, **fields: Any) -> None:
        """Add default audit fields (e.g. transport details) before start."""
        self.audit.default_fields.update(fields)
