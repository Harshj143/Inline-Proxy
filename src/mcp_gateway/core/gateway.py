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

from typing import Any, Protocol

from mcp_gateway.audit import events
from mcp_gateway.audit.recorder import AuditRecorder
from mcp_gateway.core.context import CallContext, Principal
from mcp_gateway.core.pipeline import RequestPipeline
from mcp_gateway.core.session import Session
from mcp_gateway.policy.engine import PolicyEngine
from mcp_gateway.protocol import mcp
from mcp_gateway.protocol.jsonrpc import decode_line, denied_response, encode

QUARANTINE_NOTICE = (
    "[QUARANTINED by security gateway] The result of '{tool}' was withheld "
    "from the model and flagged for human review."
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
    ):
        self.pipeline = pipeline
        self.audit = audit
        self.principal = principal or Principal()
        # Optional but recommended: with the engine present, tools/list
        # responses are filtered so tools whose action can only deny are
        # invisible to the model (smaller prompt-injection surface, no agent
        # turns wasted on doomed calls).
        self.policy = policy
        self.session = Session.new()
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

        decision = ctx.decision
        if outcome.denied:
            event = (
                events.TOOL_CALL_DENIED_SESSION_SUSPENDED
                if outcome.stage == "session_gate"
                else events.TOOL_CALL_BLOCKED
            )
            await self.audit.emit(
                event,
                tool=tool,
                id=msg.id,
                reason=outcome.reason,
                stage=outcome.stage,
                rule=decision.rule if decision else None,
                stage_timings_ms=ctx.timings_ms,
            )
            await self.transport.send_client(
                encode(denied_response(msg.id, tool, outcome.reason))
            )
            return

        assert decision is not None, "pipeline allowed a call without a decision"
        self.session.record_call(tool)
        self.session.track_pending(msg.id, tool, decision.action, ctx.disposition)

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

        if pending.disposition == "quarantine" and not mcp.result_is_error(msg.raw):
            # The data ran upstream but never enters the model's context
            # window; audit records size only, never content.
            outbound = {
                **msg.raw,
                "result": {"content": [{
                    "type": "text",
                    "text": QUARANTINE_NOTICE.format(tool=pending.tool),
                }]},
            }
            await self.audit.emit(
                events.TOOL_RESULT_QUARANTINED,
                tool=pending.tool,
                id=msg.id,
                duration_ms=round(pending.elapsed_ms(), 1),
                withheld_bytes=result_bytes,
            )
            await self.transport.send_client(encode(outbound))
            return

        # Phase 2 hooks result redaction here for disposition == "redact".
        await self.audit.emit(
            events.TOOL_RESULT,
            tool=pending.tool,
            id=msg.id,
            action=pending.action,
            duration_ms=round(pending.elapsed_ms(), 1),
            is_error=mcp.result_is_error(msg.raw),
            result_bytes=result_bytes,
        )
        await self.transport.send_client(encode(msg.raw))

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
        shown: list[Any] = []
        hidden: list[str] = []
        for entry in tools:
            name = entry.get("name") if isinstance(entry, dict) else None
            if isinstance(name, str) and not self.policy.is_visible(name, role=role):
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
