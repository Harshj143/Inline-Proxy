"""Turn audit events into metrics — by reusing the recorder's fan-out.

The recorder (`audit/recorder.py`) already fans every event out to a list of
sinks, and its docstring anticipated this: audit errors surface "as
metrics/alarms" in a later phase. This is that sink. Adding a `MetricsAuditSink`
alongside the spool sink means every decision the gateway makes is counted with
zero new call sites and zero coupling to the enforcement path — the same event
that lands in the audit trail bumps a counter.

The counters are deliberately low-cardinality (see `metrics.py`): a universal
`audit_events_total{event}` over the fixed set of event names, plus a
`tool_calls_total{outcome}` decision split and a couple of security-signal
totals. No tool name or principal id is ever a label — those live in the audit
trail, which is built to hold high-cardinality detail; metrics are for rates and
alerts.
"""

from __future__ import annotations

from typing import Any

from mcp_gateway.observability.metrics import REGISTRY, Registry

# Event names that represent a decided tool call, and their coarse outcome.
_ALLOWED = {"tool_call_allowed"}
_DENIED = {"tool_call_blocked", "tool_call_denied_session_suspended"}
# Security signals worth a dedicated total (bounded set).
_SIGNALS = {
    "session_tainted", "session_suspended", "anomaly_detected",
    "tool_result_redacted", "tool_result_quarantined", "approval_requested",
    "policy_bundle_rejected",
}


class MetricsAuditSink:
    """An `AuditSink` that counts events instead of storing them."""

    def __init__(self, registry: Registry | None = None):
        reg = registry or REGISTRY
        self._events = reg.counter(
            "mcpgw_audit_events_total",
            "Audit events emitted, by event name.",
            ["event"],
        )
        self._calls = reg.counter(
            "mcpgw_tool_calls_total",
            "Policed tool calls, by outcome (allow|deny).",
            ["outcome"],
        )
        self._signals = reg.counter(
            "mcpgw_security_signals_total",
            "Security-relevant events (taint, suspend, anomaly, redact, "
            "quarantine, approval, bundle rejection), by signal.",
            ["signal"],
        )

    async def emit(self, event: dict[str, Any]) -> None:
        name = event.get("event")
        if not isinstance(name, str):
            return
        self._events.inc(event=name)
        if name in _ALLOWED:
            self._calls.inc(outcome="allow")
        elif name in _DENIED:
            self._calls.inc(outcome="deny")
        if name in _SIGNALS:
            self._signals.inc(signal=name)

    async def close(self) -> None:  # nothing to flush; here for the sink protocol
        return None
