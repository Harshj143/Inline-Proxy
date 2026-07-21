"""Audit event schema, version 1.

Every event carries `schema_version` from day one so sinks, the console, and
SIEM mappings can evolve the shape without guessing what they are reading
(docs/ARCHITECTURE.md §6). Event names are constants — string-typed events
scattered through call sites are how audit trails drift.

Convention: events record decisions and *counts*, never raw payloads, unless
a policy explicitly opts a field in (arrives with the backtester phases).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

SCHEMA_VERSION = 1

# Lifecycle
GATEWAY_START = "gateway_start"
GATEWAY_STOP = "gateway_stop"
UPSTREAM_EXIT = "upstream_exit"

# Traffic that is not tools/call
PASSTHROUGH_REQUEST = "passthrough_request"    # client -> upstream, parsed
PASSTHROUGH_OPAQUE = "passthrough_opaque"      # unparseable line, either direction
UPSTREAM_REQUEST = "upstream_request"          # server-initiated request -> client

# Enforcement
TOOL_CALL_ALLOWED = "tool_call_allowed"
TOOL_CALL_BLOCKED = "tool_call_blocked"
TOOL_CALL_DENIED_SESSION_SUSPENDED = "tool_call_denied_session_suspended"
TOOL_RESULT = "tool_result"
TOOL_RESULT_QUARANTINED = "tool_result_quarantined"
TOOLS_LIST_FILTERED = "tools_list_filtered"

# Transport health
TRANSPORT_OVERRUN = "transport_line_overrun"


def make_event(event: str, **fields: Any) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
        "event": event,
        **fields,
    }
