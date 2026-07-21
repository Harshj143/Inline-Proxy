"""Fan-out audit recorder.

One recorder per gateway; sinks implement `async emit(event: dict)` (and
optionally `async close()`). Two hard rules:

1. A sink failure must never fail the call being audited — enforcement
   outcomes were already decided; audit errors surface on stderr and (in
   later phases) as metrics/alarms, not as tool-call failures.
2. Default fields (session id, principal) are stamped on every event exactly
   once, here — call sites never repeat plumbing fields.
"""

from __future__ import annotations

import contextlib
import sys
from typing import Any, Protocol

from mcp_gateway.audit.events import make_event


class AuditSink(Protocol):
    async def emit(self, event: dict[str, Any]) -> None: ...


class AuditRecorder:
    def __init__(self, sinks: list[AuditSink], default_fields: dict[str, Any] | None = None):
        self._sinks = sinks
        self.default_fields: dict[str, Any] = dict(default_fields or {})

    async def emit(self, event: str, **fields: Any) -> None:
        record = make_event(event, **{**self.default_fields, **fields})
        for sink in self._sinks:
            try:
                await sink.emit(record)
            except Exception as exc:  # noqa: BLE001 — rule 1: audit never raises
                print(
                    f"mcp-gateway: audit sink {type(sink).__name__} failed: {exc}",
                    file=sys.stderr,
                )

    async def close(self) -> None:
        for sink in self._sinks:
            close = getattr(sink, "close", None)
            if close is not None:
                with contextlib.suppress(Exception):
                    await close()
