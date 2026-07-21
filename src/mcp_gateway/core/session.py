"""Per-session state: identity of the run, call history, pending correlation.

Phase 0 keeps this in-process (one session per stdio transport). The shape is
what Phase 5's StateStore interface will serialize: everything here must stay
plain data so a Redis-backed implementation can drop in without changing the
pipeline.

`suspended` exists now, checked first in the pipeline, so that when the risk
engine arrives (Phase 3) suspension is a state flip — not a pipeline change.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(slots=True)
class PendingCall:
    """A forwarded tools/call awaiting its response, keyed by request id.

    `disposition` is how the response path must treat the result:
    "none" (deliver), "quarantine" (withhold, substitute a notice), and
    later "redact" (scrub before delivery).
    """

    tool: str
    action: str
    started: float  # perf_counter at forward time
    disposition: str = "none"

    def elapsed_ms(self) -> float:
        return (time.perf_counter() - self.started) * 1000


@dataclass(slots=True)
class Session:
    id: str
    started_at: str
    suspended: bool = False
    history: list[str] = field(default_factory=list)
    pending: dict[Any, PendingCall] = field(default_factory=dict)

    @classmethod
    def new(cls) -> Session:
        return cls(
            id=uuid.uuid4().hex[:8],
            started_at=datetime.now(UTC).isoformat(timespec="milliseconds"),
        )

    def record_call(self, tool: str) -> None:
        self.history.append(tool)

    def track_pending(
        self, request_id: Any, tool: str, action: str, disposition: str = "none"
    ) -> None:
        # A client reusing an in-flight id is misbehaving; last write wins and
        # the earlier call simply loses response-path handling (safe direction:
        # nothing is released un-inspected, the entry is only bookkeeping).
        self.pending[request_id] = PendingCall(
            tool=tool, action=action, started=time.perf_counter(), disposition=disposition
        )

    def resolve_pending(self, request_id: Any) -> PendingCall | None:
        return self.pending.pop(request_id, None)
