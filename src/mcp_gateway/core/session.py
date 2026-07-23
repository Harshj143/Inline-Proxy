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
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp_gateway.redaction.spec import RedactionSpec


@dataclass(slots=True)
class PendingCall:
    """A forwarded tools/call awaiting its response, keyed by request id.

    `disposition` is how the response path must treat the result:
    "none" (deliver), "quarantine" (withhold, substitute a notice), or
    "redact" (scrub before delivery using `redaction`).
    """

    tool: str
    action: str
    started: float  # perf_counter at forward time
    disposition: str = "none"
    redaction: RedactionSpec | None = None

    def elapsed_ms(self) -> float:
        return (time.perf_counter() - self.started) * 1000


@dataclass(slots=True)
class Session:
    id: str
    started_at: str
    suspended: bool = False
    history: list[str] = field(default_factory=list)
    pending: dict[Any, PendingCall] = field(default_factory=dict)
    # Taint state (sequence.SequencePolicy): set once an untrusted source runs.
    tainted: bool = False
    taint_origin: str | None = None
    # Risk state (risk.RiskEngine): score accumulates; suspended flips at
    # the threshold. Kept as plain fields so a Redis store can mirror them.
    risk_score: int = 0
    risk_events: list[dict] = field(default_factory=list)

    @classmethod
    def new(cls, session_id: str | None = None) -> Session:
        return cls(
            id=session_id or uuid.uuid4().hex[:8],
            started_at=datetime.now(UTC).isoformat(timespec="milliseconds"),
        )

    def record_call(self, tool: str) -> None:
        self.history.append(tool)

    def mark_tainted(self, origin: str) -> bool:
        """Mark the session tainted; return True only on the first taint."""
        if self.tainted:
            return False
        self.tainted = True
        self.taint_origin = origin
        return True

    def track_pending(
        self,
        request_id: Any,
        tool: str,
        action: str,
        disposition: str = "none",
        redaction: RedactionSpec | None = None,
    ) -> None:
        # A client reusing an in-flight id is misbehaving; last write wins and
        # the earlier call simply loses response-path handling (safe direction:
        # nothing is released un-inspected, the entry is only bookkeeping).
        self.pending[request_id] = PendingCall(
            tool=tool, action=action, started=time.perf_counter(),
            disposition=disposition, redaction=redaction,
        )

    def resolve_pending(self, request_id: Any) -> PendingCall | None:
        return self.pending.pop(request_id, None)

    # ---- serialization for a shared store (Phase 5c) ----------------------
    # `pending` is intentionally excluded: an in-flight call belongs to the
    # replica that forwarded it and cannot be handed off (it holds a live
    # perf_counter start and a RedactionSpec). Everything else is the durable,
    # shareable state — taint, risk, suspension, history.
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "started_at": self.started_at,
            "suspended": self.suspended,
            "history": list(self.history),
            "tainted": self.tainted,
            "taint_origin": self.taint_origin,
            "risk_score": self.risk_score,
            "risk_events": list(self.risk_events),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Session:
        return cls(
            id=data["id"],
            started_at=data.get("started_at", ""),
            suspended=bool(data.get("suspended", False)),
            history=list(data.get("history", [])),
            tainted=bool(data.get("tainted", False)),
            taint_origin=data.get("taint_origin"),
            risk_score=int(data.get("risk_score", 0)),
            risk_events=list(data.get("risk_events", [])),
        )
