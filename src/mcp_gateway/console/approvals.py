"""Live pending-approval queue — the console side of the approval contract.

The gateway's `HttpChannel` POSTs an `ApprovalRequest.to_wire()` to
`POST /api/approvals` and *holds the connection open* until a human decides.
This queue is what makes that block real: the POST handler parks an
`asyncio.Future` here and awaits it; the UI lists what is parked
(`GET /api/approvals/pending`) and an approver completes one
(`POST /api/approvals/{id}/resolve`), which sets the future and unblocks the
gateway with `{approved, approver, note}`.

Why the queue lives here and not in the audit index: a pending approval is
*live state*, not history. The audit trail only ever records an approval after
it is decided (`approval_requested`), so it can't answer "what is waiting right
now". This is that answer, and it evaporates on restart by design — an
in-flight tool call whose console restarted should fail closed (the gateway's
broker deadline fires), never silently resurrect.

Each parked request gets a server-minted `approval_id` (the wire `request_id`
is only unique within a session, and the UI needs one stable handle). Resolving
an unknown id is a no-op returning False, so a double-click or a late resolve
after timeout can't crash or double-answer.

Stdlib asyncio only.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class PendingApproval:
    approval_id: str
    request: dict[str, Any]          # the wire ApprovalRequest
    created_ts: float
    future: asyncio.Future = field(repr=False)

    def public(self) -> dict[str, Any]:
        """UI-facing view. Arguments are included so a human can judge the call
        (the wire contract already sends them); a deployment handling sensitive
        arguments should redact them before they reach the approver."""
        return {
            "approval_id": self.approval_id,
            "request_id": self.request.get("request_id"),
            "session_id": self.request.get("session_id"),
            "tool": self.request.get("tool"),
            "arguments": self.request.get("arguments"),
            "principal": self.request.get("principal"),
            "reason": self.request.get("reason"),
            "created_ts": self.created_ts,
        }


class ApprovalQueue:
    def __init__(self) -> None:
        self._pending: dict[str, PendingApproval] = {}
        self._lock = asyncio.Lock()

    async def submit(self, request: dict[str, Any], *, now: float) -> PendingApproval:
        loop = asyncio.get_running_loop()
        approval_id = uuid.uuid4().hex
        item = PendingApproval(
            approval_id=approval_id,
            request=request,
            created_ts=now,
            future=loop.create_future(),
        )
        async with self._lock:
            self._pending[approval_id] = item
        return item

    async def wait(self, item: PendingApproval, *, timeout: float) -> dict[str, Any]:
        """Block until resolved or `timeout`. On timeout, fail closed.

        The gateway's broker also has a deadline; whichever fires first, the
        result is a denial — a call must never proceed on an unanswered
        approval.
        """
        try:
            return await asyncio.wait_for(asyncio.shield(item.future), timeout)
        except TimeoutError:
            return {"approved": False, "approver": "console",
                    "note": "fail-closed: approval timed out"}
        finally:
            async with self._lock:
                self._pending.pop(item.approval_id, None)

    async def resolve(
        self, approval_id: str, *, approved: bool, approver: str, note: str = ""
    ) -> bool:
        """Complete a pending approval. Returns False if it is unknown/already
        resolved (idempotent — a double resolve is harmless)."""
        async with self._lock:
            item = self._pending.get(approval_id)
            if item is None or item.future.done():
                return False
            item.future.set_result(
                {"approved": bool(approved), "approver": approver, "note": note}
            )
            return True

    async def pending(self) -> list[dict[str, Any]]:
        async with self._lock:
            return [p.public() for p in self._pending.values()]

    async def count(self) -> int:
        async with self._lock:
            return len(self._pending)
