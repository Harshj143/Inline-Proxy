"""The approval broker: deadline + fail-closed wrapper around a channel.

The broker owns the two things a channel must not be trusted to get right: the
DEADLINE (a human who never answers must not block a session forever) and the
FAIL-CLOSED conversion (any timeout, transport error, or malformed response
becomes a denial, never an accidental allow).
"""

from __future__ import annotations

import sys

from mcp_gateway.approvals.channels import (
    AllowChannel,
    ApprovalChannel,
    DenyChannel,
    HttpChannel,
)
from mcp_gateway.approvals.models import ApprovalRequest, Resolution

# asyncio is imported lazily in request() only to keep import-time light; the
# broker is constructed even when no approval rule ever fires.


class ApprovalBroker:
    def __init__(
        self,
        channel: ApprovalChannel,
        deadline: float = 300.0,
        fail_open: bool = False,
    ):
        self.channel = channel
        self.deadline = deadline
        # When True, an unreachable/timed-out approver APPROVES (availability
        # over security — the customer's explicit `on_failure.approval: open`).
        # Default False: an unavailable approver denies.
        self.fail_open = fail_open

    @property
    def mode(self) -> str:
        return self.channel.name

    @property
    def can_approve(self) -> bool:
        """False when the channel can only deny (deny mode) — drives whether
        approval-gated tools are visible in tools/list."""
        return self.channel.can_approve

    async def request(self, req: ApprovalRequest) -> Resolution:
        import asyncio

        try:
            return await asyncio.wait_for(self.channel.request(req), timeout=self.deadline)
        except TimeoutError:
            return self._on_error(f"no decision within {self.deadline:.0f}s")
        except Exception as exc:  # noqa: BLE001 — a failed approver never silently allows
            print(f"mcp-gateway: approval channel error: {exc}", file=sys.stderr)
            return self._on_error(f"approver unavailable ({type(exc).__name__})")

    def _on_error(self, note: str) -> Resolution:
        if self.fail_open:
            return Resolution(
                approved=True, approver="system",
                note=f"fail-open: {note} (posture=open)",
            )
        return Resolution.fail_closed(note)


def build_broker(
    mode: str, url: str | None = None, deadline: float = 300.0, fail_open: bool = False
) -> ApprovalBroker:
    """Construct a broker for a CLI `--approvals` mode. `fail_open` (from the
    policy's `on_failure.approval`) controls what an unreachable approver does."""
    if mode == "deny":
        return ApprovalBroker(DenyChannel(), deadline, fail_open)
    if mode == "allow":
        return ApprovalBroker(AllowChannel(), deadline, fail_open)
    if mode == "http":
        if not url:
            raise ValueError("--approvals http requires --approvals-url")
        return ApprovalBroker(HttpChannel(url, timeout=deadline), deadline, fail_open)
    raise ValueError(f"unknown approvals mode {mode!r}; use deny|allow|http")
