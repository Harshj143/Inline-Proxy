"""Local, non-interactive channels: fail-closed deny and dev-only allow."""

from __future__ import annotations

from mcp_gateway.approvals.channels.base import ApprovalChannel
from mcp_gateway.approvals.models import ApprovalRequest, Resolution


class DenyChannel(ApprovalChannel):
    """No approver configured — every request is denied (the safe default).

    A gateway wired for `require_approval` but with no human on the other end
    must never silently allow the call.
    """

    name = "deny"
    can_approve = False  # can only refuse → approval-gated tools stay hidden

    async def request(self, req: ApprovalRequest) -> Resolution:
        return Resolution(
            approved=False, approver="policy",
            note="no approver configured; fail-closed deny",
        )


class AllowChannel(ApprovalChannel):
    """Auto-approve everything. DEVELOPMENT AND TESTING ONLY.

    Named loudly because shipping this in production defeats the control.
    """

    name = "allow"

    async def request(self, req: ApprovalRequest) -> Resolution:
        return Resolution(
            approved=True, approver="auto", note="auto-approved (dev mode)",
        )
