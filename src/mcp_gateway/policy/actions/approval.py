"""require_approval — pause and ask a human; proceed only on sign-off.

On approval the call continues as the rule's `then` action (default allow) —
so `then: redact` means "a human approves, then the result is still scrubbed".
On denial it blocks and scores approval_denied risk.

Fail-closed when no broker is wired: the handler DENIES (and is `terminal_deny`
for visibility), because auto-waving a call meant for human review is exactly
the failure this control exists to prevent.

The handler dispatches the `then` action through the same handler set it lives
in (`self.handlers`, wired by build_action_handlers), so `then` gets its real
behavior (redact scrubs, rewrite rewrites) rather than a bare allow.
"""

from __future__ import annotations

from mcp_gateway.approvals.broker import ApprovalBroker
from mcp_gateway.approvals.models import ApprovalRequest
from mcp_gateway.core.context import CallContext, Decision
from mcp_gateway.core.outcome import StageOutcome, deny
from mcp_gateway.policy.actions.base import ActionHandler
from mcp_gateway.risk.scoring import APPROVAL_DENIED


class RequireApprovalHandler(ActionHandler):
    name = "require_approval"

    def __init__(self, broker: ApprovalBroker | None = None):
        self.broker = broker
        # Deny-only (and thus hidden from tools/list) when there is no broker,
        # or the broker's channel can only refuse (deny mode).
        self.terminal_deny = broker is None or not broker.can_approve
        # Set by build_action_handlers so `then` can be dispatched to its real
        # handler. Defaults to empty; a missing `then` handler fails closed.
        self.handlers: dict[str, ActionHandler] = {}

    async def on_request(self, ctx: CallContext, decision: Decision) -> StageOutcome:
        if self.broker is None:
            return deny(
                "action 'require_approval' requires an approval broker; failing closed"
            )

        resolution = await self.broker.request(ApprovalRequest(
            request_id=ctx.request_id,
            session_id=ctx.session.id,
            tool=ctx.tool,
            arguments=ctx.arguments,
            principal=ctx.principal.id,
            reason=decision.reason,
        ))
        ctx.approval = resolution  # for the gateway's approval_requested audit

        if not resolution.approved:
            return deny(
                f"human approval denied ({resolution.note})",
                risk_event=APPROVAL_DENIED,
            )

        # Approved: continue as `then`. Guard against a `then: require_approval`
        # misconfiguration (would recurse) — fail closed.
        then = decision.then_action
        if then == self.name:
            return deny("misconfigured rule: then=require_approval; failing closed")
        then_handler = self.handlers.get(then)
        if then_handler is None:
            return deny(f"no handler for then action {then!r}; failing closed")
        return await then_handler.on_request(ctx, decision)
