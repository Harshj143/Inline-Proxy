"""require_approval — pause and ask a human; proceed only on sign-off.

Phase 1 stub: the approval broker arrives in Phase 3. Until then this
handler DENIES (fail closed) — auto-approving would silently waive the
human sign-off the policy author required. Phase 3 wires the broker in and
falls through to the rule's `then` action on approval.
"""

from __future__ import annotations

from mcp_gateway.core.context import CallContext, Decision
from mcp_gateway.core.outcome import StageOutcome, deny
from mcp_gateway.policy.actions.base import ActionHandler


class RequireApprovalHandler(ActionHandler):
    name = "require_approval"
    terminal_deny = True  # Phase 3 flips this when the broker lands

    async def on_request(self, ctx: CallContext, decision: Decision) -> StageOutcome:
        return deny(
            "action 'require_approval' requires the approval broker (arrives in "
            "Phase 3); failing closed"
        )
