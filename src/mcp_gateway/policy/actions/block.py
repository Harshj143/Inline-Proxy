"""block — refuse the call at the gateway; it never reaches the server."""

from __future__ import annotations

from mcp_gateway.core.context import CallContext, Decision
from mcp_gateway.core.outcome import StageOutcome, deny
from mcp_gateway.policy.actions.base import ActionHandler


class BlockHandler(ActionHandler):
    name = "block"
    terminal_deny = True

    async def on_request(self, ctx: CallContext, decision: Decision) -> StageOutcome:
        return deny(decision.reason)
