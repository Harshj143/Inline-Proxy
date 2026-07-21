"""allow — pass the call through untouched."""

from __future__ import annotations

from mcp_gateway.core.context import CallContext, Decision
from mcp_gateway.core.outcome import StageOutcome, proceed
from mcp_gateway.policy.actions.base import ActionHandler


class AllowHandler(ActionHandler):
    name = "allow"

    async def on_request(self, ctx: CallContext, decision: Decision) -> StageOutcome:
        return proceed()
