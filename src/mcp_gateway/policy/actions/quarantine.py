"""quarantine — run the call upstream, but withhold the result from the LLM.

The data is fetched (so a human can review it out-of-band via the audit
trail/console) but never enters the model's context window; the model
receives a notice instead. The request stage only marks the disposition —
the substitution happens on the gateway's response path.
"""

from __future__ import annotations

from mcp_gateway.core.context import CallContext, Decision
from mcp_gateway.core.outcome import StageOutcome, proceed
from mcp_gateway.policy.actions.base import ActionHandler


class QuarantineHandler(ActionHandler):
    name = "quarantine"

    async def on_request(self, ctx: CallContext, decision: Decision) -> StageOutcome:
        ctx.disposition = "quarantine"
        return proceed()
