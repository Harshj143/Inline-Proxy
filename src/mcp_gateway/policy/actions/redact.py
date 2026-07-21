"""redact — allow, but scrub PII/secrets from arguments and result.

Phase 1 stub: the redaction engine arrives in Phase 2. Until then this
handler DENIES — downgrading redact to allow would ship the raw PII the
policy author explicitly asked to protect, and a security control never
fails in the open direction. Phase 2 replaces the body of `on_request`
(scrub arguments, set disposition "redact") and flips `terminal_deny`.
"""

from __future__ import annotations

from mcp_gateway.core.context import CallContext, Decision
from mcp_gateway.core.outcome import StageOutcome, deny
from mcp_gateway.policy.actions.base import ActionHandler


class RedactHandler(ActionHandler):
    name = "redact"
    terminal_deny = True  # Phase 2 flips this when redaction becomes executable

    async def on_request(self, ctx: CallContext, decision: Decision) -> StageOutcome:
        return deny(
            "action 'redact' requires the redaction engine (arrives in Phase 2); "
            "failing closed"
        )
