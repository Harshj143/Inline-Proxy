"""redact — allow, but scrub PII/secrets from arguments and result.

Request stage (this file): scrub the ARGUMENTS the agent is sending upstream
(outbound DLP — the agent shouldn't be able to exfiltrate PII through a tool
call either) and mark the response for redaction. The RESULT is scrubbed on
the gateway's response path, where the disposition and spec set here are read.

Fail-closed when redaction is unavailable: a RedactHandler with no service
(the default registered handler) DENIES, because downgrading redact to allow
would ship the very PII the policy exists to protect. `enable_redaction`
swaps in a service-backed handler and flips visibility so redact-ed tools stop
being hidden from the model.
"""

from __future__ import annotations

from mcp_gateway.core.context import CallContext, Decision
from mcp_gateway.core.outcome import StageOutcome, deny, proceed
from mcp_gateway.policy.actions.base import ActionHandler
from mcp_gateway.redaction.service import RedactionService
from mcp_gateway.redaction.spec import RedactionSpec


class RedactHandler(ActionHandler):
    name = "redact"

    def __init__(self, service: RedactionService | None = None):
        self.service = service
        # Without a service this handler can only deny; that makes redact-ed
        # tools "denying" for visibility and fail-closed for enforcement.
        self.terminal_deny = service is None

    async def on_request(self, ctx: CallContext, decision: Decision) -> StageOutcome:
        if self.service is None:
            return deny(
                "action 'redact' requires the redaction engine to be enabled; "
                "failing closed"
            )

        spec = decision.redaction or RedactionSpec()
        # Outbound DLP: scrub arguments before they leave the boundary.
        try:
            scrubbed, report = self.service.redact(ctx.arguments, spec)
        except Exception as exc:  # noqa: BLE001 — a scrub failure must not leak
            return deny(f"argument redaction failed ({exc}); failing closed")
        if report.total:
            ctx.effective_arguments = scrubbed
            ctx.argument_redactions = report.summary()

        # Mark the response for redaction; the gateway applies `spec` there.
        ctx.disposition = "redact"
        ctx.redaction_spec = spec
        return proceed()
