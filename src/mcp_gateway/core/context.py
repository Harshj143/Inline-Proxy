"""The objects that travel the enforcement pipeline.

One CallContext per tools/call: every stage reads and annotates it, and every
audit event about the call derives from it. Single source of truth per call
(see docs/ARCHITECTURE.md §2).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp_gateway.core.session import Session
    from mcp_gateway.protocol.jsonrpc import JsonRpcMessage
    from mcp_gateway.redaction.spec import RedactionSpec


@dataclass(frozen=True, slots=True)
class Principal:
    """Who is calling.

    Phase 0: pinned at launch (stdio has no per-request identity). Phase 9
    replaces construction with OIDC/API-key resolution; the shape stays.
    """

    id: str = "local"
    roles: tuple[str, ...] = ()


@dataclass(slots=True)
class Decision:
    """The policy engine's verdict for one call.

    `rule` names which policy entry produced the verdict (e.g.
    "mock-crm:db.execute_sql" or "default", plus "+role:<r>" when a role
    overlay applied) so audit events and the backtester can attribute every
    outcome to a specific line of policy.

    `constraints` holds compiled Constraint objects and `rewrites` raw rewrite
    configs from the effective rule; the constraints and action stages consume
    them. `then_action` is what a require_approval call becomes on approval.
    """

    action: str
    tool: str
    reason: str
    rule: str
    role: str | None = None
    constraints: list[Any] = field(default_factory=list)
    rewrites: list[dict[str, Any]] = field(default_factory=list)
    redaction: RedactionSpec | None = None  # set when action is redact
    then_action: str = "allow"


@dataclass(slots=True)
class CallContext:
    """Everything the pipeline knows about one in-flight tools/call."""

    session: Session
    message: JsonRpcMessage
    tool: str
    arguments: dict[str, Any]
    principal: Principal
    decision: Decision | None = None
    # Set by the action stage when rewrites/redaction changed the arguments;
    # the gateway forwards these, never the originals, when present.
    effective_arguments: dict[str, Any] | None = None
    argument_changes: list[dict[str, Any]] = field(default_factory=list)
    # Redaction report summary for scrubbed arguments (outbound DLP), if any.
    argument_redactions: dict[str, Any] | None = None
    # How the response must be handled: "none" | "quarantine" | "redact".
    disposition: str = "none"
    # The spec to apply to the response when disposition == "redact".
    redaction_spec: RedactionSpec | None = None
    # The approval resolution, if a require_approval rule asked a human.
    approval: Any = None
    # Per-stage wall-clock cost in milliseconds, keyed by stage name.
    timings_ms: dict[str, float] = field(default_factory=dict)
    started: float = field(default_factory=time.perf_counter)

    @property
    def request_id(self) -> Any:
        return self.message.id

    @property
    def outbound_arguments(self) -> dict[str, Any]:
        """What actually gets forwarded upstream."""
        return self.effective_arguments if self.effective_arguments is not None else self.arguments
