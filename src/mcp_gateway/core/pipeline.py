"""The enforcement pipeline: an ordered chain of request stages.

Each stage does one job, annotates the CallContext, and either lets the call
continue or terminates it (deny). The first DENY wins and later stages never
run — stage order is therefore a security property, asserted by tests, not a
style preference (docs/ARCHITECTURE.md §2 explains the ordering rationale).

Order:  session_gate → policy → constraints → sequence → action
  * constraints run BEFORE the action executes so a rewrite can never
    launder a call past a constraint;
  * the sequence/taint gate sits between constraints and action — a call that
    static policy allows can still be forbidden by SESSION state (a tainted
    session reaching for a sink);
  * approval (Phase 3b) becomes part of the action stage's dispatch, last
    before forwarding, so humans are only asked about calls every other
    control already passed.

A stage that raises is treated as DENY: an enforcement component in an
unknown state must not let traffic through (fail closed).
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

# Re-exported for compatibility: outcome types live in core.outcome so that
# action handlers can use them without importing the pipeline.
from mcp_gateway.approvals.broker import ApprovalBroker
from mcp_gateway.core.context import CallContext
from mcp_gateway.core.outcome import StageOutcome, Verdict, deny, proceed
from mcp_gateway.policy.actions import ACTIONS, ActionHandler
from mcp_gateway.policy.actions.approval import RequireApprovalHandler
from mcp_gateway.policy.actions.redact import RedactHandler
from mcp_gateway.policy.engine import PolicyEngine
from mcp_gateway.redaction.service import RedactionService
from mcp_gateway.risk import scoring as risk

__all__ = [
    "ActionStage",
    "ApprovalBroker",
    "ConstraintsStage",
    "PolicyStage",
    "RequestPipeline",
    "RequestStage",
    "SequenceGateStage",
    "SessionGateStage",
    "StageOutcome",
    "Verdict",
    "build_action_handlers",
    "default_pipeline",
    "deny",
    "proceed",
]


class RequestStage(ABC):
    name: str

    @abstractmethod
    async def handle(self, ctx: CallContext) -> StageOutcome: ...


class SessionGateStage(RequestStage):
    """A suspended session gets nothing, regardless of static policy.

    Runs first: no other control should even see traffic from a session the
    risk engine has cut off. (Suspension itself arrives in Phase 3; the gate
    is in place from day one so that becomes a state flip, not a redesign.)
    """

    name = "session_gate"

    async def handle(self, ctx: CallContext) -> StageOutcome:
        if ctx.session.suspended:
            return deny("session suspended by risk engine; all tool calls refused")
        return proceed()


class PolicyStage(RequestStage):
    """Match the call against policy and record the Decision on the context.

    Match only — execution belongs to the action stage. Keeping them apart
    lets the stages between (constraints now; sequence/taint in Phase 3)
    reason about the decision before anything acts on it.
    """

    name = "policy"

    def __init__(self, engine: PolicyEngine):
        self._engine = engine

    async def handle(self, ctx: CallContext) -> StageOutcome:
        role = ctx.principal.roles[0] if ctx.principal.roles else None
        ctx.decision = self._engine.evaluate(ctx.tool, ctx.arguments, role=role)
        return proceed()


class ConstraintsStage(RequestStage):
    """Argument-level checks on WHAT the call is doing.

    Runs on the arguments as the agent sent them (pre-rewrite): a rewrite
    must never be able to launder a call past a constraint.
    """

    name = "constraints"

    async def handle(self, ctx: CallContext) -> StageOutcome:
        assert ctx.decision is not None, "constraints stage requires a decision"
        for constraint in ctx.decision.constraints:
            violation = constraint.check(ctx.arguments)
            if violation is not None:
                return deny(violation, risk_event=risk.CONSTRAINT_VIOLATION)
        return proceed()


class SequenceGateStage(RequestStage):
    """Session-state gate: taint sinks and ordered sequence rules.

    Static policy may allow this tool, but the session so far may forbid it —
    a sink after the session was tainted, or a tool the sequence rules bar
    given the history. Runs after constraints, before the action, so a human
    is never asked to approve a call this gate would refuse anyway.
    """

    name = "sequence"

    def __init__(self, sequence_policy):
        self._sequence = sequence_policy

    async def handle(self, ctx: CallContext) -> StageOutcome:
        reason = self._sequence.check(ctx.tool, ctx.session)
        if reason is not None:
            return deny(reason, risk_event=risk.SEQUENCE_VIOLATION)
        return proceed()


class ActionStage(RequestStage):
    """Dispatch to the decision's ActionHandler (allow/block/rewrite/…).

    Handlers are injected (not read from the global registry) so a service-
    backed redact handler can be wired in per gateway without mutating global
    state — which would leak the redaction-enabled flag across tests and
    across gateways in one process.
    """

    name = "action"

    def __init__(self, handlers: dict[str, ActionHandler] | None = None):
        self._handlers = handlers if handlers is not None else ACTIONS

    def denying_actions(self) -> frozenset[str]:
        """Actions this stage's handlers can only deny — drives tools/list
        visibility. Reflects the ACTUAL wired handlers (a broker-backed
        require_approval is not deny-only), so no ad-hoc subtraction is needed."""
        return frozenset(n for n, h in self._handlers.items() if h.terminal_deny)

    async def handle(self, ctx: CallContext) -> StageOutcome:
        assert ctx.decision is not None, "action stage requires a decision"
        handler = self._handlers.get(ctx.decision.action)
        if handler is None:
            # The loader validates actions against the registry, so this only
            # happens if registries diverge at runtime — fail closed, loudly.
            return deny(
                f"no handler registered for action {ctx.decision.action!r}",
                risk_event=risk.BLOCKED_TOOL,
            )
        outcome = await handler.on_request(ctx, ctx.decision)
        # A denial at the action stage (block, default-deny) scores as a
        # blocked tool unless the handler already named a more specific event.
        if outcome.denied and not outcome.risk_event:
            outcome.risk_event = risk.BLOCKED_TOOL
        return outcome


class RequestPipeline:
    def __init__(self, stages: list[RequestStage]):
        if not stages:
            raise ValueError("pipeline requires at least one stage")
        self.stages = stages

    async def run(self, ctx: CallContext) -> StageOutcome:
        for stage in self.stages:
            t0 = time.perf_counter()
            try:
                outcome = await stage.handle(ctx)
            except Exception as exc:  # noqa: BLE001 — a stage crash denies by default
                # Tagged internal_error so the gateway can apply the (opt-in)
                # fail-open posture; a legitimate policy denial is never tagged.
                outcome = deny(f"internal error in stage '{stage.name}': {exc}")
                outcome.internal_error = True
            finally:
                ctx.timings_ms[stage.name] = round((time.perf_counter() - t0) * 1000, 3)
            if outcome.denied:
                outcome.stage = stage.name
                return outcome
        return proceed()

    def denying_actions(self) -> frozenset[str]:
        """The deny-only action set of this pipeline's ActionStage."""
        for stage in self.stages:
            if isinstance(stage, ActionStage):
                return stage.denying_actions()
        from mcp_gateway.policy.actions import denying_actions
        return denying_actions()


def build_action_handlers(
    redaction: RedactionService | None = None,
    broker: ApprovalBroker | None = None,
) -> dict[str, ActionHandler]:
    """The action handler set for a gateway.

    Starts from the global registry (allow/block/rewrite/quarantine and the
    fail-closed redact/approval stubs) and swaps in service-backed handlers
    when the services are provided: a redact handler that actually scrubs, and
    an approval handler that actually asks a human. The approval handler is
    given a reference to the completed set so it can dispatch its `then` action.
    """
    handlers = dict(ACTIONS)
    if redaction is not None:
        handlers["redact"] = RedactHandler(redaction)
    approval = RequireApprovalHandler(broker)
    handlers["require_approval"] = approval
    approval.handlers = handlers  # wired after the dict is complete
    return handlers


def default_pipeline(
    engine: PolicyEngine,
    redaction: RedactionService | None = None,
    broker: ApprovalBroker | None = None,
) -> RequestPipeline:
    """The canonical stage order (docs/ARCHITECTURE.md §2)."""
    return RequestPipeline([
        SessionGateStage(),
        PolicyStage(engine),
        ConstraintsStage(),
        SequenceGateStage(engine.build_sequence_policy()),
        ActionStage(build_action_handlers(redaction, broker)),
    ])
