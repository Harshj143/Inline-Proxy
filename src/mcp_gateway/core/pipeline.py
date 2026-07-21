"""The enforcement pipeline: an ordered chain of request stages.

Each stage does one job, annotates the CallContext, and either lets the call
continue or terminates it (deny). The first DENY wins and later stages never
run — stage order is therefore a security property, asserted by tests, not a
style preference (docs/ARCHITECTURE.md §2 explains the ordering rationale).

Phase 1 order:  session_gate → policy → constraints → action
  * constraints run BEFORE the action executes so a rewrite can never
    launder a call past a constraint;
  * the sequence/taint gate (Phase 3) slots between constraints and action;
  * approval (Phase 3) becomes part of the action stage's dispatch, last
    before forwarding, so humans are only asked about calls every other
    control already passed.

A stage that raises is treated as DENY: an enforcement component in an
unknown state must not let traffic through (fail closed).
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

from mcp_gateway.core.context import CallContext

# Re-exported for compatibility: outcome types live in core.outcome so that
# action handlers can use them without importing the pipeline.
from mcp_gateway.core.outcome import StageOutcome, Verdict, deny, proceed
from mcp_gateway.policy.actions import ACTIONS
from mcp_gateway.policy.engine import PolicyEngine

__all__ = [
    "ActionStage",
    "ConstraintsStage",
    "PolicyStage",
    "RequestPipeline",
    "RequestStage",
    "SessionGateStage",
    "StageOutcome",
    "Verdict",
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
                return deny(violation)
        return proceed()


class ActionStage(RequestStage):
    """Dispatch to the decision's ActionHandler (allow/block/rewrite/…)."""

    name = "action"

    async def handle(self, ctx: CallContext) -> StageOutcome:
        assert ctx.decision is not None, "action stage requires a decision"
        handler = ACTIONS.get(ctx.decision.action)
        if handler is None:
            # The loader validates actions against the registry, so this only
            # happens if registries diverge at runtime — fail closed, loudly.
            return deny(
                f"no handler registered for action {ctx.decision.action!r}"
            )
        return await handler.on_request(ctx, ctx.decision)


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
            except Exception as exc:  # noqa: BLE001 — fail closed, never fail open
                outcome = deny(f"internal error in stage '{stage.name}': {exc}")
            finally:
                ctx.timings_ms[stage.name] = round((time.perf_counter() - t0) * 1000, 3)
            if outcome.denied:
                outcome.stage = stage.name
                return outcome
        return proceed()


def default_pipeline(engine: PolicyEngine) -> RequestPipeline:
    """The canonical Phase 1 stage order."""
    return RequestPipeline([
        SessionGateStage(),
        PolicyStage(engine),
        ConstraintsStage(),
        ActionStage(),
    ])
