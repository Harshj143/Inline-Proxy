"""Pipeline runner: ordering, short-circuit, fail-closed, timings."""

import asyncio

from mcp_gateway.core.context import CallContext, Principal
from mcp_gateway.core.pipeline import (
    PolicyStage,
    RequestPipeline,
    RequestStage,
    SessionGateStage,
    default_pipeline,
    deny,
    proceed,
)
from mcp_gateway.core.session import Session
from mcp_gateway.policy.engine import PolicyEngine
from mcp_gateway.protocol.jsonrpc import decode_line


def make_engine(tools=None, default_action="block"):
    return PolicyEngine.from_documents([(
        {"schema_version": 1, "default_action": default_action, "tools": tools or {}},
        "test",
    )])


def make_ctx(tool="search.docs", arguments=None, suspended=False, role=None) -> CallContext:
    session = Session.new()
    session.suspended = suspended
    args = arguments or {}
    msg = decode_line(
        '{"jsonrpc":"2.0","id":1,"method":"tools/call",'
        f'"params":{{"name":"{tool}","arguments":{{}}}}}}'
    )
    assert msg is not None
    return CallContext(
        session=session, message=msg, tool=tool, arguments=args,
        principal=Principal(roles=(role,) if role else ()),
    )


class RecordingStage(RequestStage):
    def __init__(self, name, outcome=None, log=None):
        self.name = name
        self._outcome = outcome or proceed()
        self._log = log if log is not None else []

    async def handle(self, ctx):
        self._log.append(self.name)
        return self._outcome


class ExplodingStage(RequestStage):
    name = "exploding"

    async def handle(self, ctx):
        raise RuntimeError("stage bug")


# ---------------------------------------------------------------- the runner
def test_stages_run_in_order_and_all_continue():
    log = []
    pipeline = RequestPipeline([
        RecordingStage("a", log=log),
        RecordingStage("b", log=log),
        RecordingStage("c", log=log),
    ])
    outcome = asyncio.run(pipeline.run(make_ctx()))
    assert not outcome.denied
    assert log == ["a", "b", "c"]


def test_first_deny_short_circuits():
    log = []
    pipeline = RequestPipeline([
        RecordingStage("a", log=log),
        RecordingStage("b", outcome=deny("nope"), log=log),
        RecordingStage("c", log=log),  # must never run
    ])
    outcome = asyncio.run(pipeline.run(make_ctx()))
    assert outcome.denied
    assert outcome.stage == "b" and outcome.reason == "nope"
    assert log == ["a", "b"]


def test_stage_exception_fails_closed():
    pipeline = RequestPipeline([ExplodingStage()])
    outcome = asyncio.run(pipeline.run(make_ctx()))
    assert outcome.denied
    assert "internal error" in outcome.reason


def test_timings_recorded_per_stage():
    ctx = make_ctx()
    pipeline = RequestPipeline([RecordingStage("only")])
    asyncio.run(pipeline.run(ctx))
    assert "only" in ctx.timings_ms
    assert ctx.timings_ms["only"] >= 0


# ----------------------------------------------------------- canonical order
def test_default_pipeline_order():
    # This ordering is a security property (docs/ARCHITECTURE.md §2), not a
    # style choice — the assertion is the contract.
    pipeline = default_pipeline(make_engine())
    assert [s.name for s in pipeline.stages] == [
        "session_gate", "policy", "constraints", "action",
    ]


def test_suspended_session_denied_before_policy_runs():
    log = []
    engine = make_engine(default_action="allow")

    class SpyPolicy(PolicyStage):
        async def handle(self, ctx):
            log.append("policy")
            return await super().handle(ctx)

    pipeline = RequestPipeline([SessionGateStage(), SpyPolicy(engine)])
    outcome = asyncio.run(pipeline.run(make_ctx(suspended=True)))
    assert outcome.denied and outcome.stage == "session_gate"
    assert log == []  # policy never consulted


# ------------------------------------------------------- stage interactions
def test_block_denies_at_action_stage_with_decision_recorded():
    ctx = make_ctx(tool="db.execute_sql")
    engine = make_engine({"db.execute_sql": {"action": "block", "reason": "no raw SQL"}})
    outcome = asyncio.run(default_pipeline(engine).run(ctx))
    assert outcome.denied and outcome.stage == "action"
    assert outcome.reason == "no raw SQL"
    assert ctx.decision is not None
    assert ctx.decision.rule == "test:db.execute_sql"


def test_constraint_violation_denies_before_action():
    ctx = make_ctx(tool="db.execute_sql", arguments={"sql": "DROP TABLE x"})
    engine = make_engine({"db.execute_sql": {
        "action": "allow",
        "constraints": [{"arg": "sql", "must_match": r"^\s*SELECT\b", "flags": "i",
                         "reason": "SELECT only"}],
    }})
    outcome = asyncio.run(default_pipeline(engine).run(ctx))
    assert outcome.denied and outcome.stage == "constraints"
    assert outcome.reason == "SELECT only"


def test_rewrite_flows_through_full_pipeline():
    ctx = make_ctx(tool="db.execute_sql", arguments={"sql": "SELECT * FROM t"})
    engine = make_engine({"db.execute_sql": {
        "action": "rewrite",
        "constraints": [{"arg": "sql", "must_match": r"^\s*SELECT\b", "flags": "i"}],
        "rewrites": [{"arg": "sql", "append": " LIMIT 100",
                      "unless_match": r"\blimit\b", "flags": "i"}],
    }})
    outcome = asyncio.run(default_pipeline(engine).run(ctx))
    assert not outcome.denied
    assert ctx.outbound_arguments["sql"] == "SELECT * FROM t LIMIT 100"


def test_role_overlay_changes_pipeline_outcome():
    engine = make_engine({"crm.get": {
        "action": "block",
        "roles": {"admin": {"action": "allow"}},
    }})
    denied = asyncio.run(default_pipeline(engine).run(make_ctx(tool="crm.get")))
    assert denied.denied

    allowed = asyncio.run(
        default_pipeline(engine).run(make_ctx(tool="crm.get", role="admin"))
    )
    assert not allowed.denied
