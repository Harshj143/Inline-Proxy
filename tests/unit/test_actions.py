"""Action handlers: dispatch behavior and the registry's deny semantics."""

import asyncio

from mcp_gateway.core.context import CallContext, Decision, Principal
from mcp_gateway.core.session import Session
from mcp_gateway.policy.actions import ACTIONS, denying_actions
from mcp_gateway.policy.actions.rewrite import apply_rewrites
from mcp_gateway.protocol.jsonrpc import JsonRpcMessage


def make_ctx(tool="t", arguments=None):
    args = arguments or {}
    return CallContext(
        session=Session.new(),
        message=JsonRpcMessage({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                "params": {"name": tool, "arguments": args}}),
        tool=tool,
        arguments=args,
        principal=Principal(),
    )


def decision(action, **kw):
    return Decision(action=action, tool="t", reason="r", rule="test", **kw)


def dispatch(action, ctx, dec):
    return asyncio.run(ACTIONS[action].on_request(ctx, dec))


# ---------------------------------------------------------------- handlers
def test_allow_proceeds():
    assert not dispatch("allow", make_ctx(), decision("allow")).denied


def test_block_denies_with_rule_reason():
    outcome = dispatch("block", make_ctx(), decision("block"))
    assert outcome.denied and outcome.reason == "r"


def test_rewrite_records_changes_and_effective_args():
    ctx = make_ctx(arguments={"sql": "SELECT 1"})
    dec = decision("rewrite", rewrites=[
        {"arg": "sql", "append": " LIMIT 10", "unless_match": r"\blimit\b", "flags": "i"},
        {"arg": "read_only", "set": True},
    ])
    outcome = dispatch("rewrite", ctx, dec)
    assert not outcome.denied
    assert ctx.outbound_arguments == {"sql": "SELECT 1 LIMIT 10", "read_only": True}
    assert {c["op"] for c in ctx.argument_changes} == {"append", "set"}
    assert ctx.arguments == {"sql": "SELECT 1"}  # originals never mutated


def test_rewrite_noop_leaves_context_clean():
    ctx = make_ctx(arguments={"sql": "SELECT 1 LIMIT 5"})
    dec = decision("rewrite", rewrites=[
        {"arg": "sql", "append": " LIMIT 10", "unless_match": r"\blimit\b", "flags": "i"},
    ])
    dispatch("rewrite", ctx, dec)
    assert ctx.effective_arguments is None  # nothing changed → forward original


def test_quarantine_sets_disposition_and_proceeds():
    ctx = make_ctx()
    outcome = dispatch("quarantine", ctx, decision("quarantine"))
    assert not outcome.denied
    assert ctx.disposition == "quarantine"


def test_redact_fails_closed_until_phase2():
    outcome = dispatch("redact", make_ctx(), decision("redact"))
    assert outcome.denied and "failing closed" in outcome.reason


def test_require_approval_fails_closed_until_phase3():
    outcome = dispatch("require_approval", make_ctx(), decision("require_approval"))
    assert outcome.denied and "approval broker" in outcome.reason


# ---------------------------------------------------------------- registry
def test_denying_actions_reflect_current_build():
    # Visibility filtering depends on this set; when Phase 2/3 implement
    # redact/approval these move out and tools/list re-shows the tools.
    assert denying_actions() == {"block", "redact", "require_approval"}


# ------------------------------------------------------------ apply_rewrites
def test_apply_rewrites_set_skips_when_already_equal():
    new_args, changes = apply_rewrites({"read_only": True},
                                       [{"arg": "read_only", "set": True}])
    assert new_args == {"read_only": True} and changes == []


def test_apply_rewrites_append_creates_missing_arg():
    new_args, changes = apply_rewrites({}, [{"arg": "suffix", "append": "x"}])
    assert new_args == {"suffix": "x"}
    assert changes == [{"arg": "suffix", "op": "append", "added": "x"}]
