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


def test_redact_stub_fails_closed_without_a_service():
    # The DEFAULT registered redact handler has no service and must deny —
    # downgrading redact to allow would leak the PII the policy protects.
    outcome = dispatch("redact", make_ctx(), decision("redact"))
    assert outcome.denied and "failing closed" in outcome.reason


def test_redact_handler_with_service_scrubs_and_marks_disposition():
    from mcp_gateway.policy.actions.redact import RedactHandler
    from mcp_gateway.redaction.service import RedactionService
    from mcp_gateway.redaction.spec import RedactionSpec

    handler = RedactHandler(RedactionService())
    assert handler.terminal_deny is False  # a real handler never deny-only

    ctx = make_ctx(arguments={"note": "email alice@example.com"})
    outcome = asyncio.run(
        handler.on_request(ctx, decision("redact", redaction=RedactionSpec("standard")))
    )
    assert not outcome.denied
    # Outbound DLP: the argument was scrubbed before forwarding.
    assert ctx.outbound_arguments["note"] == "email [REDACTED:EMAIL]"
    assert ctx.argument_redactions["total"] == 1
    # And the response is marked for redaction with the spec carried forward.
    assert ctx.disposition == "redact"
    assert ctx.redaction_spec.profile == "standard"


def test_require_approval_stub_fails_closed_without_a_broker():
    outcome = dispatch("require_approval", make_ctx(), decision("require_approval"))
    assert outcome.denied and "approval broker" in outcome.reason


def test_approval_denied_blocks_with_risk_event():
    from mcp_gateway.approvals.broker import ApprovalBroker
    from mcp_gateway.approvals.channels import DenyChannel
    from mcp_gateway.core.pipeline import build_action_handlers

    handlers = build_action_handlers(broker=ApprovalBroker(DenyChannel()))
    ctx = make_ctx(tool="admin.delete_user")
    outcome = asyncio.run(handlers["require_approval"].on_request(
        ctx, decision("require_approval", then_action="allow")
    ))
    assert outcome.denied and outcome.risk_event == "approval_denied"
    assert ctx.approval is not None and ctx.approval.approved is False


def test_approval_granted_falls_through_to_then_action():
    from mcp_gateway.approvals.broker import ApprovalBroker
    from mcp_gateway.approvals.channels import AllowChannel
    from mcp_gateway.core.pipeline import build_action_handlers

    handlers = build_action_handlers(broker=ApprovalBroker(AllowChannel()))
    ctx = make_ctx(tool="admin.delete_user")
    outcome = asyncio.run(handlers["require_approval"].on_request(
        ctx, decision("require_approval", then_action="allow")
    ))
    assert not outcome.denied              # approved -> proceeds as `then: allow`
    assert ctx.approval.approved is True


def test_approval_then_redact_scrubs_on_approval():
    # then: redact must run the real redact handler, not a bare allow.
    from mcp_gateway.approvals.broker import ApprovalBroker
    from mcp_gateway.approvals.channels import AllowChannel
    from mcp_gateway.core.pipeline import build_action_handlers
    from mcp_gateway.redaction.service import RedactionService

    handlers = build_action_handlers(
        redaction=RedactionService(), broker=ApprovalBroker(AllowChannel())
    )
    ctx = make_ctx(tool="x", arguments={"note": "alice@example.com"})
    outcome = asyncio.run(handlers["require_approval"].on_request(
        ctx, decision("require_approval", then_action="redact")
    ))
    assert not outcome.denied
    assert ctx.disposition == "redact"                    # then=redact took effect
    assert ctx.outbound_arguments["note"] == "[REDACTED:EMAIL]"  # scrubbed on approval


def test_approval_then_cannot_recurse():
    from mcp_gateway.approvals.broker import ApprovalBroker
    from mcp_gateway.approvals.channels import AllowChannel
    from mcp_gateway.core.pipeline import build_action_handlers

    handlers = build_action_handlers(broker=ApprovalBroker(AllowChannel()))
    outcome = asyncio.run(handlers["require_approval"].on_request(
        make_ctx(), decision("require_approval", then_action="require_approval")
    ))
    assert outcome.denied and "misconfigured" in outcome.reason


# ---------------------------------------------------------------- registry
def test_denying_actions_reflect_default_registry():
    # The global default registry's redact is the fail-closed stub, so redact
    # is deny-only here; a gateway with a redaction service computes a narrower
    # set (see gateway tools/list filtering). require_approval lands in Phase 3.
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
