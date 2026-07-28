"""The Slack connector pack: full-surface coverage + its golden decisions.

The pack polices the *entire* Slack MCP tool surface (all 22 tools of
korotovsky/slack-mcp-server), not a curated subset. These tests keep that true:
every tool in tools.yaml must carry an explicit rule, and the risk
classification must agree with the action the policy takes. Default-deny catches
anything new, but silently falling through to it is exactly the drift this
guards against after an upstream version bump.

The taint/sequence controls live in test_slack_sequence.py (the golden harness
is static-policy only).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_gateway.connectors import load_connector
from mcp_gateway.policy.testing import run_policy_tests

PACK = Path(__file__).resolve().parents[2] / "connectors" / "slack"

# A read is redacted (Slack text is untrusted); a secret-adjacent read is either
# strict-redacted (conversational text keeps a useful scrubbed view) or
# quarantined (opaque file bytes); a write must be gated. This server exposes no
# destructive tool, so that class is intentionally absent.
ALLOWED_BY_RISK = {
    "read": {"redact"},
    "write": {"require_approval"},
    "secret_adjacent": {"quarantine", "redact"},
}


@pytest.fixture(scope="module")
def connector():
    return load_connector(PACK)


@pytest.fixture(scope="module")
def engine(connector):
    return connector.build_engine()


def test_pack_loads_with_both_layers(connector):
    assert connector.name == "slack"
    assert [p.name for p in connector.policy_layers()] == ["policy.yaml", "roles.yaml"]


def test_inventory_is_the_full_surface(connector):
    # 22 tools in korotovsky/slack-mcp-server (extracted from pkg/server/server.go).
    # A bump that changes the surface should fail here until the pack is re-reviewed.
    assert len(connector.tools()) == 22


def test_every_tool_has_an_explicit_rule(connector, engine):
    """No tool may rely on default-deny: an unrated tool is an unreviewed tool."""
    missing = [
        tool for tool in connector.tools()
        if engine.evaluate(tool, {}).rule == "default"
    ]
    assert not missing, f"{len(missing)} tool(s) fall through to default deny: {missing}"


def test_actions_match_risk_classification(connector, engine):
    wrong = []
    for tool, meta in connector.tools().items():
        risk = meta.get("risk")
        action = engine.evaluate(tool, {}).action
        if action not in ALLOWED_BY_RISK[risk]:
            wrong.append((tool, risk, action))
    assert not wrong, f"action/risk mismatches: {wrong}"


def test_no_destructive_tools_exist(connector):
    """This server exposes no delete/archive tool; the pack ships no block-on-
    destructive rules because there is nothing to block. If a future version
    adds one it lands under default-deny — which this asserts stays true."""
    assert not [t for t, m in connector.tools().items() if m.get("risk") == "destructive"]


def test_default_action_is_block(engine):
    assert engine.default_action == "block"
    assert engine.evaluate("a_tool_that_does_not_exist", {}).action == "block"


def test_message_and_file_reads_never_reach_the_model_raw(engine):
    """Slack is where humans paste secrets; message text is strict-redacted and
    opaque file bytes are withheld entirely."""
    for tool in ("conversations_history", "conversations_search_messages", "saved_list"):
        assert engine.evaluate(tool, {}).action == "redact", tool
    assert engine.evaluate("attachment_get_data", {}).action == "quarantine"


def test_bot_role_cannot_write(connector, engine):
    """An unattended identity has no approver, so writes are blocked outright."""
    writes = [t for t, m in connector.tools().items() if m.get("risk") == "write"]
    for tool in writes:
        assert engine.evaluate(tool, {}, role="bot").action == "block", tool


def test_support_agent_sends_but_does_not_administer(engine):
    """Messaging is the agent's normal work; user-group administration is not."""
    ev = lambda tool, role: engine.evaluate(tool, {}, role=role).action  # noqa: E731
    assert ev("conversations_add_message", "support-agent") == "allow"
    assert ev("reactions_add", "support-agent") == "allow"
    assert ev("usergroups_create", "support-agent") == "require_approval"


def test_workspace_admin_gets_every_write(connector, engine):
    writes = [t for t, m in connector.tools().items() if m.get("risk") == "write"]
    for tool in writes:
        assert engine.evaluate(tool, {}, role="workspace-admin").action == "allow", tool


def test_taint_model_is_wired(engine):
    assert "conversations_history" in engine.taint_sources
    assert "users_search" in engine.taint_sources
    assert "conversations_add_message" in engine.taint_sinks   # the primary exfil sink
    assert engine.sequence_rules, "expected exfiltration sequence rules"


def test_goldens_pass():
    results = run_policy_tests(
        [str(PACK / "policy.yaml"), str(PACK / "roles.yaml")],
        str(PACK / "policy_tests.yaml"),
    )
    failures = [r for r in results if not r.passed]
    assert results and not failures, [(r.name, r.failures) for r in failures]
