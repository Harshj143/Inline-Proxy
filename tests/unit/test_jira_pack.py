"""The Jira connector pack: full-surface coverage + its golden decisions.

The pack's central claim is that it polices the *entire* Jira MCP tool surface
(all 63 `jira_*` tools of sooperset/mcp-atlassian), not a curated subset. These
tests keep that true: every tool in tools.yaml must carry an explicit rule, and
the risk classification must agree with the action the policy takes. Default-deny
catches anything new, but silently falling through to it is exactly the drift
this guards against after an upstream version bump.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_gateway.connectors import load_connector
from mcp_gateway.policy.testing import run_policy_tests

PACK = Path(__file__).resolve().parents[2] / "connectors" / "jira"

# Actions the pack is allowed to use, per risk class. A read is redacted (Jira
# text is untrusted); a secret-adjacent read (opaque attachment bytes) is
# quarantined; a write must be gated; destructive must be blocked outright.
ALLOWED_BY_RISK = {
    "read": {"redact"},
    "write": {"require_approval"},
    "destructive": {"block"},
    "secret_adjacent": {"quarantine", "redact"},
}


@pytest.fixture(scope="module")
def connector():
    return load_connector(PACK)


@pytest.fixture(scope="module")
def engine(connector):
    return connector.build_engine()


def test_pack_loads_with_both_layers(connector):
    assert connector.name == "jira"
    assert [p.name for p in connector.policy_layers()] == ["policy.yaml", "roles.yaml"]


def test_inventory_is_the_full_surface(connector):
    # 63 jira_* tools in mcp-atlassian (extracted from servers/jira.py). A bump
    # that changes the surface should fail here until the pack is re-reviewed.
    assert len(connector.tools()) == 63


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


def test_default_action_is_block(engine):
    assert engine.default_action == "block"
    assert engine.evaluate("a_tool_that_does_not_exist", {}).action == "block"


def test_destructive_tool_is_blocked_for_every_role(connector, engine):
    """No role overlay may escalate an irreversible action."""
    destructive = [t for t, m in connector.tools().items() if m.get("risk") == "destructive"]
    assert destructive == ["jira_delete_issue"], destructive
    for tool in destructive:
        for role in (None, "support-agent", "project-admin", "bot"):
            assert engine.evaluate(tool, {}, role=role).action == "block", (tool, role)


def test_bot_role_cannot_write(connector, engine):
    """An unattended identity has no approver, so writes are blocked outright."""
    writes = [t for t, m in connector.tools().items() if m.get("risk") == "write"]
    for tool in writes:
        assert engine.evaluate(tool, {}, role="bot").action == "block", tool


def test_bot_role_can_still_read(connector, engine):
    reads = [t for t, m in connector.tools().items() if m.get("risk") == "read"]
    for tool in reads:
        assert engine.evaluate(tool, {}, role="bot").action == "redact", tool


def test_project_admin_gets_writes_but_not_delete(connector, engine):
    """The project owner performs writes directly, but the destructive delete
    still requires nobody — it stays blocked."""
    assert engine.evaluate("jira_create_issue", {}, role="project-admin").action == "allow"
    assert engine.evaluate("jira_update_issue", {}, role="project-admin").action == "allow"
    assert engine.evaluate("jira_delete_issue", {}, role="project-admin").action == "block"


def test_support_agent_gets_jsm_work_only(engine):
    """Comment/transition are the JSM front line's normal work; issue creation
    is not their grant and stays gated."""
    assert engine.evaluate("jira_add_comment", {}, role="support-agent").action == "allow"
    assert engine.evaluate("jira_transition_issue", {}, role="support-agent").action == "allow"
    assert engine.evaluate("jira_create_issue", {}, role="support-agent").action == "require_approval"


def test_taint_model_is_wired(engine):
    # Untrusted, free-form content reads taint; exfil-capable writes are sinks.
    assert "jira_get_issue" in engine.taint_sources
    assert "jira_get_queue_issues" in engine.taint_sources         # JSM customer content
    assert "jira_create_remote_issue_link" in engine.taint_sinks   # external URL = exfil
    assert "jira_add_comment" in engine.taint_sinks
    assert engine.sequence_rules, "expected exfiltration sequence rules"


def test_attachment_reads_are_quarantined(engine):
    """Opaque attachment/image bytes have no useful partial view — withhold."""
    for tool in ("jira_download_attachments", "jira_get_issue_images"):
        assert engine.evaluate(tool, {}).action == "quarantine", tool


def test_goldens_pass():
    results = run_policy_tests(
        [str(PACK / "policy.yaml"), str(PACK / "roles.yaml")],
        str(PACK / "policy_tests.yaml"),
    )
    failures = [r for r in results if not r.passed]
    assert results and not failures, [(r.name, r.failures) for r in failures]
