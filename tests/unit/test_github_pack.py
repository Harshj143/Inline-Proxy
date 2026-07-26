"""The GitHub connector pack: full-surface coverage + its golden decisions.

The pack's central claim is that it polices the *entire* GitHub MCP tool surface,
not a curated subset. These tests are what keep that true: every tool in
tools.yaml must carry an explicit rule, and the risk classification must agree
with the action the policy takes. Default-deny catches anything new, but silently
falling through to it is exactly the drift this guards against (e.g. after an
upstream version bump adds tools).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_gateway.connectors import load_connector
from mcp_gateway.policy.testing import run_policy_tests

PACK = Path(__file__).resolve().parents[2] / "connectors" / "github"

# Actions the pack is allowed to use, per risk class. A read may be redacted, or
# quarantined/strict-redacted when it is secret-adjacent; a write must be gated;
# destructive must be blocked outright.
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
    assert connector.name == "github"
    assert [p.name for p in connector.policy_layers()] == ["policy.yaml", "roles.yaml"]


def test_inventory_is_the_full_surface(connector):
    # 109 tools in github-mcp-server v1.7.0 (extracted from pkg/github/*.go).
    # A version bump that changes the surface should fail here until the pack is
    # re-reviewed — that is the point.
    assert len(connector.tools()) == 109


def test_every_tool_has_an_explicit_rule(connector, engine):
    """No tool may rely on default-deny: an unrated tool is an unreviewed tool."""
    missing = [
        tool for tool in connector.tools()
        if engine.evaluate(tool, {}).rule == "default"
    ]
    assert not missing, f"{len(missing)} tool(s) fall through to default deny: {missing}"


def test_actions_match_risk_classification(connector, engine):
    """The action taken must be defensible for the tool's risk class."""
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


def test_destructive_tools_are_blocked_for_every_role(connector, engine):
    """No role overlay may escalate an irreversible action."""
    destructive = [t for t, m in connector.tools().items() if m.get("risk") == "destructive"]
    assert destructive, "expected at least one destructive tool in the inventory"
    for tool in destructive:
        for role in (None, "developer", "reviewer", "release-manager", "bot"):
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


def test_taint_model_is_wired(engine):
    # Untrusted, free-form content reads taint; exfil-capable writes are sinks.
    assert "issue_read" in engine.taint_sources
    assert "get_file_contents" in engine.taint_sources
    assert "create_gist" in engine.taint_sinks
    assert "push_files" in engine.taint_sinks
    assert engine.sequence_rules, "expected exfiltration sequence rules"


def test_secret_bearing_reads_never_reach_the_model(engine):
    """CI logs and secret-scanning results must be withheld, not just scrubbed."""
    for tool in ("get_job_logs", "list_secret_scanning_alerts",
                 "get_secret_scanning_alert"):
        assert engine.evaluate(tool, {}).action == "quarantine", tool


def test_goldens_pass():
    results = run_policy_tests(
        [str(PACK / "policy.yaml"), str(PACK / "roles.yaml")],
        str(PACK / "policy_tests.yaml"),
    )
    failures = [r for r in results if not r.passed]
    assert results and not failures, [ (r.name, r.failures) for r in failures ]
