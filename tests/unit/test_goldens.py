"""Run every shipped policy pack's golden tests in CI.

The same harness backs `mcp-gateway policy test` and (Phase 10) the CI/CD
pipeline — asserting it here means a pack change that alters decisions
fails the build unless its goldens are updated to match.
"""

from pathlib import Path

from mcp_gateway.policy.testing import run_policy_tests

ROOT = Path(__file__).resolve().parents[2]
POLICIES = ROOT / "policies"
CONNECTORS = ROOT / "connectors"


def _assert_goldens(policy_layers, tests_path, minimum):
    results = run_policy_tests(policy_layers, tests_path)
    failures = [
        f"{r.name}: {'; '.join(r.failures)}" for r in results if not r.passed
    ]
    assert not failures, "\n".join(failures)
    assert len(results) >= minimum  # the pack keeps meaningful coverage


def test_mock_crm_pack_goldens():
    _assert_goldens(
        [POLICIES / "mock-crm.yaml"], POLICIES / "mock-crm.tests.yaml", minimum=10
    )


def test_slack_pack_goldens():
    """Both layers: role cases need roles.yaml merged on top of policy.yaml,
    exactly as `Connector.policy_layers()` orders them at runtime."""
    pack = CONNECTORS / "slack"
    _assert_goldens(
        [pack / "policy.yaml", pack / "roles.yaml"],
        pack / "policy_tests.yaml",
        minimum=25,
    )


def test_github_pack_goldens():
    """Both layers, like Slack: the reviewer/release-manager/bot role cases only
    resolve once roles.yaml is merged on top of policy.yaml (the order
    `Connector.policy_layers()` uses at runtime). Running only policy.yaml would
    leave every role case failing closed on the base require_approval."""
    pack = CONNECTORS / "github"
    _assert_goldens(
        [pack / "policy.yaml", pack / "roles.yaml"],
        pack / "policy_tests.yaml",
        minimum=20,
    )
