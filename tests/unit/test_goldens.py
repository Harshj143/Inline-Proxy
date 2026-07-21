"""Run every shipped policy pack's golden tests in CI.

The same harness backs `mcp-gateway policy test` and (Phase 10) the CI/CD
pipeline — asserting it here means a pack change that alters decisions
fails the build unless its goldens are updated to match.
"""

from pathlib import Path

from mcp_gateway.policy.testing import run_policy_tests

POLICIES = Path(__file__).resolve().parents[2] / "policies"


def test_mock_crm_pack_goldens():
    results = run_policy_tests(
        [POLICIES / "mock-crm.yaml"], POLICIES / "mock-crm.tests.yaml"
    )
    failures = [
        f"{r.name}: {'; '.join(r.failures)}" for r in results if not r.passed
    ]
    assert not failures, "\n".join(failures)
    assert len(results) >= 10  # the pack keeps meaningful coverage
