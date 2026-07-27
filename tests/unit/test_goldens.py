"""Every shipped policy pack, checked the way CI checks it.

This file used to name each pack by hand, and it showed twice: the GitHub pack
shipped 23 goldens that nothing ran until a follow-up PR (0cab075) added the
call by hand, and the same gap would open again for the next pack. The packs are
now *discovered* (`policy/ci.py`), which is the same discovery the `policy-ci`
workflow uses — so a new pack is covered here and in CI the moment its directory
lands, and the two can never disagree about what "checked" means. That commit's
own message named this the class of miss Phase 10 should make impossible;
discovery is how.

`check_target` is the single implementation behind both: it loads a pack's
layers in runtime order (`policy.yaml` **then** `roles.yaml` — loading only the
base makes every role case fail closed on the base `require_approval` and pass
for the wrong reason), runs the goldens, asserts every inventoried tool has an
explicit rule, and smoke-tests the backtest replay path.
"""

from pathlib import Path

import pytest

from mcp_gateway.policy.ci import CONNECTOR, check_target, discover_targets

ROOT = Path(__file__).resolve().parents[2]
TARGETS = discover_targets(ROOT)

# A ratchet, not a pack list. Discovery already guarantees every pack is checked;
# this only raises the floor for packs whose coverage we have deliberately
# invested in, so gutting a suite fails the build instead of quietly shrinking
# it. A pack absent from this map still runs — it just has to ship at least one.
MIN_GOLDENS = {
    "github": 20,
    "slack": 25,
    "mock-crm": 10,
}
DEFAULT_MIN_GOLDENS = 1


def test_discovery_finds_every_shipped_pack():
    """Guards the parametrized tests below from passing vacuously.

    A discovery bug that returned nothing would make every `test_pack` case
    disappear silently — green CI that checked no policy at all.
    """
    found = {t.name for t in TARGETS}
    assert {"example", "github", "slack", "mock-crm"} <= found
    assert all(t.error is None for t in TARGETS), [
        (t.name, t.error) for t in TARGETS if t.error
    ]


def test_every_ratcheted_pack_still_exists():
    """A rename that silently drops a pack's floor should not go unnoticed."""
    missing = set(MIN_GOLDENS) - {t.name for t in TARGETS}
    assert not missing, f"MIN_GOLDENS names packs that no longer exist: {sorted(missing)}"


@pytest.mark.parametrize("target", TARGETS, ids=lambda t: t.label)
def test_pack(target):
    """Validate + goldens + tool coverage + backtest replay, per pack."""
    report = check_target(
        target, min_goldens=MIN_GOLDENS.get(target.name, DEFAULT_MIN_GOLDENS)
    )
    failures = [f"[{c.name}] {f}" for c in report.checks for f in c.failures]
    assert not failures, f"{target.label}:\n" + "\n".join(failures)


@pytest.mark.parametrize(
    "target", [t for t in TARGETS if t.kind == CONNECTOR], ids=lambda t: t.name
)
def test_connector_packs_ship_goldens(target):
    """A connector pack without goldens is an unverified security control."""
    assert target.tests is not None, f"{target.name}: missing policy_tests.yaml"
