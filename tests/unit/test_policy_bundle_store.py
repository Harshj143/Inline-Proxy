"""The bundle store: a bad push must never take the gateway to no-policy.

The store's job is entirely about what happens when something goes wrong — a
forged bundle is offered, the live file rots, a policy that verified turns out to
be wrong. So these tests spend their time on those paths: a rejected install
leaves the previous policy live, a corrupted current bundle self-heals to
last-known-good, a rollback is itself reversible, and a bundle swapped on disk
after install is caught because the store re-verifies on every read.
"""

from __future__ import annotations

import json

import pytest

from mcp_gateway.policy import bundle as B
from mcp_gateway.policy import signing as S
from mcp_gateway.policy.bundle_store import BundleStore

POLICY = """\
schema_version: 1
name: demo
default_action: block
tools:
  demo.read: {{action: {action}, reason: r}}
"""


@pytest.fixture
def key():
    return S.generate_keypair()


def make_bundle(tmp_path, key, version, action="redact", name="demo"):
    layer = tmp_path / f"{version}.yaml"
    layer.write_text(POLICY.format(action=action))
    bundle = B.build_bundle([layer], name=name, version=version)
    return B.sign_bundle(bundle, key)


@pytest.fixture
def store(tmp_path, key):
    return BundleStore(tmp_path / "store", key.verifying_key())


# --------------------------------------------------------------- install
def test_store_needs_a_verifying_key(tmp_path):
    with pytest.raises(B.BundleError, match="verifying key"):
        BundleStore(tmp_path / "store", None)


def test_install_makes_a_bundle_current(store, tmp_path, key):
    result = store.install(make_bundle(tmp_path, key, "v1"))
    assert result.accepted
    resolved = store.current("demo")
    assert resolved.bundle.version == "v1" and resolved.source == "current"


def test_second_install_demotes_the_first_to_lkg(store, tmp_path, key):
    store.install(make_bundle(tmp_path, key, "v1"))
    result = store.install(make_bundle(tmp_path, key, "v2", action="quarantine"))
    assert result.accepted and result.displaced_version == "v1"
    assert store.current("demo").bundle.version == "v2"


def test_a_forged_bundle_is_rejected_and_current_is_unchanged(store, tmp_path, key):
    store.install(make_bundle(tmp_path, key, "v1"))
    attacker = S.generate_keypair()
    forged = make_bundle(tmp_path, attacker, "evil")
    result = store.install(forged)
    assert not result.accepted and "signature invalid" in result.reason
    # The good policy is still the one being served.
    assert store.current("demo").bundle.version == "v1"


def test_first_install_has_no_lkg(store, tmp_path, key):
    result = store.install(make_bundle(tmp_path, key, "v1"))
    assert result.displaced_version is None


def test_reinstalling_the_same_version_is_idempotent(store, tmp_path, key):
    store.install(make_bundle(tmp_path, key, "v1"))
    result = store.install(make_bundle(tmp_path, key, "v1"))
    assert result.accepted and result.displaced_version is None
    assert store.current("demo").bundle.version == "v1"


# --------------------------------------------------------------- self-heal
def test_current_self_heals_to_lkg_when_the_live_bundle_is_corrupt(store, tmp_path, key):
    store.install(make_bundle(tmp_path, key, "v1"))
    store.install(make_bundle(tmp_path, key, "v2"))
    # Corrupt the v2 file on disk (bit-rot / botched edit).
    (tmp_path / "store" / "demo" / "bundles" / "v2.json").write_text("{ broken")
    resolved = store.current("demo")
    assert resolved.bundle.version == "v1"
    assert resolved.source == "last_known_good" and resolved.fell_back


def test_current_is_none_when_nothing_is_usable(store, tmp_path, key):
    store.install(make_bundle(tmp_path, key, "v1"))
    (tmp_path / "store" / "demo" / "bundles" / "v1.json").write_text("{ broken")
    assert store.current("demo") is None


def test_a_bundle_swapped_on_disk_after_install_is_caught_on_read(store, tmp_path, key):
    """Re-verify on read: the store does not trust a file just because it once
    verified. An attacker who rewrites the installed bundle is caught here."""
    store.install(make_bundle(tmp_path, key, "v1"))
    path = tmp_path / "store" / "demo" / "bundles" / "v1.json"
    doc = json.loads(path.read_text())
    doc["payload"]["layers"][0]["text"] = "schema_version: 1\ndefault_action: allow\n"
    path.write_text(json.dumps(doc))
    # No LKG to fall back to, and the tampered current no longer verifies.
    assert store.current("demo") is None


# --------------------------------------------------------------- rollback
def test_rollback_promotes_lkg_and_is_reversible(store, tmp_path, key):
    store.install(make_bundle(tmp_path, key, "v1"))
    store.install(make_bundle(tmp_path, key, "v2"))
    assert store.rollback("demo").accepted
    assert store.current("demo").bundle.version == "v1"
    # v2 became the new LKG, so rolling back again returns to it.
    assert store.rollback("demo").accepted
    assert store.current("demo").bundle.version == "v2"


def test_rollback_with_no_lkg_fails_cleanly(store, tmp_path, key):
    store.install(make_bundle(tmp_path, key, "v1"))
    result = store.rollback("demo")
    assert not result.accepted and "no last-known-good" in result.reason
    assert store.current("demo").bundle.version == "v1"


def test_history_lists_installed_versions_newest_first(store, tmp_path, key):
    store.install(make_bundle(tmp_path, key, "2026.01"))
    store.install(make_bundle(tmp_path, key, "2026.02"))
    assert store.history("demo") == ["2026.02", "2026.01"]


# --------------------------------------------------------------- multi-pack
def test_one_store_holds_several_packs_independently(store, tmp_path, key):
    store.install(make_bundle(tmp_path, key, "v1", name="alpha"))
    store.install(make_bundle(tmp_path, key, "v1", name="beta"))
    assert store.current("alpha").bundle.name == "alpha"
    assert store.current("beta").bundle.name == "beta"
    assert store.current("gamma") is None
