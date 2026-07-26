"""Connector framework: load, registry discovery/precedence, scaffold, overrides."""

from __future__ import annotations

import pytest

from mcp_gateway.connectors import find_connector, list_connectors, load_connector
from mcp_gateway.connectors.registry import _candidate_dirs
from mcp_gateway.connectors.scaffold import scaffold_connector
from mcp_gateway.core.errors import ConnectorError


@pytest.fixture
def pack(tmp_path):
    """A freshly scaffolded, valid connector named 'demo' under tmp_path."""
    scaffold_connector("demo", tmp_path)
    return tmp_path / "demo"


# ------------------------------------------------------------------ scaffold
def test_scaffold_produces_a_loadable_connector(pack):
    c = load_connector(pack)
    assert c.name == "demo"
    assert (pack / "manifest.yaml").is_file()
    assert (pack / "policy.yaml").is_file()
    assert c.tests_path() is not None
    assert "demo.ping" in c.tools()


def test_scaffolded_policy_validates_and_passes_goldens(pack):
    from mcp_gateway.policy.testing import run_policy_tests

    # Loads + compiles (would raise PolicyError on an invalid document):
    engine = load_connector(pack).build_engine()
    assert engine.default_action == "block"
    # The generated golden file passes against the generated policy:
    results = run_policy_tests([str(pack / "policy.yaml")], str(pack / "policy_tests.yaml"))
    assert results and all(r.passed for r in results)


def test_scaffold_refuses_to_clobber_nonempty(tmp_path):
    scaffold_connector("demo", tmp_path)
    with pytest.raises(ConnectorError, match="already exists"):
        scaffold_connector("demo", tmp_path)
    scaffold_connector("demo", tmp_path, force=True)  # force overwrites


def test_scaffold_rejects_bad_name(tmp_path):
    with pytest.raises(ConnectorError, match="identifier"):
        scaffold_connector("no spaces!", tmp_path)


# ------------------------------------------------------------------ loading
def test_load_missing_manifest_fails_closed(tmp_path):
    (tmp_path / "broken").mkdir()
    with pytest.raises(ConnectorError, match="missing manifest.yaml"):
        load_connector(tmp_path / "broken")


def test_load_missing_policy_fails_closed(tmp_path):
    d = tmp_path / "nopolicy"
    d.mkdir()
    (d / "manifest.yaml").write_text("name: nopolicy\n")
    with pytest.raises(ConnectorError, match="missing policy.yaml"):
        load_connector(d)


def test_load_name_must_match_directory(tmp_path):
    d = tmp_path / "alpha"
    d.mkdir()
    (d / "manifest.yaml").write_text("name: beta\n")
    (d / "policy.yaml").write_text("schema_version: 1\ndefault_action: block\ntools: {}\n")
    with pytest.raises(ConnectorError, match="does not match directory"):
        load_connector(d)


def test_load_not_a_directory(tmp_path):
    with pytest.raises(ConnectorError, match="not a directory"):
        load_connector(tmp_path / "does-not-exist")


# ------------------------------------------------------------------ registry
def test_registry_finds_and_lists_scoped_paths(tmp_path):
    scaffold_connector("demo", tmp_path)
    scaffold_connector("other", tmp_path)
    names = [c.name for c in list_connectors(paths=[tmp_path])]
    assert names == ["demo", "other"]
    assert find_connector("demo", paths=[tmp_path]).name == "demo"


def test_registry_precedence_first_path_wins(tmp_path):
    high = tmp_path / "high"
    low = tmp_path / "low"
    scaffold_connector("demo", high)
    scaffold_connector("demo", low)
    # Distinguish the two by editing the high-priority one's manifest.
    manifest = (high / "demo" / "manifest.yaml").read_text()
    (high / "demo" / "manifest.yaml").write_text(
        manifest.replace("Security pack", "HIGH-PRIORITY pack")
    )
    resolved = find_connector("demo", paths=[high, low])
    assert "HIGH-PRIORITY" in resolved.description
    # And it appears exactly once in the list (shadowing, not duplication):
    listed = [c for c in list_connectors(paths=[high, low]) if c.name == "demo"]
    assert len(listed) == 1


def test_registry_unknown_name_fails_closed(tmp_path):
    with pytest.raises(ConnectorError, match="unknown connector 'ghost'"):
        find_connector("ghost", paths=[tmp_path])


def test_list_skips_malformed_pack(tmp_path):
    scaffold_connector("good", tmp_path)
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "manifest.yaml").write_text("name: bad\n")  # has manifest, no policy.yaml
    # list tolerates the broken pack (returns the good one)...
    assert [c.name for c in list_connectors(paths=[tmp_path])] == ["good"]
    # ...but find surfaces the precise error for the broken one.
    with pytest.raises(ConnectorError, match="missing policy.yaml"):
        find_connector("bad", paths=[tmp_path])
    # A directory without a manifest is not a candidate at all.
    (tmp_path / "notaconnector").mkdir()
    assert {n for n, _ in _candidate_dirs([tmp_path])} == {"good", "bad"}


# ------------------------------------------------------------------ overrides
def test_override_layers_on_top_without_forking(tmp_path):
    scaffold_connector("demo", tmp_path)
    pack = tmp_path / "demo"
    # A company override that adds a rule the pack didn't ship.
    override = tmp_path / "company.yaml"
    override.write_text(
        "schema_version: 1\n"
        "default_action: block\n"
        "tools:\n"
        "  demo.export:\n"
        "    action: block\n"
        "    reason: company forbids export\n"
    )
    engine = load_connector(pack).build_engine(overrides=[override])
    # Base rule still present, override rule merged in.
    assert engine.evaluate("demo.ping", {}).action == "allow"
    export = engine.evaluate("demo.export", {})
    assert export.action == "block" and "company forbids" in export.reason
