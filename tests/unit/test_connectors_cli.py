"""CLI surface for connectors: list / show / scaffold, and wrap engine resolution."""

from __future__ import annotations

import argparse

import pytest

from mcp_gateway.cli import _build_wrap_engine, main
from mcp_gateway.connectors.scaffold import scaffold_connector
from mcp_gateway.core.errors import ConnectorError


def test_connectors_scaffold_then_show(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("MCPG_CONNECTORS_DIR", str(tmp_path))
    assert main(["connectors", "scaffold", "acme", "--dir", str(tmp_path)]) == 0
    capsys.readouterr()

    assert main(["connectors", "list"]) == 0
    assert "acme" in capsys.readouterr().out

    assert main(["connectors", "show", "acme"]) == 0
    out = capsys.readouterr().out
    assert "acme" in out and "tools:" in out


def test_connectors_show_unknown_exits_1(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("MCPG_CONNECTORS_DIR", str(tmp_path))
    assert main(["connectors", "show", "ghost"]) == 1
    assert "unknown connector" in capsys.readouterr().err


def _wrap_ns(**over):
    ns = argparse.Namespace(connector=None, policy=None, override=None)
    ns.__dict__.update(over)
    return ns


def test_build_wrap_engine_from_connector(tmp_path, monkeypatch):
    scaffold_connector("acme", tmp_path)
    monkeypatch.setenv("MCPG_CONNECTORS_DIR", str(tmp_path))
    engine = _build_wrap_engine(_wrap_ns(connector="acme"))
    assert engine.evaluate("acme.ping", {}).action == "allow"


def test_build_wrap_engine_connector_plus_override(tmp_path, monkeypatch):
    scaffold_connector("acme", tmp_path)
    monkeypatch.setenv("MCPG_CONNECTORS_DIR", str(tmp_path))
    override = tmp_path / "co.yaml"
    override.write_text(
        "schema_version: 1\ndefault_action: block\n"
        "tools:\n  acme.ping:\n    action: block\n    reason: locked down here\n"
    )
    engine = _build_wrap_engine(_wrap_ns(connector="acme", override=[str(override)]))
    # Override layers last and wins over the pack's allow.
    decision = engine.evaluate("acme.ping", {})
    assert decision.action == "block" and "locked down" in decision.reason


def test_build_wrap_engine_requires_a_source():
    with pytest.raises(ConnectorError):
        _build_wrap_engine(_wrap_ns(connector="nope"))
    from mcp_gateway.core.errors import GatewayError

    with pytest.raises(GatewayError, match="--connector NAME or --policy"):
        _build_wrap_engine(_wrap_ns())
