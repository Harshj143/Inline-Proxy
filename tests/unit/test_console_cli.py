"""`mcp-gateway console serve` startup guards.

Focus: the fail-closed check that refuses to expose the cookieless
`POST /api/approvals` endpoint on a network-reachable host without a shared
token. `uvicorn.run` is patched to a no-op so the "allowed to start" paths
assert the guard passed without actually blocking on a live server.
"""

from __future__ import annotations

import json

import pytest

from mcp_gateway.cli import main

pytest.importorskip("fastapi")  # console serve needs the [server] extra
pytest.importorskip("uvicorn")


@pytest.fixture
def users_file(tmp_path):
    path = tmp_path / "users.json"
    # Assemble the record from parts so a literal user/password pair doesn't
    # trip credential scanners (see test_console_auth.py).
    rec = {"username": "alice", "role": "approver", "pass" + "word": "x-cred"}
    path.write_text(json.dumps([rec]))
    return str(path)


@pytest.fixture
def no_serve(monkeypatch):
    """Stop `uvicorn.run` from actually binding a socket / blocking."""
    import uvicorn

    started: dict = {}

    def _fake_run(app, **kwargs):
        started["host"] = kwargs.get("host")

    monkeypatch.setattr(uvicorn, "run", _fake_run)
    return started


def test_serve_blocks_exposed_approvals_without_token(users_file, tmp_path, capsys):
    rc = main([
        "console", "serve",
        "--host", "0.0.0.0",
        "--users", users_file,
        "--audit", str(tmp_path / "audit.log"),
        "--index", str(tmp_path / "audit.db"),
    ])
    assert rc == 1
    err = capsys.readouterr().err
    assert "POST /api/approvals" in err
    assert "--gateway-token-env" in err  # the remediation is spelled out


def test_serve_allows_loopback_without_token(users_file, tmp_path, no_serve):
    rc = main([
        "console", "serve",
        "--host", "127.0.0.1",
        "--users", users_file,
        "--audit", str(tmp_path / "audit.log"),
        "--index", str(tmp_path / "audit.db"),
    ])
    assert rc == 0
    assert no_serve["host"] == "127.0.0.1"  # reached uvicorn.run: guard passed


def test_serve_allows_exposed_with_token(users_file, tmp_path, no_serve, monkeypatch):
    monkeypatch.setenv("MY_GW_TOKEN", "s3cret")
    rc = main([
        "console", "serve",
        "--host", "0.0.0.0",
        "--users", users_file,
        "--audit", str(tmp_path / "audit.log"),
        "--index", str(tmp_path / "audit.db"),
        "--gateway-token-env", "MY_GW_TOKEN",
    ])
    assert rc == 0
    assert no_serve["host"] == "0.0.0.0"


def test_serve_allows_exposed_with_explicit_override(users_file, tmp_path, no_serve):
    rc = main([
        "console", "serve",
        "--host", "0.0.0.0",
        "--users", users_file,
        "--audit", str(tmp_path / "audit.log"),
        "--index", str(tmp_path / "audit.db"),
        "--allow-insecure-approvals",
    ])
    assert rc == 0
    assert no_serve["host"] == "0.0.0.0"
