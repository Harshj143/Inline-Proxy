"""Phase 10c exit criterion, end to end: a signed bundle is enforced; a tampered
one is *rejected with an audit event* and the gateway refuses to start.

This runs the real `mcp-gateway wrap --bundle` as a subprocess, the way an
operator would deploy a signed policy in front of a server. The two cases that
matter are the two the whole scheme exists for: a good bundle policing traffic
exactly as loose `--policy` files would, and a bundle altered after signing
being refused rather than enforced — with the refusal written to the audit
trail, because "the gateway silently ran the wrong policy" is the failure this
prevents.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from mcp_gateway.policy import bundle as B
from mcp_gateway.policy import signing as S

REPO = Path(__file__).resolve().parents[2]
MOCK_SERVER = REPO / "demo" / "mock_server.py"
TIMEOUT_S = 10

# A minimal signed-in-the-test policy: allow the harmless search, block the rest.
POLICY = """\
schema_version: 1
name: bundle-demo
default_action: block
tools:
  search.docs: {action: allow, reason: public docs search}
"""


def _env() -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO / "src") + os.pathsep + env.get("PYTHONPATH", "")
    return env


class GatewayProc:
    """A `wrap --bundle` subprocess spoken to over stdio like an MCP client."""

    def __init__(self, args: list[str]):
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_gateway", "wrap", *args,
             "--", sys.executable, str(MOCK_SERVER)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, env=_env(),
        )
        self._lines: queue.Queue[str] = queue.Queue()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self._lines.put(line)

    def call(self, msg: dict) -> dict:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        try:
            return json.loads(self._lines.get(timeout=TIMEOUT_S))
        except queue.Empty:
            stderr = self.proc.stderr.read() if self.proc.stderr else ""
            pytest.fail(f"no response within {TIMEOUT_S}s. stderr:\n{stderr}")

    def close(self):
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        self.proc.wait(timeout=TIMEOUT_S)


def _read_audit(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def _tool_call(id_, name, arguments=None):
    return {"jsonrpc": "2.0", "id": id_, "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}}}


@pytest.fixture
def signed_bundle(tmp_path):
    (tmp_path / "policy.yaml").write_text(POLICY)
    key = S.generate_keypair()
    (tmp_path / "signing.pub.pem").write_bytes(S.public_key_to_pem(key.public_raw))
    bundle = B.sign_bundle(B.build_bundle([tmp_path / "policy.yaml"]), key)
    bundle.write(tmp_path / "bundle.json")
    return tmp_path


def test_a_signed_bundle_polices_traffic(signed_bundle):
    audit = signed_bundle / "audit.jsonl"
    gw = GatewayProc([
        "--bundle", str(signed_bundle / "bundle.json"),
        "--public-key", str(signed_bundle / "signing.pub.pem"),
        "--audit", str(audit),
    ])
    try:
        init = gw.call({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        assert init["result"]["serverInfo"]["name"] == "mock-crm-server"
        # The bundle's policy allows search.docs and it reaches the real server.
        ok = gw.call(_tool_call(2, "search.docs", {"q": "hi"}))
        assert "result" in ok
        # …and default-deny still blocks everything else.
        denied = gw.call(_tool_call(3, "db.execute_sql", {"sql": "DROP TABLE t"}))
        assert denied["error"]["code"] == -32001
    finally:
        gw.close()

    events = _read_audit(audit)
    loaded = [e for e in events if e["event"] == "policy_bundle_loaded"]
    assert loaded and loaded[0]["bundle"] == "bundle-demo"
    assert loaded[0]["signer_key_id"]


def test_a_tampered_bundle_is_refused_with_an_audit_event(signed_bundle):
    # Alter one policy byte after signing: default-deny -> default-allow.
    path = signed_bundle / "bundle.json"
    doc = json.loads(path.read_text())
    doc["payload"]["layers"][0]["text"] = "schema_version: 1\ndefault_action: allow\n"
    path.write_text(json.dumps(doc))

    audit = signed_bundle / "audit.jsonl"
    proc = subprocess.run(
        [sys.executable, "-m", "mcp_gateway", "wrap",
         "--bundle", str(path),
         "--public-key", str(signed_bundle / "signing.pub.pem"),
         "--audit", str(audit),
         "--", sys.executable, str(MOCK_SERVER)],
        env=_env(), capture_output=True, text=True, timeout=TIMEOUT_S,
    )
    # Fail closed: the gateway refuses to start rather than enforce the fake.
    assert proc.returncode != 0
    assert "rejected" in proc.stderr.lower()

    # And the refusal is on the record.
    events = _read_audit(audit)
    rejected = [e for e in events if e["event"] == "policy_bundle_rejected"]
    assert rejected, f"no rejection event; audit was {events}"
    assert "mismatch" in rejected[0]["reason"].lower()


def test_a_bundle_without_a_public_key_fails_closed(signed_bundle):
    proc = subprocess.run(
        [sys.executable, "-m", "mcp_gateway", "wrap",
         "--bundle", str(signed_bundle / "bundle.json"),
         "--audit", str(signed_bundle / "audit.jsonl"),
         "--", sys.executable, str(MOCK_SERVER)],
        env=_env(), capture_output=True, text=True, timeout=TIMEOUT_S,
    )
    assert proc.returncode != 0
    assert "public-key" in proc.stderr


def test_bundle_and_policy_are_mutually_exclusive(signed_bundle):
    proc = subprocess.run(
        [sys.executable, "-m", "mcp_gateway", "wrap",
         "--bundle", str(signed_bundle / "bundle.json"),
         "--public-key", str(signed_bundle / "signing.pub.pem"),
         "--policy", str(signed_bundle / "policy.yaml"),
         "--audit", str(signed_bundle / "audit.jsonl"),
         "--", sys.executable, str(MOCK_SERVER)],
        env=_env(), capture_output=True, text=True, timeout=TIMEOUT_S,
    )
    assert proc.returncode != 0
    assert "cannot be combined" in proc.stderr


def test_wrap_loads_the_current_bundle_from_a_store(signed_bundle):
    """The store path: install a bundle, then `wrap --bundle-store` serves it."""
    from mcp_gateway.policy.bundle_store import BundleStore

    key_pub = signed_bundle / "signing.pub.pem"
    store_dir = signed_bundle / "store"
    store = BundleStore(store_dir, S.load_verifying_key(key_pub))
    assert store.install(B.load_bundle(signed_bundle / "bundle.json")).accepted

    audit = signed_bundle / "audit.jsonl"
    gw = GatewayProc([
        "--bundle-store", str(store_dir), "--bundle-name", "bundle-demo",
        "--public-key", str(key_pub), "--audit", str(audit),
    ])
    try:
        init = gw.call({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        assert init["result"]["serverInfo"]["name"] == "mock-crm-server"
        ok = gw.call(_tool_call(2, "search.docs", {"q": "hi"}))
        assert "result" in ok
    finally:
        gw.close()

    loaded = [e for e in _read_audit(audit) if e["event"] == "policy_bundle_loaded"]
    assert loaded and loaded[0]["version"]
