"""Phase 3b-i: human-in-the-loop approvals end-to-end.

admin.delete_user is `require_approval` (then: allow) in the mock-crm pack.

  * --approvals deny (default): the call is refused fail-closed, and the tool
    is hidden from tools/list (it can only ever deny).
  * --approvals allow: a human "approves", the call falls through to `then`
    and reaches the server, and the tool becomes visible.
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

REPO = Path(__file__).resolve().parents[2]
MOCK = REPO / "demo" / "mock_server.py"
PACK = REPO / "policies" / "mock-crm.yaml"
TIMEOUT_S = 10


class GatewayProc:
    def __init__(self, audit_path: Path, approvals: str = "deny"):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO / "src") + os.pathsep + env.get("PYTHONPATH", "")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_gateway", "wrap",
             "--policy", str(PACK), "--audit", str(audit_path),
             "--approvals", approvals,
             "--", sys.executable, str(MOCK)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, env=env,
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
            err = self.proc.stderr.read() if self.proc.poll() is not None else ""
            pytest.fail(f"no response within {TIMEOUT_S}s. stderr:\n{err}")

    def close(self):
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        self.proc.wait(timeout=TIMEOUT_S)


def delete_call(id_):
    return {"jsonrpc": "2.0", "id": id_, "method": "tools/call",
            "params": {"name": "admin.delete_user", "arguments": {"id": "8842"}}}


def read_audit(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def test_approval_denied_fail_closed(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    gw = GatewayProc(audit_path, approvals="deny")
    try:
        # Hidden from tools/list: with no approver, it can only deny.
        resp = gw.call({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = {t["name"] for t in resp["result"]["tools"]}
        assert "admin.delete_user" not in names

        resp = gw.call(delete_call(2))
        assert resp["error"]["code"] == -32001
        assert "approval denied" in resp["error"]["message"].lower()
    finally:
        gw.close()

    audit = read_audit(audit_path)
    approvals = [e for e in audit if e["event"] == "approval_requested"]
    assert approvals and approvals[0]["approved"] is False


def test_approval_granted_reaches_server(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    gw = GatewayProc(audit_path, approvals="allow")
    try:
        # Visible now that approval can succeed.
        resp = gw.call({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = {t["name"] for t in resp["result"]["tools"]}
        assert "admin.delete_user" in names

        # Approved -> falls through to `then: allow` -> the mock deletes.
        resp = gw.call(delete_call(2))
        assert "result" in resp
        body = json.loads(resp["result"]["content"][0]["text"])
        assert body["deleted"] == "8842"
    finally:
        gw.close()

    audit = read_audit(audit_path)
    approvals = [e for e in audit if e["event"] == "approval_requested"]
    assert approvals and approvals[0]["approved"] is True
    assert any(e["event"] == "tool_call_allowed" and e["tool"] == "admin.delete_user"
               for e in audit)
