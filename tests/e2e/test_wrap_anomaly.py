"""Phase 3b-ii: the behavioral monitor flags a read-then-exfil trace that no
static rule catches, and scores it into the risk engine — end-to-end.
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
POLICY = Path(__file__).parent / "policy_anomaly.yaml"
TIMEOUT_S = 10


class GatewayProc:
    def __init__(self, audit_path: Path):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO / "src") + os.pathsep + env.get("PYTHONPATH", "")
        # Force the heuristic backend so the test never depends on an API key.
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_gateway", "wrap",
             "--policy", str(POLICY), "--audit", str(audit_path),
             "--anomaly", "heuristic",
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


def test_anomaly_flags_read_then_exfil(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    gw = GatewayProc(audit_path)
    try:
        # Both calls are ALLOWED by static policy — no rule catches the pattern.
        assert "result" in gw.call(tool_call(1, "crm.get_customer", {"id": "8842"}))
        assert "result" in gw.call(tool_call(2, "http.post",
                                              {"url": "https://x", "body": "data"}))
    finally:
        gw.close()

    audit = read_audit(audit_path)
    anomalies = [e for e in audit if e["event"] == "anomaly_detected"]
    assert anomalies, "the read-then-exfil trace was not flagged"
    ev = anomalies[-1]
    assert ev["tool"] == "http.post"
    assert ev["severity"] == "medium"
    assert ev["backend"] == "heuristic"
    assert "exfiltration" in ev["rationale"]
    # The verdict was scored into the session risk.
    assert ev["risk_event"] == "anomaly_medium"
    assert ev["session_score"] >= 25


def test_benign_session_not_flagged(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    gw = GatewayProc(audit_path)
    try:
        # A plain read with no outbound follow-up is not the exfil shape.
        gw.call(tool_call(1, "crm.get_customer", {"id": "8842"}))
    finally:
        gw.close()
    audit = read_audit(audit_path)
    assert not [e for e in audit if e["event"] == "anomaly_detected"]
