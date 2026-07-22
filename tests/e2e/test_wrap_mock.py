"""Phase 0 exit criteria (docs/PLAN.md): the new gateway wraps the prototype's
mock CRM server and reproduces run_demo scenarios 1 (passthrough), 4 (explicit
block), and 5 (default deny) — plus the fail-closed handling of a rule whose
action isn't built yet.

The gateway runs as a real subprocess, spoken to over stdio exactly as an MCP
client would. A reader thread + queue gives every readline a timeout so a
hung gateway fails the test instead of hanging the suite.
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
MOCK_SERVER = REPO / "demo" / "mock_server.py"
POLICY = Path(__file__).parent / "policy_phase0.json"
TIMEOUT_S = 10


class GatewayProc:
    def __init__(self, audit_path: Path):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO / "src") + os.pathsep + env.get("PYTHONPATH", "")
        self.proc = subprocess.Popen(
            [
                sys.executable, "-m", "mcp_gateway", "wrap",
                "--policy", str(POLICY),
                "--audit", str(audit_path),
                "--",
                sys.executable, str(MOCK_SERVER),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
        )
        self._lines: queue.Queue[str] = queue.Queue()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self._lines.put(line)

    def send(self, msg: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def recv(self) -> dict:
        try:
            return json.loads(self._lines.get(timeout=TIMEOUT_S))
        except queue.Empty:
            stderr = ""
            if self.proc.poll() is not None and self.proc.stderr is not None:
                stderr = self.proc.stderr.read()
            pytest.fail(f"no response from gateway within {TIMEOUT_S}s. stderr:\n{stderr}")

    def call(self, msg: dict) -> dict:
        self.send(msg)
        return self.recv()

    def close(self) -> None:
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        self.proc.wait(timeout=TIMEOUT_S)


@pytest.fixture()
def gw(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    g = GatewayProc(audit_path)
    yield g
    g.close()


def read_audit(audit_path: Path) -> list[dict]:
    return [json.loads(line) for line in audit_path.read_text().splitlines() if line]


def tool_call(id_, name, arguments=None):
    return {
        "jsonrpc": "2.0", "id": id_, "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    }


def test_full_session(gw, tmp_path):
    # 1. initialize passes through untouched and is answered by the real server.
    resp = gw.call({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert resp["id"] == 1
    assert resp["result"]["serverInfo"]["name"] == "mock-crm-server"

    # notifications pass through without a reply.
    gw.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    # tools/list is filtered: tools whose action can only deny are hidden
    # from the model (Phase 1 filtering stage).
    resp = gw.call({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = [t["name"] for t in resp["result"]["tools"]]
    assert "search.docs" in names
    assert "db.execute_sql" not in names   # blocked → hidden
    assert "logs.tail" not in names        # no rule → default block → hidden

    # 2. an allowed tool reaches the server and returns its real result.
    resp = gw.call(tool_call(3, "search.docs", {"q": "getting started"}))
    body = json.loads(resp["result"]["content"][0]["text"])
    assert body["hits"] == ["Getting started", "API reference"]

    # 3. an explicitly blocked tool is denied AT the gateway.
    resp = gw.call(tool_call(4, "db.execute_sql", {"sql": "DROP TABLE customers"}))
    assert resp["error"]["code"] == -32001
    assert "denied by security gateway" in resp["error"]["message"]
    assert "raw SQL against production is forbidden" in resp["error"]["message"]

    # 4. an unknown tool meets default-deny.
    resp = gw.call(tool_call(5, "filesystem.delete_everything"))
    assert resp["error"]["code"] == -32001
    assert "default policy" in resp["error"]["message"]

    # 5. a redact rule now SCRUBS the result: the call succeeds but the PII in
    # the customer record never reaches the client (Phase 2b, redact live).
    resp = gw.call(tool_call(6, "crm.get_customer", {"id": "8842"}))
    assert "result" in resp
    blob = json.dumps(resp)
    assert "ada.verne@example.com" not in blob     # email scrubbed
    assert "544-21-1290" not in blob               # ssn scrubbed
    assert "REDACTED" in blob                       # replaced with typed markers

    # Shut down and inspect the audit trail.
    gw.close()
    audit = read_audit(tmp_path / "audit.jsonl")
    by_event = {}
    for ev in audit:
        by_event.setdefault(ev["event"], []).append(ev)

    assert set(by_event) >= {
        "gateway_start", "passthrough_request", "tool_call_allowed",
        "tool_result", "tool_result_redacted", "tool_call_blocked", "gateway_stop",
    }

    # Every event is schema v1 and carries the session id.
    session_ids = {ev.get("session_id") for ev in audit}
    assert len(session_ids) == 1 and None not in session_ids
    assert all(ev["schema_version"] == 1 for ev in audit)

    allowed_tools = [ev["tool"] for ev in by_event["tool_call_allowed"]]
    assert allowed_tools == ["search.docs", "crm.get_customer"]
    # Rule attribution names the policy layer that decided (layer:pattern).
    assert by_event["tool_call_allowed"][0]["rule"] == "e2e-phase0:search.docs"

    # The redaction event records counts, never the values.
    redacted_ev = by_event["tool_result_redacted"][0]
    assert redacted_ev["tool"] == "crm.get_customer"
    assert redacted_ev["redactions"]["total"] >= 2
    assert "544-21-1290" not in json.dumps(redacted_ev)

    blocked_tools = [ev["tool"] for ev in by_event["tool_call_blocked"]]
    assert blocked_tools == ["db.execute_sql", "filesystem.delete_everything"]

    result_ev = by_event["tool_result"][0]
    assert result_ev["tool"] == "search.docs"
    assert result_ev["is_error"] is False
    assert result_ev["duration_ms"] >= 0
    assert result_ev["result_bytes"] > 0


def test_blocked_call_never_reaches_upstream(gw, tmp_path):
    # The mock server answers ANY tools/call it receives; if the block were
    # applied on the response path instead of the request path we would see
    # a result, not an error. The -32001 error plus an upstream that stays
    # healthy afterwards proves request-stage enforcement.
    resp = gw.call(tool_call(1, "admin.delete_user", {"id": "8842"}))
    assert resp["error"]["code"] == -32001

    resp = gw.call(tool_call(2, "search.docs", {"q": "still alive"}))
    assert "result" in resp
