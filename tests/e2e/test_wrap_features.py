"""Phase 1 features end-to-end, against the real mock CRM server with the
shipped mock-crm pack: rewrites, constraints, quarantine, role overlays,
and tools/list filtering — driven through the actual gateway subprocess.
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
PACK = REPO / "policies" / "mock-crm.yaml"
TIMEOUT_S = 10


class GatewayProc:
    def __init__(self, audit_path: Path, role: str | None = None):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO / "src") + os.pathsep + env.get("PYTHONPATH", "")
        cmd = [
            sys.executable, "-m", "mcp_gateway", "wrap",
            "--policy", str(PACK),
            "--audit", str(audit_path),
        ]
        if role:
            cmd += ["--role", role]
        cmd += ["--", sys.executable, str(MOCK_SERVER)]
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1, env=env,
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
            stderr = self.proc.stderr.read() if self.proc.poll() is not None else ""
            pytest.fail(f"no response within {TIMEOUT_S}s. stderr:\n{stderr}")

    def close(self) -> None:
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        self.proc.wait(timeout=TIMEOUT_S)


def tool_call(id_, name, arguments=None):
    return {"jsonrpc": "2.0", "id": id_, "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}}}


def read_audit(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def test_rewrite_quarantine_and_filtering(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    gw = GatewayProc(audit_path)
    try:
        # tools/list: only tools that can actually succeed are visible.
        resp = gw.call({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = {t["name"] for t in resp["result"]["tools"]}
        assert names == {"search.docs", "db.execute_sql", "logs.tail"}
        # hidden: crm.get_customer (redact→deny, no role), web.fetch/http.post
        # (blocked until taint), admin.delete_user (approval→deny)

        # rewrite: the mock server echoes nothing about sql, but the audit
        # trail proves what was forwarded.
        resp = gw.call(tool_call(2, "db.execute_sql", {"sql": "SELECT * FROM customers"}))
        assert "result" in resp

        # constraint: non-SELECT denied at the gateway.
        resp = gw.call(tool_call(3, "db.execute_sql", {"sql": "DELETE FROM customers"}))
        assert resp["error"]["code"] == -32001
        assert "read-only SELECT" in resp["error"]["message"]

        # quarantine: call runs upstream, model sees only the notice.
        resp = gw.call(tool_call(4, "logs.tail", {"path": "/var/log/app"}))
        text = resp["result"]["content"][0]["text"]
        assert "QUARANTINED by security gateway" in text
        assert "db_password" not in json.dumps(resp)   # the secret never crossed
    finally:
        gw.close()

    audit = read_audit(audit_path)
    by_event = {}
    for ev in audit:
        by_event.setdefault(ev["event"], []).append(ev)

    filtered = by_event["tools_list_filtered"][0]
    assert filtered["total"] == 7 and filtered["shown"] == 3
    assert set(filtered["hidden"]) == {
        "crm.get_customer", "web.fetch", "http.post", "admin.delete_user",
    }

    rewritten = [ev for ev in by_event["tool_call_allowed"] if ev.get("rewrites")]
    assert rewritten[0]["tool"] == "db.execute_sql"
    assert rewritten[0]["rewrites"] == [
        {"arg": "sql", "op": "append", "added": " LIMIT 1000"},
    ]

    quarantined = by_event["tool_result_quarantined"][0]
    assert quarantined["tool"] == "logs.tail"
    assert quarantined["withheld_bytes"] > 0


def test_admin_role_overlay_sees_raw_pii(tmp_path):
    gw = GatewayProc(tmp_path / "audit.jsonl", role="admin")
    try:
        # With the admin overlay, crm.get_customer is visible and allowed raw.
        resp = gw.call({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = {t["name"] for t in resp["result"]["tools"]}
        assert "crm.get_customer" in names

        resp = gw.call(tool_call(2, "crm.get_customer", {"id": "8842"}))
        record = json.loads(resp["result"]["content"][0]["text"])
        assert record["email"] == "ada.verne@example.com"  # raw, by policy
    finally:
        gw.close()
