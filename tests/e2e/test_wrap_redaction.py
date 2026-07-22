"""Phase 2b exit criterion: a planted GitHub PAT (and other secrets/PII) in a
real tool result is scrubbed end-to-end before it reaches the client, driven
through the actual gateway subprocess with the redact action live.
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
MOCK = Path(__file__).parent / "redaction_mock.py"
POLICY = Path(__file__).parent / "policy_redaction.yaml"
TIMEOUT_S = 10

PLANTED = {
    "github_token": "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
    "aws_key": "AKIAIOSFODNN7EXAMPLE",
    "email": "ada.verne@example.com",
    "ssn": "544-21-1290",
}


class GatewayProc:
    def __init__(self, audit_path: Path):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO / "src") + os.pathsep + env.get("PYTHONPATH", "")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_gateway", "wrap",
             "--policy", str(POLICY), "--audit", str(audit_path),
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


def read_audit(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def test_planted_secrets_scrubbed_end_to_end(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    gw = GatewayProc(audit_path)
    try:
        resp = gw.call({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "vault.read", "arguments": {"id": "1"}}})
    finally:
        gw.close()

    assert "result" in resp
    blob = json.dumps(resp)
    # None of the planted secrets or PII survive into what the client receives.
    for label, value in PLANTED.items():
        assert value not in blob, f"{label} leaked through the gateway"
    assert "REDACTED" in blob

    # The audit trail proves the redaction happened and records COUNTS ONLY —
    # not one planted value appears anywhere in the log.
    audit = read_audit(audit_path)
    log_text = json.dumps(audit)
    for value in PLANTED.values():
        assert value not in log_text, "a secret leaked into the audit log"

    redacted = [e for e in audit if e["event"] == "tool_result_redacted"]
    assert len(redacted) == 1
    summary = redacted[0]["redactions"]
    assert summary["total"] >= 4
    assert summary["by_entity"].get("GITHUB_TOKEN") == 1
    assert summary["by_entity"].get("AWS_ACCESS_KEY_ID") == 1
    assert summary["by_entity"].get("EMAIL") == 1
    assert summary["by_entity"].get("SSN") == 1
