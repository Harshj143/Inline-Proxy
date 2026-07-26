"""Phase 6b exit criterion — the GitHub pack stops a real injection-to-exfil chain.

The scenario, run against the SHIPPED `connectors/github` pack (no test-only
policy) and the real GitHub tool names:

  1. the agent reads a poisoned issue        -> allowed, redacted, session TAINTED
  2. it reads the repo's .env                -> allowed, secrets scrubbed
  3. it reads CI job logs                    -> QUARANTINED (secrets withheld)
  4. it tries to publish the loot as a gist  -> BLOCKED (taint/sequence gate)
  5. it tries to push the loot to a branch   -> BLOCKED

Why the approval mode matters here: the pack gates every write behind
`require_approval`, which FAILS CLOSED with no approver. Running these tests with
the default `--approvals deny` would block the gist for the wrong reason and
prove nothing about taint. So the exfil tests run with `--approvals allow`
(auto-approve, dev-only) — writes are permitted, and the ONLY thing left standing
between the attacker and the data is the taint/sequence gate. The control test
(`test_clean_session_may_gist`) confirms the same call succeeds in a clean
session, isolating session state as the deciding factor.

The gateway never interprets the injected instructions; it refuses to let a
session that has *read untrusted content* complete an exfiltration.
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
MOCK = REPO / "tests" / "e2e" / "github_mock.py"
TIMEOUT_S = 15

# Secrets planted in the mock's .env / CI logs. None may ever reach the client.
PLANTED_SECRETS = (
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
)


class GatewayProc:
    """The gateway wrapping the mock GitHub server, driven over stdio."""

    def __init__(self, audit_path: Path, *, approvals: str = "deny",
                 role: str | None = None, exfil_marker: Path | None = None):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO / "src") + os.pathsep + env.get("PYTHONPATH", "")
        cmd = [sys.executable, "-m", "mcp_gateway", "wrap",
               "--connector", "github",           # the SHIPPED pack
               "--audit", str(audit_path),
               "--approvals", approvals]
        if role:
            cmd += ["--role", role]
        cmd += ["--", sys.executable, str(MOCK)]
        if exfil_marker:
            cmd.append(str(exfil_marker))
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


def is_denied(resp: dict) -> bool:
    return "error" in resp and resp["error"]["code"] == -32001


# ------------------------------------------------------------- the full chain
def test_poisoned_issue_to_gist_exfiltration_is_blocked(tmp_path):
    """The headline defense: injection in, nothing out."""
    audit_path = tmp_path / "audit.jsonl"
    marker = tmp_path / "exfiltrated.jsonl"      # written only if a sink executes
    gw = GatewayProc(audit_path, approvals="allow", exfil_marker=marker)
    try:
        # 1. Read the attacker's issue. Allowed (agents must read issues), but
        #    the session is now tainted by untrusted content.
        resp = gw.call(tool_call(1, "issue_read", {"owner": "acme", "repo": "web",
                                                   "issue_number": 42}))
        assert "result" in resp, resp
        # The contact email in the issue body is PII and must be scrubbed.
        assert "helpful.stranger@evil.example" not in json.dumps(resp)

        # 2. Read the .env the injection asked for. Allowed, but scrubbed —
        #    the model never sees the credentials.
        resp = gw.call(tool_call(2, "get_file_contents",
                                 {"owner": "acme", "repo": "web", "path": ".env"}))
        assert "result" in resp, resp
        blob = json.dumps(resp)
        for secret in PLANTED_SECRETS:
            assert secret not in blob, f"leaked {secret} through get_file_contents"

        # 3. Read the CI logs. QUARANTINED: the result is withheld entirely,
        #    because a log's secrets are the payload, not an accident.
        resp = gw.call(tool_call(3, "get_job_logs",
                                 {"owner": "acme", "repo": "web", "job_id": 7}))
        blob = json.dumps(resp)
        for secret in PLANTED_SECRETS:
            assert secret not in blob, f"leaked {secret} through get_job_logs"

        # 4. Publish the loot as a gist -> BLOCKED by the taint/sequence gate,
        #    even though approvals are wide open in this run.
        resp = gw.call(tool_call(4, "create_gist",
                                 {"filename": "debug-output", "content": "…loot…"}))
        assert is_denied(resp), f"gist was NOT blocked: {resp}"

        # 5. The other exfil route is closed too.
        resp = gw.call(tool_call(5, "push_files",
                                 {"owner": "acme", "repo": "web", "branch": "main"}))
        assert is_denied(resp), f"push was NOT blocked: {resp}"
    finally:
        gw.close()

    # Containment: no sink ever reached the upstream server.
    assert not marker.exists(), (
        f"exfiltration reached the server: {marker.read_text()}")

    audit = read_audit(audit_path)
    events = {e["event"] for e in audit}
    assert "session_tainted" in events, "reading the issue should taint the session"

    blocked = [e for e in audit if e["event"] == "tool_call_blocked"]
    blocked_tools = {e["tool"] for e in blocked}
    assert {"create_gist", "push_files"} <= blocked_tools

    # The taint/sequence gate is what fired — not approval, not the policy stage.
    assert any(e["tool"] == "create_gist" and e["stage"] == "sequence"
               for e in blocked), blocked

    # Quarantine is recorded, and the audit itself holds no raw secrets.
    assert "tool_result_quarantined" in events
    spool = audit_path.read_text()
    for secret in PLANTED_SECRETS:
        assert secret not in spool, f"audit log leaked {secret}"


def test_clean_session_may_gist(tmp_path):
    """Control: the same call succeeds when the session never read untrusted
    content — so step 4 above was blocked by session state, not a blanket ban."""
    marker = tmp_path / "exfiltrated.jsonl"
    gw = GatewayProc(tmp_path / "audit.jsonl", approvals="allow", exfil_marker=marker)
    try:
        resp = gw.call(tool_call(1, "create_gist",
                                 {"filename": "notes.txt", "content": "hello"}))
        assert "result" in resp, resp
    finally:
        gw.close()
    assert marker.exists(), "the clean-session gist should have reached the server"


# --------------------------------------------------- the pack's other defenses
def test_writes_fail_closed_without_an_approver(tmp_path):
    """Default posture: no approver wired -> every write is refused."""
    gw = GatewayProc(tmp_path / "audit.jsonl")          # --approvals deny
    try:
        for i, (tool, args) in enumerate([
            ("create_pull_request", {"owner": "acme", "repo": "web", "title": "x",
                                     "head": "f", "base": "main"}),
            ("create_gist", {"filename": "a.txt", "content": "b"}),
            ("push_files", {"owner": "acme", "repo": "web", "branch": "main"}),
        ]):
            resp = gw.call(tool_call(i + 1, tool, args))
            assert is_denied(resp), f"{tool} should fail closed: {resp}"
    finally:
        gw.close()


def test_destructive_tool_is_blocked_outright(tmp_path):
    """delete_file is blocked even with approvals wide open and a privileged role."""
    gw = GatewayProc(tmp_path / "audit.jsonl", approvals="allow",
                     role="release-manager")
    try:
        resp = gw.call(tool_call(1, "delete_file",
                                 {"owner": "acme", "repo": "web", "path": "prod.env"}))
        assert is_denied(resp), f"delete_file should be blocked: {resp}"
    finally:
        gw.close()

    audit = read_audit(tmp_path / "audit.jsonl")
    blocked = [e for e in audit if e["event"] == "tool_call_blocked"]
    assert any(e["tool"] == "delete_file" and e["stage"] == "action" for e in blocked)


def test_tools_list_hides_what_the_policy_would_deny(tmp_path):
    """Shrink the injection surface: tools that can only deny are invisible."""
    gw = GatewayProc(tmp_path / "audit.jsonl")          # --approvals deny
    try:
        resp = gw.call({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = {t["name"] for t in resp["result"]["tools"]}
    finally:
        gw.close()

    # Reads survive (they are redacted, not denied).
    assert {"get_me", "issue_read", "get_file_contents"} <= names
    # Destructive is always hidden; writes are hidden while no approver exists.
    assert "delete_file" not in names
    assert "create_pull_request" not in names
    assert "create_gist" not in names
