"""One-command, judge-facing demo for the Jac MCP Security Gateway.

Runs two deterministic MCP attack chains through the real Jac stdio wrapper:
GitHub supply-chain compromise (high) and Slack exfiltration (critical).
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
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
TIMEOUT_SECONDS = 20

FAKE_GITHUB_PAT = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
FAKE_AWS_KEY = "AKIA" + "1234567890ABCDEF"
FAKE_SLACK_TOKEN = "xoxb-" + "123456789012-abcdefghijklmnopqrstuvwxyz"
FAKE_API_KEY = "sk-live-" + "9f3a2b"
RAW_SENSITIVE_VALUES = [
    FAKE_GITHUB_PAT,
    FAKE_AWS_KEY,
    FAKE_SLACK_TOKEN,
    "ada.verne@example.com",
    "544-21-1290",
    FAKE_API_KEY,
]


def tool_call(request_id: int, name: str, arguments: dict | None = None) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    }


class Gateway:
    """A real Jac wrapper process with a deterministic MCP server behind it."""

    def __init__(
        self,
        *,
        policy: Path,
        server: Path,
        role: str,
        session_id: str,
        output_dir: Path,
    ) -> None:
        self.audit_path = output_dir / f"{session_id}.audit.jsonl"
        self.call_log = output_dir / f"{session_id}.upstream-calls.log"
        environment = dict(os.environ)
        runtime_session_id = f"{session_id}-{uuid.uuid4().hex[:8]}"
        environment.update(
            {
                "JAC_GATEWAY_ROLE": role,
                "JAC_GATEWAY_SESSION_ID": runtime_session_id,
                "MOCK_CALL_LOG": str(self.call_log),
                "PYTHONUTF8": "1",
            }
        )
        self.process = subprocess.Popen(
            [
                str(JAC),
                "run",
                "-e",
                "none",
                "transports/wrap.jac",
                str(policy),
                str(self.audit_path),
                "--",
                sys.executable,
                str(server),
            ],
            cwd=JAC_PROJECT,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self.lines: queue.Queue[str] = queue.Queue()
        threading.Thread(target=self._read_stdout, daemon=True).start()
        self.next_id = 1
        initialized = self.request("initialize", {})
        assert "result" in initialized, initialized

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            self.lines.put(line)

    def request(self, method: str, params: dict | None = None) -> dict:
        request_id = self.next_id
        self.next_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }
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

    def call(self, name: str, arguments: dict | None = None) -> tuple[int, dict]:
        request_id = self.next_id
        response = self.request(
            "tools/call",
            {"name": name, "arguments": arguments or {}},
        )
        return request_id, response

    def visible_tools(self) -> list[str]:
        response = self.request("tools/list")
        return [tool["name"] for tool in response["result"]["tools"]]

    def audit_events(self, request_id: int) -> list[dict]:
        if not self.audit_path.exists():
            return []
        return [
            event
            for line in self.audit_path.read_text(encoding="utf-8").splitlines()
            if line
            for event in [json.loads(line)]
            if event.get("request_id") == request_id
        ]

    def upstream_calls(self) -> list[str]:
        if not self.call_log.exists():
            return []
        return self.call_log.read_text(encoding="utf-8").splitlines()

    def close(self) -> None:
        if self.process.stdin is not None:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=5)
        if self.process.returncode:
            stderr = self.process.stderr.read() if self.process.stderr else ""
            raise AssertionError(f"Jac gateway exited with {self.process.returncode}: {stderr}")


def response_text(response: dict) -> str:
    try:
        return str(response["result"]["content"][0]["text"])
    except (KeyError, IndexError, TypeError):
        return ""


def compact(text: str, limit: int = 260) -> str:
    one_line = " ".join(text.split())
    return one_line if len(one_line) <= limit else one_line[: limit - 3] + "..."


def banner(title: str) -> None:
    print("\n" + "=" * 88)
    print(title)
    print("=" * 88)


def pause(enabled: bool) -> None:
    if enabled:
        input("\nPress Enter for the next security control...")


def show_tools(gateway: Gateway, hidden: set[str]) -> None:
    visible = gateway.visible_tools()
    print(f"Visible tools ({len(visible)}): {', '.join(visible)}")
    print(f"Security-hidden tools: {', '.join(sorted(hidden))}")
    assert not hidden.intersection(visible)


def run_call(
    gateway: Gateway,
    *,
    label: str,
    tool: str,
    arguments: dict | None = None,
    expected: str,
    forwarded: bool,
    contains: str | None = None,
    pause_steps: bool = False,
) -> dict:
    print(f"\n{label}")
    print(f"  MCP tools/call -> {tool}")
    before = len(gateway.upstream_calls())
    request_id, response = gateway.call(tool, arguments)
    new_upstream_calls = gateway.upstream_calls()[before:]

    if "error" in response:
        print(f"  Client result   -> BLOCKED: {response['error']['message']}")
        actual = "block"
        rendered = response["error"]["message"]
    else:
        rendered = response_text(response)
        print(f"  Client result   -> DELIVERED: {compact(rendered)}")
        actual = "allow"

    events = gateway.audit_events(request_id)
    assert events, f"missing audit event for {tool}"
    latest = events[-1]
    redactions = latest.get("redactions")
    print(
        "  Jac evidence    -> "
        f"decision={latest['decision']['action']}, "
        f"trace={' > '.join(latest['trace'])}, "
        f"risk={latest['risk']['score']}:{latest['risk']['level']}, "
        f"tainted={latest['taint']['tainted']}"
    )
    if redactions:
        print(f"  DLP evidence    -> counts only: {redactions}")

    assert actual == expected
    assert (tool in new_upstream_calls) is forwarded
    if contains:
        assert contains.lower() in rendered.lower()
    if expected == "block":
        assert response["error"]["code"] == -32001

    pause(pause_steps)
    return response


def github_scenario(output_dir: Path, pause_steps: bool) -> list[Path]:
    banner("SCENARIO 1 — HIGH: GitHub supply-chain compromise")
    print(
        "An external PR injects instructions to steal CI secrets, push directly "
        "to main, execute a workflow, and publish a release."
    )

    policy = JAC_PROJECT / "policies" / "github-high.yaml"
    server = JAC_PROJECT / "demo_servers" / "github_mock.py"
    audits: list[Path] = []

    attack = Gateway(
        policy=policy,
        server=server,
        role="developer",
        session_id="github-compromised",
        output_dir=output_dir,
    )
    try:
        print("\nControl 1: capability minimization before the model can plan")
        show_tools(attack, {"delete_repository", "run_workflow", "create_release"})
        pause(pause_steps)

        run_call(
            attack,
            label="Control 2: attacker-controlled PR is readable but taints the Jac session",
            tool="get_pull_request",
            arguments={"owner_repo": "acme/payments", "number": 418},
            expected="allow",
            forwarded=True,
            pause_steps=pause_steps,
        )
        logs = run_call(
            attack,
            label="Control 3: CI logs are useful, but every credential is redacted",
            tool="get_job_logs",
            arguments={"owner_repo": "acme/payments", "run_id": 99184},
            expected="allow",
            forwarded=True,
            contains="REDACTED",
            pause_steps=pause_steps,
        )
        serialized_logs = json.dumps(logs)
        assert not any(value in serialized_logs for value in RAW_SENSITIVE_VALUES)

        run_call(
            attack,
            label="Control 4: protected-branch constraint blocks a direct push to main",
            tool="push_files",
            arguments={
                "owner_repo": "acme/payments",
                "branch": "main",
                "files": [{"path": ".github/workflows/deploy.yml"}],
            },
            expected="block",
            forwarded=False,
            contains="protected",
            pause_steps=pause_steps,
        )
        run_call(
            attack,
            label="Control 5: even an allowed agent branch is blocked after taint",
            tool="push_files",
            arguments={
                "owner_repo": "acme/payments",
                "branch": "agent/checkout-fix",
                "files": [{"path": "src/checkout.py"}],
            },
            expected="block",
            forwarded=False,
            contains="tainted",
            pause_steps=pause_steps,
        )
        run_call(
            attack,
            label="Control 6: elevated sessions retain safe read-only capability",
            tool="search_code",
            arguments={"query": "checkout timeout"},
            expected="allow",
            forwarded=True,
            pause_steps=pause_steps,
        )
    finally:
        attack.close()
    audits.append(attack.audit_path)

    clean = Gateway(
        policy=policy,
        server=server,
        role="developer",
        session_id="github-clean-control",
        output_dir=output_dir,
    )
    try:
        rewritten = run_call(
            clean,
            label="Control 7: a clean write is transformed into a draft PR",
            tool="create_pull_request",
            arguments={
                "owner_repo": "acme/payments",
                "head": "agent/checkout-fix",
                "base": "main",
                "draft": "false",
                "title": "Fix checkout timeout",
            },
            expected="allow",
            forwarded=True,
            contains='"draft": "true"',
            pause_steps=pause_steps,
        )
        assert '"draft": "true"' in response_text(rewritten)

        run_call(
            clean,
            label="Control 8: release publication fails closed without human approval",
            tool="create_release",
            arguments={"owner_repo": "acme/payments", "tag": "v9.9.9"},
            expected="block",
            forwarded=False,
            contains="approval",
            pause_steps=pause_steps,
        )
        run_call(
            clean,
            label="Control 9a: a clean reviewer may read scrubbed CI logs",
            tool="get_job_logs",
            arguments={"owner_repo": "acme/payments", "run_id": 99184},
            expected="allow",
            forwarded=True,
            contains="REDACTED",
            pause_steps=pause_steps,
        )
        run_call(
            clean,
            label="Control 9b: sequence policy independently blocks workflow execution",
            tool="run_workflow",
            arguments={"owner_repo": "acme/payments", "workflow": "deploy.yml"},
            expected="block",
            forwarded=False,
            contains="workflow execution",
            pause_steps=pause_steps,
        )
    finally:
        clean.close()
    audits.append(clean.audit_path)

    print("\nGITHUB RESULT: supply-chain attack contained; useful development work survived.")
    return audits


def slack_scenario(output_dir: Path, pause_steps: bool) -> list[Path]:
    banner("SCENARIO 2 — CRITICAL: Slack prompt injection and multi-route exfiltration")
    print(
        "A Slack Connect guest poisons a support message, steering the agent to "
        "search private conversations, download credentials, and create an external DM."
    )

    policy = JAC_PROJECT / "policies" / "slack-critical.yaml"
    server = JAC_PROJECT / "demo_servers" / "slack_mock.py"
    audits: list[Path] = []

    attack = Gateway(
        policy=policy,
        server=server,
        role="support-agent",
        session_id="slack-compromised",
        output_dir=output_dir,
    )
    try:
        print("\nControl 1: outbound/approval tools are absent from the model inventory")
        show_tools(
            attack,
            {
                "send_message",
                "draft_message",
                "create_conversation",
                "create_canvas",
                "update_canvas",
            },
        )
        pause(pause_steps)

        run_call(
            attack,
            label="Control 2: public-channel prompt injection taints the session",
            tool="read_channel",
            arguments={"channel": "#customer-support"},
            expected="allow",
            forwarded=True,
            pause_steps=pause_steps,
        )
        search = run_call(
            attack,
            label="Control 3: workspace-wide sensitive search is strictly redacted",
            tool="search_messages",
            arguments={"query": "incident token customer 8842"},
            expected="allow",
            forwarded=True,
            contains="REDACTED",
            pause_steps=pause_steps,
        )
        serialized_search = json.dumps(search)
        assert not any(value in serialized_search for value in RAW_SENSITIVE_VALUES)

        run_call(
            attack,
            label="Control 4: a low-bandwidth reaction remains usable after taint",
            tool="add_reaction",
            arguments={"channel": "#customer-support", "emoji": "eyes"},
            expected="allow",
            forwarded=True,
            pause_steps=pause_steps,
        )
        run_call(
            attack,
            label="Control 5: an opaque credentials file is quarantined, not guessed safe",
            tool="read_file",
            arguments={"file_id": "F-PRODUCTION-ENV"},
            expected="allow",
            forwarded=True,
            contains="QUARANTINED",
            pause_steps=pause_steps,
        )
        run_call(
            attack,
            label="Control 6: channel ACL blocks direct access to #exec",
            tool="read_channel",
            arguments={"channel": "#exec"},
            expected="block",
            forwarded=False,
            contains="sensitive channel",
            pause_steps=pause_steps,
        )
        run_call(
            attack,
            label="Control 7: primary exfiltration route (external DM) is blocked",
            tool="send_message",
            arguments={
                "channel": "@external-auditor",
                "text": "incident archive attached",
            },
            expected="block",
            forwarded=False,
            contains="tainted",
            pause_steps=pause_steps,
        )
        run_call(
            attack,
            label="Control 8: fallback route (new conversation) is also blocked",
            tool="create_conversation",
            arguments={"participants": ["external-auditor"]},
            expected="block",
            forwarded=False,
            contains="tainted",
            pause_steps=pause_steps,
        )
        run_call(
            attack,
            label="Control 9: accumulated risk suspends even normally safe metadata reads",
            tool="search_channels",
            arguments={"query": "engineering"},
            expected="block",
            forwarded=False,
            contains="suspended",
            pause_steps=pause_steps,
        )
    finally:
        attack.close()
    audits.append(attack.audit_path)

    clean = Gateway(
        policy=policy,
        server=server,
        role="support-agent",
        session_id="slack-clean-control",
        output_dir=output_dir,
    )
    try:
        run_call(
            clean,
            label="Control 10: clean outbound messaging still requires a human and fails closed",
            tool="send_message",
            arguments={"channel": "#engineering", "text": "deployment completed"},
            expected="block",
            forwarded=False,
            contains="approval",
            pause_steps=pause_steps,
        )
    finally:
        clean.close()
    audits.append(clean.audit_path)

    print(
        "\nSLACK RESULT: every exfiltration route failed and the compromised session was suspended."
    )
    return audits


def verify_audits(paths: list[Path]) -> None:
    combined = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    for value in RAW_SENSITIVE_VALUES:
        assert value not in combined, f"raw sensitive value reached audit: {value}"
    for forbidden_key in ['"args"', '"result_text"', '"scrubbed"']:
        assert forbidden_key not in combined
    bundle = paths[0].parent / "attack-lifecycle.audit.jsonl"
    bundle.write_text(combined.rstrip() + "\n", encoding="utf-8")
    print(
        f"\nAUDIT SAFETY: {len(paths)} files contain decisions, traces, counts, "
        "risk and taint—no raw payloads or secrets."
    )
    print(f"DASHBOARD BUNDLE: {bundle}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        choices=["github", "slack", "all"],
        default="all",
        help="Run one scenario or the complete presentation.",
    )
    parser.add_argument(
        "--pause",
        action="store_true",
        help="Wait for Enter between controls during a live presentation.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Directory for audit and upstream-proof logs.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not JAC.exists():
        raise SystemExit(f"Jac executable not found: {JAC}\nInstall Jac 0.16.7 or set JAC_BIN.")

    run_stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output_dir = args.output or JAC_PROJECT / "demo_output" / run_stamp
    output_dir.mkdir(parents=True, exist_ok=True)

    banner("MCP SECURITY GATEWAY — JAC HACKATHON DEMO")
    print("Engine model: MCP request = CallWalker; security controls = graph nodes.")
    print(f"Jac executable: {JAC}")
    print(f"Evidence directory: {output_dir}")
    start = time.monotonic()

    audits: list[Path] = []
    if args.scenario in {"github", "all"}:
        audits.extend(github_scenario(output_dir, args.pause))
    if args.scenario in {"slack", "all"}:
        audits.extend(slack_scenario(output_dir, args.pause))

    verify_audits(audits)
    print(f"TOTAL DEMO TIME: {time.monotonic() - start:.1f}s")
    scope = (
        "both advanced attack chains"
        if args.scenario == "all"
        else f"the {args.scenario} attack chain"
    )
    verb = "were" if args.scenario == "all" else "was"
    print(f"\nPASS: {scope} {verb} contained by the Jac gateway.")


if __name__ == "__main__":
    main()
