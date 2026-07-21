"""End-to-end demo: plays the role of the MCP client (the agent host).

Launches the gateway (which launches the mock server), then sends:
  1. initialize + tools/list          -> passthrough
  2. crm.get_customer (PII-heavy)     -> allowed, response REDACTED
  3. search.docs                      -> allowed untouched
  4. db.execute_sql                   -> BLOCKED at the gateway
  5. an unknown tool                  -> BLOCKED by default_action

Run from the project root:  python demo/run_demo.py
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BAR = "=" * 66


def main() -> None:
    proc = subprocess.Popen(
        [sys.executable, "-m", "gateway.main",
         "--policy", str(ROOT / "policies.json"),
         "--audit", str(ROOT / "audit.log"),
         "--", sys.executable, str(ROOT / "demo" / "mock_server.py")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,  # set to None to watch the live audit feed
        text=True, bufsize=1, cwd=ROOT,
    )

    def rpc(msg: dict, expect_reply: bool = True) -> dict | None:
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()
        if not expect_reply:
            return None
        return json.loads(proc.stdout.readline())

    def show(title: str, reply: dict) -> None:
        print(f"\n{BAR}\n{title}\n{BAR}")
        print(json.dumps(reply, indent=2))

    # -- handshake -----------------------------------------------------------
    show("1. initialize (passthrough)", rpc({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-03-26",
                   "clientInfo": {"name": "demo-agent", "version": "0.0.1"},
                   "capabilities": {}},
    }))
    rpc({"jsonrpc": "2.0", "method": "notifications/initialized"},
        expect_reply=False)

    show("2. tools/list (passthrough)", rpc(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))

    # -- PII redaction -------------------------------------------------------
    show("3. crm.get_customer -> ALLOWED, response PII REDACTED", rpc({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "crm.get_customer", "arguments": {"id": "8842"}},
    }))

    # -- clean allow ---------------------------------------------------------
    show("4. search.docs -> ALLOWED untouched", rpc({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "search.docs", "arguments": {"q": "rate limits"}},
    }))

    # -- argument-level constraint: read-only SQL allowed ---------------------
    show("5. db.execute_sql SELECT -> ALLOWED (satisfies read-only constraint)", rpc({
        "jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": "db.execute_sql",
                   "arguments": {"sql": "SELECT count(*) FROM orders"}},
    }))

    # -- argument-level constraint: destructive SQL blocked -------------------
    show("6. db.execute_sql DROP -> BLOCKED by argument constraint (+20 risk)", rpc({
        "jsonrpc": "2.0", "id": 6, "method": "tools/call",
        "params": {"name": "db.execute_sql",
                   "arguments": {"sql": "DROP TABLE customers"}},
    }))

    # -- escalation: repeated violations push risk score past 80 --------------
    print(f"\n{BAR}\n7. Misbehaving agent keeps probing: watch the session risk"
          f" score climb\n{BAR}")
    for i, bad_tool in enumerate(["files.read_any", "secrets.dump",
                                  "admin.create_user"], start=7):
        reply = rpc({
            "jsonrpc": "2.0", "id": i * 10, "method": "tools/call",
            "params": {"name": bad_tool, "arguments": {}},
        })
        print(f"  {bad_tool}: {reply['error']['message'][:100]}...")

    # -- suspended: even a previously ALLOWED tool is now denied --------------
    show("8. search.docs (was allowed in step 4) -> DENIED: session suspended", rpc({
        "jsonrpc": "2.0", "id": 99, "method": "tools/call",
        "params": {"name": "search.docs", "arguments": {"q": "anything"}},
    }))

    proc.stdin.close()
    proc.wait(timeout=5)

    print(f"\n{BAR}\nAudit trail (audit.log)\n{BAR}")
    for line in (ROOT / "audit.log").read_text().splitlines():
        print(line)


if __name__ == "__main__":
    main()
