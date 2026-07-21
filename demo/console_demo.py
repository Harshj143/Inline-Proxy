"""Interactive console demo: the browser becomes the human-in-the-loop.

Start the console first, then run this. It launches the gateway with
`--approvals http` in front of the REAL filesystem MCP server and drives a
realistic session. When it hits a `write_file` / `edit_file`, the gateway
BLOCKS and the call appears in the console with Approve / Deny buttons — the
script waits for your click before continuing.

    # terminal 1
    python dashboard/server.py --audit audit.log        # http://localhost:8000
    # terminal 2
    python demo/console_demo.py

Requires Node/npx. This plays the role Claude Desktop / Claude Code would play.
"""

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONSOLE = "http://localhost:8000"


def main() -> None:
    sandbox = ROOT / "sandbox"
    sandbox.mkdir(exist_ok=True)
    (sandbox / "customer_notes.txt").write_text(
        "Ada Verne — ada.verne@example.com, (415) 555-0142, SSN 544-21-1290.\n")
    (sandbox / "readme.txt").write_text("Public notes.\n")

    cmd = [sys.executable, "-m", "gateway.main",
           "--policy", str(ROOT / "policies.filesystem.json"),
           "--audit", str(ROOT / "audit.log"),
           "--role", "analyst",
           "--approvals", "http", "--approvals-url", CONSOLE,
           "--anomaly", "heuristic",
           "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", str(sandbox)]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, bufsize=1, cwd=ROOT)

    def rpc(msg, expect=True):
        proc.stdin.write(json.dumps(msg) + "\n"); proc.stdin.flush()
        return json.loads(proc.stdout.readline()) if expect else None

    def call(cid, name, args, note):
        print(f"\n→ {name}  {note}")
        reply = rpc({"jsonrpc": "2.0", "id": cid, "method": "tools/call",
                     "params": {"name": name, "arguments": args}})
        if "error" in reply:
            print(f"  BLOCKED: {reply['error']['message'][:90]}")
        else:
            print(f"  OK: {' '.join(reply['result']['content'][0]['text'].split())[:80]}")

    print("Open " + CONSOLE + " and watch. Approvals need YOUR click.\n")
    rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-03-26",
                    "clientInfo": {"name": "console-demo", "version": "0"},
                    "capabilities": {}}})
    rpc({"jsonrpc": "2.0", "method": "notifications/initialized"}, expect=False)
    time.sleep(0.6)

    call(10, "list_directory", {"path": str(sandbox)}, "(allow)")
    call(11, "read_text_file", {"path": str(sandbox / "customer_notes.txt")},
         "(redact — PII stripped)")
    print("\n… next call needs approval — click Approve or Deny in the console …")
    call(12, "write_file", {"path": str(sandbox / "summary.txt"),
                            "content": "Agent summary."}, "(require_approval — WAITING FOR YOU)")
    print("\n… one more approval …")
    call(13, "edit_file", {"path": str(sandbox / "readme.txt"),
                           "edits": [{"oldText": "Public", "newText": "Updated"}]},
         "(require_approval — WAITING FOR YOU)")
    call(14, "delete_file", {"path": str(sandbox / "readme.txt")}, "(default-deny)")

    proc.stdin.close(); proc.wait(timeout=10)
    print("\nDone — see the full trace and this run under 'Sessions' in the console.")


if __name__ == "__main__":
    main()
