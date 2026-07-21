"""Real end-to-end demo: the gateway in front of the REAL filesystem MCP server.

Unlike run_demo.py (which talks to a mock), this launches Anthropic's actual
`@modelcontextprotocol/server-filesystem` over npx and drives real operations
against real files on disk, through the gateway, using policies.filesystem.json.

    python demo/real_filesystem_demo.py

Pair it with the live dashboard to watch decisions stream in:

    # terminal 1
    python dashboard/server.py --audit audit.log
    # terminal 2
    python demo/real_filesystem_demo.py

Requires Node/npx (for the filesystem server). The calls are paced with small
sleeps so the dashboard animates; this script plays the role Claude Desktop /
Claude Code would play in a real deployment.
"""

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BAR = "=" * 70


def main() -> None:
    sandbox = ROOT / "sandbox"
    sandbox.mkdir(exist_ok=True)
    # A real file with real PII on disk — exactly what redaction is for.
    (sandbox / "customer_notes.txt").write_text(
        "Follow-up with Ada Verne.\n"
        "Reach her at ada.verne@example.com or (415) 555-0142.\n"
        "SSN on file: 544-21-1290. Card 4111 1111 1111 1111.\n"
    )
    (sandbox / "readme.txt").write_text("Public project notes. Nothing secret.\n")

    cmd = [sys.executable, "-m", "gateway.main",
           "--policy", str(ROOT / "policies.filesystem.json"),
           "--audit", str(ROOT / "audit.log"),
           "--role", "analyst",
           "--approvals", "allow",   # a human is "present" and approves writes
           "--anomaly", "heuristic",
           "--", "npx", "-y", "@modelcontextprotocol/server-filesystem",
           str(sandbox)]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, bufsize=1, cwd=ROOT)

    def rpc(msg, expect=True):
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()
        return json.loads(proc.stdout.readline()) if expect else None

    def call(cid, name, args, note):
        reply = rpc({"jsonrpc": "2.0", "id": cid, "method": "tools/call",
                     "params": {"name": name, "arguments": args}})
        if "error" in reply:
            out = f"[BLOCKED] {reply['error']['message'][:80]}"
        else:
            text = reply["result"]["content"][0]["text"]
            out = f"[OK] {' '.join(text.split())[:80]}"
        print(f"  {name:<18} {note}\n     -> {out}")
        time.sleep(0.9)

    print(f"{BAR}\nGateway in front of the REAL filesystem MCP server\n"
          f"  sandbox: {sandbox}\n  policy:  policies.filesystem.json\n{BAR}")

    rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-03-26",
                    "clientInfo": {"name": "real-demo", "version": "0"},
                    "capabilities": {}}})
    rpc({"jsonrpc": "2.0", "method": "notifications/initialized"}, expect=False)
    time.sleep(0.6)

    call(10, "list_directory", {"path": str(sandbox)}, "(allow — metadata only)")
    call(11, "read_text_file", {"path": str(sandbox / "readme.txt")},
         "(redact — but nothing to strip)")
    call(12, "read_text_file", {"path": str(sandbox / "customer_notes.txt")},
         "(redact — real PII stripped before the model sees it)")
    call(13, "search_files", {"path": str(sandbox), "pattern": "txt"},
         "(allow — search)")
    call(14, "write_file", {"path": str(sandbox / "summary.txt"),
                            "content": "Agent-generated summary."},
         "(require_approval — human approves, real file written)")
    call(15, "edit_file", {"path": str(sandbox / "readme.txt"),
                           "edits": [{"oldText": "Public", "newText": "Updated"}]},
         "(require_approval — human approves the edit)")
    call(16, "delete_file", {"path": str(sandbox / "customer_notes.txt")},
         "(default-deny — not on the allowlist)")

    proc.stdin.close()
    proc.wait(timeout=10)

    print(f"\n{BAR}\nReal files, real server, real decisions. Every line above is "
          f"in\naudit.log — open the dashboard to see it live.\n{BAR}")


if __name__ == "__main__":
    main()
