"""Maintenance tool: re-extract the Slack MCP tool inventory from upstream source.

`tools.yaml` must list EVERY tool the server exposes — a hand-maintained list
drifts, and a missed tool is an unreviewed capability. This derives the inventory
from the upstream Go source (`korotovsky/slack-mcp-server`) instead, so an
upgrade is a mechanical re-run plus a human risk review of whatever is new.

The upstream declares the tool names as `Tool<Name> = "wire_name"` constants in
`pkg/server/server.go` and registers each with
`s.AddTool(mcp.NewTool(Tool<Name>, mcp.WithDescription("..."), ...))`. We read
the constant table, then each `NewTool(...)` body (balanced parens — descriptions
contain nested parens) for the description. Four write tools are gated behind
env vars (`SLACK_MCP_ADD_MESSAGE_TOOL`, `SLACK_MCP_REACTION_TOOL`,
`SLACK_MCP_ATTACHMENT_TOOL`) upstream — they are still inventoried here, because
the gateway must have a rule ready for the moment an operator enables them.

Usage (from a checkout of the upstream server at the commit in manifest.yaml):

    git clone --depth 1 https://github.com/korotovsky/slack-mcp-server.git /tmp/slack
    python3 connectors/slack/tools/extract_inventory.py /tmp/slack /tmp/slack.json

It prints the tool list and writes raw JSON. Then: classify any new tool, add its
rule to policy.yaml, extend policy_tests.yaml, and bump `tested_versions` in
manifest.yaml. `tests/unit/test_slack_pack.py::test_inventory_is_the_full_surface`
guards the count, so a surface change fails CI until the pack is re-reviewed.
"""

import json
import re
import sys
from pathlib import Path


def _balanced(text: str, start: int) -> str:
    depth = 1
    i = start
    while i < len(text) and depth:
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        i += 1
    return text[start:i - 1]


def extract(src_root: Path) -> list[dict]:
    server_go = (src_root / "pkg" / "server" / "server.go").read_text(encoding="utf-8")
    consts = dict(re.findall(r'(Tool\w+)\s*=\s*"([a-z0-9_]+)"', server_go))
    tools: list[dict] = []
    seen: set[str] = set()
    for m in re.finditer(r"mcp\.NewTool\(", server_go):
        body = _balanced(server_go, m.end())
        cm = re.match(r"\s*(Tool\w+)", body)
        if not cm or cm.group(1) not in consts:
            continue
        name = consts[cm.group(1)]
        if name in seen:
            continue
        seen.add(name)
        desc = re.search(r'WithDescription\(\s*"((?:[^"\\]|\\.)*)"', body)
        tools.append({
            "name": name,
            "description": (desc.group(1) if desc else "").replace("\\n", " ").strip()[:160],
        })
    return tools


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: extract_inventory.py <slack-mcp-server checkout> [out.json]")
    tools = extract(Path(sys.argv[1]))
    print(f"{len(tools)} Slack tools")
    for t in tools:
        print(f"  {t['name']}")
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(json.dumps(tools, indent=2))
        print(f"wrote {sys.argv[2]}")


if __name__ == "__main__":
    main()
