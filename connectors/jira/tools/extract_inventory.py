"""Maintenance tool: re-extract the Jira MCP tool inventory from upstream source.

`tools.yaml` must list EVERY Jira tool the server exposes — a hand-maintained
list drifts, and a missed tool is an unreviewed capability. This script derives
the inventory from the upstream Python source (`sooperset/mcp-atlassian`) instead,
so an upgrade is a mechanical re-run plus a human risk review of whatever is new.

The upstream registers each Jira tool with an `@jira_mcp.tool(...)` decorator
whose tag set carries `"read"` or `"write"` and a `"toolset:jira_<area>"` tag,
and mounts the sub-server under the `jira` namespace (`main.py`:
`main_mcp.mount(jira_mcp, namespace="jira")`), so the wire tool name is
`jira_<function name>`. We read the decorator's balanced-paren body (descriptions
contain nested parens, so a naive regex mis-pairs the tag with the wrong
function), then the following `async def`, then the first line of its docstring.

Usage (from a checkout of the upstream server at the commit in manifest.yaml):

    git clone --depth 1 https://github.com/sooperset/mcp-atlassian.git /tmp/atl
    python3 connectors/jira/tools/extract_inventory.py /tmp/atl /tmp/jira.json

It prints a per-toolset summary (name, read/write) and writes raw JSON. Then:
classify any new tool, add its rule to policy.yaml, extend policy_tests.yaml, and
bump `tested_versions` in manifest.yaml.
`tests/unit/test_jira_pack.py::test_inventory_is_the_full_surface` guards the
count, so a surface change fails CI until the pack is re-reviewed.
"""

import json
import re
import sys
from pathlib import Path

DECORATOR = "@jira_mcp.tool("


def _balanced(text: str, start: int) -> tuple[str, int]:
    """Return the substring inside the parens opened just before `start`, and
    the index just past the closing paren."""
    depth = 1
    i = start
    while i < len(text) and depth:
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        i += 1
    return text[start:i - 1], i


def _first_docstring_line(body: str) -> str:
    m = re.search(r'"""(.*?)(?:\n|""")', body, re.S)
    if not m:
        return ""
    return " ".join(m.group(1).strip().split())[:160]


def extract(src_root: Path) -> list[dict]:
    jira_py = src_root / "src" / "mcp_atlassian" / "servers" / "jira.py"
    text = jira_py.read_text(encoding="utf-8")
    tools = []
    i = 0
    while True:
        k = text.find(DECORATOR, i)
        if k < 0:
            break
        deco, after = _balanced(text, k + len(DECORATOR))
        m = re.search(r"async def (\w+)\s*\(", text[after:after + 600])
        if not m:
            i = after
            continue
        func = m.group(1)
        # function body up to the next decorator or EOF, for the docstring
        nxt = text.find(DECORATOR, after)
        body = text[after:nxt if nxt > 0 else len(text)]
        rw = "write" if re.search(r'["\']write["\']', deco) else (
            "read" if re.search(r'["\']read["\']', deco) else "?")
        ts = re.search(r"toolset:(\w+)", deco)
        name_override = re.search(r'name\s*=\s*["\'](\w+)["\']', deco)
        wire = "jira_" + (name_override.group(1) if name_override else func)
        tools.append({
            "name": wire,
            "readwrite": rw,
            "toolset": ts.group(1) if ts else "?",
            "description": _first_docstring_line(body),
        })
        i = after
    return tools


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: extract_inventory.py <mcp-atlassian checkout> [out.json]")
    tools = extract(Path(sys.argv[1]))
    reads = sum(t["readwrite"] == "read" for t in tools)
    writes = sum(t["readwrite"] == "write" for t in tools)
    print(f"{len(tools)} Jira tools: {reads} read, {writes} write")
    by_ts: dict[str, int] = {}
    for t in tools:
        by_ts[t["toolset"]] = by_ts.get(t["toolset"], 0) + 1
    for ts, n in sorted(by_ts.items()):
        print(f"  {ts:26} {n}")
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(json.dumps(tools, indent=2))
        print(f"wrote {sys.argv[2]}")


if __name__ == "__main__":
    main()
