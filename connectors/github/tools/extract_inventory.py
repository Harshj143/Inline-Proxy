"""Maintenance tool: re-extract the GitHub MCP tool inventory from upstream source.

`tools.yaml` must list EVERY tool the server exposes — a hand-maintained list
drifts, and a missed tool is an unreviewed capability. This script derives the
inventory from the upstream Go source instead, so an upgrade is a mechanical
re-run plus a human risk review of whatever is new.

Usage (from a checkout of the upstream server at the tag in manifest.yaml):

    git clone --depth 1 --branch v1.7.0 \\
        https://github.com/github/github-mcp-server.git /tmp/gh-mcp
    python3 connectors/github/tools/extract_inventory.py /tmp/gh-mcp /tmp/tools.json

It prints a per-toolset summary (name, read-only vs write, destructive) and
writes the raw JSON. Then: classify any new tool, add its rule to policy.yaml,
extend policy_tests.yaml, and bump `tested_versions` in manifest.yaml.
`tests/unit/test_github_pack.py::test_inventory_is_the_full_surface` guards the
count, so a surface change fails CI until the pack is re-reviewed.

Parsed pattern:
    NewTool( ToolsetMetadataXxx, mcp.Tool{
        Name: "...", Description: t("KEY", "default" | `raw`),
        Annotations: &mcp.ToolAnnotations{ ReadOnlyHint: bool, DestructiveHint: bool },
    } ... )

Note: two label tools live in labels.go under ToolsetMetadataIssues but are
declared via a helper the regex cannot attribute — they surface as toolset "?"
and are corrected when tools.yaml is generated. MCP *resources* (ui_resources.go)
are intentionally not tools and are excluded.
"""
import json
import re
import sys
from pathlib import Path

src = Path(sys.argv[1]) / "pkg" / "github"
tools = {}

for go in sorted(src.glob("*.go")):
    if go.name.endswith("_test.go"):
        continue
    text = go.read_text()
    # Find each NewTool( and read its balanced-paren body.
    for m in re.finditer(r"NewTool\(", text):
        i = m.end()
        depth = 1
        j = i
        while j < len(text) and depth:
            c = text[j]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            j += 1
        body = text[i:j]
        # toolset = first identifier argument
        ts = re.search(r"\bToolsetMetadata(\w+)", body)
        name = re.search(r'Name:\s*"([a-z0-9_]+)"', body)
        if not name:
            continue
        # Description default string: either "..." or a Go `raw` string.
        dq = re.search(r'Description:\s*t\(\s*"[^"]*"\s*,\s*"((?:[^"\\]|\\.)*)"', body)
        bt = re.search(r'Description:\s*t\(\s*"[^"]*"\s*,\s*`([^`]*)`', body)
        raw = (dq.group(1) if dq else (bt.group(1) if bt else "")).replace('\\"', '"')
        # Terse one-liner for the inventory: first non-empty line.
        desc = next((ln.strip() for ln in raw.splitlines() if ln.strip()), "")
        ro = re.search(r"ReadOnlyHint:\s*(true|false)", body)
        de = re.search(r"DestructiveHint:\s*(true|false)", body)
        tools[name.group(1)] = {
            "toolset": ts.group(1).lower() if ts else "?",
            "read_only": (ro.group(1) == "true") if ro else None,
            "destructive": (de.group(1) == "true") if de else None,
            "description": desc,
            "file": go.name,
        }

# Group by toolset
by_ts = {}
for name, meta in sorted(tools.items()):
    by_ts.setdefault(meta["toolset"], []).append((name, meta))

print(f"TOTAL TOOLS: {len(tools)}\n")
for ts in sorted(by_ts):
    rows = by_ts[ts]
    print(f"== {ts} ({len(rows)}) ==")
    for name, meta in rows:
        ro = "RO" if meta["read_only"] else ("WRITE" if meta["read_only"] is False else "?")
        de = " DESTRUCTIVE" if meta["destructive"] else ""
        print(f"  {name:<38} {ro}{de}")
    print()

Path(sys.argv[2]).write_text(json.dumps(tools, indent=2))
print(f"\nwrote {sys.argv[2]}")
