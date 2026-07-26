"""Generate a new connector skeleton.

`mcp-gateway connectors scaffold <name>` writes a complete, *valid* connector
directory the author then fills in: it loads, passes `policy validate`, and its
one golden test passes out of the box. That gives a connector author (or two
working in parallel on different packs) a working, default-deny starting point
instead of a blank directory — the fastest safe path from "add a server" to "a
policed server".

The templates are the single source of truth for the layout; the committed
`connectors/example/` pack is generated from them, so the reference and the
generator never drift.
"""

from __future__ import annotations

from pathlib import Path

from mcp_gateway.core.errors import ConnectorError

_MANIFEST = """\
# Connector manifest — what this pack protects and how to launch it.
# See docs/CONTRIBUTING.md for the authoring guide.
name: {name}
description: "Security pack for the {name} MCP server"
upstream:
  server: {name}-mcp-server
  # The package or binary that starts the real MCP server (fill in):
  package: ""
  # Upstream versions this pack was validated against (fill in):
  tested_versions: []
# Template command the gateway launches in sidecar mode, e.g.
#   ["npx", "-y", "@modelcontextprotocol/server-{name}"]
launch: []
"""

_POLICY = """\
# yaml-language-server: $schema=../../policies/policy.schema.json
#
# Default security policy for the {name} connector.
#
# DEFAULT-DENY: a tool is blocked unless a rule below permits it. Start from the
# tool inventory in tools.yaml, classify each tool, and add rules that use the
# least-powerful action that still works: allow < rewrite/redact < quarantine <
# require_approval < block. See README.md for the threat model.
schema_version: 1
name: {name}
default_action: block

# Untrusted content that could carry an injected instruction should taint the
# session; mutating/outbound tools become sinks blocked once tainted. Fill in:
# taint_sources: []
# taint_sinks: []
# sequence_rules: []

tools:
  # Replace this example with the real tools (see tools.yaml for the inventory).
  {name}.ping:
    action: allow
    reason: harmless liveness check, exposes no sensitive data
"""

_TOOLS = """\
# Tool inventory for the {name} MCP server, risk-classified.
#
# Informational: this documents and reviews the attack surface; policy.yaml is
# what enforces. Every tool the server exposes should appear here with a risk:
#   read | write | destructive | secret_adjacent
tools:
  {name}.ping:
    risk: read
    description: liveness check
"""

_TESTS = """\
# Golden decision tests for the {name} connector.
# Run: mcp-gateway policy test \\
#        --policy connectors/{name}/policy.yaml \\
#        --tests connectors/{name}/policy_tests.yaml
tests:
  - name: ping is allowed
    tool: {name}.ping
    expect:
      outcome: allow
      action: allow

  - name: unknown tool meets default deny
    tool: {name}.unknown_tool
    expect:
      outcome: deny
      action: block
      reason_contains: default policy
"""

_README = """\
# {name} connector

Security pack for the **{name}** MCP server.

## Threat model

_Describe what an attacker could do through this server and what this pack
prevents. For each capability class:_

- **Reads** — what sensitive data can be read, and how it is redacted.
- **Writes** — what can be mutated, and which writes require approval.
- **Destructive** — what is blocked outright.
- **Taint** — which inputs are untrusted sources, which tools are sinks.

## Rules

_Explain every rule in `policy.yaml` and why it uses the action it does._

## Overriding without forking

A deployment customizes this pack by layering its own file on top — no fork:

```bash
mcp-gateway wrap --connector {name} --override my-company.yaml -- <server cmd>
```

Later layers win (field-level merge), so `my-company.yaml` can tighten or
relax individual rules while inheriting everything else.
"""

_FILES = {
    "manifest.yaml": _MANIFEST,
    "policy.yaml": _POLICY,
    "tools.yaml": _TOOLS,
    "policy_tests.yaml": _TESTS,
    "README.md": _README,
}


def scaffold_connector(name: str, dest_dir: str | Path, *, force: bool = False) -> Path:
    """Write a new connector skeleton named `name` under `dest_dir`.

    Returns the created connector directory. Refuses to overwrite an existing
    non-empty directory unless `force` is set — a pack under active authoring
    must never be clobbered by a stray scaffold.
    """
    if not name.isidentifier() and not all(
        part.isidentifier() for part in name.split("-")
    ):
        raise ConnectorError(
            f"connector name {name!r} must be a simple identifier "
            f"(letters, digits, underscores, hyphens)"
        )
    target = Path(dest_dir) / name
    if target.exists() and any(target.iterdir()) and not force:
        raise ConnectorError(
            f"{target} already exists and is not empty (pass force to overwrite)"
        )
    target.mkdir(parents=True, exist_ok=True)
    for filename, template in _FILES.items():
        (target / filename).write_text(template.format(name=name), encoding="utf-8")
    return target
