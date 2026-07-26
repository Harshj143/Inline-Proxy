# example connector

Security pack for the **example** MCP server.

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
mcp-gateway wrap --connector example --override my-company.yaml -- <server cmd>
```

Later layers win (field-level merge), so `my-company.yaml` can tighten or
relax individual rules while inheriting everything else.
