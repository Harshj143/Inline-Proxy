# MCP Security Gateway

**A firewall + DLP for AI agents.** It sits between an agent (Claude Desktop/Code,
a custom agent) and the MCP servers it uses, and enforces a policy on every
`tools/call` — the agent thinks it is talking to the tool, but it is talking to
the gateway, which forwards the call to the real server **only if policy allows**
and can transform the request or the response on the way through. Every decision
is audited.

Once an AI agent can call real tools (GitHub, a database, Slack, internal APIs),
nothing watches what it actually does — it can read a customer's SSN and paste it
into an outbound request, run a destructive command, or be tricked by a prompt
injection into exfiltrating data. This is the enforcement layer that stops that.
No changes to the agent, no changes to the server: point the client at the gateway.

```
agent / MCP client  ──►  GATEWAY  ──►  real MCP server
                          │  policy · redaction · taint · audit
                          ▼
                    audit.log ──►  SIEM (S3 / Splunk / webhook)
```

## What the policy can do, per call

| Action | Meaning |
|---|---|
| `allow` | pass through |
| `block` | refuse (default-deny for anything unmatched) |
| `rewrite` | fix arguments (append `LIMIT 1000` to an unbounded query) |
| `redact` | scrub PII/secrets from the result or arguments before the model sees them |
| `quarantine` | run upstream but withhold the result (raw logs that may hold secrets) |
| `require_approval` | pause for a human |

On top of static rules: **taint/sequence tracking** (reading untrusted content
taints a session; exfil sinks are then blocked — breaks the "lethal trifecta"
without having to detect the injection), **risk scoring with auto-suspend**, a
behavioral **anomaly monitor** (Claude Haiku or a local heuristic), and a
validated **redaction engine** (regex PII + secret detectors + optional Presidio
NER + an encrypted tokenization vault).

## Quick start (Python 3.12+)

```bash
pip install -e '.[server,vault]'      # from a checkout; extras are opt-in
```

### Sidecar — police one server over stdio (the 5-minute path)

```bash
# Front the GitHub MCP server with the shipped, default-deny GitHub pack:
mcp-gateway wrap --connector github -- \
  docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN ghcr.io/github/github-mcp-server
```

The agent points at `mcp-gateway` instead of the server. Reads are redacted,
writes need approval, destructive tools are blocked, and a poisoned issue that
tries to exfiltrate via a gist is stopped at the taint gate. Use `--policy
your.yaml` instead of `--connector` to run your own policy.

### Central — one HTTP service in front of many servers

```bash
mcp-gateway serve --config gateway.example.yaml        # MCP Streamable HTTP
# each upstream at /servers/<name>/mcp, policed by its own pack;
# /healthz /readyz /metrics for your orchestrator and Prometheus.
docker compose up                                       # gateway + console + redis + postgres
```

## What's included

- **Connector packs** (`connectors/`) — curated, default-deny security bundles
  covering the *entire* tool surface of a server, extracted from upstream source:
  **GitHub** (109 tools), **Jira** (63), **Slack** (22). Each ships a threat model,
  role matrix, taint model, and golden tests. Author your own with
  `mcp-gateway connectors scaffold`.
- **Redaction** — validated PII + secret detection with precision/recall gated in
  CI, five operators (mask/partial/hash/tokenize/drop), a reversible encrypted
  vault, and optional NER.
- **Policy CI/CD** — `mcp-gateway policy ci` validates and golden-tests every pack
  by discovery; `policy diff` posts a blast-radius comment on a PR; merges produce
  **Ed25519-signed policy bundles** the gateway verifies, atomically swaps, and
  keeps a last-known-good of.
- **Identity** — OIDC (JWT/JWKS, Okta/Auth0) and API keys resolve a caller to a
  `Principal`; IdP groups map to policy roles. Per-request, fail-closed.
- **SIEM audit sinks** — `mcp-gateway audit forward` tails the audit spool to S3,
  Splunk HEC, or a webhook (OCSF/ECS mapping), at-least-once with a watermark. It
  reads the spool, never the hot path, so a down SIEM never stalls a tool call.
- **Ops console** — a FastAPI web UI: live decision feed (SSE), click-to-approve,
  session replay, policy view, and a policy backtester.
- **Observability** — Prometheus `/metrics`, `/healthz` (liveness), `/readyz`
  (readiness), a container stack, and a load-test harness.

## Design invariants

- **Fail closed.** Any unexpected error on the enforcement path denies — a call is
  never let through un-inspected, a result never released unscanned. The only
  exception is an *explicitly configured* fail-open posture.
- **The engine decides; it never executes.** `policy/engine.py` computes a
  `Decision`; action handlers execute it.
- **Audit records decisions and counts, never raw payloads** — "redacted 3 PII
  items", never the values.
- **No heavy dependencies in the core install** — FastAPI, redis, cryptography,
  presidio, the anomaly SDK all live behind extras.

## Documentation

- **[AGENTS.md](AGENTS.md)** — the fastest orientation (read this first).
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — the enforcement pipeline and design.
- **[docs/PLAN.md](docs/PLAN.md)** — phase-by-phase status.
- **[docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)** — workflow + authoring a connector pack.
- **[sinks.example.md](sinks.example.md)** — forwarding the audit trail to a SIEM.

## Development

```bash
PYTHONPATH=src python3 -m pytest tests/ -q      # tests
python3 -m ruff check src tests                 # lint
```

There is no conftest that sets the path — always prefix `PYTHONPATH=src`. Tests
that need a live Redis/Postgres/Presidio skip cleanly when absent.

## License

MIT.
