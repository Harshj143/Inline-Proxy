# AGENTS.md — MCP Security Gateway

Orientation for an AI coding agent (Codex, Claude, etc.) working in this repo.
Read this first; it is the fastest path to understanding the whole project.
Companion docs: `docs/ARCHITECTURE.md` (design), `docs/PLAN.md` (phase-by-phase
status with a "➡️ You are here" marker), `docs/SYSTEM_DESIGN.md` (deep rationale),
`docs/CONTRIBUTING.md` (workflow + how to author a connector pack).

---

## 1. What this project is

A transparent **security gateway (inline proxy) for MCP tool calls** — a
firewall + DLP for AI agents. It sits between an AI agent (Claude Desktop/Code,
a custom agent) and the MCP servers that agent uses, and enforces a policy on
every `tools/call`. The agent thinks it is talking directly to the tool; it is
actually talking to the gateway, which forwards the call to the real server
**only if policy allows**, and can transform the request or the response on the
way through. Every decision is audited.

**The problem it solves:** once an AI agent can call real tools (GitHub, a
database, Slack, internal APIs), nothing watches what it actually does — it can
read a customer's SSN and paste it into an outbound request, run a destructive
command, or be tricked by a prompt injection into exfiltrating data. This
gateway is the enforcement layer that stops that.

**Per `tools/call`, the policy can:**

| Action | Meaning | Example |
|---|---|---|
| `allow` | pass through | public docs search |
| `block` | refuse | a destructive tool that's off-limits |
| `rewrite` | fix arguments | append `LIMIT 1000` to an unbounded SQL query |
| `redact` | scrub the result/args | strip PII/secrets from a record before the model sees it |
| `quarantine` | run upstream but withhold the result | raw CI logs that may contain secrets |
| `require_approval` | pause for a human | deleting a user; a write to GitHub |

On top of static rules there are **session-state controls**: taint/sequence
tracking (reading untrusted content taints a session; exfil sinks are then
blocked), risk scoring with auto-suspend, and a behavioral anomaly monitor.

**Two deployment modes, one binary, same policy engine:**
- **Sidecar** (`mcp-gateway wrap … -- <server cmd>`): a stdio proxy in front of
  one server. Zero infra, the 5-minute path.
- **Central** (`mcp-gateway serve --config gateway.yaml`): a long-lived HTTP
  service (MCP Streamable HTTP) fronting many servers at `/servers/<name>/mcp`,
  with stateless replicas sharing taint/risk via Redis and an audit index in
  Postgres.

---

## 2. Core mental model — the enforcement pipeline

Every `tools/call` flows through an interceptor chain (`core/pipeline.py`). Stage
order (see `docs/ARCHITECTURE.md` §2):

```
session_gate → policy match → constraints → sequence/taint → action
```

Response path: correlate → result control (quarantine/redact) → risk → anomaly → deliver.

Two invariants that explain most of the code:

- **The engine decides; it never executes.** `policy/engine.py` computes a
  `Decision` (a data object). Action *handlers* in `policy/actions/` execute it.
  Keep that separation.
- **Fail closed.** Any unexpected error on the enforcement path denies — never
  let a call through un-inspected or release a result unscanned. The one
  exception is the *explicitly configured* `on_failure` posture
  (`core/failure.py`). Policy denials, config errors, and unmatched tools always
  enforce regardless of posture.

One `CallContext` travels the chain (principal, session, message, decision,
redaction report, timings) — the single source of truth per call.

---

## 3. Golden rules (do not violate)

1. **Fail closed** on the enforcement path (see above).
2. **Audit records decisions and COUNTS, never raw payloads.** An event says
   "redacted 3 PII items", never the values. Never add a field that could turn
   the audit log into a PII/secret sink. (`audit/events.py`, `report.py`.)
3. **No heavy dependencies in the core install.** FastAPI, redis, psycopg,
   cryptography, presidio, the anomaly SDK all live behind extras. Guard their
   imports and degrade gracefully when absent.
4. **Least-privilege actions.** Prefer the weakest action that works:
   `allow < rewrite/redact < quarantine < require_approval < block`.
5. **Authoring a connector pack requires ZERO engine changes.** If a pack seems
   to need an engine change, stop and reconsider — that's a design discussion.

---

## 4. Repo layout

```
src/mcp_gateway/
  core/         pipeline, gateway, session, context (CallContext/Decision), failure posture, errors
  protocol/     JSON-RPC codec, MCP helpers, id correlation, tools/list filtering
  policy/       loader → merge → matcher → engine; actions/ (one file per action), constraints/
  redaction/    engine, detectors/ (regex_pii, secrets, presidio, custom), operators/ (mask/hash/tokenize/drop), vault, profiles, structured, eval
  sequence/     taint sources/sinks + sequence rules
  risk/         weighted risk scoring + auto-suspend thresholds
  approvals/    ApprovalBroker + channels/ (deny/allow/http)
  anomaly/      heuristic + Claude (Haiku) backends, debounced monitor
  transports/   stdio.py, streamable_http.py, upstream.py
  central/      config.py — `serve --config gateway.yaml` multi-upstream assembly
  audit/        events, recorder, spool (JSONL source of truth), reader, index (SQLite)
  state/        memory.py / redis.py (sessions); sqlite via audit/index, postgres.py (index)
  console/      FastAPI Security Ops Console: REST+OpenAPI, SSE feed, approvals, static SPA
  connectors/   the connector FRAMEWORK: base.py, registry.py, scaffold.py
  cli/          the `mcp-gateway` entrypoint (all subcommands)

connectors/     shipped packs (DATA, not code): example/, github/, jira/, slack/
policies/       mock-crm.yaml (+ .tests.yaml), policy.schema.json (JSON Schema)
tests/          unit/, e2e/ (wrap real/mock servers), redaction_corpus/ (precision-recall eval)
docs/           ARCHITECTURE, SYSTEM_DESIGN, PLAN, CONTRIBUTING, HANDOFF-*
```

---

## 5. How to build, test, run

Python **3.12+**. There is no conftest that sets the path — always prefix
`PYTHONPATH=src`.

```bash
pip install -e '.[server,vault,redis,postgres,dev]'   # dev install with extras
PYTHONPATH=src python3 -m pytest tests/ -q             # ~574 pass, a few skip cleanly
python3 -m ruff check src tests                        # lint — keep clean
```

Skips are expected: tests needing a live Redis/Postgres/Presidio skip when the
service/extra is absent — that is not a failure.

**CLI** (`mcp-gateway <cmd>`):

```bash
wrap        --connector github [--override company.yaml] -- <server cmd>   # sidecar
serve       --config gateway.yaml                                          # central HTTP mode
console serve --users users.yaml --audit audit.log                        # ops console
policy      validate | show | test --policy P --tests T                    # policy tooling
policy      backtest --audit LOG --policy P                                # traffic replay (needs an audit log)
policy      ci [--only NAME] [--github]                                    # discover + check every pack (the CI gate)
policy      diff --base DIR --head DIR [--markdown]                        # blast radius of a policy change (no audit log)
policy      keygen --out signing                                          # Ed25519 keypair for signed bundles
policy      bundle build|verify|show|install|rollback|current             # versioned signed policy bundles
connectors  list | show <name> | scaffold <name>                          # connector packs
wrap        --bundle B.mcgb.json --public-key K.pub.pem -- <server cmd>    # run a verified signed bundle
redact / detokenize / audit reindex / version
```

Note `wrap` needs **either** `--connector NAME` or `--policy FILE`.

---

## 6. Policy packs and connectors

A **policy** is a layered YAML document (`policies/policy.schema.json`):
`schema_version: 1`, `default_action` (usually `block` = default-deny), a `tools:`
map of rules, plus `taint_sources`/`taint_sinks`/`sequence_rules`/`risk`/
`roles`/`on_failure`. Layers merge field-level, later wins — so a company
customizes with an `--override` file instead of forking.

A **connector** is a curated security bundle for ONE MCP server: a directory
under `connectors/<name>/` with `manifest.yaml`, `policy.yaml` (+ optional
`roles.yaml`), `tools.yaml` (risk inventory), `policy_tests.yaml` (goldens),
`README.md` (threat model). The framework (`src/mcp_gateway/connectors/`) resolves
a connector to ordered policy layers and layers overrides on top — no engine
changes needed to add a pack. Scaffold a new one with
`mcp-gateway connectors scaffold <name>`.

Shipped packs — all default-deny over the FULL source-verified tool surface,
each with a committed `tools/extract_inventory.py` (extract from upstream source,
guard the count in a test, so a version bump that adds a tool fails CI until
re-reviewed):
- **github** — all 109 tools of github-mcp-server v1.7.0; reads→redact,
  CI-logs/secret-scanning→quarantine, writes→approval, destructive→block; taint
  model + developer/reviewer/release-manager/bot roles; e2e poisoned issue →
  attempted exfil gist → blocked.
- **jira** — all 63 `jira_*` tools of sooperset/mcp-atlassian; reads→redact,
  attachments→quarantine, writes→approval, `jira_delete_issue`→block; taint model
  (issues + JSM customer requests as sources, `create_remote_issue_link` etc. as
  the exfil sinks) + support-agent/project-admin/bot roles.
- **slack** — all 22 tools of korotovsky/slack-mcp-server. Deliberately NOT
  Slack's first-party `mcp.slack.com`: that server publishes no `tools/call`
  identifiers, so a verifiable complete default-deny policy is impossible against
  it — the open-source server is source-extractable, which is what full coverage
  requires. Message reads→redact:strict, attachments→quarantine, writes→approval,
  no destructive tool exists; taint read→send + support-agent/workspace-admin/bot.

---

## 7. Conventions

- **Module docstrings explain the design RATIONALE**, not just what the code
  does. Match that voice when adding modules.
- **Every new rule/pack ships golden tests** (`*.tests.yaml` /
  `policy_tests.yaml`). `tests/unit/test_goldens.py` **discovers** packs (Phase
  10a), so a new pack is checked automatically — no wiring needed beyond an
  optional `MIN_GOLDENS` ratchet entry. `mcp-gateway policy ci` runs the same
  `check_target` locally.
- Branch per feature; PR to `main`; never commit to `main` directly. Keep
  `docs/PLAN.md` checkboxes current.

---

## 8. Gotchas (things that will bite you)

- **Pack goldens must load BOTH layers.** Run a pack's tests with
  `[policy.yaml, roles.yaml]` (as `Connector.policy_layers()` does at runtime).
  Loading only `policy.yaml` makes every role case fail closed on the base
  `require_approval`. See `test_goldens.py`.
- **`require_approval` fails closed without a broker.** In a bare `policy test`
  (no broker wired) an approval rule evaluates to deny — goldens should expect
  that (`action: require_approval`, outcome deny), not `allow`.
- The **console app and streamable-HTTP transport deliberately omit
  `from __future__ import annotations`** — FastAPI misreads stringized route
  annotations. They live behind the `[server]` extra; keep it that way.
- **`redact` needs a `RedactionService`; approvals need a broker** — the gateway
  wires these in `cli`. The pure engine only reports the action.
- Test fixtures contain **deliberately fake secrets** (AWS's own
  `AKIAIOSFODNN7EXAMPLE`, sequential fake PATs) to prove redaction works.
  `.gitguardian.yaml` documents them; do not "fix" them by weakening the fixtures.

---

## 9. Status (see docs/PLAN.md for the authoritative, dated checklist)

Done: **Phase 0** (core proxy) · **1** (policy engine v2) · **2** (redaction
subsystem: validated PII + secrets + optional Presidio NER + encrypted
tokenization vault + custom recognizers) · **3** (session controls: taint/
sequence, risk auto-suspend, approvals broker, anomaly monitor) · **4** (Console
v2) · **5** (Streamable HTTP + central mode + Redis/Postgres) · **6a** (connector
framework) · **6b** (GitHub pack) · **7** (Jira pack) · **8** (Slack pack) ·
**9** (OIDC identity: `identity/` — JWT/JWKS + API keys → `Principal`,
per-request auth on the HTTP transport, fail-closed) · **10** (Policy CI/CD:
`policy ci` discover-and-check, `policy diff` blast-radius PR comment,
Ed25519-signed policy bundles).

Remaining: **11** (SIEM audit sinks: S3/Splunk/webhook, OCSF mapping) ·
**12** (DX & release polish: quickstarts, mkdocs site, Prometheus/healthz, SBOM).

When you finish work, update `docs/PLAN.md` (checkboxes + the "You are here"
marker) and add/extend golden tests.
