# MCP Security Gateway — project guide for Claude

A transparent security gateway (inline proxy) for MCP tool calls. It sits
between an AI agent and the MCP servers it uses, and enforces a policy on every
`tools/call`: allow, block, rewrite arguments, redact sensitive data, quarantine
a result, require human approval, or gate on session risk/taint. Think "firewall
+ DLP for AI agents."

This file is loaded automatically for anyone working in the repo. Read
`docs/PLAN.md` (phase status, "➡️ You are here" marker), then `docs/ARCHITECTURE.md`
for the design. `docs/CONTRIBUTING.md` has the collaboration workflow.

## Golden rules

- **Fail closed.** On any unexpected error on the enforcement path, deny — never
  let a call through un-inspected or release a result unscanned. The only
  exception is the *explicitly configured* `on_failure` posture (see
  `core/failure.py`). Config errors, policy denials, and unmatched tools always
  enforce regardless of posture.
- **Audit records decisions and counts, never raw payloads.** An audit event
  says "redacted 3 PII items", never the values. Don't add a field that could
  turn the log into a PII/secret sink.
- **No heavy dependencies in the core install.** FastAPI, redis, psycopg,
  cryptography, presidio, the anomaly SDK — all live behind extras
  (`[server]`, `[redis]`, `[postgres]`, `[vault]`, `[presidio]`, `[anomaly]`).
  Guard their imports and degrade gracefully when absent.
- **Least-privilege actions.** Prefer the weakest action that works:
  `allow < rewrite/redact < quarantine < require_approval < block`.
- **The engine decides; it never executes.** `policy/engine.py` computes a
  `Decision`; action handlers (`policy/actions/`) execute it.

## Commands (run from the repo root)

```bash
PYTHONPATH=src python3 -m pytest tests/ -q      # tests — keep all green, only add
python3 -m ruff check src tests                 # lint — keep clean
pip install -e '.[server,vault,redis,postgres,dev]'   # dev install with extras
```

There is no `pytest.ini`/conftest that sets the path — always prefix
`PYTHONPATH=src`. Tests that need a live Redis/Postgres/Presidio skip cleanly
when the service/extra is absent; that's expected, not a failure.

## Layout

`src/mcp_gateway/`: `core/` (pipeline, gateway, session, failure posture),
`policy/` (loader → merge → matcher → engine; `actions/`, `constraints/`),
`redaction/` (engine, `detectors/`, `operators/`, vault), `sequence/` + `risk/`
(taint + risk scoring), `approvals/`, `anomaly/`, `transports/` (stdio +
streamable_http), `audit/` (events, spool, index), `state/` (memory/redis +
sqlite/postgres index), `console/` (FastAPI ops console), `connectors/`
(the connector framework — see below). Policy packs live in top-level
`connectors/` and `policies/`; the JSON Schema is `policies/policy.schema.json`.

## Connector packs

A connector is a curated security bundle for **one** MCP server: a directory of
`manifest.yaml`, `policy.yaml` (+ optional `roles.yaml`), `tools.yaml` (risk
inventory), `policy_tests.yaml` (goldens), `README.md` (threat model). Packs are
built purely from framework + policy primitives — **authoring a pack should
require zero engine changes**; if you find yourself editing the engine to make a
pack work, stop and reconsider.

```bash
mcp-gateway connectors scaffold <name>          # new pack skeleton (default-deny, valid, self-testing)
mcp-gateway connectors list | show <name>       # discover / inspect
mcp-gateway policy test --policy connectors/<name>/policy.yaml \
                        --tests  connectors/<name>/policy_tests.yaml
mcp-gateway policy ci                           # what CI runs: every pack, discovered
mcp-gateway wrap --connector <name> [--override company.yaml] -- <server cmd>   # run it
```

A deployment customizes a pack with `--override` (a policy layer merged on top —
field-level, later wins), never by forking it.

`policy ci` (`policy/ci.py`) **discovers** packs rather than taking a list, so a
new pack is checked with no workflow or test edit. It validates every layer plus
the merged result, runs the goldens, requires every inventoried tool to have an
explicit rule, and smoke-tests the backtest replay path. `tests/unit/test_goldens.py`
runs the same `check_target`, so pytest and CI cannot drift.

## Conventions

- Module docstrings explain the *design rationale*, not just what the code does —
  match that voice.
- Every new rule/pack ships golden tests (`*.tests.yaml` / `policy_tests.yaml`).
- Branch per feature; PR to `main`; never commit to `main` directly. Keep
  `docs/PLAN.md` and the phase checkboxes current as you go.
