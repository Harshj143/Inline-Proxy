# Build Plan — MCP Security Gateway

Greenfield rebuild. The existing `gateway/`, `dashboard/`, and `demo/` code is
the **reference prototype**: keep it runnable and untouched until Phase 3,
because its demo scenarios are the acceptance bar the new build must clear.

How to use this file: phases are strictly ordered unless marked independent.
Work top-down; check items off; each phase ends with **exit criteria** that
must pass before moving on. Sizes: S ≈ one session, M ≈ 2–3 sessions,
L ≈ 4+ sessions.

**➡️ You are here: Phases 0–1 complete (2026-07-19). Next: Phase 2 — Redaction subsystem.**

---

## Phase 0 — Repo scaffold + core proxy MVP (size: M) ✅ DONE

The skeleton everything hangs off: new src-layout package, asyncio stdio
proxy, pipeline with the minimal stages, file audit.

- [x] `pyproject.toml` (extras stubs, ruff/pyright/pytest config), `src/mcp_gateway/` layout per ARCHITECTURE §7
- [x] `core/context.py` — `CallContext`, `Principal`, `Decision` dataclasses
- [x] `protocol/` — JSON-RPC codec (`jsonrpc.py`), MCP helpers (`mcp.py`), request-id correlation, passthrough rules
- [x] `transports/stdio.py` — asyncio subprocess + stdin/stdout pumps, 16 MiB frame limit (fail-closed on overrun), blocking-I/O fallback when stdio is a regular file
- [x] `core/pipeline.py` — interceptor chain (SessionGate → Policy), first-DENY-wins, stage exceptions fail closed, per-stage timings
- [x] `audit/` — event schema (`schema_version: 1`), fan-out recorder (sink failure never fails a call), JSONL spool sink
- [x] `cli/` — `mcp-gateway wrap --policy … --audit … -- <server cmd>` + `version`; `python -m mcp_gateway` works uninstalled
- [x] Tests: 26 passing — codec, policy fail-closed goldens, pipeline order/short-circuit, e2e wrap of `demo/mock_server.py`; CI workflow (ruff + pytest)

**Exit criteria: MET.** `mcp-gateway wrap` in front of the prototype's
`demo/mock_server.py` passes run_demo scenarios 1, 4, 5 (passthrough,
explicit block, default-deny) with schema-v1 audit events written
(`tests/e2e/test_wrap_mock.py`). Phase 0 additions beyond the original list:
not-yet-implemented actions (redact/…) and rules with not-yet-supported
fields (constraints/roles/…) **fail closed** with explanatory reasons, so a
Phase 0 gateway can never silently downgrade a richer policy.

## Phase 1 — Policy engine v2 (size: M) ✅ DONE

- [x] YAML+JSON loader (`policy/loader.py`), published JSON Schema (`policies/policy.schema.json`, `$schema` autocomplete), `schema_version: 1` required
- [x] Layered merge (`policy/merge.py`): field-level override (base constraints survive an action override — fail-safe), `replace: true` escape hatch, per-role roles merge, provenance tracking + precedence tests
- [x] Matcher (`policy/matcher.py`): exact > glob (fnmatch, specificity = literal chars, later-layer tie-break) > default; role overlays with field-replace semantics precompiled per role
- [x] Actions as `ActionHandler` plugins (`policy/actions/`, one file each): allow, block, rewrite (executable), quarantine (executable end-to-end incl. response substitution), redact (fail-closed stub → Phase 2), require_approval (fail-closed stub → Phase 3); registry drives vocabulary + `terminal_deny` visibility
- [x] Constraints: `Constraint` interface + registry (`policy/constraints/`), regex builtin with must_match/must_not_match + load-time compilation; rewrites (set/append/unless_match) validated at load
- [x] `tools/list` filtering (gateway response path): tools whose action can only deny are hidden per role; `tools_list_filtered` audit event
- [x] `mcp-gateway policy validate` (per-file + merged), `policy show [--json]`, `policy test`; `wrap --policy` repeatable for layering
- [x] Golden decision harness (`policy/testing.py`, `*.tests.yaml` format — the Phase 10 CI engine); mock-crm pack goldens run in pytest

**Exit criteria: MET.** Prototype `policies.json` converted to
`policies/mock-crm.yaml` (12/12 goldens pass): rewrite + constraints +
quarantine + role overlays fully executable; redact/approval rules fail
closed pending Phases 2–3; web.fetch/http.post blocked pending taint
(Phase 3) rather than allowed without the guard. `tools/list` visibly
filtered (e2e-verified: 7 tools → 3 without a role, crm.get_customer
reappears for `--role admin`). 52 tests green.

## Phase 2 — Redaction subsystem (size: L — the flagship)

- [ ] `redaction/engine.py` — detector pipeline, span merge by confidence, operator application, report
- [ ] `detectors/regex_pii.py` — email/phone/SSN/IP/card **with validators** (Luhn, SSN area rules, octet ranges)
- [ ] `detectors/secrets.py` — AWS keys, GitHub PATs, Slack tokens, JWTs, private-key blocks, high-entropy strings
- [ ] `detectors/presidio.py` — optional extra; pool-executor execution; size cap + chunking + latency budget
- [ ] `detectors/custom.py` — company recognizers from config (employee IDs, hostnames, codenames)
- [ ] `operators/` — mask, partial-mask, deterministic HMAC hash, tokenize (vault + envelope encryption), drop
- [ ] `context.py` — allowlists/denylists, context words; `structured.py` — JSON-path targeting, key-name hints
- [ ] `profiles.py` — secrets-only / standard / strict; policy rules reference profiles
- [ ] Fail-closed wiring: detector error or over-budget on response path → quarantine result
- [ ] `tests/redaction_corpus/` — labeled corpus + **precision/recall eval harness** per entity per detector

**Exit criteria:** corpus eval reports published in CI; a GitHub PAT planted in
a mock tool result is caught end-to-end; prototype `redact.py` behavior is a
strict subset of the new engine.

## Phase 3 — Session controls + approvals + anomaly (size: M)

- [ ] `state/memory.py` store: session registry, history, taint, risk (interfaces ready for Redis)
- [ ] Sequence/taint gate stage; risk scoring with thresholds + auto-suspend; suspension broadcast via store
- [ ] Pipeline ordering per ARCHITECTURE §2: constraints → sequence/taint → **approval last**; taint marking only after gates pass
- [ ] `approvals/broker.py` (deadline, fail-closed) + console channel (HTTP callback)
- [ ] `anomaly/` — port heuristic + Claude backends; debounced (not every call); verdict → risk points
- [ ] Quarantine response path end-to-end

**Exit criteria:** prototype `attack_scenario.py` and `feature_demo.py`
scenarios pass against the new gateway (ported as e2e tests); approval asked
only for calls that pass all other gates.

## Phase 4 — Console v2 (size: M)

- [ ] FastAPI app (`[server]` extra): REST + OpenAPI — sessions, events, policy, approvals, backtest
- [ ] SQLite (WAL) index store fed from the spool; rebuildable (`mcp-gateway audit reindex`)
- [ ] SSE live feed with `Last-Event-ID` resume; approvals UI; sessions + replay; policy view
- [ ] `mcp-gateway policy backtest --audit <log>` in core CLI; console backtest panel calls the same engine
- [ ] Console authn (session cookie against local users now; OIDC later), read-only vs approver roles

**Exit criteria:** console_demo flow works browser-first (live feed, click-to-approve,
replay); `curl` against the OpenAPI spec covers every console feature.

## Phase 5 — Streamable HTTP transport + central mode (size: L)

- [ ] `transports/streamable_http.py` — MCP Streamable HTTP endpoint, `Mcp-Session-Id`, SSE streams
- [ ] Multi-upstream routing: `/servers/<name>/mcp` bound to pack + policy; per-upstream supervision/backoff
- [ ] `state/redis.py` + `state/postgres.py` (index); config switches memory/sqlite ↔ redis/postgres
- [ ] `mcp-gateway serve --config gateway.yaml`; Dockerfile + docker-compose (gateway + console + redis + postgres)
- [ ] Load test: sustained 100 calls/sec, p99 added latency < 50 ms on regex path

**Exit criteria:** Claude Code connects to `http://gateway/servers/filesystem/mcp`
and is policed identically to sidecar mode; two replicas share taint/risk via Redis.

## Phase 6 — Connector framework + GitHub pack (size: L)

- [ ] `connectors/base.py` + registry + `mcp-gateway add <name>`; override file mechanism
- [ ] GitHub pack per ARCHITECTURE §4: full `tools.yaml` inventory (risk-classified), `policy.yaml`
      (reads redacted, CI logs quarantined, writes approval-gated, destructive blocked, default-deny)
- [ ] Taint model: issue/PR bodies + comments = sources; push/PR/comment/gist = sinks
- [ ] `constraints.py`: org allowlist, protected branches; rewrites: draft PRs, search caps
- [ ] `detectors.py`: PAT patterns, Actions-log secrets; `roles.yaml`: developer/reviewer/release-manager/bot
- [ ] `policy_tests.yaml` goldens for every rule; pack README with threat model
- [ ] E2E demo: poisoned-issue → attempted exfil PR, blocked; recorded as acceptance test

**Exit criteria:** real `github-mcp-server` policed end-to-end; the pack is the
documented template for all future connectors.

## Phase 7 — Jira pack (size: M) · Phase 8 — Slack pack (size: M)

- [ ] Jira: JQL constraint plugin (project allowlist, forbid unbounded sweeps), `maxResults` rewrite,
      customer-PII redaction profile, JSM content = taint source, roles support-agent/project-admin/bot, goldens
- [ ] Slack: channel-ACL constraints (block `#exec`, `#hr-*` reads), history redaction (PII+secrets),
      post = approval to external/shared channels, `rate_limit` action (new ActionHandler), taint private-read → post, goldens

**Exit criteria (each):** real server policed e2e; pack authored purely with
framework primitives — zero engine changes (that's the pluggability proof).

## Phases 9–11 are independent of each other; 9 before 11 is recommended (principal-level audit enriches SIEM events).

## Phase 9 — Identity: OIDC (size: M)

- [ ] `identity/oidc.py` — JWT validation, JWKS fetch/cache/rotation, fail-closed expiry policy
- [ ] `identity/mapping.py` — IdP groups → roles (`identity.yaml`); Okta + Auth0 documented setups
- [ ] `identity/apikey.py` for headless agents; `principal` on every audit event; console OIDC login

**Exit criteria:** live Okta dev tenant: two users in different groups get
different policy treatment on the same tool; revoked token fails closed.

## Phase 10 — Policy CI/CD (size: S–M)

- [ ] `policy test` (golden harness from Phase 1, CLI-first), `validate`, `backtest` — CI-friendly output
- [ ] GitHub Action: PR → validate + test + backtest, **diff posted as PR comment**
- [ ] Merge → versioned bundle (content hash + signature); gateway verifies, atomically swaps, keeps last-known-good

**Exit criteria:** a policy PR in a demo repo shows the blast-radius comment;
a tampered bundle is rejected with an audit event.

## Phase 11 — Audit sinks: SIEM (size: M)

- [ ] Spool-reader sink framework (at-least-once, batch, backoff, watermark alarm)
- [ ] `sinks/s3.py` — gzip batches, `dt=/hour=` partitioned keys; `sinks/splunk.py` — HEC + retry; `sinks/webhook.py`
- [ ] `audit/ocsf.py` — OCSF (and ECS) mapping; Splunk dashboard example in docs

**Exit criteria:** SIEM outage test — sink down for an hour, zero loss, zero
hot-path stalls, spool drains on recovery.

## Phase 12 — DX & release polish (size: M)

- [ ] Quickstarts: `pipx install` sidecar in <5 min; `docker compose up` central demo
- [ ] Docs site (mkdocs-material): concepts, per-connector threat models, policy reference from JSON Schema
- [ ] Prometheus metrics + `/healthz` `/readyz`; SBOM per release; versioning policy; delete the prototype

---

## Dependency graph

```
0 → 1 → 2 → 3 → 4 → 5 → 6 → 7/8 (parallel)
                    5 → 9, 10, 11 (independent; 9 before 11 recommended) → 12
```

Phases 1–3 give a sidecar strictly better than the prototype. Phase 5 unlocks
enterprise. Phase 6 sets the connector template that makes 7/8 fast.
