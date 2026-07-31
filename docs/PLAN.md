# Build Plan — MCP Security Gateway

Greenfield rebuild. The existing `gateway/`, `dashboard/`, and `demo/` code is
the **reference prototype**: keep it runnable and untouched until Phase 3,
because its demo scenarios are the acceptance bar the new build must clear.

How to use this file: phases are strictly ordered unless marked independent.
Work top-down; check items off; each phase ends with **exit criteria** that
must pass before moving on. Sizes: S ≈ one session, M ≈ 2–3 sessions,
L ≈ 4+ sessions.

**➡️ You are here: Phases 0–6 COMPLETE. Connector packs: GitHub (6b), Slack (8,
retargeted to korotovsky/slack-mcp-server), Jira (7) — all full-surface,
source-verified, default-deny. Phase 9 (OIDC identity) COMPLETE 2026-07-28 and
Phase 10 (Policy CI/CD) COMPLETE 2026-07-27 (10a discover-and-check, 10b
blast-radius comment, 10c signed bundles). Remaining: 11 (SIEM audit sinks),
12 (DX & release polish).**

**Cross-cutting: configurable fail-open/closed posture ✅ DONE (2026-07-19).**
Customer-owned risk choice via `on_failure` in the policy document (global
`open`/`closed`, or per-category `pipeline`/`redaction`/`approval`; default
closed). Governs UNEXPECTED runtime errors ONLY — never policy denials, config
errors, or unmatched tools (those always enforce). `core/failure.py`
`FailurePosture`; pipeline tags stage crashes `internal_error`; gateway
forwards-on-crash / releases-unscanned only when opted in, and every fail-open
event is loudly audited (`fail_open_enabled` at startup + stderr banner,
`stage_error_fail_open`, `redaction_error_fail_open`); approval broker gains
`fail_open` (unreachable approver approves). Set via a tiny layered override
pack. 14 tests (`test_failure.py`, `test_gateway_failure.py`).

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

Split into 2a (standalone engine, DONE), 2b (policy + gateway wiring), 2c
(Presidio tier, tokenization vault, expanded corpus).

### Phase 2a — Engine core ✅ DONE (2026-07-19)

- [x] `redaction/engine.py` — detector pipeline, span merge by confidence (`spans.resolve_overlaps`), right-to-left operator application, report
- [x] `detectors/regex_pii.py` — email/phone/SSN/IP/card **with validators** (`validators.py`: Luhn, SSN area/group/serial rules, IPv4 octet ranges). Fixed a real bug: card regex was capturing a trailing separator
- [x] `detectors/secrets.py` — AWS keys, GitHub PATs (ghp_/github_pat_), Slack tokens, JWTs, private-key blocks, high-entropy heuristic (Shannon, low-confidence, de-duped against provider hits, disable-able)
- [x] `operators/` — mask, partial-mask (keep last 4, falls back to full mask for short values), deterministic keyed HMAC hash (correlation without exposure), drop
- [x] `entities.py` (registry, PII/SECRET categories), `report.py` (**counts only, never raw values** — audit must not become a PII sink)
- [x] `profiles.py` — secrets-only / standard / strict (strict auto-uses Presidio if present); `build_engine(profile)`
- [x] `tests/redaction_corpus/` — labeled corpus (positives + look-alike negatives) + **precision/recall eval harness** with CI thresholds; currently **precision 1.000 / recall 1.000**
- [x] 34 redaction tests; 86 total green; ruff clean

Deferred to 2b/2c (not cut — sequenced): `detectors/presidio.py`,
`detectors/custom.py`, tokenize operator + vault + envelope encryption,
`context.py` (denylists/context words), `structured.py` (JSON-path/key-name
targeting), detector `DetectionContext.allowlist` is in but the richer context
signals are 2b.

### Phase 2b — Wire redaction into policy + gateway ✅ DONE (2026-07-19)

- [x] `redact` action executable (`RedactHandler(service)`, `terminal_deny` False when a service is present): scrubs ARGUMENTS outbound (DLP) + marks disposition "redact". The no-service stub still fails closed
- [x] Gateway response path (`_deliver_redacted`): result run through the engine before delivery; `tool_result_redacted` audit with counts-only
- [x] Fail-closed wiring: detector error / missing service on the response path → withhold the result (`tool_result_redaction_failed`, never release unscanned); error results delivered as-is
- [x] Policy `redaction:` field (string or object form) selects profile + targeting per tool/role; loader validates profile names against the registry; `RedactionSpec` compiled onto the Decision; JSON Schema updated
- [x] `redaction/structured.py` — token-based key-name hints (catches `password`/`aws_secret_access_key`, spares `token_count`/`authorized_users`) + `exclude_keys`; `redaction/spec.py`; denylist/allowlist literals via `DetectionContext`
- [x] `mcp-gateway redact` CLI (text + `--json` structural + `--eval` corpus metrics); corpus/eval moved into the package (`redaction/eval.py`) so it ships
- [x] Design: threaded redaction explicitly (pipeline `build_action_handlers`, per-gateway visibility `denying` set) instead of mutating the global registry — no cross-test/cross-gateway leakage
- [x] e2e: planted GitHub PAT + AWS key + PII in a real tool result scrubbed end-to-end (`test_wrap_redaction.py`), audit proven to hold no raw values; mock-crm redaction goldens flipped fail-closed → real (12/12); 106 tests green

Deferred to 2c (not cut): context-word confidence boosting (natural with
Presidio); over-budget size caps (arrive with the Presidio latency budget).

### Phase 2c-i — Tokenization vault + custom recognizers + budget ✅ DONE (2026-07-19)

- [x] `redaction/vault.py` — `TokenVault` interface; `InMemoryVault` (stdlib, keyed BLAKE2, non-persistent); `EncryptedSqliteVault` (envelope encryption: KEK wraps a per-vault DEK, values AES-GCM at rest, deterministic HMAC token ids, persistent across restarts). `cryptography` as `[vault]` extra
- [x] `operators/tokenize.py` — reversible redaction via a vault (deterministic tokens → correlation without exposure); registered operator
- [x] `redaction/profiles.py` — `reversible` profile (PII tokenized, secrets still one-way hashed); `build_engine` gains operator-override + extra-detector params; `RedactionService` owns one shared vault + exposes `detokenize`
- [x] `detectors/custom.py` — config-driven company recognizers (entity + regex + confidence), auto-register CUSTOM entities; wired via service + `--recognizers` file
- [x] Engine size budget (`max_bytes` → `RedactionBudgetExceeded`); gateway already catches → withholds (fail closed)
- [x] `mcp-gateway detokenize --vault … TOKEN` (audited, principal-attributed); `wrap --vault/--recognizers`; verified cross-process reverse through the encrypted vault
- [x] 17 new tests (vault round-trip/persistence/wrong-KEK/at-rest-encryption, tokenize, custom, budget); 123 total green, ruff clean

### Phase 2c-ii — Presidio tier + span-level eval ✅ DONE (2026-07-19)

- [x] `detectors/presidio.py` — optional `[presidio]` extra; NER for PERSON/LOCATION/NRP only (regex tier owns the structured entities); analyzer lazy-loaded + process-cached (cheap construction); thread-locked (spaCy not thread-safe); whitespace chunking for large text; **graceful degrade** when extra/model absent (auto-joins `strict`, verified both ways); Presidio types mapped to our entity names, never leaked
- [x] Gateway offloads redaction to a worker thread (`asyncio.to_thread`) so NER never stalls the event loop
- [x] Context-word confidence boosting: `DetectionContext.context_words` + engine boost before threshold; wired through `RedactionSpec`/loader/schema (`redaction.context_words`)
- [x] `engine.detect_spans()` exposes positioned resolved spans; span-labeled corpus + `evaluate_spans` (overlap match, distinguishes PERSON from LOCATION); CI publishes a redaction-metrics artifact
- [x] 12 new tests (Presidio present+absent, context boost, span eval); 135 total green, ruff clean. Span eval strict = 1.000/1.000 incl. PERSON/LOCATION with Presidio installed

**Phase 2 COMPLETE.** All exit criteria met: corpus eval in CI (2a),
planted-PAT caught end-to-end (2b), prototype `redact.py` a strict subset
(regex+validators supersede it). The redaction subsystem now spans validated
regex PII, secrets, optional NER, custom recognizers, five operators
(mask/partial/hash/tokenize/drop), an encrypted reversible vault, profiles,
structured + context targeting, and span-level accuracy measurement.

## Phase 3 — Session controls + approvals + anomaly (size: M)

### Phase 3a — Session state + risk + taint/sequence gate ✅ DONE (2026-07-19)

- [x] `state/` — `SessionStore` interface + `MemorySessionStore` (Redis-ready seam); `Session` extended with taint + risk fields
- [x] `risk/scoring.py` — `RiskEngine`, weighted events, NORMAL/ELEVATED/SUSPENDED thresholds, auto-suspend on transition; policy-configurable (`risk:` block)
- [x] `sequence/policy.py` — taint sources/sinks + sequence rules (glob-aware); `SequenceGateStage` between constraints and action
- [x] Pipeline order per ARCHITECTURE §2: session_gate → policy → constraints → **sequence** → action; taint marked only AFTER a call passes every gate; `StageOutcome.risk_event` scores denials
- [x] Gateway: builds risk+sequence from policy, records risk on denials (session_gate denial adds none — no double-punishment), `session_tainted`/`session_suspended` audit, heavy-redaction scoring on the response path
- [x] Policy loader/merge/schema: `taint_sources`/`taint_sinks` (union across layers), `sequence_rules` (concat), `risk` (last-wins); mock-crm.yaml restored web.fetch/http.post to allow (now safe under taint)
- [x] e2e `test_wrap_attack.py`: poisoned-fetch → taint → PII read redacted → exfil POST **blocked** (taint + sequence); clean session still POSTs; repeated violations auto-suspend. 159 tests green, ruff clean

### Phase 3b-i — Approvals broker ✅ DONE (2026-07-19)

- [x] `approvals/` — `ApprovalBroker` (deadline + fail-closed wrapper), channels `DenyChannel`/`AllowChannel`/`HttpChannel` (stdlib urllib in a worker thread; POSTs to `{url}/api/approvals`, the console contract for Phase 4), `build_broker(mode, url)`
- [x] `require_approval` executable (`RequireApprovalHandler(broker)`): on approve → dispatches the `then` action's REAL handler (redact scrubs, etc.), on deny → blocks + approval_denied risk; recursion-guarded; fail-closed with no broker
- [x] Approval is the last action-stage step (only reached after session/policy/constraints/sequence pass); `can_approve` capability → deny-mode tools stay hidden, allow/http tools become visible
- [x] Visibility refactor: `RequestPipeline.denying_actions()` derives from the ACTUAL wired handlers (no ad-hoc registry subtraction); `approval_requested` audit event; CLI `--approvals deny|allow|http` + `--approvals-url`
- [x] e2e `test_wrap_approval.py`: denied fail-closed (hidden + refused) and approved (visible + reaches server via then:allow); 172 tests green, ruff clean

### Phase 3b-ii — Anomaly detector ✅ DONE (2026-07-19)

- [x] `anomaly/` — `AnomalyBackend` interface + `SessionTrace`/`Verdict`; `HeuristicBackend` (read-then-exfil, recon sprawl); `ClaudeBackend` (Haiku, `output_config` JSON schema, `[anomaly]` extra, graceful degrade → `available` False without SDK/key); `AnomalyMonitor` (debounced sampling, `force=True` on blocks) + `build_monitor` (claude → heuristic fallback with stderr note)
- [x] Gateway `_run_anomaly` after every call (force on denials); verdict → `anomaly_{low,medium,high}` risk points → can auto-suspend; runs in a worker thread (Claude); `anomaly_detected` audit event with rationale + backend
- [x] CLI `--anomaly off|heuristic|claude` + `--anomaly-debounce N`; `anomaly_backend` on gateway_start
- [x] e2e `test_wrap_anomaly.py`: statically-allowed read-then-exfil flagged (medium) and scored into risk though NO static rule fired; benign session not flagged. 201 tests green, ruff clean

**Phase 3 COMPLETE.** All exit criteria met: attack_scenario passes (3a),
approvals denied-then-approved (3b-i), anomaly flags read-then-exfil (3b-ii),
approval asked only after every other gate passes. The gateway is now adaptive:
static policy + argument constraints + taint/sequence + risk auto-suspend +
human approvals + behavioral monitoring, all feeding one risk score.

## Phase 4 — Console v2 (size: M)

Split rationale: 4a is pure stdlib (sqlite3) and fully unit-testable with no
server dependency, so it lands first and the whole console reads from it. 4b
adds the FastAPI app (`[server]` extra) over that index. 4c is the browser UI.
Each sub-phase is finished + verified (tests green, ruff clean, PLAN updated)
before the next starts.

### Phase 4a — Audit index + backtest (no server dep) ✅ DONE (2026-07-23)

- [x] `audit/reader.py` — tolerant JSONL spool reader (skips a torn final line, bad lines counted not fatal; byte offset per record = `Last-Event-ID`)
- [x] `audit/index.py` — SQLite (WAL) index store fed from the spool: `events` table (PK = spool byte offset), derived `sessions` roll-up, `meta` watermark; incremental catch-up (idempotent) + full rebuild
- [x] `mcp-gateway audit reindex --audit <log> --index <db> [--incremental]` — rebuild/catch up the index from the spool
- [x] Query layer (`AuditIndex.query_events`, `list_sessions`, `session_detail`, `approval_history`, `counts_by_event`) — the REST surface reads through this (live *pending* approvals are held in the 4b server, not the audit index)
- [x] `policy/backtest.py` — replay recorded tool calls through a (possibly new) policy, diff the action decisions vs what was recorded (blast-radius); tool+role granularity (audit is counts-only, so no argument-level constraint replay); collapses identical calls, flags the block stage for honesty
- [x] `mcp-gateway policy backtest --audit <log> --policy <new> [--json]` in the core CLI
- [x] Tests: reader torn-line tolerance, index build/rebuild/incremental, query layer, backtest diff (20 new; 217 total green, ruff clean)

### Phase 4b — FastAPI app (`[server]` extra) ✅ DONE (2026-07-23)

- [x] `console/app.py` — FastAPI app factory (`create_app`); REST + OpenAPI over the index: sessions, session detail (with replay events), events (filter + cursor), stats, policy, backtest. Index refreshed on demand per request (catch-up from spool watermark)
- [x] SSE live feed (`/api/stream`) tailing the spool; `Last-Event-ID` resume (query or header) as an *exclusive* offset cursor; `once=true` mode for deterministic testing
- [x] Approvals endpoint implementing the `channels/http.py` contract: gateway POSTs `ApprovalRequest.to_wire()` to `/api/approvals`, BLOCKS until a human decides (`console/approvals.py` live `ApprovalQueue` of asyncio futures, fail-closed on timeout); `{approved, approver, note}` response. `GET /api/approvals/pending` + `POST /api/approvals/{id}/resolve` for the UI
- [x] Cookie-session authn against local users (`console/auth.py`): PBKDF2 password hashes, HMAC-signed session cookie with expiry, `viewer` vs `approver` roles; resolve requires `approver`; optional shared token guards the gateway-facing approvals POST
- [x] `mcp-gateway console serve` CLI + `console hash-password` helper (in the `[server]` extra; lazy import with a clear error when absent). fastapi/uvicorn already declared in extras; httpx added as a test dep
- [x] Tests: TestClient over REST + OpenAPI, SSE resume (query + header, exclusive), approvals round-trip + blocking (httpx ASGI single-loop) + timeout, authn/role gating (31 new: auth 8, queue 4, api 18 + module skips without the extra). 248 passed / 4 skipped, ruff clean

### Phase 4c — Browser console UI ✅ DONE (2026-07-23)

- [x] Static SPA (vanilla JS/CSS, no framework — served by FastAPI from `console/static/`, packaged via `package-data`): live feed (`EventSource`, native Last-Event-ID resume), click-to-approve, session list + replay, policy view, backtest panel with blast-radius chips
- [x] Login page (cookie session); approver-only approve controls (server-enforced too); `create_app(static_dir=...)` can disable the UI for an API-only deployment
- [x] e2e (`tests/e2e/test_console_approval.py`): the REAL gateway `ApprovalBroker` + `HttpChannel` block against a uvicorn-served console and are resolved through the approver API (+ fail-closed on timeout). Manually verified: `curl` login → sessions → session replay → SSE `once` → OpenAPI (13 paths) all green against a live `console serve`

**Exit criteria: MET.** Browser-first flow works (SPA live feed via SSE,
click-to-approve through the real HttpChannel contract, session replay);
`curl`/urllib against the OpenAPI spec covers every console feature. 253 tests
green (52 new across 4a/4b/4c), ruff clean.

**Phase 4 COMPLETE (2026-07-23).** REST + OpenAPI console over a rebuildable
SQLite audit index, SSE live feed with resume, human approvals implementing the
gateway's HTTP contract, cookie authn with viewer/approver roles, policy view,
and a policy backtester (CLI + panel) sharing one engine.

## Phase 5 — Streamable HTTP transport + central mode (size: L) ✅ DONE (2026-07-23)

Split into 5a–5d; work strictly in order, finish + verify each before the next.

### Phase 5a — Streamable HTTP transport, single upstream ✅ DONE (2026-07-23)

- [x] `transports/upstream.py` — `SubprocessUpstream` + `Upstream` protocol: launch + pump an upstream MCP subprocess (16 MiB frame limit, fail-closed on overrun, grace-then-kill shutdown), factored so the HTTP transport reuses it and tests inject an in-process fake
- [x] `transports/streamable_http.py` — per-`Mcp-Session-Id` session = its own `SecurityGateway` + upstream, acting as the gateway's `Transport` (`send_client` resolves the pending POST future or enqueues to the session's SSE channel; `send_upstream` writes to the upstream). `create_streamable_http_app(...)` FastAPI app: `POST /mcp` (initialize → mint session id; request → policed, awaits correlated response as JSON, gateway-deadline → JSON-RPC error; notification → 202), `GET /mcp` (SSE server→client channel), `DELETE /mcp` (terminate)
- [x] Per-session audit recorder over a shared spool via `_NonClosingSink` (no cross-session `session_id` bleed; shared spool closed once at app shutdown); fail-closed on unknown/missing session id (404/400)
- [x] Tests: in-process ASGI via httpx ASGITransport with a fake upstream — initialize handshake + session id, allowed call reaches upstream, blocked call returns the policy-denied error (never reaches upstream), tools/list filtered, unknown session 404, missing session 400, notification 202, DELETE terminates, session isolation, gateway timeout (10 new; 263 total green, ruff clean)

### Phase 5b — Multi-upstream routing + `mcp-gateway serve --config` ✅ DONE (2026-07-23)

- [x] `create_central_app(hubs)` — `/servers/<name>/mcp` routing, each name bound to its own `StreamableHttpGateway` (policy pack + session registry); per-endpoint isolation (a session id belongs to one upstream); `GET /servers` lists them; unknown upstream → 404 (`-32004`). Shared POST/GET/DELETE handlers factored so single- and multi-upstream apps differ only in routing
- [x] `central/config.py` — `GatewayConfig` + `load_gateway_config` (YAML/JSON, fail-closed validation: non-empty upstreams, unique names, command/policy shape, supported state backend) + `build_central_app(config, upstream_factory=…)` (each upstream → engine + RedactionService + deny-broker, shared spool; upstream factory injectable for tests). `gateway.example.yaml` added
- [x] `mcp-gateway serve --config gateway.yaml [--host --port]` (in the `[server]` extra; lazy import, clear error without it)
- [x] Tests: 14 new — config load/defaults/JSON/validation (parametrized fail-closed cases), multi-upstream routing polices each by its own policy, cross-upstream session isolation, unknown upstream, config→app assembly with injected fakes. Verified live: `serve` in front of `demo/mock_server.py` — session handshake, policy-filtered `tools/list`, and **PII-redacted** `crm.get_customer` result (central polices identically to sidecar; audit holds counts only). 277 total green, ruff clean

### Phase 5c — Redis / Postgres state (honor the SessionStore seam)

- [x] **5c-i Redis session store** ✅ (2026-07-23): `Session.to_dict/from_dict` (durable state; `pending` excluded — belongs to the forwarding replica); `SessionStore.save()` (no-op default; the gateway calls it after each message); `state/redis.py` `RedisSessionStore` (sync redis client, `[redis]` extra, TTL, fail-closed on corrupt blob); gateway gains a `session_id` param so its id == the client's `Mcp-Session-Id` (also fixes audit correlation) and can bind an existing id to resume shared state; `central/config.py` `backend: redis` (+ `state.url`) wires ONE shared store into every session's gateway. Tests (fakeredis): dict round-trip, two replicas share taint/suspension/risk (store-level + through the real gateway), corrupt-blob/TTL/unknown-id. `fakeredis` in the `[dev]` extra.
- [x] **5c-ii Postgres audit-index store** ✅ (2026-07-23): `state/postgres.py` `PostgresAuditIndex` mirroring `audit/index.py`'s full query surface over Postgres (`%s` placeholders, `ON CONFLICT` upsert, `event_offset` column since `offset` is reserved), `[postgres]` extra (`psycopg[binary]`, guarded import). Row-shaping/roll-up factored into pure helpers (`event_columns`, `rollup_values`, `hydrate`, `session_row`) — 7 unit tests run in the sandbox; the DB round-trip test is skip-guarded on `$TEST_PG_DSN` (absent here → skips cleanly)

### Phase 5d — Dockerfile + compose + load test ✅ DONE (2026-07-23)

- [x] `Dockerfile` (python:3.12-slim, `[server,vault,redis,postgres]` extras, non-root, entrypoint = `mcp-gateway` CLI) + `docker-compose.yml` (gateway + console + redis + postgres, shared `audit-data` volume, healthchecks) + `deploy/gateway.docker.yaml` (redis-backed) + `deploy/users.example.yaml`. Authored + statically validated (compose parses; the docker config loads through `load_gateway_config`); docker itself is not runnable in the sandbox
- [x] `scripts/loadtest.py` — regex-path added-latency harness (policy match + regex constraint, no-op transport) with `--calls`/`--assert-p99-ms`; `tests/unit/test_loadtest.py` sandbox smoke. **Measured: ~24k calls/sec, p99 ≈ 0.1 ms** — far under the 100 calls/sec, p99 < 50 ms target

**Exit criteria: MET.** (1) An MCP client connects to `/servers/<name>/mcp` and is
policed identically to sidecar mode — verified live against `demo/mock_server.py`
(filtered `tools/list`, PII-redacted result, counts-only audit) in 5b. (2) Two
replicas share taint/risk via Redis — verified in 5c-i (shared store, through the
real gateway). Regex-path latency target beaten by ~500× in 5d.

**Phase 5 COMPLETE (2026-07-23).** Central mode: MCP Streamable HTTP transport,
multi-upstream routing bound to per-pack policy, `mcp-gateway serve --config`,
Redis-shared session state across replicas, a Postgres audit-index option, and a
container stack — the gateway now runs as an enterprise service, not only a sidecar.

## Phase 6 — Connector framework + GitHub pack (size: L) ✅ DONE

Split so the framework lands first and unblocks parallel pack authoring
(GitHub + Slack can then proceed independently — see Phase 8).

### Phase 6a — Connector framework ✅ DONE (2026-07-25)

- [x] `connectors/base.py` — `Connector` (validated directory bundle → ordered
      policy layers), `load_connector` fail-closed on missing manifest/policy or
      name≠dir; `ConnectorError`
- [x] `connectors/registry.py` — discovery across search paths ($MCPG_CONNECTORS_DIR
      → user dir → bundled `connectors/`), first-match precedence, tolerant `list`
      vs precise-error `find`
- [x] `connectors/scaffold.py` + `mcp-gateway connectors scaffold` — generates a
      complete default-deny skeleton that loads, validates, and passes its goldens;
      `connectors/example/` committed as the reference (generated from the templates)
- [x] CLI: `connectors list | show | scaffold`; `wrap --connector NAME` with
      `--override FILE` layering (customize a pack without forking) — reuses the
      Phase 1 layered merge; either `--connector` or `--policy` required
- [x] 18 tests (load/validate, registry precedence, scaffold, override layering,
      CLI); `CLAUDE.md` + `docs/CONTRIBUTING.md` (collaboration + authoring guide)

Deferred (scoped, not cut): per-connector Python plugins (`constraints.py` /
`detectors.py` dynamic import) — a trust decision of its own; packs use the
builtin registered constraints/detectors for now. Bundling packs into the
installed wheel is a Phase 12 packaging task.

### Phase 6b — GitHub pack (size: M) — parallelizable

- [x] **Complete inventory (2026-07-25):** all **109 tools** of `github-mcp-server`
      **v1.7.0**, extracted from upstream source (`pkg/github/*.go`) rather than
      hand-listed — `connectors/github/tools/extract_inventory.py` is committed so an
      upgrade is a mechanical re-run + risk review. Risk split: 49 read / 50 write /
      8 secret-adjacent / 2 destructive. MCP *resources* (ui_resources.go) correctly
      excluded as non-tools
- [x] `policy.yaml`: default-deny with an explicit rule for **every** tool — reads
      `redact:standard`; security findings `redact:strict`; raw-secret reads
      (`get_job_logs`, secret-scanning) `quarantine`; all 50 writes
      `require_approval` (fail-closed with no approver); 2 destructive `block`
- [x] Taint model: 14 sources (issue/PR/discussion/gist/file/code-search reads),
      4 sinks (`create_gist`/`update_gist`/`push_files`/`create_or_update_file`) +
      2 sequence rules (CI-logs/secret-alerts → gist)
- [x] `roles.yaml`: developer (default) / reviewer (comment+review allowed, merge
      still gated) / release-manager (merge+push+CI) / bot (writes BLOCKED — no
      approver exists). No role escalates a destructive action (test-enforced)
- [x] `policy_tests.yaml` — 23 goldens across every risk class + role; README with
      the full threat model (why GitHub is its own exfil channel), per-toolset table,
      override recipe, upgrade procedure
- [x] `tests/unit/test_github_pack.py` — 11 tests incl. **every tool has an explicit
      rule** (no silent default-deny), action⇄risk agreement, bot/destructive
      invariants, inventory-count guard. 342 passed / 5 skipped, ruff clean
- [x] **E2E acceptance test (2026-07-25):** `tests/e2e/test_wrap_github_attack.py` —
      poisoned issue read (tainted) → `.env` read (secrets scrubbed) → CI logs
      (quarantined) → exfil gist **BLOCKED** at the sequence stage → push **BLOCKED**;
      a containment marker proves no sink ever reached the upstream, and the audit
      spool is asserted to hold no raw secrets. Run with `--approvals allow` on
      purpose: the pack's approval gate would have blocked the gist anyway, so
      auto-approving isolates taint as the control actually doing the work, and
      `test_clean_session_may_gist` is the paired control. Plus writes-fail-closed,
      destructive-blocked-for-every-role, and `tools/list` filtering
- [ ] `constraints.py`: org allowlist, protected branches; rewrites: draft PRs, search caps

**Security fix found by the e2e (2026-07-25).** The `.env` read leaked an AWS
**secret** access key through the DEFAULT `standard` profile. Two compounding
causes: `AWS_SECRET_ACCESS_KEY` was a *registered entity no detector ever emitted*,
and the high-entropy safety net (confidence 0.55) sits below `standard`'s
`min_confidence` 0.6 — so it only ever fired in `strict`. Fixed in
`detectors/secrets.py`: label-anchored `AWS_SECRET_ACCESS_KEY` pattern (0.95 — shape
alone would flag every base64 hash), a text-mode **labeled-secret** pass reusing
`structured.py`'s key vocabulary (closes the documented Phase-2b gap where dict-key
awareness can't apply to JSON-in-text results — catches `DB_PASSWORD=hunter2`), and
the entropy candidate no longer swallows a `LABEL=` prefix into the span. Corpus
precision/recall unchanged at 1.000/1.000 in both profiles; 12 regression tests.

Deferred within 6b (needs the framework's per-connector plugin loading, itself
deferred in 6a): pack-local `constraints.py` / `detectors.py` (org allowlist,
protected-branch checks, PAT + Actions-log detectors). The gateway's builtin
regex constraints and the redaction engine's GitHub-PAT/secret detectors already
cover the critical paths; the pack-local plugins are refinement, not a gap in
enforcement.

**Exit criteria:** real `github-mcp-server` policed end-to-end; the pack is the
documented template for all future connectors.

## Phase 7 — Jira pack ✅ DONE (2026-07-27) · Phase 8 — Slack pack ✅ DONE (retargeted 2026-07-27)

**Both packs cover the ENTIRE, source-verified tool surface** of their upstream —
the same rigor as the GitHub pack (extract from source, guard the count in a
test, default-deny with an explicit rule per tool). The deciding constraint: a
complete default-deny policy needs verifiable `tools/call` identifiers, which
only a **source-extractable** server can give — so both target open-source
servers, and each ships a committed `tools/extract_inventory.py` so an upstream
bump is a mechanical re-run + a risk review.

### Phase 7 — Jira pack (`connectors/jira/`) — [`sooperset/mcp-atlassian`]

- [x] **All 63 `jira_*` tools**, extracted from `servers/jira.py` (`@jira_mcp.tool`
      decorators). Default-deny; every tool has an explicit rule
- [x] 36 reads → `redact:standard`; 2 attachment/image reads → `quarantine`
      (opaque bytes); 24 writes → `require_approval`; `jira_delete_issue` → `block`
      (only destructive)
- [x] Taint: 14 content-read sources (issues, JSM customer requests, dev info),
      7 sinks (`create_remote_issue_link` — the external-URL exfil channel —
      `create_issue`, comments, `create_customer_request`), 4 sequence rules
- [x] `roles.yaml`: support-agent (JSM comment/transition un-gated) /
      project-admin (writes un-gated **except** the destructive delete) / bot
      (all writes blocked). No role escalates delete (test-enforced)
- [x] 22 goldens + `tests/unit/test_jira_pack.py` (13: full-surface count guard,
      action⇄risk agreement, role invariants, taint wired); README threat model
      (Jira as an ingestion point for attacker text + an external-link exfil
      channel). Deferred: JQL constraint plugin / `maxResults` rewrite (needs the
      connector-local constraint plugin the framework defers — reads are
      `redact`-ed meanwhile)

### Phase 8 — Slack pack (`connectors/slack/`) — RETARGETED to [`korotovsky/slack-mcp-server`]

The pack originally targeted Slack's **first-party** `mcp.slack.com`, which was
permanently blocked: Slack documents that server in prose and never publishes
`tools/call` ids, so a verifiable complete policy is impossible from outside.
Retargeted to `korotovsky/slack-mcp-server` — the most powerful open-source Slack
MCP server, source-extractable — which unblocks it AND satisfies "the entire tool
surface." The transferable threat-model prose (Slack as a prompt-injection
delivery vector; content inspection over tool identity) carried over.

- [x] **All 22 tools**, extracted from `pkg/server/server.go` (`Tool*` constants +
      `NewTool` registrations). Default-deny; explicit rule per tool
- [x] 5 message/file reads → `redact:strict`; `attachment_get_data` →
      `quarantine`; 4 metadata reads → `redact:standard`; 12 writes →
      `require_approval`. **No destructive rules** — the server exposes no
      delete/archive tool (test-pinned); anything new lands under default-deny
- [x] Taint: 7 content-read sources, sinks `conversations_add_message` (primary
      exfil: a DM leaves instantly, invisible to channel monitoring) +
      `usergroups_create/update`; 3 sequence rules. `roles.yaml`
      (support-agent / workspace-admin / bot) — taint still applies over a grant
- [x] 18 goldens + `tests/unit/test_slack_pack.py` (12) + `test_slack_sequence.py`
      (22 session-state tests — the golden harness can't reach the sequence gate);
      README documents the retargeting rationale; `overrides.example.yaml`
      (channel-ID ACL, search tightening, taint-relaxation caveat)

**Exit criteria: MET.** Both real servers policed by a complete default-deny
policy; both authored purely with framework primitives — **zero engine changes**
(the pluggability proof). `policy ci` discovers and passes both automatically
(coverage 63/63 and 22/22; backtest zero-diff). Deferred, unchanged: a native
remote HTTP upstream (both servers also ship stdio/container entrypoints the
gateway launches directly); per-connector constraint plugins; the `rate_limit`
action (a framework change, raised as an issue not built).

## Phases 9–11 are independent of each other; 9 before 11 is recommended (principal-level audit enriches SIEM events).

## Phase 9 — Identity: OIDC ✅ DONE (2026-07-28)

Split into 9a (identity core, no server dep) and 9b (transport wiring), each
finished + verified before the next.

### Phase 9a — Identity core ✅ DONE (2026-07-28)

- [x] `identity/oidc.py` — validate a Bearer JWT against a configured
      issuer/audience + the issuer's JWKS. **`alg` is dictated by us, never the
      token**: an asymmetric-only allowlist refuses `alg=none` and the RS→HS
      confusion before a key is selected. `JwksProvider` caches keys by `kid`
      with a TTL and refetches **once** on an unknown kid — the single refetch
      makes ordinary rotation transparent while a genuinely unknown/revoked key
      fails closed. The fetch is injectable, so the whole validator is tested
      offline with no network
- [x] `identity/mapping.py` — verified claims → `Principal`: subject claim → id,
      IdP groups → roles in **config order** (most-privileged first, since the
      engine evaluates `roles[0]`). No group match → `default_role`; no usable
      subject → fail closed (an unauditable call is one we don't make)
- [x] `identity/apikey.py` — headless agents: sha256-hashed keys resolved in
      constant time, plaintext never at rest. `identity/resolver.py` — the single
      front door (`Authorization` header → `Principal`, `Bearer`=OIDC /
      `ApiKey`=store, every other case → `IdentityError`); an opt-in
      `anonymous_principal` is the one escape hatch for a no-IdP sidecar.
      `identity/config.py` — `identity.yaml` → ready resolver, fail-closed
      validation (a config that authenticates nobody is rejected; a plaintext-
      looking API key is rejected). pyjwt behind `[oidc]`, guarded, absent = fail
      closed. CI installs `[oidc]`
- [x] 34 tests: offline JWKS, expired/wrong-iss/wrong-aud/alg=none/HS256/
      foreign-key/unknown-kid all refused, transparent rotation, revoked key
      fails closed, mapping order + default + no-subject, api keys, resolver
      dispatch, config load/validation, pyjwt-absent fail-closed

### Phase 9b — Transport wiring + central config ✅ DONE (2026-07-28)

- [x] `transports/streamable_http.py` — an optional `resolver` on the hub turns on
      **per-request** authentication: every POST/GET/DELETE is re-authenticated,
      so a token revoked or expired mid-session is refused on its *very next call*
      (the fail-closed revocation path). A 401 carries `WWW-Authenticate`; the
      session is bound to the principal that created it, and a valid token for a
      *different* identity may not drive it (403 — a session id in a header is not
      a second bearer token). No resolver = authenticate nobody (backward compatible)
- [x] `central/config.py` — an `identity: { config: identity.yaml }` block
      (resolved relative to the gateway file) loads a resolver into every hub;
      `build_central_app(resolver=…)` is injectable for offline tests. `serve`
      picks it up with no CLI change. `identity.example.yaml` + a commented block
      in `gateway.example.yaml`
- [x] Integration `test_streamable_http_identity.py` (7) — the exit criterion made
      executable: **two identities in different groups get different verdicts on
      the same `admin.tool`** (admin allowed → reaches upstream; developer blocked
      at the gateway, never reaches it); no/expired token → 401; revoked key →
      401 next call; a foreign identity on another's session → 403; api key
      authenticates a headless caller. Plus config tests. 574 passed, ruff clean

**Exit criteria: MET.** Two users in different groups get different policy
treatment on the same tool; a revoked/expired/missing token fails closed (401),
proven end-to-end over the real HTTP transport with an offline JWKS. (Verified
against a self-signed issuer rather than a live Okta tenant — the validation path
is issuer-agnostic; `identity.example.yaml` documents the Okta/Auth0 setup.)
Deferred, not cut: console OIDC login (the console already has local cookie auth)
and JWKS discovery via `.well-known/openid-configuration` (today `jwks_uri` is
derived by convention or set explicitly).

## Phase 10 — Policy CI/CD (size: S–M)

The pluggability payoff: a pack is only safely pluggable if adding one requires
zero pipeline edits. Split into 10a (the gate), 10b (the blast-radius comment),
10c (signed bundles).

### Phase 10a — `policy ci`: validate + test every pack, by discovery ✅ DONE (2026-07-27)

- [x] `policy/ci.py` — **discovers** what to check (every `connectors/<pack>/` +
      every standalone `policies/*.yaml`) instead of being handed a list, so a
      new pack is covered on the next PR with no workflow edit. Discovery is
      deliberately *intolerant*, the one place it diverges from
      `registry.list_connectors()`: a pack that fails to load is a build failure,
      never a silently-skipped row (fail-closed applied to the policy supply chain)
- [x] Four checks per pack, weakest→strongest: **validate** (every layer parses
      *and* the merged result compiles — layers can be individually valid and
      conflict when merged) · **goldens** (loads BOTH layers in runtime order,
      so role cases can't pass for the wrong reason; a connector with no
      `policy_tests.yaml` FAILS — an unverified policy is an unverified control) ·
      **coverage** (every tool in `tools.yaml` resolves to an explicit rule, not
      `default_action`: default-deny is safe but unrated means unreviewed — this
      generalizes the GitHub pack's own invariant to all packs) · **backtest**
      (self-consistency smoke, below)
- [x] Backtest smoke: synthesizes an audit spool holding one recorded call per
      (tool, role) across the pack's whole inventory, replays it through the same
      policy, and requires a **zero diff** — any changed row means the Phase 4a
      replay path disagrees with the live matcher (a dropped role in the bucket
      key, a shifted outcome mapping). Scores outcomes against the *golden*
      handler set so a service-backed `redact` isn't misread as a denial. ~436
      replayed calls for GitHub on every PR. Explicitly NOT evidence about
      production traffic — that stays `policy backtest --audit <real log>`
- [x] `mcp-gateway policy ci [--root --only --min-goldens --no-backtest --json
      --github]`; `--github` emits `::error` annotations anchored to the policy
      file a reviewer edits (with workflow-command escaping) and appends a summary
      table to `$GITHUB_STEP_SUMMARY`. Exits non-zero — a gate, unlike `backtest`,
      which only reports
- [x] `.github/workflows/policy-ci.yml` — its own red/green on the PR, **core
      install only**, which doubles as a standing proof that policy tooling pulls
      in no extras
- [x] `tests/unit/test_goldens.py` rewritten discovery-first: it named packs by
      hand before, and it showed — the GitHub pack's 23 goldens ran nowhere until
      a follow-up PR (`0cab075`) added the call by hand, and the same gap would
      have opened for the next pack. This supersedes that fix structurally.
      pytest and CI now run the *same* `check_target`, so they cannot drift; a
      vacuity guard fails if discovery returns nothing; and a `MIN_GOLDENS`
      ratchet keeps `0cab075`'s per-pack floor so gutting a suite fails the build
      (a floor map, not a pack list — an unlisted pack still runs)
- [x] `tests/unit/test_policy_ci.py` — 26 tests against synthetic broken repos
      (a checker that never fails is indistinguishable from one that does
      nothing): every check catches its failure, discovery intolerance, `--only`
      typo fails rather than checking nothing, annotation escaping, CLI exit codes.
      372 passed / 1 skipped, ruff clean

### Phase 10b — Blast-radius PR comment ✅ DONE (2026-07-27)

**Design note — why this is a policy diff, not a traffic backtest.** The phase
was scoped as "post the backtest blast radius". A CI runner has no audit log, so
that would have meant committing a traffic fixture and reporting blast radius
against synthetic history — precise-looking numbers about traffic that never
happened. The reviewer's question is different anyway: not "which recorded calls
flip" but **"what does this PR change?"**. So `policy diff` compiles both
revisions and enumerates every decision. `policy backtest --audit <real log>`
remains the operator's tool for weighting a change by actual traffic; the two
answer different questions and both survive.

- [x] `policy/diff.py` — compiles each pack on **both** sides and evaluates every
      tool × every role view. This is the part a YAML diff cannot do: layered
      merge, glob specificity, and role overlays mean a three-line `roles.yaml`
      edit can move a hundred decisions, and deleting a rule silently hands a tool
      to `default_action`
- [x] Changes are ranked on the project's own least-privilege ladder
      (`allow < rewrite/redact < quarantine < require_approval < block`):
      `loosened` / `tightened` / `changed`. **A binary allowed-vs-blocked verdict
      gets the most common real edit wrong** — `block → require_approval` reads as
      "both refuse" to a bare gateway, but it is exactly how a tool gets opened up.
      `crosses_deny_boundary` carries the harder, narrower claim (refused before,
      un-gated now) so the headline can state it without leaning on it for
      everything
- [x] A pack that only **appeared** is reported by its action distribution, not as
      N loosened decisions — it adds enforcement where the repo had none, and
      calling that a loosening would bury real findings on the pack-authoring PRs
      this project is full of. A **removed** pack is flagged loudly: deleting
      `connectors/<pack>/` deletes controls, which a text diff makes look like
      housekeeping
- [x] `mcp-gateway policy diff --base DIR --head DIR [--markdown --json
      --fail-on-crossing]`. Reports by default (like `backtest`); the gate is
      opt-in
- [x] `policy-ci.yml` gains a `blast-radius` job: worktrees the base ref, renders
      the comment, and posts **one sticky comment per PR** edited in place —
      twelve stale blast-radius comments train reviewers to ignore all of them. It
      stays quiet when the diff is clean *and* no comment exists, but still
      updates a previously-alarming comment once the branch goes clean. Always
      writes the job summary too, so a fork PR (read-only token, cannot comment)
      still shows the blast radius
- [x] `tests/unit/test_policy_diff.py` — 29 tests pinning the judgments: the full
      ladder, deny-boundary crossing as a separate signal, role-overlay-only
      changes visible, deleted rule → `default_action` fallthrough, glob rules
      diffed through concrete inventory tools, added/removed pack framing,
      broken-head reported not crashed, and that every rendering states what is
      *not* replayed. 400 passed / 7 skipped, ruff clean

### Phase 10c — Signed policy bundles ✅ DONE (2026-07-27)

- [x] `policy/bundle.py` — a bundle is one self-describing, `cat`-inspectable JSON
      file: manifest (name, version, created, `content_hash`, signer id) + payload
      (raw layer text) + Ed25519 signature. **Two-link integrity chain, both
      checked on load:** `content_hash = sha256(canonical(payload))` binds the
      policy; the signature is over the canonical manifest, which *contains* the
      hash. Flip a policy byte → hash mismatches; recompute the hash to cover the
      edit → signature over the manifest fails. You cannot fix both without the
      private key (a test pins exactly that attack). Payload stores raw text so the
      gateway re-parses through the normal loader — a bundle can't smuggle a shape
      the file path would reject; `build` also parses up front so an invalid policy
      is never sealed into a signed artifact
- [x] `policy/signing.py` — **Ed25519, not a shared-secret MAC, on purpose:** it
      splits capabilities. The private key lives only where bundles are produced
      and signs; the gateway holds only the public key and can do nothing but
      verify, so compromising the gateway does not yield the ability to mint
      policy. Crypto lives behind `[vault]`; signing/verifying **fail closed** when
      it is absent (a gateway that can't check a signature refuses the bundle).
      `key_id` = short hash of the public key (a label, not a control)
- [x] `policy/bundle_store.py` — the reload primitive. `install` **verifies before
      it swaps** (a forged/corrupt bundle is refused, the current policy keeps
      enforcing — fail-closed reload); the swap is `os.replace`-**atomic** (no torn
      read); each install demotes the prior bundle to **last-known-good**;
      `current()` **re-verifies on every read** and self-heals to LKG when the live
      bundle is corrupt on disk; `rollback()` promotes LKG and is itself reversible.
      A store with no verifying key refuses to resolve (an unverified store is just
      rewritable files)
- [x] CLI: `policy keygen` (private key written 0600), `policy bundle
      build|verify|show`, and store ops `bundle install|rollback|current`. `wrap
      --bundle FILE --public-key KEY` and `wrap --bundle-store DIR --bundle-name
      NAME --public-key KEY` verify before enforcing and **audit** the outcome
      (`policy_bundle_loaded` / `policy_bundle_rejected` / `policy_bundle_fallback`);
      a bundle without `--public-key`, or one that fails to verify, fails closed at
      startup
- [x] `policy-ci.yml` gains a `sign-bundles` job on merge to main: discovers packs
      (same discovery as `policy ci`), builds + signs a bundle per pack from the
      `POLICY_SIGNING_KEY` secret, uploads them as artifacts. Skips cleanly when
      the secret is unset (a fork, or an unconfigured repo) — signing is a release
      convenience, not a gate. Runs on `[vault]`; the gateway verifies with the
      committed **public** half
- [x] Tests: `test_policy_bundle.py` (37 — round-trip, every tamper variant incl.
      recomputed-hash-still-fails-signature, wrong/stale key, unsigned-when-required,
      malformed envelopes, PEM I/O, crypto-absent fail-closed, all CLI paths),
      `test_policy_bundle_store.py` (13 — reject-keeps-current, self-heal to LKG,
      swap-on-disk caught on read, reversible rollback, multi-pack), and e2e
      `test_wrap_bundle.py` (5 — real `wrap --bundle` polices traffic; a **tampered
      bundle is refused with a `policy_bundle_rejected` audit event** and the
      gateway refuses to start; store path). 458 passed / 7 skipped, ruff clean

**Exit criteria: MET.** Blast-radius comment posts (10b); a tampered bundle is
rejected with an audit event and the gateway fails closed (10c, e2e-proven).

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
