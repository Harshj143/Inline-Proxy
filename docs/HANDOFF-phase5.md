# Phase 5 — Streamable HTTP transport + central mode: Handoff

_Rewritten from scratch each chunk. Last update: 2026-07-23._

Branch: `feat/streamable-http`, **stacked on `feat/console-v2`** (Phase 4, unmerged).
Never commit to `main` or to `feat/console-v2`. Draft PR #3: "Phase 5: Streamable
HTTP transport + central mode", base `feat/console-v2`.

## Environment (next run MUST read)
Repo needs Python **>=3.12**; container default `python3` is 3.11 and pip is
PEP-668 managed. Use a 3.12 venv:
```
python3.12 -m venv .venv
.venv/bin/pip install -e '.[server,vault]' pytest ruff pyyaml httpx
```
Quality gate (every commit):
```
PYTHONPATH=src .venv/bin/python -m pytest tests/ -q   # 277 passed, 4 skipped
.venv/bin/python -m ruff check src tests              # All checks passed!
```
Phase 4 baseline 253 → 5a +10 → 5b +14 → 5c-i +9 → **286**. Only add.
`fakeredis` is in the `[dev]` extra (Redis store tests); install it in the venv.

## Done
- **Phase 5a COMPLETE** — Streamable HTTP transport, single upstream.
  - `transports/upstream.py` — `Upstream` protocol + `SubprocessUpstream` (launch+pump,
    16 MiB limit, fail-closed on overrun, grace-then-kill). Pure stdlib.
  - `transports/streamable_http.py` — `_Session` (IS the gateway's Transport;
    send_client resolves the in-flight POST future by id or enqueues to SSE; send_upstream
    → upstream; handle_request registers future, feeds on_client_line, awaits reply or
    times out → -32002), `StreamableHttpGateway` (session registry: create/get/terminate/
    shutdown_all), `_NonClosingSink` (shared spool, per-session recorder), `build_session_parts`,
    `create_streamable_http_app` (single upstream at `/mcp`).
- **Phase 5b COMPLETE** — multi-upstream routing + `serve --config`.
  - `transports/streamable_http.py` — POST/GET/DELETE logic factored into module-level
    `_handle_post/_handle_get/_handle_delete(hub, request)`; `create_central_app(hubs)`
    registers `/servers/{name}/mcp` (+ `GET /servers`); unknown upstream → 404 (-32004).
  - `central/config.py` — `GatewayConfig`/`UpstreamConfig`, `load_gateway_config` (YAML/JSON,
    fail-closed validation), `build_central_app(config, upstream_factory=None)` → `(app, spool)`;
    each upstream gets engine + RedactionService + deny-broker over a shared spool. Factory
    injectable so tests use fakes.
  - CLI `mcp-gateway serve --config gateway.yaml [--host --port]`; `gateway.example.yaml`.
  - Verified LIVE against `demo/mock_server.py` (real subprocess): initialize handshake,
    policy-filtered tools/list, PII-redacted crm.get_customer result, audit = counts only.

## In progress
- Nothing mid-flight. 5a + 5b + **5c-i (Redis)** committed; 5a/5b pushed. Push 5c-i next.

## Done (5c-i — Redis session store)
- `core/session.py` — `Session.to_dict()/from_dict()` (durable state; `pending` excluded).
- `state/base.py` — `SessionStore.save(session)` no-op default (memory needs none).
- `core/gateway.py` — new `session_id` param (gateway id == client Mcp-Session-Id → audit
  correlates, and a replica can bind an existing id); `on_client_line`/`on_upstream_line`
  now wrap `_dispatch_*` + `self._persist()` (calls `store.save` after every message).
- `state/redis.py` — `RedisSessionStore` (sync redis client, `[redis]` extra, TTL, fail-closed
  on corrupt blob, `from_url`).
- `transports/streamable_http.py` — `build_session_parts(store=…)` passes store + session_id
  to each gateway.
- `central/config.py` — `backend: redis` (+ `state.url`) builds ONE shared store for all
  upstreams/replicas; `_build_store`.
- Tests `tests/unit/test_state_redis.py` (9, fakeredis) incl. two replicas sharing taint via
  the REAL gateway. `fakeredis` added to `[dev]`.

## Exact next steps — Phase 5c-ii (Postgres audit-index store)
1. `state/postgres.py` — a `PostgresAuditIndex` mirroring `audit/index.py`'s QUERY surface
   (`list_sessions`, `session_detail`, `query_events`, `counts_by_event`, `approval_history`)
   over Postgres, so the console can read from PG in central mode. This is the INDEX store, not
   sessions (Redis owns sessions). `[postgres]` extra (`psycopg[binary]>=3.1`), guard the import.
2. Schema mirrors `audit/index.py` (events keyed on spool offset, sessions roll-up). Reuse the
   same `read_spool` reader to feed it; keep `catch_up`/`rebuild` semantics.
3. NO live PG in the sandbox: `pytest.importorskip("psycopg")` AND skip unless a `TEST_PG_DSN`
   env var is set (there won't be one here → tests skip cleanly). Keep the code correct-by-reading.
   Consider factoring a shared SQL-ish query contract, but don't over-engineer — a thin parallel
   implementation is fine.
4. Optional: let the console/`serve` config point the console's read model at PG. Low priority;
   the console currently opens SQLite directly. Document rather than force it.

If time is short before the deadline, 5c-ii can be deferred — 5c-i (the exit-criterion shared
taint/risk) is the important half. Mark clearly in PLAN.md what is done vs deferred.

## Phase 5d (after 5c green + pushed)
Dockerfile + docker-compose (gateway + console + redis + postgres) — author carefully, validate
statically (no docker here). Load-test script (100 calls/sec, p99 < 50 ms on the regex path,
documented) + a small in-process smoke assertion.

## Gotchas / decisions made
- **Per-session gateway** is the central-mode model — one `SecurityGateway` per `Mcp-Session-Id`.
  For 5c shared state, the `store` is the seam: inject ONE shared store into every session's
  gateway so they share taint/risk. `build_session_parts` must grow a `store` param.
- **Shared spool, per-session recorder** (`_NonClosingSink`) avoids `session_id` bleed.
- **FastAPI annotation quirk**: `streamable_http.py` and `console/app.py` omit `from __future__
  import annotations` and import FastAPI at module top (else body/Request params misread as query).
  `central/config.py` is pure (no FastAPI at top) — it imports the app builder lazily inside
  `build_central_app`. Keep that split.
- **Re-entrant vs async response**: sync fake upstream resolves within send_upstream; real
  subprocess resolves later on the pump task. Both work (verified live with the mock server).
- **CI**: Phase 4 PR #2 GitGuardian went green after rewriting history to drop credential-like
  test literals — the App only honors `.gitguardian.yaml` ignores from `main`, not a PR branch.
  Watch for this if a new test fixture ever trips it.
- Sub-phase discipline: finish + verify 5c (tests green, ruff clean, PLAN + this file updated,
  push) before 5d.

## Deadline
A fresh scheduled run continues from origin `feat/streamable-http` + this file. Stop by
09:00 UTC; per-chunk pushes are the safety net. If all of Phase 5 completes before then, mark it
done in PLAN.md, move the marker to Phase 6, write a final handoff, push, STOP (do not start Phase 6).
