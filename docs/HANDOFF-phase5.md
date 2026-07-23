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
Phase 4 baseline 253 → 5a +10 → 5b +14 → **277**. Only add.

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
- Nothing mid-flight. 5a + 5b committed + pushed, green. (Push 5b + open/refresh PR #3 next.)

## Exact next steps — Phase 5c (Redis / Postgres state)
Goal (exit criterion): two gateway replicas sharing one store see each other's taint/risk.
1. **Understand the seam first.** `state/base.py` `SessionStore` ABC has `get_or_create(id)`
   and `get(id)`. `MemorySessionStore` returns LIVE `Session` objects, so mutations (taint,
   risk_score, suspend) are visible with no write-back. A Redis store CANNOT do that — it
   must persist `Session` state after each mutation. Read `core/session.py` to see every
   mutation point (`mark_tainted`, `record_call`, `track_pending`/`resolve_pending`,
   `risk_score +=` in `risk/scoring.py`). Decide the persistence model:
   - Simplest robust option: add `save(session)` to the `SessionStore` ABC (no-op for memory),
     and have the gateway call `store.save(self.session)` after each mutation batch (e.g. at the
     end of `_handle_tool_call`, on risk updates, on taint). `pending` calls are in-flight and
     short-lived — decide whether they need to survive a replica handoff (probably not for 5c;
     document it).
   - Serialize `Session` to a dict (it has taint fields, risk_score, risk_events, history). Add
     `Session.to_dict()/from_dict()` if not present.
2. `state/redis.py` — `RedisSessionStore(SessionStore)` over a Redis hash/JSON per session id;
   `[redis]` extra (`redis>=5`). Guard import; NO live redis in the sandbox — test with
   `fakeredis` (add to a test-only path; `pytest.importorskip("fakeredis")`).
3. `state/postgres.py` — Postgres-backed AUDIT INDEX store (mirror `audit/index.py`'s query
   surface over Postgres), `[postgres]` extra. This is the index store, not sessions. Skip-guard
   tests (no live PG); consider `pytest.importorskip("psycopg")` + a skip if no DSN. Keep it thin
   — the console reads through the same query methods.
4. Wire `state.backend` in `central/config.py`: `redis` → build a shared `RedisSessionStore` and
   pass it to every session's gateway (`SecurityGateway(store=…)`); `build_session_parts` needs a
   `store` param (currently each gateway defaults to its own MemorySessionStore). Extend
   `_SUPPORTED_STATE`.
5. Tests: two `SecurityGateway`s sharing one `RedisSessionStore` (fakeredis) — taint/suspend set
   by one is seen by the other. Config with `backend: redis` builds and wires the shared store.

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
