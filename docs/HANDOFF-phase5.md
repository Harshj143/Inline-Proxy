# Phase 5 — Streamable HTTP transport + central mode: Handoff

_Rewritten from scratch each chunk. Last update: 2026-07-23._

Branch: `feat/streamable-http`, **stacked on `feat/console-v2`** (Phase 4, unmerged).
Never commit to `main` or to `feat/console-v2`. Draft PR: "Phase 5: Streamable
HTTP transport + central mode", base `feat/console-v2` (open after first push).

## Environment (next run MUST read)
Repo needs Python **>=3.12**; container default `python3` is 3.11 and pip is
PEP-668 managed. Use a 3.12 venv:
```
python3.12 -m venv .venv
.venv/bin/pip install -e '.[server,vault]' pytest ruff pyyaml httpx
```
Quality gate (every commit):
```
PYTHONPATH=src .venv/bin/python -m pytest tests/ -q   # 263 passed, 4 skipped
.venv/bin/python -m ruff check src tests              # All checks passed!
```
Phase 4 baseline was 253; Phase 5a added 10 → 263. Only add.

## Done
- **Phase 5a COMPLETE** — Streamable HTTP transport, single upstream.
  - `src/mcp_gateway/transports/upstream.py` — `Upstream` protocol +
    `SubprocessUpstream`: `start(on_line, on_exit)` launches the subprocess and
    pumps stdout as newline-JSON to `on_line`; `send(line)` writes stdin;
    `shutdown()` terminates (grace then kill). 16 MiB frame limit, fail-closed on
    overrun. Pure stdlib — importable without the [server] extra.
  - `src/mcp_gateway/transports/streamable_http.py` — the central-mode transport.
    - `_Session` = one MCP session; IS the gateway's `Transport`. `send_upstream`
      → upstream; `send_client` → resolve the in-flight POST future by JSON-RPC id,
      else enqueue to the session's SSE channel. `handle_request` registers a
      future, feeds `gateway.on_client_line`, awaits the correlated reply (or a
      `response_timeout` → JSON-RPC error -32002).
    - `StreamableHttpGateway` — session registry: `create()` mints a `uuid` session
      id, builds gateway+upstream via a `SessionParts` factory, `on_start`s and
      `start`s the upstream; `get`, `terminate`, `shutdown_all`.
    - `_NonClosingSink` — wraps the shared spool so each per-session `AuditRecorder`
      (own `session_id`) can't close it; the real spool closes once at app shutdown.
    - `build_session_parts(engine, spool, upstream_factory, ...)` — default factory:
      sessions share engine/redaction/broker/spool, each gets its own gateway +
      recorder + upstream.
    - `create_streamable_http_app(hub, path="/mcp")` — FastAPI: `POST /mcp`
      (initialize w/o session → mint + `Mcp-Session-Id` header; request → policed,
      await reply as JSON; notification → 202; unknown session → 404; missing → 400),
      `GET /mcp` (SSE server→client), `DELETE /mcp` (terminate). Lifespan shuts down
      all sessions.
    - **IMPORTANT**: like `console/app.py`, this module omits `from __future__ import
      annotations` and imports FastAPI at module top (FastAPI misreads stringised
      `request: Request` as a query param). Keep it that way; it's `[server]`-gated.
  - Tests: `tests/unit/test_streamable_http.py` (10) with an in-process `FakeUpstream`.

## In progress
- Nothing mid-flight. 5a committed + pushed, green.

## Exact next steps — Phase 5b (multi-upstream routing + `serve --config`)
1. `transports/streamable_http.py` currently serves ONE upstream at a fixed path.
   For 5b, mount many: `/servers/<name>/mcp`, each a `StreamableHttpGateway` bound to
   its own `PolicyEngine` (pack + policy). Options: (a) a factory that builds one app
   with multiple routers keyed by `<name>`, or (b) refactor `create_streamable_http_app`
   to take a `dict[name -> StreamableHttpGateway]` and register `/servers/{name}/mcp`
   routes that dispatch on the path param. Prefer (b) — one app, N upstreams.
   Keep per-upstream isolation: a session id belongs to one upstream (namespace the
   registry by upstream name, or include the name in session lookup).
2. Per-upstream supervision/backoff: if a `SubprocessUpstream` dies, `_on_upstream_exit`
   already marks the session closed. Add restart/backoff policy at the hub level for
   central mode (a dead upstream shouldn't kill the process; new sessions respawn it).
3. `gateway.yaml` config: upstreams (name → command + policy files), state backend
   (memory/sqlite now; redis/postgres in 5c), console wiring. Add a loader (reuse the
   yaml/json pattern in `cli/__init__.py::_load_config_file_generic`). `mcp-gateway
   serve --config gateway.yaml` starts uvicorn with the multi-upstream app (+ optionally
   the console app mounted). Declare no new core deps; server deps already in [server].
4. Tests: two upstreams under different policies on one app (fake upstreams), each policed
   independently; config load + validation (bad config fails closed with a clear error).

## Phase 5c / 5d (later — do NOT start until 5b is green + pushed)
- 5c: `state/redis.py` (SessionStore over Redis) + `state/postgres.py` (audit index).
  Honor the `SessionStore` ABC in `state/base.py` (`get_or_create`, `get`). Deps in
  `[redis]`/`[postgres]` extras. NO live redis/postgres in the sandbox — use `fakeredis`
  (add to a test path) or skip-guard the tests. Prove two gateways sharing one store see
  each other's taint/suspension (the exit-criteria "two replicas share taint/risk").
  NOTE: the `SecurityGateway` currently binds ONE session at construction and does
  `store.get_or_create(uuid...)`. For shared state, the store is the seam — a Redis store
  makes `Session` reads/writes hit Redis. Check how `Session` mutations (taint, risk_score)
  are persisted; `MemorySessionStore` holds live objects, but a Redis store needs explicit
  write-back after each mutation. This may need a small `store.save(session)` addition to
  the `SessionStore` ABC — design it in 5c.
- 5d: Dockerfile + docker-compose (gateway + console + redis + postgres) — author carefully,
  validate statically (no docker here). Load-test script (100 calls/sec, p99 < 50 ms on the
  regex path, documented) + a small in-process smoke assertion.

## Gotchas / decisions made
- **Per-session gateway** is the central-mode model: reuse the gateway unchanged, one per
  `Mcp-Session-Id`. Don't try to make one gateway multiplex sessions — its `self.session`
  is singular by design.
- **Shared spool, per-session recorder** — a shared recorder's `default_fields.setdefault
  ("session_id", ...)` would stamp the FIRST session's id on everyone. `_NonClosingSink`
  keeps the shared spool open across session ends.
- **Re-entrant response path**: with a synchronous fake upstream, `send_upstream` →
  `on_line` → `on_upstream_line` → `send_client` → resolve future all run nested inside
  `on_client_line`. Works because the gateway `track_pending`s before `send_upstream`.
  Real subprocess upstreams are async (response arrives on the pump task) — both paths
  are exercised (unit fake = sync; a real e2e in 5b/5d = async).
- **FastAPI annotation quirk** (see 5a IMPORTANT above) — same as the console.
- **CI is green on Phase 4 PR #2** (GitGuardian false-positive on test fixtures was fixed
  by rewriting history to remove the credential-like literals; `.gitguardian.yaml`'s App
  ignores only apply from `main`, not a PR branch — remember that for any future fixture).
- Sub-phase discipline: finish + verify 5b (tests green, ruff clean, PLAN + this file
  updated, push) before 5c.

## Deadline
A fresh scheduled run continues from origin `feat/streamable-http` + this file. Stop by
09:00 UTC; per-chunk pushes are the safety net.
