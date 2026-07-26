# Phase 5 — Streamable HTTP transport + central mode: Handoff — ✅ PHASE COMPLETE (2026-07-23)

Branch: `feat/streamable-http`, **stacked on `feat/console-v2`** (Phase 4, unmerged).
Draft PR #3: base `feat/console-v2`. Never commit to `main`/`feat/console-v2`; never merge.

**Phase 5 is COMPLETE** — 5a + 5b + 5c-i + 5c-ii + 5d all done, tested, committed, pushed.
Both exit criteria met. Next phase is **Phase 6 — Connector framework + GitHub pack**
(a fresh run should pick it up per PLAN.md; do NOT start it from this handoff).

## Environment (next run MUST read)
Repo needs Python **>=3.12**; container default `python3` is 3.11, pip is PEP-668 managed.
```
python3.12 -m venv .venv
.venv/bin/pip install -e '.[server,vault]' pytest ruff pyyaml httpx fakeredis
PYTHONPATH=src .venv/bin/python -m pytest tests/ -q   # 295 passed, 5 skipped
.venv/bin/python -m ruff check src tests              # All checks passed!
```
Baseline into Phase 6 is **295** (5 skipped: presidio/anomaly + the live-Postgres test).

## What shipped in Phase 5 (all on `feat/streamable-http`)
- **5a** — `transports/upstream.py` (`Upstream` protocol + `SubprocessUpstream`) and
  `transports/streamable_http.py` (per-`Mcp-Session-Id` gateway acting as the Transport;
  `create_streamable_http_app` single-upstream POST/GET/DELETE `/mcp`; fail-closed on
  unknown/missing session; gateway-deadline → JSON-RPC error).
- **5b** — `create_central_app(hubs)` routing `/servers/<name>/mcp` (per-endpoint isolation,
  `GET /servers`); `central/config.py` (`GatewayConfig`, `load_gateway_config` fail-closed,
  `build_central_app`); `mcp-gateway serve --config`; `gateway.example.yaml`. Verified LIVE
  against `demo/mock_server.py`: policed identically to sidecar (filtered list, redacted PII).
- **5c-i** — Redis shared session state: `Session.to_dict/from_dict`, `SessionStore.save()`,
  gateway `session_id` param + `_persist()` after every message, `state/redis.py`, config
  `backend: redis`. Two replicas share taint/risk (tested via the real gateway, fakeredis).
- **5c-ii** — `state/postgres.py` `PostgresAuditIndex` (mirrors the SQLite index query surface;
  pure roll-up helpers unit-tested; DB round-trip skip-guarded on `$TEST_PG_DSN`). `[postgres]`.
- **5d** — `Dockerfile` + `docker-compose.yml` (gateway+console+redis+postgres) + `deploy/`
  configs; `scripts/loadtest.py` + smoke. Regex-path added latency **p99 ≈ 0.1 ms @ ~24k/s**.

## Decisions worth keeping (so Phase 6 doesn't fight them)
- **Per-session gateway** in central mode (one `SecurityGateway` per `Mcp-Session-Id`); the
  `store` is the shared-state seam (inject ONE store into all sessions for replica sharing).
- **`session_id` param on the gateway** makes its id == the client's Mcp-Session-Id, so audit,
  the console read model, and the HTTP session all correlate. Keep passing it.
- **Shared spool, per-session recorder** (`_NonClosingSink`) — no `session_id` bleed.
- **`streamable_http.py` and `console/app.py` omit `from __future__ import annotations`** and
  import FastAPI at module top (FastAPI misreads stringised body/Request annotations as query
  params). `central/config.py` is pure and imports the app builder lazily. Keep that split.
- **Extras discipline**: server/redis/postgres/vault deps live in extras; the core install is
  still just `pyyaml`. `[dev]` carries httpx + fakeredis for tests.
- **GitGuardian** (Phase 4 PR #2) only honors `.gitguardian.yaml` ignores from `main`, not a PR
  branch — a credential-like test fixture on a branch must be written so the detector doesn't
  fire (helper, no literal username/password pair), or history rewritten. Watch for this.

## Phase 6 pointers (for the NEXT run — from PLAN.md; not this handoff's job to start)
`connectors/base.py` + registry + `mcp-gateway add <name>`; a GitHub connector pack
(`tools.yaml` risk-classified inventory, `policy.yaml`, taint model, constraints, detectors,
roles, `policy_tests.yaml` goldens, README threat model). The pack is authored purely with
existing framework primitives — the pluggability proof is zero engine changes. Central mode
(Phase 5) is ready to bind a pack to `/servers/github/mcp`. Start Phase 6 on a NEW branch
stacked appropriately once the Phase 4/5 PRs are dealt with.

## PR / CI status
- PR #2 (Phase 4 → main): GitGuardian green after a history rewrite; CI test/ruff jobs run on
  3.12/3.13.
- PR #3 (Phase 5 → feat/console-v2, stacked): draft. Watch CI on the latest push.
- Both are DRAFT; do not merge. Subscriptions active — CI/review webhooks handled as they arrive.
