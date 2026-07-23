# Phase 4 — Console v2: Handoff

_Rewritten from scratch each chunk. Last update: 2026-07-23._

Branch: `feat/console-v2` (never commit to `main`). Draft PR to `main`:
"Phase 4: Console v2" (open it after the first push if none exists; never merge).

## ⚠️ PUSH IS CURRENTLY BLOCKED (read this first)
As of 2026-07-23 this session's GitHub integration has **read access but no
write permission** on `Harshj143/Inline-Proxy`:
- `git push` → `403 Forbidden` at `git-receive-pack` (the origin rejects it via the relay).
- GitHub API `create_branch` / `push_files` → `403 Resource not accessible by integration`.

So the remote branch `feat/console-v2` **does not exist yet** and none of this work
is pushed. All Phase 4a + 4b work is committed **locally** on `feat/console-v2`.
The container is ephemeral — if write access is not granted, this is lost.

**Action needed from a human:** grant the Claude/GitHub integration write
(contents + workflows) access to `Harshj143/Inline-Proxy`. Once granted, retry:
`git push -u origin feat/console-v2` (it should carry all local commits), then
open the draft PR. A notification was sent to the user describing this.

## Environment note (IMPORTANT for the next run)
Repo requires Python **>=3.12** but the container default `python3` is **3.11**
and pip is PEP-668 externally-managed. Use a 3.12 venv:
```
python3.12 -m venv .venv
.venv/bin/pip install -e '.[server,vault]' pytest ruff pyyaml httpx
```
Quality gate (run before every commit):
```
PYTHONPATH=src .venv/bin/python -m pytest tests/ -q   # 248 passed, 4 skipped
.venv/bin/python -m ruff check src tests              # All checks passed!
```
Note: without the `[server]` extra, `tests/unit/test_console_api.py` skips
(module-level `importorskip("fastapi")`), while `test_console_auth.py` and
`test_console_approvals.py` (pure stdlib) still run. That is intended.

## Done
- **Phase 4a COMPLETE** (committed): `audit/reader.py` (tolerant JSONL reader,
  byte-offset = Last-Event-ID), `audit/index.py` (SQLite WAL read model keyed on
  offset, sessions roll-up, watermark, rebuild/catch-up, query layer),
  `policy/backtest.py` (action-level blast-radius diff), CLI `audit reindex` +
  `policy backtest`. 20 tests.
- **Phase 4b COMPLETE** (committed): the FastAPI console over 4a.
  - `console/auth.py` — `hash_password`/`verify_password` (PBKDF2), `LocalUsers`
    (from config: `password` plaintext dev-only OR `password_hash`; roles
    `viewer`/`approver`), `CookieSigner` (HMAC-signed cookie w/ expiry, fails
    closed on tamper/expiry). Pure stdlib.
  - `console/approvals.py` — `ApprovalQueue`: `submit()` parks an asyncio Future,
    `wait(timeout)` blocks and fails closed on timeout, `resolve()` completes it
    (idempotent), `pending()` for the UI. Live state, evaporates on restart by design.
  - `console/app.py` — `create_app(index_path, spool_path, users, signer, ...)`.
    Routes: `POST /api/login|logout`, `GET /api/me`, `GET /api/sessions`,
    `GET /api/sessions/{id}` (with chronological replay events), `GET /api/events`
    (filters + `after` cursor), `GET /api/stats`, `GET /api/policy`,
    `POST /api/backtest`, `GET /api/stream` (SSE, `Last-Event-ID` exclusive resume,
    `once=` for tests), `POST /api/approvals` (gateway contract, blocks),
    `GET /api/approvals/pending`, `POST /api/approvals/{id}/resolve` (approver-only).
    **This module intentionally does NOT use `from __future__ import annotations`**
    and imports FastAPI/Pydantic at module top — FastAPI resolves annotations at
    decoration time and stringised/late-bound ones get misread as query params
    (verified failure mode with fastapi 0.139). The module is `[server]`-gated so
    that's safe. Models `LoginBody`/`ResolveBody`/`BacktestBody` are module-level.
  - CLI: `mcp-gateway console serve --index --audit --users [--policy --host --port
    --secret-env --gateway-token-env --approval-timeout]` and
    `mcp-gateway console hash-password`. Lazy import; clear error without the extra.
  - `pyproject.toml`: ruff `flake8-bugbear.extend-immutable-calls` for
    `fastapi.Depends`/`fastapi.Query` (the DI idiom); httpx added to the `dev` extra.
  - Tests: `test_console_auth.py` (8), `test_console_approvals.py` (4),
    `test_console_api.py` (18, gated on the extra). The blocking approval round-trip
    uses `httpx.AsyncClient` + ASGI transport on ONE event loop (TestClient serialises
    through one portal and would deadlock on a blocking request + its resolver).

## In progress
- Nothing mid-flight. 4a + 4b are committed locally and green. Only the push is blocked.

## Exact next steps
1. **If push access is now granted:** `git push -u origin feat/console-v2`, then open
   the draft PR "Phase 4: Console v2" (`create_pull_request` with `draft: true`, base
   `main`). Subscribe to it. THEN start 4c.
2. **Phase 4c — browser console UI** (`console/static/`, served by FastAPI):
   - Serve static assets + an index page from `create_app` (mount `StaticFiles` or a
     couple of routes returning HTML; keep it vanilla JS — minimal-dependency ethos).
   - Login page (POST /api/login, cookie set automatically). Show role; hide approve
     controls for `viewer`.
   - Live feed: `EventSource('/api/stream')`, render events; reconnect uses the browser's
     native Last-Event-ID.
   - Approvals: poll/subscribe pending, click-to-approve → `POST /resolve` (approver only).
   - Sessions list + click → session detail replay (`GET /api/sessions/{id}` events).
   - Policy view (`GET /api/policy`) and a backtest panel (`POST /api/backtest` with a
     pasted policy doc) rendering the blast-radius report.
3. **Exit-criteria e2e** (the phase gate): a real end-to-end demo wiring the gateway's
   actual `HttpChannel` (`approvals/channels/http.py`) to a running console: `mcp-gateway
   wrap --approvals http --approvals-url http://localhost:PORT ... ` → a require_approval
   tool blocks → approve in the console → call proceeds. And a `curl` script exercising
   every REST endpoint against the OpenAPI spec. Add as `tests/e2e/test_console_*.py`
   (spin uvicorn on an ephemeral port in a thread) or a `docs/` demo script.

## Gotchas / decisions made
- **Audit is counts-only**: spool stores no arguments/session state — that's why the
  index stores no payloads and the backtest is action-level. Don't try to reconstruct args.
- **Offset = event id** everywhere (index PK, SSE Last-Event-ID exclusive cursor, backtest).
- **`denying_actions()`** = `{block, redact, require_approval}` by default. Backtest +
  `POST /api/backtest` accept a `deny_set` override for deployments that wire redaction/approval.
- **Pending approvals are live, not audit** — the queue lives in the running console and is
  lost on restart (an in-flight call then fails closed via the gateway broker deadline).
- **FastAPI version quirk**: `from __future__ import annotations` breaks body-param detection
  in this env; console/app.py deliberately omits it (see Done). Don't "fix" it back.
- **TestClient can't do the blocking approval test** — use httpx AsyncClient on one loop.
- Sub-phase discipline: finish + verify 4c fully (tests green, ruff clean, PLAN + this file
  updated, push) before declaring Phase 4 done and moving the marker to Phase 5.
