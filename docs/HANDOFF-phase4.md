# Phase 4 — Console v2: Handoff — ✅ PHASE COMPLETE (2026-07-23)

Branch: `feat/console-v2` (never commit to `main`).

**Phase 4 (Console v2) is COMPLETE.** All of 4a + 4b + 4c are implemented,
tested (253 passed / 4 skipped, ruff clean), and committed locally. The next
phase is **Phase 5 — Streamable HTTP transport + central mode** (do NOT start it
from this handoff; a fresh run should pick it up per PLAN.md).

## ⚠️ PUSH IS BLOCKED — the one outstanding action
As of 2026-07-23 this session's GitHub integration has **read but no write**
permission on `Harshj143/Inline-Proxy`:
- `git push` → `403 Forbidden` at `git-receive-pack`.
- GitHub API `create_branch`/`push_files` → `403 Resource not accessible by integration`.

So the remote branch `feat/console-v2` **does not exist yet** and nothing is
pushed — all Phase 4 work is committed **locally only**. The container is
ephemeral; unpushed work is lost if the container is reclaimed.

**Human action needed:** grant the Claude/GitHub integration **write (contents +
workflows)** access to `Harshj143/Inline-Proxy`. Then, from a run on this branch:
```
git push -u origin feat/console-v2
```
and open a **draft** PR "Phase 4: Console v2" → base `main` (create_pull_request
draft:true), subscribe to it, never merge. A push-retry reminder was scheduled;
a notification was sent to the user. Until access is granted there is nothing
more code-side to do.

## Environment (next run MUST read)
Repo needs Python **>=3.12**; container default `python3` is 3.11 and pip is
PEP-668 managed. Use a 3.12 venv:
```
python3.12 -m venv .venv
.venv/bin/pip install -e '.[server,vault]' pytest ruff pyyaml httpx
```
Quality gate:
```
PYTHONPATH=src .venv/bin/python -m pytest tests/ -q   # 253 passed, 4 skipped
.venv/bin/python -m ruff check src tests              # All checks passed!
```
Without `[server]`, the FastAPI-dependent tests skip (module `importorskip`);
pure-stdlib console tests (auth, approval queue) still run.

## What shipped in Phase 4
- **4a — read model (stdlib):** `audit/reader.py` (tolerant JSONL, byte-offset =
  Last-Event-ID), `audit/index.py` (SQLite WAL, offset-keyed, sessions roll-up,
  watermark, rebuild/catch-up, query layer), `policy/backtest.py` (action-level
  blast-radius diff, honest about not replaying constraints/taint/approvals).
  CLI: `audit reindex`, `policy backtest`.
- **4b — FastAPI app (`[server]`):** `console/auth.py` (PBKDF2 + HMAC-signed
  cookie, viewer/approver), `console/approvals.py` (live asyncio-future queue,
  fail-closed timeout), `console/app.py` `create_app(...)` — REST + OpenAPI over
  the index, SSE feed with exclusive Last-Event-ID resume, and the gateway
  approval contract endpoints. CLI: `console serve`, `console hash-password`.
- **4c — browser UI:** `console/static/{index.html,style.css,app.js}` served by
  FastAPI (`GET /`, `/static`), packaged via `package-data`. Vanilla JS SPA:
  live feed, sessions+replay, click-to-approve, policy view, backtest panel.
  e2e `tests/e2e/test_console_approval.py` drives the REAL `ApprovalBroker` +
  `HttpChannel` against a uvicorn console (approve + fail-closed-timeout).

## Design decisions worth keeping (so Phase 5 doesn't fight them)
- **Audit is counts-only** — no arguments/session state in the spool; the index
  stores no payloads and the backtest is action-level by necessity.
- **Offset = event id** everywhere: index PK, SSE Last-Event-ID (exclusive
  cursor), backtest. Don't add a second sequence.
- **`console/app.py` deliberately omits `from __future__ import annotations`**
  and imports FastAPI at module top — this FastAPI version misreads stringised
  body annotations as query params. Keep it that way; the module is `[server]`-gated.
- **Pending approvals are live, not audit** — the queue is in the running
  console and evaporates on restart (in-flight calls then fail closed via the
  broker deadline). The audit log only records a *decided* approval.
- **`denying_actions()` = {block, redact, require_approval}**; backtest +
  `/api/backtest` accept a `deny_set` override for deployments wiring those services.
- **Blocking-approval tests need one event loop** — TestClient serialises through
  one portal and deadlocks; use httpx.AsyncClient (unit) / uvicorn-in-a-thread (e2e).

## Phase 5 pointers (for the NEXT run — from PLAN.md, not this handoff's job)
`transports/streamable_http.py` (MCP Streamable HTTP, `Mcp-Session-Id`, SSE),
multi-upstream routing `/servers/<name>/mcp`, `state/redis.py` + `state/postgres.py`,
`mcp-gateway serve --config gateway.yaml`, Dockerfile/compose, load test. The
console (Phase 4) and its index/state seams are ready for it. Start Phase 5 on a
NEW branch/PR per repo discipline once Phase 4's PR is open.
