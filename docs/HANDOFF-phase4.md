# Phase 4 — Console v2: Handoff

_Rewritten from scratch each chunk. Last update: 2026-07-23._

Branch: `feat/console-v2` (never commit to `main`). Draft PR to `main`:
"Phase 4: Console v2" (open it after the first push if none exists; never merge).

## Environment note (IMPORTANT for the next run)
The repo requires Python **>=3.12** but the container's default `python3` is
**3.11**, and `pip install` is PEP-668 externally-managed. Use a venv built
with 3.12:

```
python3.12 -m venv .venv
.venv/bin/pip install -e '.[vault]' pytest ruff pyyaml
```

Quality gate (run before every commit):
```
PYTHONPATH=src .venv/bin/python -m pytest tests/ -q      # 217 passed, 4 skipped
.venv/bin/python -m ruff check src tests                 # All checks passed!
```

## Done
- **Phase 4a COMPLETE** — audit index + backtest, pure stdlib, no server dep.
  - `src/mcp_gateway/audit/reader.py` — tolerant JSONL spool reader. `read_spool(path, start=0)`
    returns `ReadResult(records, next_offset, bad_lines, torn_tail)`; each `SpoolRecord`
    carries `offset`/`end_offset` (byte offsets) — the offset is the `Last-Event-ID`.
    Torn final line (no newline) is left for a later read; bad complete lines counted, not fatal.
  - `src/mcp_gateway/audit/index.py` — `AuditIndex(db_path)`. SQLite WAL. `events` table keyed
    on spool byte offset (`INSERT OR IGNORE` → idempotent catch-up), derived `sessions` roll-up,
    `meta.next_offset` watermark. Methods: `rebuild(spool)`, `catch_up(spool)`, `query_events(...)`,
    `get_event(offset)`, `latest_offset()`, `list_sessions()`, `session_detail(sid)`,
    `approval_history()`, `counts_by_event()`. Context manager (`with AuditIndex(...) as ix`).
  - `src/mcp_gateway/policy/backtest.py` — `backtest_policy(audit_path, engine, deny_set=None)`
    → `BacktestReport`. Replays recorded `tool_call_allowed`/`tool_call_blocked` calls through a
    policy, diffs action + allow/deny disposition. Collapses identical (tool,role,outcome) rows to
    a `count`. **Action-level only** — constraints/taint/sequence/approval are NOT replayed
    (audit is counts-only); blocked calls keep `old_stage` so a reviewer sees when a "newly_allowed"
    line was originally a constraint/sequence denial. `format_report()` for the CLI.
  - CLI (`src/mcp_gateway/cli/__init__.py`): `mcp-gateway audit reindex --audit <log> --index <db>
    [--incremental]` and `mcp-gateway policy backtest --policy <f> --audit <log> [--json]`.
  - Tests: `tests/unit/test_audit_reader.py`, `test_audit_index.py`, `test_backtest.py` (20 new).

## In progress
- Nothing mid-flight. 4a is committed + pushed and green.

## Exact next steps — start Phase 4b (FastAPI app, `[server]` extra)
1. `pyproject.toml` already declares `server = ["fastapi>=0.111", "uvicorn>=0.30"]`. Install it in
   the venv: `.venv/bin/pip install -e '.[server,vault]'`. Add `httpx` (FastAPI TestClient needs
   it) to a `dev`/test path or just `pip install httpx` in the venv for tests. If you introduce any
   new runtime dep for the server, declare it in the `[server]` extra — keep the core install clean.
2. `src/mcp_gateway/console/` new package:
   - `app.py` — `create_app(index_path, spool_path, users=...) -> FastAPI`. REST over `AuditIndex`:
     `GET /api/sessions`, `GET /api/sessions/{id}`, `GET /api/events`, `GET /api/policy`
     (serve `PolicyEngine.describe()`), `POST /api/backtest`. OpenAPI is automatic.
   - SSE `GET /api/stream` — tail the spool via `read_spool(path, start=Last-Event-ID)`, emit
     `id: <offset>` per event so `Last-Event-ID` resume works. Reuse the reader; poll the file.
   - Approvals: implement the **existing gateway contract** — the gateway's `HttpChannel`
     (`src/mcp_gateway/approvals/channels/http.py`) POSTs `ApprovalRequest.to_wire()` JSON to
     `POST {base_url}/api/approvals` and **blocks** until a human decides; respond
     `{"approved": bool, "approver": str, "note": str}`. So the console holds a **live in-memory
     pending queue**: `/api/approvals` (from the gateway) parks a future; `GET /api/approvals/pending`
     lists them for the UI; `POST /api/approvals/{request_id}/resolve` (approver role) completes the
     future and unblocks the gateway. Use an `asyncio.Future` per pending request + a timeout.
   - `auth.py` — cookie session against local users (dict of user→{password_hash, role}); roles
     `viewer` (read-only) and `approver`. Approve endpoints require `approver`. Keep it stdlib-simple
     (signed cookie via `hmac`, or FastAPI dependency) — no new heavy dep.
   - CLI: `mcp-gateway console serve --index <db> --audit <log> [--host --port --users <file>]`,
     guarded by a friendly error if `[server]` isn't installed (import fastapi lazily, like the
     redaction/anomaly extras are handled).
3. Tests (`tests/console/` or `tests/unit/test_console_*.py`): FastAPI `TestClient` over REST +
   `/openapi.json`; SSE resume from a `Last-Event-ID`; approvals round-trip (POST parks, resolve
   unblocks, returns the decision) + blocking/timeout; authn + role gating (viewer can't approve).
   Gate the whole module behind `pytest.importorskip("fastapi")` so the suite still passes without
   the extra (mirror how `test_redaction_presidio.py` skips).

## Gotchas / decisions made
- **Audit is counts-only**: the spool never stores tool arguments or session state. That's why the
  backtest is action-level and the index stores no payloads — don't try to reconstruct arguments.
- **Offset = event id**: everything (index PK, SSE Last-Event-ID, backtest cursor) keys on the spool
  byte offset from `reader.py`. Keep using it; don't add a second sequence counter.
- **`denying_actions()`** returns `{block, redact, require_approval}` by default (redact/approval are
  deny-only unless a service is wired). The backtest uses that set for new-outcome disposition and
  lets callers override via `deny_set` (a deployment wiring redaction should pass a narrower set).
  The 4b `/api/backtest` should expose that too.
- **Pending approvals are live, not from audit** — the audit log only ever sees an approval *after*
  a human decided (`approval_requested` with `approved=`). The pending queue lives in the 4b server.
- Sub-phase discipline: finish + verify 4b fully (tests green, ruff clean, PLAN + this file updated,
  push) before starting 4c (browser UI).
- Python 3.12 venv is mandatory (see Environment note). `python3` alone is 3.11 and will refuse the
  editable install.
