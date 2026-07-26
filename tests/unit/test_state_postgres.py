"""Phase 5c-ii: Postgres audit-index store.

The row-shaping/roll-up logic is pure and tested here directly. The DB-backed
integration test is skipped unless a live Postgres DSN is provided via
$TEST_PG_DSN (there is none in the sandbox), so the suite stays green while the
SQL is exercisable wherever a database exists.
"""

from __future__ import annotations

import os

import pytest

from mcp_gateway.audit.reader import SpoolRecord
from mcp_gateway.state.postgres import (
    event_columns,
    hydrate,
    rollup_values,
    session_row,
)


def _rec(offset, ev):
    return SpoolRecord(offset=offset, end_offset=offset + 1, event=ev)


# ------------------------------------------------------------- pure helpers
def test_event_columns_shape():
    ev = {"ts": "t1", "event": "tool_call_allowed", "session_id": "s1",
          "tool": "crm.get", "rule": "r", "action": "allow", "id": 7, "reason": None}
    cols = event_columns(_rec(42, ev))
    assert cols[0] == 42                 # offset
    assert cols[2] == "tool_call_allowed"
    assert cols[7] == "7"                # id stringified
    assert '"tool":"crm.get"' in cols[9]  # body json


def test_event_columns_defaults_unknown_event():
    cols = event_columns(_rec(0, {"session_id": "s"}))
    assert cols[2] == "unknown"
    assert cols[7] is None               # no id


def test_rollup_new_session():
    ev = {"event": "tool_call_allowed", "ts": "t1", "session_id": "s"}
    r = rollup_values(None, ev)
    assert r["event_count"] == 1
    assert r["allowed_count"] == 1
    assert r["blocked_count"] == 0
    assert r["first_ts"] == "t1" and r["last_ts"] == "t1"
    assert r["tainted"] is False and r["suspended"] is False


def test_rollup_accumulates_and_flags():
    r0 = rollup_values(None, {"event": "gateway_start", "ts": "t0", "session_id": "s"})
    r1 = rollup_values(r0, {"event": "tool_call_allowed", "ts": "t1", "session_id": "s"})
    r2 = rollup_values(r1, {"event": "session_tainted", "ts": "t2", "session_id": "s"})
    r3 = rollup_values(r2, {"event": "tool_call_blocked", "ts": "t3", "session_id": "s",
                            "session_score": 40, "session_level": "ELEVATED"})
    r4 = rollup_values(r3, {"event": "session_suspended", "ts": "t4", "session_id": "s",
                            "session_score": 80})
    assert r4["event_count"] == 5
    assert r4["allowed_count"] == 1
    assert r4["blocked_count"] == 1
    assert r4["tainted"] is True
    assert r4["suspended"] is True
    assert r4["risk_score"] == 80
    assert r4["first_ts"] == "t0" and r4["last_ts"] == "t4"


def test_blocked_suspended_counts_as_blocked():
    r = rollup_values(None, {"event": "tool_call_denied_session_suspended",
                             "ts": "t", "session_id": "s"})
    assert r["blocked_count"] == 1


def test_hydrate_injects_offset():
    ev = hydrate(99, '{"event":"x","tool":"t"}')
    assert ev["offset"] == 99 and ev["event"] == "x"


def test_session_row_coerces_bools():
    r = session_row({
        "session_id": "s", "first_ts": "a", "last_ts": "b", "event_count": 3,
        "allowed_count": 1, "blocked_count": 2, "tainted": 1, "suspended": 0,
        "risk_score": 40, "risk_level": "ELEVATED",
    })
    assert r["tainted"] is True and r["suspended"] is False
    assert r["blocked_count"] == 2


# ------------------------------------------------------- live PG (skip-guarded)
_DSN = os.environ.get("TEST_PG_DSN")


@pytest.mark.skipif(not _DSN, reason="no TEST_PG_DSN; live Postgres not available")
def test_postgres_index_roundtrip(tmp_path):
    pytest.importorskip("psycopg")
    import json

    from mcp_gateway.state.postgres import PostgresAuditIndex

    spool = tmp_path / "audit.log"
    events = [
        {"schema_version": 1, "ts": "t1", "event": "gateway_start", "session_id": "s1"},
        {"schema_version": 1, "ts": "t2", "event": "tool_call_allowed",
         "session_id": "s1", "tool": "crm.get", "action": "allow", "rule": "r", "id": 1},
        {"schema_version": 1, "ts": "t3", "event": "tool_call_blocked",
         "session_id": "s1", "tool": "http.post", "stage": "action", "id": 2},
    ]
    with spool.open("wb") as fh:
        for e in events:
            fh.write((json.dumps(e) + "\n").encode())

    with PostgresAuditIndex(_DSN) as index:
        index.rebuild(spool)
        sessions = index.list_sessions()
        assert sessions[0]["session_id"] == "s1"
        assert sessions[0]["blocked_count"] == 1
        assert index.counts_by_event()["tool_call_allowed"] == 1
        detail = index.session_detail("s1")
        assert [e["event"] for e in detail["events"]][0] == "gateway_start"
