"""SQLite audit index: build, rebuild, incremental catch-up, queries."""

from __future__ import annotations

import json

from mcp_gateway.audit.index import AuditIndex


def _spool(path, events):
    with path.open("wb") as fh:
        for ev in events:
            fh.write((json.dumps(ev) + "\n").encode("utf-8"))


def _sample():
    # Two sessions worth of decided calls + a taint + a suspend.
    return [
        {"schema_version": 1, "ts": "t1", "event": "gateway_start", "session_id": "s1"},
        {"schema_version": 1, "ts": "t2", "event": "tool_call_allowed",
         "session_id": "s1", "tool": "crm.get", "action": "allow", "rule": "r1", "id": 1},
        {"schema_version": 1, "ts": "t3", "event": "session_tainted",
         "session_id": "s1", "tool": "web.fetch"},
        {"schema_version": 1, "ts": "t4", "event": "tool_call_blocked",
         "session_id": "s1", "tool": "http.post", "stage": "sequence",
         "reason": "taint sink", "session_score": 40, "session_level": "ELEVATED", "id": 2},
        {"schema_version": 1, "ts": "t5", "event": "session_suspended",
         "session_id": "s1", "session_score": 80},
        {"schema_version": 1, "ts": "t6", "event": "tool_call_allowed",
         "session_id": "s2", "tool": "crm.get", "action": "redact", "rule": "r2", "id": 1},
    ]


def test_rebuild_indexes_events_and_sessions(tmp_path):
    spool = tmp_path / "audit.log"
    _spool(spool, _sample())
    with AuditIndex(tmp_path / "audit.db") as index:
        stats = index.rebuild(spool)
        assert stats["inserted"] == 6

        sessions = {s["session_id"]: s for s in index.list_sessions()}
        assert set(sessions) == {"s1", "s2"}
        s1 = sessions["s1"]
        assert s1["allowed_count"] == 1
        assert s1["blocked_count"] == 1
        assert s1["tainted"] is True
        assert s1["suspended"] is True
        assert s1["risk_score"] == 80

        counts = index.counts_by_event()
        assert counts["tool_call_allowed"] == 2
        assert counts["tool_call_blocked"] == 1


def test_offset_is_the_event_id(tmp_path):
    spool = tmp_path / "audit.log"
    _spool(spool, _sample())
    with AuditIndex(tmp_path / "audit.db") as index:
        index.rebuild(spool)
        events = index.query_events(limit=100, ascending=True)
        offsets = [e["offset"] for e in events]
        assert offsets == sorted(offsets)
        assert offsets[0] == 0
        # get_event round-trips by offset.
        first = index.get_event(offsets[0])
        assert first["event"] == "gateway_start"


def test_incremental_catch_up_is_idempotent(tmp_path):
    spool = tmp_path / "audit.log"
    events = _sample()
    _spool(spool, events[:3])
    db = tmp_path / "audit.db"
    with AuditIndex(db) as index:
        first = index.catch_up(spool)
        assert first["inserted"] == 3
        # Re-running with no new data inserts nothing (idempotent watermark).
        assert index.catch_up(spool)["inserted"] == 0

        # Append the rest; catch-up only ingests the new tail.
        with spool.open("ab") as fh:
            for ev in events[3:]:
                fh.write((json.dumps(ev) + "\n").encode("utf-8"))
        second = index.catch_up(spool)
        assert second["inserted"] == 3
        assert index.counts_by_event()["tool_call_allowed"] == 2


def test_session_detail_returns_chronological_events(tmp_path):
    spool = tmp_path / "audit.log"
    _spool(spool, _sample())
    with AuditIndex(tmp_path / "audit.db") as index:
        index.rebuild(spool)
        detail = index.session_detail("s1")
        assert detail is not None
        assert detail["session_id"] == "s1"
        names = [e["event"] for e in detail["events"]]
        assert names == ["gateway_start", "tool_call_allowed",
                         "session_tainted", "tool_call_blocked", "session_suspended"]
        assert index.session_detail("missing") is None


def test_query_events_filters(tmp_path):
    spool = tmp_path / "audit.log"
    _spool(spool, _sample())
    with AuditIndex(tmp_path / "audit.db") as index:
        index.rebuild(spool)
        blocked = index.query_events(event="tool_call_blocked")
        assert len(blocked) == 1 and blocked[0]["tool"] == "http.post"
        by_tool = index.query_events(tool="crm.get")
        assert len(by_tool) == 2
        by_session = index.query_events(session_id="s2")
        assert all(e["session_id"] == "s2" for e in by_session)


def test_after_cursor_pages_events(tmp_path):
    spool = tmp_path / "audit.log"
    _spool(spool, _sample())
    with AuditIndex(tmp_path / "audit.db") as index:
        index.rebuild(spool)
        first_two = index.query_events(limit=2, ascending=True)
        cursor = first_two[-1]["offset"]
        nxt = index.query_events(after=cursor, limit=2, ascending=True)
        assert nxt[0]["offset"] > cursor


def test_rebuild_is_clean_slate(tmp_path):
    spool = tmp_path / "audit.log"
    _spool(spool, _sample())
    db = tmp_path / "audit.db"
    with AuditIndex(db) as index:
        index.rebuild(spool)
        # Shrink the spool to a single event and rebuild: stale rows are gone.
        _spool(spool, _sample()[:1])
        index.rebuild(spool)
        assert index.counts_by_event() == {"gateway_start": 1}
        assert index.list_sessions()[0]["event_count"] == 1


def test_approval_history(tmp_path):
    spool = tmp_path / "audit.log"
    _spool(spool, [
        {"schema_version": 1, "ts": "t1", "event": "approval_requested",
         "session_id": "s1", "tool": "admin.delete", "approved": True,
         "approver": "alice", "note": "ok"},
    ])
    with AuditIndex(tmp_path / "audit.db") as index:
        index.rebuild(spool)
        hist = index.approval_history()
        assert len(hist) == 1 and hist[0]["approver"] == "alice"
