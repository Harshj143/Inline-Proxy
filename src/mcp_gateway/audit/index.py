"""SQLite index over the JSONL audit spool — the console's read model.

The spool is the source of truth (append-only, crash-tolerant, never the thing
a query blocks on). This module builds a *derived, disposable* index from it so
the console can answer "show me session X", "the last 50 events", "how many
blocks today" without scanning a growing text file on every request. Delete the
db and rebuild it from the spool at any time — that is the whole design (`audit
reindex`).

Design choices, all in service of "the index is a cache, the spool is truth":

  * **The primary key is the spool byte offset.** Not an autoincrement id: the
    offset is already a stable, monotonic, gap-tolerant cursor produced by the
    reader, and it doubles as the SSE `Last-Event-ID`. Ingesting the same event
    twice (a re-run after a crash mid-ingest) is an idempotent `INSERT OR
    IGNORE` on that key — catch-up is safe to repeat.
  * **WAL mode.** The gateway is not writing here (it writes the spool), but the
    console reads while a `reindex`/catch-up writes; WAL lets readers proceed
    without blocking on the writer.
  * **A derived `sessions` roll-up** maintained incrementally as events are
    ingested, so the session list is a single indexed scan, not a GROUP BY over
    every event on every page load.
  * **A `meta` watermark** (`next_offset`) so catch-up is incremental: read the
    spool only from where we last stopped.

Counts-only discipline holds: we store whatever the spool line contains, and
the spool already records counts/decisions, never raw payloads. The index adds
no new data — it only reshapes what audit already deemed safe to persist.

Pure stdlib (`sqlite3`). No server dependency.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from mcp_gateway.audit.reader import SpoolRecord, read_spool

# Event names the roll-up cares about. Kept local (not imported from events.py
# as a hard coupling) so the index tolerates unknown/future event names — it
# buckets them under "other" rather than failing.
_ALLOWED = "tool_call_allowed"
_BLOCKED = "tool_call_blocked"
_BLOCKED_SUSPENDED = "tool_call_denied_session_suspended"
_SUSPENDED = "session_suspended"
_TAINTED = "session_tainted"
_APPROVAL = "approval_requested"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    offset       INTEGER PRIMARY KEY,   -- spool byte offset == Last-Event-ID
    ts           TEXT,
    event        TEXT NOT NULL,
    session_id   TEXT,
    tool         TEXT,
    rule         TEXT,
    action       TEXT,
    request_id   TEXT,                  -- JSON-RPC id of the call, as text
    reason       TEXT,
    body         TEXT NOT NULL          -- full event JSON
);
CREATE INDEX IF NOT EXISTS ix_events_session ON events(session_id, offset);
CREATE INDEX IF NOT EXISTS ix_events_event   ON events(event, offset);
CREATE INDEX IF NOT EXISTS ix_events_tool    ON events(tool, offset);

CREATE TABLE IF NOT EXISTS sessions (
    session_id     TEXT PRIMARY KEY,
    first_ts       TEXT,
    last_ts        TEXT,
    event_count    INTEGER NOT NULL DEFAULT 0,
    allowed_count  INTEGER NOT NULL DEFAULT 0,
    blocked_count  INTEGER NOT NULL DEFAULT 0,
    tainted        INTEGER NOT NULL DEFAULT 0,
    suspended      INTEGER NOT NULL DEFAULT 0,
    risk_score     INTEGER NOT NULL DEFAULT 0,
    risk_level     TEXT NOT NULL DEFAULT 'NORMAL'
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


class AuditIndex:
    """A SQLite index over one audit spool. Open, catch up, query, close."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------- ingest
    def next_offset(self) -> int:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key='next_offset'"
        ).fetchone()
        return int(row["value"]) if row else 0

    def _set_next_offset(self, offset: int) -> None:
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES('next_offset', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(offset),),
        )

    def ingest(self, records: list[SpoolRecord]) -> int:
        """Insert records (idempotent on offset) and update the session roll-up.

        Returns the number of newly inserted events.
        """
        inserted = 0
        for rec in records:
            ev = rec.event
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO events"
                "(offset, ts, event, session_id, tool, rule, action, request_id, reason, body)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    rec.offset,
                    ev.get("ts"),
                    ev.get("event", "unknown"),
                    ev.get("session_id"),
                    ev.get("tool"),
                    ev.get("rule"),
                    ev.get("action"),
                    None if ev.get("id") is None else str(ev.get("id")),
                    ev.get("reason"),
                    json.dumps(ev, separators=(",", ":"), default=str),
                ),
            )
            if cur.rowcount:
                inserted += 1
                self._roll_up(ev)
        self._conn.commit()
        return inserted

    def _roll_up(self, ev: dict[str, Any]) -> None:
        session_id = ev.get("session_id")
        if not session_id:
            return
        name = ev.get("event")
        ts = ev.get("ts")
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE session_id=?", (session_id,)
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO sessions(session_id, first_ts, last_ts) VALUES (?,?,?)",
                (session_id, ts, ts),
            )
            row = self._conn.execute(
                "SELECT * FROM sessions WHERE session_id=?", (session_id,)
            ).fetchone()

        allowed = row["allowed_count"] + (1 if name == _ALLOWED else 0)
        blocked = row["blocked_count"] + (
            1 if name in (_BLOCKED, _BLOCKED_SUSPENDED) else 0
        )
        tainted = 1 if (row["tainted"] or name == _TAINTED) else 0
        suspended = 1 if (row["suspended"] or name == _SUSPENDED) else 0
        # Risk score/level ride along on scored events; keep the latest seen.
        score = ev.get("session_score", row["risk_score"])
        level = ev.get("session_level", row["risk_level"])
        self._conn.execute(
            "UPDATE sessions SET last_ts=?, event_count=event_count+1, "
            "allowed_count=?, blocked_count=?, tainted=?, suspended=?, "
            "risk_score=?, risk_level=? WHERE session_id=?",
            (ts or row["last_ts"], allowed, blocked, tainted, suspended,
             int(score), str(level), session_id),
        )

    def catch_up(self, spool_path: str | Path) -> dict[str, Any]:
        """Ingest new spool records since the stored watermark. Idempotent."""
        result = read_spool(spool_path, start=self.next_offset())
        inserted = self.ingest(result.records)
        self._set_next_offset(result.next_offset)
        self._conn.commit()
        return {
            "inserted": inserted,
            "next_offset": result.next_offset,
            "bad_lines": result.bad_lines,
            "torn_tail": result.torn_tail,
        }

    def rebuild(self, spool_path: str | Path) -> dict[str, Any]:
        """Drop all derived data and rebuild the index from the spool head."""
        self._conn.executescript(
            "DELETE FROM events; DELETE FROM sessions; DELETE FROM meta;"
        )
        self._conn.commit()
        return self.catch_up(spool_path)

    # -------------------------------------------------------------- queries
    def query_events(
        self,
        *,
        session_id: str | None = None,
        event: str | None = None,
        tool: str | None = None,
        after: int | None = None,
        limit: int = 100,
        ascending: bool = False,
    ) -> list[dict[str, Any]]:
        """Filtered event page. `after` is an exclusive offset cursor.

        `ascending` orders oldest-first (used by the SSE resume path); the
        default newest-first suits the console's event table.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if session_id is not None:
            clauses.append("session_id=?")
            params.append(session_id)
        if event is not None:
            clauses.append("event=?")
            params.append(event)
        if tool is not None:
            clauses.append("tool=?")
            params.append(tool)
        if after is not None:
            clauses.append("offset > ?" if ascending else "offset < ?")
            params.append(after)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        order = "ASC" if ascending else "DESC"
        params.append(max(1, min(limit, 1000)))
        rows = self._conn.execute(
            f"SELECT offset, body FROM events {where} ORDER BY offset {order} LIMIT ?",
            params,
        ).fetchall()
        return [self._hydrate(r) for r in rows]

    def get_event(self, offset: int) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT offset, body FROM events WHERE offset=?", (offset,)
        ).fetchone()
        return self._hydrate(row) if row else None

    def latest_offset(self) -> int:
        row = self._conn.execute("SELECT MAX(offset) AS m FROM events").fetchone()
        return int(row["m"]) if row and row["m"] is not None else 0

    def list_sessions(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM sessions ORDER BY last_ts DESC LIMIT ?",
            (max(1, min(limit, 1000)),),
        ).fetchall()
        return [self._session_row(r) for r in rows]

    def session_detail(self, session_id: str, limit: int = 500) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE session_id=?", (session_id,)
        ).fetchone()
        if row is None:
            return None
        summary = self._session_row(row)
        # Replay order is chronological — the console steps through it forward.
        summary["events"] = self.query_events(
            session_id=session_id, limit=limit, ascending=True
        )
        return summary

    def approval_history(self, limit: int = 100) -> list[dict[str, Any]]:
        """Recorded approval decisions (resolved). Live *pending* approvals are
        held by the console server, not here — the audit trail only ever sees a
        decision after a human made it."""
        return self.query_events(event=_APPROVAL, limit=limit)

    def counts_by_event(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT event, COUNT(*) AS n FROM events GROUP BY event"
        ).fetchall()
        return {r["event"]: r["n"] for r in rows}

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _hydrate(row: sqlite3.Row) -> dict[str, Any]:
        event = json.loads(row["body"])
        event["offset"] = row["offset"]
        return event

    @staticmethod
    def _session_row(r: sqlite3.Row) -> dict[str, Any]:
        return {
            "session_id": r["session_id"],
            "first_ts": r["first_ts"],
            "last_ts": r["last_ts"],
            "event_count": r["event_count"],
            "allowed_count": r["allowed_count"],
            "blocked_count": r["blocked_count"],
            "tainted": bool(r["tainted"]),
            "suspended": bool(r["suspended"]),
            "risk_score": r["risk_score"],
            "risk_level": r["risk_level"],
        }

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> AuditIndex:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
