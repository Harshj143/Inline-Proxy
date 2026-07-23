"""Postgres audit-index store — the central-mode read model.

`audit/index.py` gives the console a SQLite read model over the spool; that is
perfect for a sidecar or a single console host. Central mode wants the same
query surface backed by a shared database so any console replica sees the same
history and the index survives a gateway restart. This is that store: the SAME
methods (`list_sessions`, `session_detail`, `query_events`, `counts_by_event`,
`approval_history`, `catch_up`, `rebuild`) over Postgres instead of SQLite.

It is deliberately a thin parallel of the SQLite version, not a shared ORM: the
two engines differ in exactly the places that matter (`%s` vs `?` placeholders,
`ON CONFLICT` upsert, `offset` is a reserved word in Postgres so the column is
`event_offset`), and a translation layer would hide those. The row→event and
row→session shaping is factored into pure helpers (`_hydrate`, `_session_row`)
so it is unit-testable without a live database.

Postgres is the `[postgres]` extra (`psycopg[binary]`); the import is guarded.
Counts-only discipline holds: like the spool and the SQLite index, this stores
decisions and counts, never raw payloads.
"""

from __future__ import annotations

import json
from typing import Any

from mcp_gateway.audit.reader import SpoolRecord, read_spool

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_offset  BIGINT PRIMARY KEY,      -- spool byte offset == Last-Event-ID
    ts            TEXT,
    event         TEXT NOT NULL,
    session_id    TEXT,
    tool          TEXT,
    rule          TEXT,
    action        TEXT,
    request_id    TEXT,
    reason        TEXT,
    body          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_events_session ON events(session_id, event_offset);
CREATE INDEX IF NOT EXISTS ix_events_event   ON events(event, event_offset);
CREATE INDEX IF NOT EXISTS ix_events_tool    ON events(tool, event_offset);

CREATE TABLE IF NOT EXISTS sessions (
    session_id     TEXT PRIMARY KEY,
    first_ts       TEXT,
    last_ts        TEXT,
    event_count    BIGINT NOT NULL DEFAULT 0,
    allowed_count  BIGINT NOT NULL DEFAULT 0,
    blocked_count  BIGINT NOT NULL DEFAULT 0,
    tainted        BOOLEAN NOT NULL DEFAULT FALSE,
    suspended      BOOLEAN NOT NULL DEFAULT FALSE,
    risk_score     BIGINT NOT NULL DEFAULT 0,
    risk_level     TEXT NOT NULL DEFAULT 'NORMAL'
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

_ALLOWED = "tool_call_allowed"
_BLOCKED = "tool_call_blocked"
_BLOCKED_SUSPENDED = "tool_call_denied_session_suspended"
_SUSPENDED = "session_suspended"
_TAINTED = "session_tainted"
_APPROVAL = "approval_requested"


# ---------------------------------------------------------------- pure helpers
def event_columns(rec: SpoolRecord) -> tuple:
    """The (10) column values for one events row — pure, DB-agnostic, testable."""
    ev = rec.event
    return (
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
    )


def rollup_values(current: dict[str, Any] | None, ev: dict[str, Any]) -> dict[str, Any]:
    """Fold one event into a session roll-up row. Pure — the SQL layer just
    persists the result. `current` is the existing row (or None for a new one)."""
    name = ev.get("event")
    ts = ev.get("ts")
    base = current or {
        "first_ts": ts, "last_ts": ts, "event_count": 0,
        "allowed_count": 0, "blocked_count": 0, "tainted": False,
        "suspended": False, "risk_score": 0, "risk_level": "NORMAL",
    }
    return {
        "first_ts": base["first_ts"],
        "last_ts": ts or base["last_ts"],
        "event_count": base["event_count"] + 1,
        "allowed_count": base["allowed_count"] + (1 if name == _ALLOWED else 0),
        "blocked_count": base["blocked_count"]
        + (1 if name in (_BLOCKED, _BLOCKED_SUSPENDED) else 0),
        "tainted": bool(base["tainted"] or name == _TAINTED),
        "suspended": bool(base["suspended"] or name == _SUSPENDED),
        "risk_score": int(ev.get("session_score", base["risk_score"])),
        "risk_level": str(ev.get("session_level", base["risk_level"])),
    }


def hydrate(offset: int, body: str) -> dict[str, Any]:
    event = json.loads(body)
    event["offset"] = offset
    return event


def session_row(r: dict[str, Any]) -> dict[str, Any]:
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


class PostgresAuditIndex:
    """A Postgres-backed audit index. Same query surface as `AuditIndex`."""

    def __init__(self, dsn: str):
        try:
            import psycopg
        except ModuleNotFoundError as exc:  # pragma: no cover
            raise RuntimeError(
                "the postgres index needs the [postgres] extra: "
                "pip install 'mcp-gateway[postgres]'"
            ) from exc
        self._conn = psycopg.connect(dsn, autocommit=True)
        self._conn.row_factory = psycopg.rows.dict_row
        with self._conn.cursor() as cur:
            cur.execute(_SCHEMA)

    # ------------------------------------------------------------- ingest
    def next_offset(self) -> int:
        with self._conn.cursor() as cur:
            cur.execute("SELECT value FROM meta WHERE key='next_offset'")
            row = cur.fetchone()
        return int(row["value"]) if row else 0

    def _set_next_offset(self, offset: int) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO meta(key, value) VALUES('next_offset', %s) "
                "ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                (str(offset),),
            )

    def ingest(self, records: list[SpoolRecord]) -> int:
        inserted = 0
        with self._conn.cursor() as cur:
            for rec in records:
                cur.execute(
                    "INSERT INTO events(event_offset, ts, event, session_id, tool, "
                    "rule, action, request_id, reason, body) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                    "ON CONFLICT(event_offset) DO NOTHING",
                    event_columns(rec),
                )
                if cur.rowcount:
                    inserted += 1
                    self._roll_up(cur, rec.event)
        return inserted

    def _roll_up(self, cur, ev: dict[str, Any]) -> None:
        session_id = ev.get("session_id")
        if not session_id:
            return
        cur.execute("SELECT * FROM sessions WHERE session_id=%s", (session_id,))
        current = cur.fetchone()
        vals = rollup_values(current, ev)
        if current is None:
            cur.execute(
                "INSERT INTO sessions(session_id, first_ts, last_ts, event_count, "
                "allowed_count, blocked_count, tainted, suspended, risk_score, risk_level) "
                "VALUES (%(sid)s,%(first_ts)s,%(last_ts)s,%(event_count)s,%(allowed_count)s,"
                "%(blocked_count)s,%(tainted)s,%(suspended)s,%(risk_score)s,%(risk_level)s)",
                {"sid": session_id, **vals},
            )
        else:
            cur.execute(
                "UPDATE sessions SET last_ts=%(last_ts)s, event_count=%(event_count)s, "
                "allowed_count=%(allowed_count)s, blocked_count=%(blocked_count)s, "
                "tainted=%(tainted)s, suspended=%(suspended)s, risk_score=%(risk_score)s, "
                "risk_level=%(risk_level)s WHERE session_id=%(sid)s",
                {"sid": session_id, **vals},
            )

    def catch_up(self, spool_path) -> dict[str, Any]:
        result = read_spool(spool_path, start=self.next_offset())
        inserted = self.ingest(result.records)
        self._set_next_offset(result.next_offset)
        return {"inserted": inserted, "next_offset": result.next_offset,
                "bad_lines": result.bad_lines, "torn_tail": result.torn_tail}

    def rebuild(self, spool_path) -> dict[str, Any]:
        with self._conn.cursor() as cur:
            cur.execute("TRUNCATE events, sessions, meta")
        return self.catch_up(spool_path)

    # -------------------------------------------------------------- queries
    def query_events(
        self, *, session_id=None, event=None, tool=None, after=None,
        limit=100, ascending=False,
    ) -> list[dict[str, Any]]:
        clauses, params = [], []
        if session_id is not None:
            clauses.append("session_id=%s")
            params.append(session_id)
        if event is not None:
            clauses.append("event=%s")
            params.append(event)
        if tool is not None:
            clauses.append("tool=%s")
            params.append(tool)
        if after is not None:
            clauses.append("event_offset > %s" if ascending else "event_offset < %s")
            params.append(after)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        order = "ASC" if ascending else "DESC"
        params.append(max(1, min(limit, 1000)))
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT event_offset, body FROM events {where} "
                f"ORDER BY event_offset {order} LIMIT %s",
                params,
            )
            rows = cur.fetchall()
        return [hydrate(r["event_offset"], r["body"]) for r in rows]

    def get_event(self, offset: int) -> dict[str, Any] | None:
        with self._conn.cursor() as cur:
            cur.execute("SELECT event_offset, body FROM events WHERE event_offset=%s", (offset,))
            row = cur.fetchone()
        return hydrate(row["event_offset"], row["body"]) if row else None

    def latest_offset(self) -> int:
        with self._conn.cursor() as cur:
            cur.execute("SELECT MAX(event_offset) AS m FROM events")
            row = cur.fetchone()
        return int(row["m"]) if row and row["m"] is not None else 0

    def list_sessions(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM sessions ORDER BY last_ts DESC LIMIT %s",
                (max(1, min(limit, 1000)),),
            )
            rows = cur.fetchall()
        return [session_row(r) for r in rows]

    def session_detail(self, session_id: str, limit: int = 500) -> dict[str, Any] | None:
        with self._conn.cursor() as cur:
            cur.execute("SELECT * FROM sessions WHERE session_id=%s", (session_id,))
            row = cur.fetchone()
        if row is None:
            return None
        summary = session_row(row)
        summary["events"] = self.query_events(session_id=session_id, limit=limit, ascending=True)
        return summary

    def approval_history(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.query_events(event=_APPROVAL, limit=limit)

    def counts_by_event(self) -> dict[str, int]:
        with self._conn.cursor() as cur:
            cur.execute("SELECT event, COUNT(*) AS n FROM events GROUP BY event")
            rows = cur.fetchall()
        return {r["event"]: r["n"] for r in rows}

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> PostgresAuditIndex:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
