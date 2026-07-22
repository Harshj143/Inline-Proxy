"""In-process session store — the sidecar default."""

from __future__ import annotations

from mcp_gateway.core.session import Session
from mcp_gateway.state.base import SessionStore


class MemorySessionStore(SessionStore):
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}

    def get_or_create(self, session_id: str) -> Session:
        session = self._sessions.get(session_id)
        if session is None:
            session = Session.new(session_id=session_id)
            self._sessions[session_id] = session
        return session

    def get(self, session_id: str) -> Session | None:
        return self._sessions.get(session_id)
