"""The SessionStore interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mcp_gateway.core.session import Session


class SessionStore(ABC):
    @abstractmethod
    def get_or_create(self, session_id: str) -> Session:
        """Return the session for this id, creating it if absent."""

    @abstractmethod
    def get(self, session_id: str) -> Session | None:
        """Return the session, or None if unknown (no creation)."""

    def save(self, session: Session) -> None:
        """Persist a session's durable state after a mutation.

        A no-op for stores that hold live objects (the in-memory store); a
        shared store (Redis) overrides this to write taint/risk/suspension back
        so another replica binding the same id resumes it (Phase 5c). The
        gateway calls it after handling each message.
        """
        return None
