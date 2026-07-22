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
