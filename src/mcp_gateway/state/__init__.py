"""Session state storage.

Phase 3 ships the in-memory store (one process, the sidecar case). The
interface is deliberately the seam Phase 5 fills with Redis so risk and taint
follow an agent across gateway replicas (docs/SYSTEM_DESIGN.md §6.2). Until
then the memory store returns a live Session and mutations persist naturally;
a Redis store will return a snapshot and commit explicitly.
"""

from mcp_gateway.state.base import SessionStore
from mcp_gateway.state.memory import MemorySessionStore

__all__ = ["MemorySessionStore", "SessionStore"]
