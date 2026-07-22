"""The Operator interface.

An operator maps a detected span to its replacement string. Operators are
stateless and deterministic given their configuration — the same input always
produces the same output, which is what lets a hashed value be correlated
across a session without ever revealing it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from mcp_gateway.redaction.spans import Span


class Operator(ABC):
    #: Unique registry name (referenced from profiles/policy).
    name: str

    @abstractmethod
    def apply(self, span: Span) -> str:
        """Return the replacement text for this span's matched value."""
