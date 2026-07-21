"""The Constraint interface.

Constraints are request-stage checks on WHAT an allowed tool is doing, not
WHICH tool it is (that's the matcher's job). They run before rewrites, on
the arguments as the agent sent them: a rewrite must never be able to
launder a call past a constraint.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Constraint(ABC):
    #: Config `type:` value this class handles; unique across the registry.
    type_name: str

    @classmethod
    @abstractmethod
    def from_config(cls, config: dict[str, Any], where: str) -> Constraint:
        """Validate config at policy-load time (typos must not reach runtime)."""

    @abstractmethod
    def check(self, arguments: dict[str, Any]) -> str | None:
        """Return a violation reason, or None if the call passes."""

    @abstractmethod
    def describe(self) -> dict[str, Any]:
        """A JSON-safe summary for `policy show` and the console."""
