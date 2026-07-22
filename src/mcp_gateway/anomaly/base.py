"""Anomaly backend interface and value objects."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

SEVERITIES = ("low", "medium", "high")


@dataclass(frozen=True, slots=True)
class SessionTrace:
    """What the monitor is shown about the session so far."""

    history: list[str] = field(default_factory=list)  # allowed tool calls, in order
    last_tool: str = ""
    tainted: bool = False
    blocked_count: int = 0

    def to_prompt_json(self) -> dict[str, object]:
        return {
            "tool_call_history": self.history,
            "most_recent_call": self.last_tool,
            "session_tainted_by_untrusted_content": self.tainted,
            "policy_blocks_so_far": self.blocked_count,
        }


@dataclass(frozen=True, slots=True)
class Verdict:
    anomalous: bool
    severity: str  # one of SEVERITIES
    rationale: str


class AnomalyBackend(ABC):
    #: Name reported in audit (may differ from the requested mode after fallback).
    name: str

    @property
    def available(self) -> bool:
        return True

    @abstractmethod
    async def assess(self, trace: SessionTrace) -> Verdict | None:
        """Judge the session. Return a Verdict, or None to abstain."""
