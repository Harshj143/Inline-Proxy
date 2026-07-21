"""Stage outcome types, shared by the pipeline runner and action handlers.

Lives in its own module so `policy.actions` (which produce outcomes) and
`core.pipeline` (which consumes them) don't import each other.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Verdict(Enum):
    CONTINUE = "continue"
    DENY = "deny"


@dataclass(slots=True)
class StageOutcome:
    verdict: Verdict
    reason: str = ""
    # Which stage terminated the call; filled in by the pipeline runner.
    stage: str = ""

    @property
    def denied(self) -> bool:
        return self.verdict is Verdict.DENY


def proceed() -> StageOutcome:
    return StageOutcome(Verdict.CONTINUE)


def deny(reason: str) -> StageOutcome:
    return StageOutcome(Verdict.DENY, reason=reason)
