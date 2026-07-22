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
    # The risk event this denial should score (risk.scoring names); the gateway
    # records it. Empty means "no risk points" (e.g. an already-suspended
    # session — don't punish it twice).
    risk_event: str = ""
    # True when this denial is due to an UNEXPECTED stage exception (a plugin
    # bug), not a policy decision. Only these are subject to the fail-open
    # posture — a legitimate policy block is never overridable.
    internal_error: bool = False

    @property
    def denied(self) -> bool:
        return self.verdict is Verdict.DENY


def proceed() -> StageOutcome:
    return StageOutcome(Verdict.CONTINUE)


def deny(reason: str, risk_event: str = "") -> StageOutcome:
    return StageOutcome(Verdict.DENY, reason=reason, risk_event=risk_event)
