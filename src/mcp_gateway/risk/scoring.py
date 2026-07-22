"""Per-session risk scoring with auto-suspend.

Individual events carry weights; a session accumulates a score from 0; crossing
thresholds changes enforcement posture:

  0..49    NORMAL     evaluated by policy as usual
  50..79   ELEVATED   flagged for review in audit
  80+      SUSPENDED  every subsequent tool call is denied, regardless of what
                      static policy would allow — one misbehaving agent cannot
                      keep probing.

This turns the gateway from a static allowlist into an adaptive control: one
blocked call is noise, five in a burst is an incident. Weights and thresholds
are policy-configurable (`risk:` in the policy document); the engine operates
on a Session's mutable risk fields so a future Redis-backed store can make the
same updates atomically (docs/ARCHITECTURE.md §2, §6.2).
"""

from __future__ import annotations

from dataclasses import dataclass

# Risk event names (also the keys of the weights table).
BLOCKED_TOOL = "blocked_tool"
CONSTRAINT_VIOLATION = "constraint_violation"
SEQUENCE_VIOLATION = "sequence_violation"
APPROVAL_DENIED = "approval_denied"
HEAVY_REDACTION = "heavy_redaction"
ANOMALY_LOW = "anomaly_low"
ANOMALY_MEDIUM = "anomaly_medium"
ANOMALY_HIGH = "anomaly_high"

DEFAULT_WEIGHTS: dict[str, int] = {
    BLOCKED_TOOL: 25,           # tried a tool it has no right to call
    CONSTRAINT_VIOLATION: 20,   # allowed tool, forbidden arguments
    SEQUENCE_VIOLATION: 30,     # taint/sequence gate fired (exfil-shaped)
    APPROVAL_DENIED: 25,        # a human declined a required-approval call
    HEAVY_REDACTION: 5,         # a result carried many PII entities
    ANOMALY_LOW: 10,
    ANOMALY_MEDIUM: 25,
    ANOMALY_HIGH: 45,
}

DEFAULT_ELEVATED_AT = 50
DEFAULT_SUSPEND_AT = 80

LEVEL_NORMAL = "normal"
LEVEL_ELEVATED = "elevated"
LEVEL_SUSPENDED = "suspended"


@dataclass(frozen=True, slots=True)
class RiskUpdate:
    """The result of recording one event — everything audit needs."""

    event: str
    weight: int
    score: int
    level: str
    suspended_now: bool  # True only on the transition into SUSPENDED

    def audit_fields(self) -> dict[str, object]:
        return {
            "risk_event": self.event,
            "risk_delta": self.weight,
            "session_score": self.score,
            "session_level": self.level,
        }


class RiskEngine:
    def __init__(
        self,
        weights: dict[str, int] | None = None,
        elevated_at: int = DEFAULT_ELEVATED_AT,
        suspend_at: int = DEFAULT_SUSPEND_AT,
    ):
        self.weights = {**DEFAULT_WEIGHTS, **(weights or {})}
        self.elevated_at = elevated_at
        self.suspend_at = suspend_at

    def level(self, score: int) -> str:
        if score >= self.suspend_at:
            return LEVEL_SUSPENDED
        if score >= self.elevated_at:
            return LEVEL_ELEVATED
        return LEVEL_NORMAL

    def record(self, session, event: str, detail: str = "") -> RiskUpdate:
        """Add an event to the session's score; may flip it to SUSPENDED."""
        weight = self.weights.get(event, 0)
        was_suspended = session.suspended
        session.risk_score += weight
        session.risk_events.append(
            {"event": event, "weight": weight, "detail": detail}
        )
        level = self.level(session.risk_score)
        newly_suspended = level == LEVEL_SUSPENDED and not was_suspended
        if newly_suspended:
            session.suspended = True
        return RiskUpdate(
            event=event, weight=weight, score=session.risk_score,
            level=level, suspended_now=newly_suspended,
        )
