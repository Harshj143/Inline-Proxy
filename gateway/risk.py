"""Per-session risk scoring for agent behavior.

Mirrors the composite entity risk scoring pattern from cloud detection
engineering: individual events carry weights, the session accumulates a
score from 0 upward, and crossing thresholds changes enforcement posture.

  0-49   NORMAL      requests evaluated by policy as usual
  50-79  ELEVATED    audit events flag the session for review
  80+    SUSPENDED   every subsequent tool call is denied, regardless of
                     policy. A single misbehaving agent cannot keep probing.

This turns the gateway from a static allowlist into an adaptive control:
one blocked call is noise, five in a minute is an incident.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Event weights. Tune to taste; these mirror severity-weighted alerting.
WEIGHTS = {
    "blocked_tool": 25,        # tried a tool it has no right to call
    "constraint_violation": 20,  # allowed tool, forbidden arguments
    "heavy_redaction": 5,      # result contained 3+ PII entities
    "approval_denied": 25,     # a human declined a required-approval call
    # Behavioral anomaly flagged by the LLM monitor. Weighted by severity so a
    # confident "this is an attack" can push a session to SUSPENDED on its own.
    "anomaly_low": 10,
    "anomaly_medium": 25,
    "anomaly_high": 45,
}

ELEVATED_AT = 50
SUSPEND_AT = 80


@dataclass
class SessionRisk:
    score: int = 0
    events: list[dict] = field(default_factory=list)
    suspended: bool = False

    @property
    def level(self) -> str:
        if self.score >= SUSPEND_AT:
            return "SUSPENDED"
        if self.score >= ELEVATED_AT:
            return "ELEVATED"
        return "NORMAL"

    def record(self, event: str, detail: str = "") -> dict:
        """Add a risk event. Returns a summary for the audit log."""
        weight = WEIGHTS.get(event, 0)
        self.score += weight
        self.events.append({"event": event, "weight": weight, "detail": detail})
        crossed_suspend = (not self.suspended) and self.score >= SUSPEND_AT
        if crossed_suspend:
            self.suspended = True
        return {
            "risk_event": event,
            "weight": weight,
            "session_score": self.score,
            "session_level": self.level,
            "suspended_now": crossed_suspend,
        }
