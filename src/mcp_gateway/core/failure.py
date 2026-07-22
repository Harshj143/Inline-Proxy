"""Configurable failure posture — fail-closed (default) vs fail-open.

A security control has to decide what happens when the control ITSELF errors:
a plugin throws, the redaction engine chokes, the approver is unreachable. Two
philosophies:

  fail-closed (default)  on error, DENY/WITHHOLD. Safe: an error never becomes
                         an unintended allow. The right default for a security
                         product.
  fail-open              on error, ALLOW/RELEASE. Availability over security:
                         "if the gateway breaks, I'd rather my agents keep
                         working than be blocked." A legitimate but RISKY
                         choice a customer makes for themselves.

This posture is scoped deliberately narrowly. It governs ONLY unexpected
runtime errors at three points (pipeline stage crash, redaction failure,
approver unavailable). It does NOT — and must not — affect:

  * policy validation errors (a typo refuses startup, always);
  * unknown/unimplemented actions (always blocked);
  * unmatched tools (governed by `default_action`, already a customer choice);
  * legitimate policy denials (the control working correctly).

Those are config bugs or the control doing its job — "fail-open on a typo" is
never intended, so they are never overridable.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class FailMode(StrEnum):
    CLOSED = "closed"   # on error: deny / withhold (safe default)
    OPEN = "open"       # on error: allow / release (explicit customer risk)


_CATEGORIES = ("pipeline", "redaction", "approval")


@dataclass(frozen=True, slots=True)
class FailurePosture:
    # Each governs UNEXPECTED runtime errors at that point only.
    pipeline: FailMode = FailMode.CLOSED     # a request-stage plugin raised
    redaction: FailMode = FailMode.CLOSED    # a detector crashed / over budget
    approval: FailMode = FailMode.CLOSED     # the approver was unreachable/timed out

    @property
    def any_open(self) -> bool:
        return any(getattr(self, c) is FailMode.OPEN for c in _CATEGORIES)

    def open_categories(self) -> list[str]:
        return [c for c in _CATEGORIES if getattr(self, c) is FailMode.OPEN]

    @classmethod
    def from_config(cls, config: object) -> FailurePosture:
        """Build from a validated `on_failure` value: a mode string (global) or
        a mapping with an optional `default` plus per-category overrides."""
        if config is None:
            return cls()
        if isinstance(config, str):
            m = FailMode(config)
            return cls(pipeline=m, redaction=m, approval=m)
        default = FailMode(config.get("default", "closed"))
        return cls(**{c: FailMode(config.get(c, default)) for c in _CATEGORIES})

    def describe(self) -> dict[str, str]:
        return {c: str(getattr(self, c)) for c in _CATEGORIES}
