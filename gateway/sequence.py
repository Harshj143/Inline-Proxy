"""Taint tracking and sequence-aware policy for agent sessions.

Two related session-state controls that catch attacks no single tool call
reveals on its own.

TAINT TRACKING
--------------
The core insight of agent security: once a session ingests untrusted
external content (a web page, an email, a document), the agent's later
behavior can no longer be fully trusted, because a prompt injection buried
in that content may now be steering it.

So we track a per-session "tainted" flag. Certain tools are marked as
taint sources in policy (they pull in outside content). Once any of them
runs, the session is tainted, and the request stage tightens: tools marked
as taint sinks (anything that can send data OUT or mutate state) are
blocked until a human clears the session.

This directly targets the "lethal trifecta":
  access to private data  +  exposure to untrusted content  +  ability to
  communicate externally  =  exfiltration risk.
Taint tracking breaks the combination by refusing to let the third element
follow the second.

SEQUENCE POLICIES
-----------------
Some attacks are invisible per-call but obvious as a pattern: read secrets,
THEN reach for a network tool. A sequence rule says "tool <sink> is
forbidden within the session once tool <source> has run", independent of
the taint flag. This is a tiny state machine over the tool-call history.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SequenceRule:
    after: str          # once this tool has been called...
    forbid: str         # ...this tool is forbidden for the rest of the session
    reason: str = ""


@dataclass
class SessionState:
    """Tracks taint and call history for one agent session."""

    tainted: bool = False
    taint_origin: str = ""
    called_tools: set[str] = field(default_factory=set)
    history: list[str] = field(default_factory=list)

    def record_call(self, tool: str) -> None:
        self.called_tools.add(tool)
        self.history.append(tool)

    def mark_tainted(self, origin: str) -> bool:
        """Returns True if this call is what first tainted the session."""
        if self.tainted:
            return False
        self.tainted = True
        self.taint_origin = origin
        return True


class SequencePolicy:
    """Evaluates taint sinks and ordered sequence rules against session state."""

    def __init__(
        self,
        taint_sources: list[str],
        taint_sinks: list[str],
        sequence_rules: list[dict],
    ):
        self.taint_sources = set(taint_sources)
        self.taint_sinks = set(taint_sinks)
        self.sequence_rules = [
            SequenceRule(after=r["after"], forbid=r["forbid"],
                         reason=r.get("reason", ""))
            for r in sequence_rules
        ]

    def is_taint_source(self, tool: str) -> bool:
        return tool in self.taint_sources

    def check(self, tool: str, state: SessionState) -> str | None:
        """Return a denial reason if this call is forbidden, else None."""
        # Taint sink reached while the session is tainted.
        if state.tainted and tool in self.taint_sinks:
            return (
                f"tool '{tool}' can exfiltrate or mutate data and the session "
                f"is tainted (untrusted content entered via "
                f"'{state.taint_origin}'). Blocked until a human clears the "
                f"session."
            )
        # Ordered sequence rules.
        for rule in self.sequence_rules:
            if rule.forbid == tool and rule.after in state.called_tools:
                return rule.reason or (
                    f"tool '{tool}' is forbidden after '{rule.after}' has run "
                    f"in this session"
                )
        return None
