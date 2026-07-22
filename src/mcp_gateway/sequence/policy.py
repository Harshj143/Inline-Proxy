"""Taint tracking and sequence-aware policy — session-state controls.

Two controls that catch attacks no single tool call reveals on its own.

TAINT TRACKING breaks the "lethal trifecta" (access to private data + exposure
to untrusted content + ability to communicate externally = exfiltration). Once
a session calls a taint SOURCE (a tool that ingests untrusted outside content —
`web.fetch`, `get_issue`), the session is marked tainted, and taint SINKS
(anything that sends data out or mutates state — `http.post`, `push_files`) are
blocked until a human clears the session. The gateway never has to detect the
prompt injection itself; it refuses to let a possibly-compromised session
complete the exfiltration.

SEQUENCE RULES catch ordered patterns independent of taint: "forbid tool B once
tool A has run this session" — e.g. no outbound POST after reading customer PII.
A tiny state machine over the tool-call history.

Patterns support globs (fnmatch) so a rule can name `github.*` sinks without
listing every tool.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass


def _matches_any(tool: str, patterns: frozenset[str]) -> bool:
    return any(fnmatch.fnmatch(tool, p) for p in patterns)


@dataclass(frozen=True, slots=True)
class SequenceRule:
    after: str    # once a tool matching this has been called...
    forbid: str   # ...a tool matching this is blocked for the rest of the session
    reason: str = ""


class SequencePolicy:
    def __init__(
        self,
        taint_sources: list[str] | None = None,
        taint_sinks: list[str] | None = None,
        sequence_rules: list[dict] | None = None,
    ):
        self.taint_sources = frozenset(taint_sources or ())
        self.taint_sinks = frozenset(taint_sinks or ())
        self.sequence_rules = [
            SequenceRule(after=r["after"], forbid=r["forbid"], reason=r.get("reason", ""))
            for r in (sequence_rules or [])
        ]

    @property
    def active(self) -> bool:
        return bool(self.taint_sources or self.taint_sinks or self.sequence_rules)

    def is_taint_source(self, tool: str) -> bool:
        return _matches_any(tool, self.taint_sources)

    def check(self, tool: str, session) -> str | None:
        """Return a block reason if the session state forbids this call, else None."""
        if session.tainted and _matches_any(tool, self.taint_sinks):
            return (
                f"outbound/mutating tool '{tool}' blocked: session is tainted "
                f"(untrusted content ingested via '{session.taint_origin}'); "
                f"a human must clear the session"
            )
        for rule in self.sequence_rules:
            if fnmatch.fnmatch(tool, rule.forbid) and any(
                fnmatch.fnmatch(prev, rule.after) for prev in session.history
            ):
                return rule.reason or (
                    f"'{tool}' is forbidden after '{rule.after}' in the same session"
                )
        return None
