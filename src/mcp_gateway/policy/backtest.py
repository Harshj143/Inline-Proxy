"""Policy backtest: replay recorded calls through a policy, diff the decisions.

The question a backtest answers is *blast radius*: "if I deploy this policy,
which calls that my gateway has actually seen would be decided differently?"
It reads the recorded tool calls from an audit spool and re-evaluates each one
against a candidate policy, then reports what flips.

What it can and cannot replay — stated plainly, because a security tool that
overstates its coverage is worse than one that is honest:

  * **Replayed:** tool-name matching + role overlay → the policy *action*. This
    is the matcher and the rule table, the part of a policy people actually
    edit and get wrong.
  * **NOT replayed:** argument *constraints*, *taint/sequence* gating, and
    *approval* outcomes. The audit trail is counts-only — it never stored the
    arguments or the live session state — so those cannot be reconstructed. A
    call the old policy blocked at the constraints or sequence stage is flagged
    (`old_stage`) so a reviewer knows a "newly allowed" line there is an
    action-level statement, not a promise the call would truly pass.

Decisions are compared at two levels: the exact *action string* (so `allow` →
`redact` shows up) and the coarse *allow/deny disposition* (so the headline
"12 calls newly blocked" is unambiguous). Identical calls collapse to one row
with a `count`, so a session that made the same call 100 times is one finding.

Pure engine + stdlib. No server dependency.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mcp_gateway.audit.reader import read_spool
from mcp_gateway.policy.actions import denying_actions
from mcp_gateway.policy.engine import PolicyEngine

# Audit event names that represent a decided tool call.
_ALLOWED = "tool_call_allowed"
_BLOCKED = "tool_call_blocked"
_BLOCKED_SUSPENDED = "tool_call_denied_session_suspended"


@dataclass(frozen=True, slots=True)
class ReplayedCall:
    tool: str
    role: str | None
    old_outcome: str        # "allowed" | "blocked"
    old_action: str | None  # recorded action (allowed calls only)
    old_stage: str | None   # stage that blocked it (blocked calls only)
    new_action: str
    new_outcome: str        # "allowed" | "blocked"
    count: int
    changed: bool
    change_kind: str        # "unchanged" | "newly_blocked" | "newly_allowed"
    #                         | "action_changed"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class BacktestReport:
    policy_source: str
    calls_examined: int          # total decided calls in the log (pre-dedup)
    distinct_calls: int          # rows after collapsing identical calls
    changed: list[ReplayedCall] = field(default_factory=list)
    unchanged: int = 0
    newly_blocked: int = 0
    newly_allowed: int = 0
    action_changed: int = 0
    bad_lines: int = 0
    note: str = (
        "Action-level backtest: argument constraints, taint/sequence gating, "
        "and approval outcomes are NOT replayed (audit is counts-only)."
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_source": self.policy_source,
            "calls_examined": self.calls_examined,
            "distinct_calls": self.distinct_calls,
            "summary": {
                "unchanged": self.unchanged,
                "newly_blocked": self.newly_blocked,
                "newly_allowed": self.newly_allowed,
                "action_changed": self.action_changed,
            },
            "changed": [c.to_dict() for c in self.changed],
            "bad_lines": self.bad_lines,
            "note": self.note,
        }


def _outcome(action: str, deny_set: frozenset[str]) -> str:
    return "blocked" if action in deny_set else "allowed"


def backtest_policy(
    audit_path: str | Path,
    engine: PolicyEngine,
    *,
    deny_set: frozenset[str] | None = None,
) -> BacktestReport:
    """Replay every recorded call in `audit_path` through `engine`.

    `deny_set` overrides which actions count as a denial for the new-outcome
    disposition; it defaults to the action registry's deny-only set (`redact`
    and `require_approval` are deny-only there unless a service backs them, so
    a deployment that wires those services should pass a narrower set).
    """
    deny = deny_set if deny_set is not None else denying_actions()
    result = read_spool(audit_path)

    # Collapse identical calls: (tool, role, old_outcome, old_action, old_stage).
    buckets: dict[tuple, int] = {}
    examined = 0
    for rec in result.records:
        ev = rec.event
        name = ev.get("event")
        if name == _ALLOWED:
            key = (ev.get("tool"), ev.get("role"), "allowed", ev.get("action"), None)
        elif name in (_BLOCKED, _BLOCKED_SUSPENDED):
            key = (ev.get("tool"), ev.get("role"), "blocked", None, ev.get("stage"))
        else:
            continue
        if key[0] is None:
            continue
        examined += 1
        buckets[key] = buckets.get(key, 0) + 1

    report = BacktestReport(
        policy_source=engine.source,
        calls_examined=examined,
        distinct_calls=len(buckets),
        bad_lines=result.bad_lines,
    )

    for (tool, role, old_outcome, old_action, old_stage), count in buckets.items():
        decision = engine.evaluate(tool, {}, role=role)
        new_action = decision.action
        new_outcome = _outcome(new_action, deny)

        if old_outcome != new_outcome:
            kind = "newly_blocked" if new_outcome == "blocked" else "newly_allowed"
            changed = True
        elif old_outcome == "allowed" and old_action is not None and old_action != new_action:
            kind = "action_changed"
            changed = True
        else:
            kind = "unchanged"
            changed = False

        call = ReplayedCall(
            tool=tool, role=role, old_outcome=old_outcome, old_action=old_action,
            old_stage=old_stage, new_action=new_action, new_outcome=new_outcome,
            count=count, changed=changed, change_kind=kind,
        )
        if not changed:
            report.unchanged += 1
            continue
        report.changed.append(call)
        if kind == "newly_blocked":
            report.newly_blocked += 1
        elif kind == "newly_allowed":
            report.newly_allowed += 1
        else:
            report.action_changed += 1

    # Most disruptive first: blocks, then allows, then action tweaks; by volume.
    order = {"newly_blocked": 0, "newly_allowed": 1, "action_changed": 2}
    report.changed.sort(key=lambda c: (order.get(c.change_kind, 9), -c.count))
    return report


def format_report(report: BacktestReport) -> str:
    """Human-readable backtest summary for the CLI."""
    lines = [
        f"policy:   {report.policy_source}",
        f"examined: {report.calls_examined} recorded call(s), "
        f"{report.distinct_calls} distinct",
        f"changed:  {report.newly_blocked} newly blocked, "
        f"{report.newly_allowed} newly allowed, "
        f"{report.action_changed} action changed  "
        f"({report.unchanged} unchanged)",
    ]
    if report.bad_lines:
        lines.append(f"warning:  {report.bad_lines} unparseable spool line(s) skipped")
    if report.changed:
        lines.append("")
        width = max((len(c.tool) for c in report.changed), default=10)
        for c in report.changed:
            role = f" [{c.role}]" if c.role else ""
            arrow = f"{c.old_action or c.old_outcome} -> {c.new_action}"
            stage = f" (was blocked at {c.old_stage})" if c.old_stage else ""
            lines.append(
                f"  {c.change_kind:<14} {c.tool:<{width}}{role}  "
                f"{arrow}  x{c.count}{stage}"
            )
    lines.append("")
    lines.append(f"note: {report.note}")
    return "\n".join(lines)
