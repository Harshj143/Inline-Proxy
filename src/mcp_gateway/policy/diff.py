"""Blast radius of a policy *change*: what this PR decides differently.

`backtest.py` answers "if I deploy this policy, which calls my gateway has
actually seen would flip?" — the operator's question, and it needs a recorded
audit log. A pull request has no audit log, and the reviewer's question is a
different one anyway: **what does this diff change?** Reading a YAML diff does
not answer it. Layered merge, glob specificity, and role overlays mean a
three-line edit to `roles.yaml` can move a hundred decisions, and deleting a
rule can silently hand a tool to `default_action`.

So this module enumerates decisions instead of reading text. It compiles the
policy on both sides of the change and evaluates every tool across every role
view, then ranks each difference on the project's own least-privilege ladder
(CLAUDE.md): `allow < rewrite/redact < quarantine < require_approval < block`.
Moving *down* the ladder is `loosened` — the direction a security reviewer must
never miss — moving up is `tightened`, and a swap at the same rung (`rewrite` →
`redact`) is `changed`.

The ladder matters because a binary allowed/blocked verdict gets the most common
real edit wrong. `block` → `require_approval` reads as "no change, both refuse"
to a bare gateway, but it is exactly how a tool gets opened up: wire an approver
and a human can now let it through. Ranking catches that; a boolean does not.
Alongside the rank, `crosses_deny_boundary` marks the harder claim — a call that
was refused outright and would now go through with no human in the loop — so the
headline can state that without leaning on it for everything.

Two properties this has that a traffic backtest does not, and one it lacks:

  * **No tool is invisible because nobody called it this week.** The surface is
    the pack's `tools.yaml` inventory plus every literal rule pattern on either
    side, so a rule for a rarely-used destructive tool is diffed like any other.
  * **It sees packs appear and disappear.** Deleting `connectors/<pack>/` deletes
    enforcement, which a text diff makes look like housekeeping. A pack that only
    appeared or vanished is reported by the *shape* of what arrived or left
    (its action distribution), not as N loosened decisions — there is no before
    to rank against, and a new pack adds enforcement rather than weakening it.
  * **It is not weighted by reality.** Ten decisions that flip on a tool nobody
    calls read the same as one on the hot path. `policy backtest --audit` is
    still the tool for "and how much does that matter here?".

Same honesty limit as the backtester, for the same reason: this is **action
level**. Argument constraints, taint/sequence gating, and approval outcomes
depend on runtime state that neither side can reconstruct, so a rule whose
constraints changed but whose action did not shows up as unchanged. The rendered
output says so rather than letting a green "no changes" imply more than it means.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from mcp_gateway.core.errors import GatewayError
from mcp_gateway.policy.backtest import declared_roles, effective_deny_set
from mcp_gateway.policy.ci import Target, discover_targets
from mcp_gateway.policy.engine import PolicyEngine

# Change kinds, most to least alarming.
LOOSENED = "loosened"
TIGHTENED = "tightened"
CHANGED_KIND = "changed"

# Pack-level states.
ADDED = "added"
REMOVED = "removed"
CHANGED = "changed"
UNCHANGED = "unchanged"
BROKEN = "broken"

# The least-privilege ladder from CLAUDE.md: prefer the weakest action that
# works. A policy edit is graded by which way it moves along this, so
# `block` -> `require_approval` is correctly read as opening a tool up rather
# than as a lateral no-op. Unknown actions (a future handler) sort as unranked
# and fall back to `changed` rather than guessing a direction.
STRENGTH = {
    "allow": 0,
    "rewrite": 1,
    "redact": 1,
    "quarantine": 2,
    "require_approval": 3,
    "block": 4,
}

_ORDER = {LOOSENED: 0, TIGHTENED: 1, CHANGED_KIND: 2}
_MAX_ROWS = 40  # a PR comment that lists 400 rows is a PR comment nobody reads


@dataclass(frozen=True, slots=True)
class ChangedDecision:
    tool: str
    role: str | None
    base_action: str
    head_action: str
    kind: str
    crosses_deny_boundary: bool  # was refused outright, now goes through un-gated

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool, "role": self.role,
            "base_action": self.base_action, "head_action": self.head_action,
            "kind": self.kind, "crosses_deny_boundary": self.crosses_deny_boundary,
        }


@dataclass(slots=True)
class PackDiff:
    name: str
    state: str
    decisions_examined: int = 0
    role_views: int = 0
    changed: list[ChangedDecision] = field(default_factory=list)
    unchanged: int = 0
    error: str | None = None
    # For a pack that only appeared or vanished: how its decisions break down by
    # action. There is no before/after to rank per decision, so the shape of what
    # arrived (or left) is the useful summary instead.
    action_summary: dict[str, int] = field(default_factory=dict)

    @property
    def loosened(self) -> int:
        return sum(1 for c in self.changed if c.kind == LOOSENED)

    @property
    def tightened(self) -> int:
        return sum(1 for c in self.changed if c.kind == TIGHTENED)

    @property
    def lateral(self) -> int:
        return sum(1 for c in self.changed if c.kind == CHANGED_KIND)

    @property
    def newly_allowed(self) -> int:
        """Decisions that were refused and would now go through with no gate."""
        return sum(1 for c in self.changed if c.crosses_deny_boundary)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "state": self.state,
            "decisions_examined": self.decisions_examined,
            "role_views": self.role_views,
            "summary": {
                "loosened": self.loosened,
                "tightened": self.tightened,
                "changed": self.lateral,
                "newly_allowed": self.newly_allowed,
                "unchanged": self.unchanged,
            },
            "changed": [c.to_dict() for c in self.changed],
            "action_summary": self.action_summary,
            "error": self.error,
        }


@dataclass(slots=True)
class RepoDiff:
    base_root: Path
    head_root: Path
    packs: list[PackDiff] = field(default_factory=list)

    @property
    def touched(self) -> list[PackDiff]:
        return [p for p in self.packs if p.state != UNCHANGED]

    @property
    def loosened(self) -> int:
        return sum(p.loosened for p in self.packs)

    @property
    def tightened(self) -> int:
        return sum(p.tightened for p in self.packs)

    @property
    def lateral(self) -> int:
        return sum(p.lateral for p in self.packs)

    @property
    def newly_allowed(self) -> int:
        return sum(p.newly_allowed for p in self.packs)

    @property
    def clean(self) -> bool:
        """No decision anywhere changed and no pack appeared or vanished."""
        return not self.touched

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_root": str(self.base_root),
            "head_root": str(self.head_root),
            "clean": self.clean,
            "summary": {
                "loosened": self.loosened,
                "tightened": self.tightened,
                "changed": self.lateral,
                "newly_allowed": self.newly_allowed,
                "packs_touched": len(self.touched),
            },
            "packs": [p.to_dict() for p in self.packs],
            "note": NOTE,
        }


NOTE = (
    "Action-level diff over each pack's full tool surface. Argument constraints, "
    "taint/sequence gating, and approval outcomes are not evaluated (they depend "
    "on runtime state), so a rule whose constraints changed but whose action did "
    "not is reported as unchanged."
)


# ---------------------------------------------------------------- the surface
def _tool_surface(target: Target | None, engine: PolicyEngine | None) -> set[str]:
    """Every tool name worth evaluating for one side of the diff.

    The inventory is the real surface; literal rule patterns are added because a
    policy may (legitimately) rule on a tool the inventory has not caught up to,
    and that rule still needs diffing. Glob patterns cannot be enumerated — they
    are covered through whichever concrete tools they match.
    """
    tools: set[str] = set()
    if target is not None and target.connector is not None:
        # A broken inventory is the coverage check's finding, not ours.
        with contextlib.suppress(GatewayError):
            tools.update(target.connector.tools())
    if engine is not None:
        for rule in engine.describe().get("rules", []):
            pattern = rule.get("pattern", "")
            if pattern and not any(ch in pattern for ch in "*?["):
                tools.add(pattern)
    return tools


def _glob_only_patterns(engine: PolicyEngine | None) -> list[str]:
    if engine is None:
        return []
    return [
        r["pattern"] for r in engine.describe().get("rules", [])
        if any(ch in r.get("pattern", "") for ch in "*?[")
    ]


def _compile(target: Target | None) -> tuple[PolicyEngine | None, str | None]:
    if target is None:
        return None, None
    if target.error:
        return None, target.error
    try:
        return PolicyEngine.load(list(target.layers)), None
    except GatewayError as exc:
        return None, str(exc)


# ------------------------------------------------------------------ the diff
def diff_pack(
    name: str, base: Target | None, head: Target | None
) -> PackDiff:
    """Diff one pack's decisions between two revisions of the repo."""
    base_engine, base_error = _compile(base)
    head_engine, head_error = _compile(head)

    if head_error or (base_error and base is not None and head is None):
        # A head that will not compile is `policy ci`'s failure to report; here
        # it just means there is nothing trustworthy to diff against.
        return PackDiff(name=name, state=BROKEN, error=head_error or base_error)
    if base_error:
        base_engine = None  # treat an unbuildable base as "new": show the whole surface

    if base_engine is None and head_engine is None:
        return PackDiff(name=name, state=BROKEN, error="neither side compiled")

    state = ADDED if base_engine is None else (REMOVED if head_engine is None else CHANGED)

    tools = _tool_surface(base, base_engine) | _tool_surface(head, head_engine)
    # A glob rule on one side needs concrete names to be visible in the diff;
    # the other side's literal rules supply them, which is why the surface is a
    # union rather than per-side.
    for pattern in _glob_only_patterns(base_engine) + _glob_only_patterns(head_engine):
        if not any(fnmatch(t, pattern) for t in tools):
            tools.add(pattern)  # nothing concrete matches it — show the pattern itself

    roles: list[str | None] = [None]
    for engine in (base_engine, head_engine):
        if engine is not None:
            roles.extend(r for r in declared_roles(engine) if r not in roles)

    deny = effective_deny_set()
    diff = PackDiff(name=name, state=state, role_views=len(roles))

    if state in (ADDED, REMOVED):
        # Only one side has a policy, so there is no before/after to rank: every
        # decision would score the same way and drown the real findings. A pack
        # that appeared did not *loosen* anything — it added enforcement where
        # this repo had none. Summarize the shape of what arrived (or left).
        engine = head_engine if state == ADDED else base_engine
        assert engine is not None
        for tool in sorted(tools):
            for role in roles:
                diff.decisions_examined += 1
                action = engine.evaluate(tool, {}, role=role).action
                diff.action_summary[action] = diff.action_summary.get(action, 0) + 1
        return diff

    assert base_engine is not None and head_engine is not None
    for tool in sorted(tools):
        for role in roles:
            diff.decisions_examined += 1
            base_action = base_engine.evaluate(tool, {}, role=role).action
            head_action = head_engine.evaluate(tool, {}, role=role).action
            if base_action == head_action:
                diff.unchanged += 1
                continue
            diff.changed.append(ChangedDecision(
                tool=tool, role=role,
                base_action=base_action, head_action=head_action,
                kind=classify(base_action, head_action),
                crosses_deny_boundary=base_action in deny and head_action not in deny,
            ))

    if not diff.changed:
        diff.state = UNCHANGED
    # Loosened first: that is the finding a reviewer must not scroll past.
    diff.changed.sort(key=lambda c: (_ORDER.get(c.kind, 9), c.tool, c.role or ""))
    return diff


def classify(base_action: str, head_action: str) -> str:
    """Rank one action change on the least-privilege ladder."""
    base_rank, head_rank = STRENGTH.get(base_action), STRENGTH.get(head_action)
    if base_rank is None or head_rank is None:
        return CHANGED_KIND      # an action we cannot rank; do not guess a direction
    if head_rank < base_rank:
        return LOOSENED
    if head_rank > base_rank:
        return TIGHTENED
    return CHANGED_KIND          # same rung, different treatment (rewrite -> redact)


def diff_roots(base_root: str | Path, head_root: str | Path) -> RepoDiff:
    """Diff every policy pack between two checkouts of the repo.

    Discovery runs on both sides, so a pack added in this PR (no base) and a
    pack deleted by it (no head) are both first-class results — deleting a pack
    deletes enforcement, and a text diff makes that look like housekeeping.
    """
    base_root, head_root = Path(base_root), Path(head_root)
    base = {t.name: t for t in discover_targets(base_root)}
    head = {t.name: t for t in discover_targets(head_root)}

    result = RepoDiff(base_root=base_root, head_root=head_root)
    for name in sorted(set(base) | set(head)):
        result.packs.append(diff_pack(name, base.get(name), head.get(name)))
    return result


# ---------------------------------------------------------------- formatting
def format_text(diff: RepoDiff) -> str:
    lines: list[str] = []
    if diff.clean:
        lines.append("no policy decisions changed")
    for pack in diff.touched:
        if pack.state == BROKEN:
            lines.append(f"{pack.name}: could not diff — {pack.error}")
            continue
        if pack.state in (ADDED, REMOVED):
            lines.append(
                f"{pack.name} [{pack.state}]: {pack.decisions_examined} decision(s) "
                f"across {pack.role_views} role view(s) — {_actions(pack.action_summary)}"
            )
            continue
        lines.append(
            f"{pack.name} [{pack.state}]: {pack.loosened} loosened, "
            f"{pack.tightened} tightened, {pack.lateral} changed "
            f"({pack.unchanged} unchanged of {pack.decisions_examined} decisions "
            f"across {pack.role_views} role view(s))"
        )
        for change in pack.changed[:_MAX_ROWS]:
            role = f" [{change.role}]" if change.role else ""
            flag = "  !! now un-gated" if change.crosses_deny_boundary else ""
            lines.append(
                f"    {change.kind:<10} {change.tool}{role}  "
                f"{change.base_action or '(absent)'} -> "
                f"{change.head_action or '(absent)'}{flag}"
            )
        if len(pack.changed) > _MAX_ROWS:
            lines.append(f"    ... and {len(pack.changed) - _MAX_ROWS} more")
    lines.append("")
    lines.append(f"note: {NOTE}")
    return "\n".join(lines)


# A hidden marker so CI can find and update its own comment instead of posting a
# new one on every push — a PR with twelve stale blast-radius comments trains
# reviewers to ignore all of them.
COMMENT_MARKER = "<!-- mcp-gateway:policy-diff -->"


def format_markdown(diff: RepoDiff) -> str:
    """The PR comment body."""
    lines = [COMMENT_MARKER, "## Policy blast radius", ""]

    if diff.clean:
        lines += [
            "No policy decision changes on this branch.",
            "",
            f"<sub>{NOTE}</sub>",
            "",
        ]
        return "\n".join(lines)

    lines += [
        f"**{diff.loosened} loosened** · **{diff.tightened} tightened** · "
        f"{diff.lateral} changed",
        "",
    ]

    if diff.newly_allowed:
        lines += [
            "> [!CAUTION]",
            f"> **{diff.newly_allowed} decision(s) cross the deny boundary**: refused "
            "before, and would now go through with no human in the loop. Confirm each "
            "one is intended.",
            "",
        ]
    elif diff.loosened:
        lines += [
            "> [!WARNING]",
            f"> This branch **weakens enforcement** on {diff.loosened} decision(s) "
            "(a step down the `allow < redact < quarantine < require_approval < block` "
            "ladder). None of them go through un-gated, but confirm each is intended.",
            "",
        ]

    for pack in diff.packs:
        if pack.state == UNCHANGED:
            continue
        if pack.state == BROKEN:
            lines += [f"### `{pack.name}` — could not diff", "", f"```\n{pack.error}\n```", ""]
            continue
        if pack.state == REMOVED:
            lines += [
                f"### `{pack.name}` — 🚨 pack removed",
                "",
                f"{pack.decisions_examined} decision(s) this pack enforced are gone: "
                f"{_actions(pack.action_summary)}. Anything still pointed at this "
                "upstream is now policed by whatever policy replaces it — or by none.",
                "",
            ]
            continue
        if pack.state == ADDED:
            lines += [
                f"### `{pack.name}` — 🆕 new pack",
                "",
                f"Adds {pack.decisions_examined} decision(s) across {pack.role_views} "
                f"role view(s): {_actions(pack.action_summary)}.",
                "",
            ]
            continue

        lines += [
            f"### `{pack.name}`",
            "",
            f"{pack.loosened} loosened · {pack.tightened} tightened · "
            f"{pack.lateral} changed · {pack.unchanged} unchanged "
            f"({pack.decisions_examined} decisions across {pack.role_views} role view(s))",
            "",
        ]
        if not pack.changed:
            continue
        lines += ["| | Tool | Role | Before | After |", "| --- | --- | --- | --- | --- |"]
        for change in pack.changed[:_MAX_ROWS]:
            icon = {LOOSENED: "⚠️", TIGHTENED: "🔒", CHANGED_KIND: "🔁"}.get(change.kind, "")
            if change.crosses_deny_boundary:
                icon = "🚨"
            lines.append(
                f"| {icon} | `{change.tool}` | {f'`{change.role}`' if change.role else '–'} "
                f"| {_cell(change.base_action)} | {_cell(change.head_action)} |"
            )
        if len(pack.changed) > _MAX_ROWS:
            lines.append(
                f"| | _… and {len(pack.changed) - _MAX_ROWS} more_ | | | |"
            )
        lines.append("")

    lines += [f"<sub>{NOTE}</sub>", ""]
    return "\n".join(lines)


def _cell(action: str) -> str:
    return f"`{action}`"


def _actions(summary: dict[str, int]) -> str:
    """Action distribution, strongest control first — the reviewable shape."""
    ranked = sorted(summary.items(), key=lambda kv: (-STRENGTH.get(kv[0], -1), kv[0]))
    return ", ".join(f"{count} {action}" for action, count in ranked)


__all__ = [
    "ADDED", "BROKEN", "CHANGED", "CHANGED_KIND", "COMMENT_MARKER",
    "LOOSENED", "NOTE", "REMOVED", "STRENGTH", "TIGHTENED", "UNCHANGED",
    "ChangedDecision", "PackDiff", "RepoDiff",
    "classify", "diff_pack", "diff_roots", "format_markdown", "format_text",
]
