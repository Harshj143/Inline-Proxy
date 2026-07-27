"""Policy CI: check every shipped pack the way a pipeline must, not the way a human browses.

Phase 6a's promise was that authoring a connector pack requires zero engine
changes. That promise only holds if it also requires zero *pipeline* changes —
otherwise every new pack quietly depends on someone remembering to add a line to
a workflow file, and the pack that gets forgotten is the one that ships an
unverified security control. So this module **discovers** what to check instead
of being handed a list: drop a directory into `connectors/` and CI covers it on
the next PR.

Discovery here is deliberately *intolerant*, which is the one place it diverges
from `connectors/registry.py`. `list_connectors()` skips a pack that fails to
load, on purpose — one broken pack must not hide the usable ones from an
operator. In CI the opposite is true: a pack that cannot be loaded is a build
failure, never a silently-skipped row. Same fail-closed rule as the enforcement
path, applied to the supply chain that produces the policy.

Four checks per pack, weakest to strongest:

  * **validate** — every layer parses and the *merged* result compiles. A pack
    whose layers are individually fine but conflict when merged is broken.
  * **goldens** — the pack's `policy_tests.yaml` decisions still hold. Layers are
    loaded as `Connector.policy_layers()` orders them (`policy.yaml` **then**
    `roles.yaml`); loading only the base makes every role case fail closed on the
    base `require_approval`, which is the single easiest way to write a golden
    suite that passes for the wrong reason. Doing it centrally here means no
    caller has to re-learn that. A pack with **no** goldens fails: an unverified
    policy is an unverified control.
  * **coverage** — every tool in `tools.yaml` resolves to an explicit rule rather
    than falling through to `default_action`. Default-deny keeps an unknown tool
    safe, but an *unrated* tool is an *unreviewed* tool, and that is exactly the
    drift an upstream version bump introduces.
  * **backtest** — a self-consistency smoke over the pack's whole tool surface
    (see `_check_backtest`).

The report is a data object; `format_text` / `format_markdown` /
`github_annotations` render it. Pure stdlib + the policy engine — no server
extra, so this runs on a bare CI image.
"""

from __future__ import annotations

import contextlib
import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_gateway.connectors.base import MANIFEST, Connector, load_connector
from mcp_gateway.core.errors import GatewayError
from mcp_gateway.policy.engine import PolicyEngine
from mcp_gateway.policy.loader import load_policy_file
from mcp_gateway.policy.testing import load_tests_file, run_policy_tests

CONNECTOR = "connector"
POLICY = "policy"

VALIDATE = "validate"
GOLDENS = "goldens"
COVERAGE = "coverage"
BACKTEST = "backtest"

# How many offending items a failure message lists before it summarizes.
_MAX_LISTED = 8


# --------------------------------------------------------------------- model
@dataclass(slots=True)
class Target:
    """One thing CI checks: a connector pack, or a standalone policy file."""

    name: str
    kind: str                       # CONNECTOR | POLICY
    path: Path                      # pack directory, or the policy file
    layers: list[Path] = field(default_factory=list)
    tests: Path | None = None
    connector: Connector | None = None
    error: str | None = None        # discovery failure — the target itself fails

    @property
    def label(self) -> str:
        return f"{self.kind}:{self.name}"


@dataclass(slots=True)
class Check:
    name: str
    ok: bool
    detail: str                     # one-line result, shown even when passing
    failures: list[str] = field(default_factory=list)
    skipped: bool = False           # ran nothing, and that is legitimate

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.name, "ok": self.ok, "detail": self.detail,
            "failures": self.failures, "skipped": self.skipped,
        }


@dataclass(slots=True)
class PackReport:
    target: Target
    checks: list[Check] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.target.name,
            "kind": self.target.kind,
            "path": str(self.target.path),
            "layers": [str(p) for p in self.target.layers],
            "ok": self.ok,
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass(slots=True)
class CiReport:
    root: Path
    packs: list[PackReport] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(p.ok for p in self.packs)

    @property
    def failed(self) -> list[PackReport]:
        return [p for p in self.packs if not p.ok]

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "ok": self.ok,
            "packs_checked": len(self.packs),
            "packs_failed": len(self.failed),
            "packs": [p.to_dict() for p in self.packs],
        }


# ----------------------------------------------------------------- discovery
def discover_targets(
    root: str | Path,
    *,
    connectors_dir: str = "connectors",
    policies_dir: str = "policies",
) -> list[Target]:
    """Every policy artifact under `root` that CI is responsible for.

    Connector packs first (the reviewed unit of shipping), then standalone
    policy files. A directory under `connectors/` that is not a loadable pack
    becomes a *failing* target rather than being skipped — see the module
    docstring. Directories whose name starts with `.` or `_` are treated as
    private scaffolding and ignored.
    """
    root = Path(root)
    targets: list[Target] = []

    packs_root = root / connectors_dir
    if packs_root.is_dir():
        for child in sorted(packs_root.iterdir()):
            if not child.is_dir() or child.name.startswith((".", "_")):
                continue
            if not (child / MANIFEST).is_file():
                targets.append(Target(
                    name=child.name, kind=CONNECTOR, path=child,
                    error=f"not a connector pack: missing {MANIFEST}",
                ))
                continue
            try:
                connector = load_connector(child)
            except GatewayError as exc:
                targets.append(Target(
                    name=child.name, kind=CONNECTOR, path=child, error=str(exc)
                ))
                continue
            targets.append(Target(
                name=connector.name, kind=CONNECTOR, path=child,
                layers=connector.policy_layers(), tests=connector.tests_path(),
                connector=connector,
            ))

    policies_root = root / policies_dir
    if policies_root.is_dir():
        for child in sorted(policies_root.iterdir()):
            if not child.is_file() or child.suffix not in (".yaml", ".yml"):
                continue
            if child.name.endswith((".tests.yaml", ".tests.yml")):
                continue
            tests = child.with_suffix(".tests.yaml")
            targets.append(Target(
                name=child.stem, kind=POLICY, path=child, layers=[child],
                tests=tests if tests.is_file() else None,
            ))

    return targets


# -------------------------------------------------------------------- checks
def check_target(
    target: Target, *, min_goldens: int = 1, backtest: bool = True
) -> PackReport:
    """Run every check against one target, short-circuiting on a broken policy.

    A policy that does not compile makes the later checks meaningless (they
    would all report the same root cause), so validation gates the rest.
    """
    report = PackReport(target=target)
    if target.error:
        report.checks.append(Check(VALIDATE, False, "pack failed to load", [target.error]))
        return report

    engine = _check_validate(target, report)
    if engine is None:
        return report
    _check_goldens(target, report, min_goldens)
    _check_coverage(target, report, engine)
    if backtest:
        _check_backtest(target, report, engine)
    return report


def _check_validate(target: Target, report: PackReport) -> PolicyEngine | None:
    """Each layer parses on its own, and the merged document compiles."""
    documents = []
    failures: list[str] = []
    for layer in target.layers:
        try:
            documents.append(load_policy_file(layer))
        except GatewayError as exc:
            failures.append(str(exc))
    if failures:
        report.checks.append(Check(VALIDATE, False, "policy did not parse", failures))
        return None
    try:
        engine = PolicyEngine(documents)
    except GatewayError as exc:
        # Layers that are individually valid can still conflict once merged.
        report.checks.append(Check(
            VALIDATE, False, "merged policy did not compile", [str(exc)]
        ))
        return None
    report.checks.append(Check(
        VALIDATE, True, f"{len(target.layers)} layer(s) ok, merged ok"
    ))
    return engine


def _check_goldens(target: Target, report: PackReport, min_goldens: int) -> None:
    if target.tests is None:
        if target.kind == CONNECTOR:
            # The pack contract requires goldens; shipping without them means
            # nothing asserts what this policy actually decides.
            report.checks.append(Check(
                GOLDENS, False, "no golden tests",
                ["a connector pack must ship policy_tests.yaml — "
                 "an unverified policy is an unverified security control"],
            ))
        else:
            report.checks.append(Check(
                GOLDENS, True, "no goldens alongside this file (validate-only)",
                skipped=True,
            ))
        return

    try:
        results = run_policy_tests(list(target.layers), target.tests)
    except GatewayError as exc:
        report.checks.append(Check(GOLDENS, False, "golden suite did not run", [str(exc)]))
        return

    failures = [f"{r.name}: {'; '.join(r.failures)}" for r in results if not r.passed]
    if len(results) < min_goldens:
        failures.append(
            f"only {len(results)} golden case(s); at least {min_goldens} required"
        )
    passed = len(results) - len([r for r in results if not r.passed])
    report.checks.append(Check(
        GOLDENS, not failures, f"{passed}/{len(results)} golden decisions hold", failures
    ))


def _check_coverage(target: Target, report: PackReport, engine: PolicyEngine) -> None:
    """Every inventoried tool must match an explicit rule, not default-deny."""
    if target.connector is None:
        return
    try:
        inventory = target.connector.tools()
    except GatewayError as exc:
        report.checks.append(Check(COVERAGE, False, "tool inventory did not load", [str(exc)]))
        return
    if not inventory:
        report.checks.append(Check(
            COVERAGE, True, "no tools.yaml inventory to check", skipped=True
        ))
        return

    missing = [t for t in inventory if engine.evaluate(t, {}).rule == "default"]
    failures = []
    if missing:
        failures.append(
            f"{len(missing)} inventoried tool(s) fall through to default_action "
            f"(unrated means unreviewed): {_summarize(missing)}"
        )
    report.checks.append(Check(
        COVERAGE, not missing,
        f"{len(inventory) - len(missing)}/{len(inventory)} tools have an explicit rule",
        failures,
    ))


def _check_backtest(target: Target, report: PackReport, engine: PolicyEngine) -> None:
    """Replay the pack's own decisions through the pack and require a zero diff.

    This is a *smoke* check, and worth naming precisely so it is not mistaken for
    a real backtest. It writes a synthetic audit spool holding one recorded call
    per (tool, role) across the pack's whole inventory, then runs the Phase 4a
    backtester over it against the same policy. Replaying a policy against
    decisions that policy just made must produce no differences at all, so any
    changed row means the replay path disagrees with the live matcher — a
    dropped role in the bucket key, a shifted outcome mapping, an event name that
    the reader stopped recognizing. It exercises spool → bucket → re-evaluate →
    diff at real pack scale (~400 calls for GitHub) on every PR.

    What it is not: evidence about production traffic. That is
    `mcp-gateway policy backtest --audit <real log>`, which is the operator's
    tool, not CI's.
    """
    from mcp_gateway.policy.backtest import (
        backtest_policy,
        declared_roles,
        effective_deny_set,
    )

    tools = sorted(target.connector.tools()) if target.connector else []
    if not tools and target.tests is not None:
        tools = sorted({
            c["tool"] for c in load_tests_file(target.tests)
            if isinstance(c, dict) and isinstance(c.get("tool"), str)
        })
    if not tools:
        report.checks.append(Check(
            BACKTEST, True, "no tools to replay", skipped=True
        ))
        return

    roles: list[str | None] = [None, *declared_roles(engine)]
    # Score against the handlers a real gateway runs (the goldens wire a
    # RedactionService), not the bare registry's fail-closed baseline.
    deny = effective_deny_set()
    expected = len(tools) * len(roles)

    with tempfile.TemporaryDirectory(prefix="mcpg-ci-") as tmp:
        spool = Path(tmp) / "synthetic-audit.log"
        _write_synthetic_spool(spool, engine, tools, roles, deny)
        result = backtest_policy(spool, engine, deny_set=deny)

    failures = []
    if result.calls_examined != expected:
        failures.append(
            f"backtest read {result.calls_examined} of {expected} synthesized call(s) "
            f"({result.bad_lines} unparseable line(s))"
        )
    if result.changed:
        rows = [
            f"{c.tool}{f' [{c.role}]' if c.role else ''}: "
            f"{c.old_action or c.old_outcome} -> {c.new_action} ({c.change_kind})"
            for c in result.changed
        ]
        failures.append(
            "replaying the pack's own decisions through the pack changed "
            f"{len(result.changed)} of them — the backtest replay path disagrees "
            f"with the live matcher: {_summarize(rows)}"
        )
    report.checks.append(Check(
        BACKTEST, not failures,
        f"{result.calls_examined} replayed call(s) across {len(roles)} role view(s), "
        f"zero-diff" if not failures else f"{len(result.changed)} unexpected diff(s)",
        failures,
    ))


def _write_synthetic_spool(
    path: Path,
    engine: PolicyEngine,
    tools: list[str],
    roles: list[str | None],
    deny: frozenset[str],
) -> None:
    """Write the audit events a gateway would have recorded for these calls.

    Only the fields the backtester reads are emitted (event/tool/role/action/
    stage) — this is a fixture for the replay path, not a spec for the audit
    schema, and it holds no arguments or payloads by construction.
    """
    with path.open("w", encoding="utf-8") as fh:
        for tool in tools:
            for role in roles:
                decision = engine.evaluate(tool, {}, role=role)
                blocked = decision.action in deny
                event: dict[str, Any] = {
                    "schema_version": 1,
                    "event": "tool_call_blocked" if blocked else "tool_call_allowed",
                    "tool": tool,
                    "role": role,
                }
                if blocked:
                    event["stage"] = "action"
                else:
                    event["action"] = decision.action
                fh.write(json.dumps(event) + "\n")


def _summarize(items: list[str]) -> str:
    shown = ", ".join(items[:_MAX_LISTED])
    extra = len(items) - _MAX_LISTED
    return f"{shown}, and {extra} more" if extra > 0 else shown


# --------------------------------------------------------------------- entry
def run_policy_ci(
    root: str | Path,
    *,
    min_goldens: int = 1,
    backtest: bool = True,
    only: list[str] | None = None,
) -> CiReport:
    """Discover and check every policy artifact under `root`.

    `only` restricts the run to named targets (by pack/file name); a name that
    matches nothing is itself a failure, so a typo in a workflow cannot quietly
    reduce CI to checking nothing.
    """
    root = Path(root)
    targets = discover_targets(root)
    report = CiReport(root=root)

    if only:
        wanted = set(only)
        targets = [t for t in targets if t.name in wanted]
        for name in sorted(wanted - {t.name for t in targets}):
            report.packs.append(PackReport(
                target=Target(name=name, kind=CONNECTOR, path=root),
                checks=[Check(VALIDATE, False, "no such pack", [
                    f"--only {name!r} matched no connector pack or policy file under {root}"
                ])],
            ))

    for target in targets:
        report.packs.append(
            check_target(target, min_goldens=min_goldens, backtest=backtest)
        )
    return report


# ---------------------------------------------------------------- formatting
def format_text(report: CiReport) -> str:
    """Human/CI-log output: one line per check, failures indented beneath."""
    lines: list[str] = []
    for pack in report.packs:
        lines.append(f"{'PASS' if pack.ok else 'FAIL'}  {pack.target.label}")
        for check in pack.checks:
            mark = "skip" if check.skipped else ("ok" if check.ok else "FAIL")
            lines.append(f"      {mark:>4}  {check.name:<9} {check.detail}")
            for failure in check.failures:
                lines.append(f"            - {failure}")
    lines.append("")
    checked, failed = len(report.packs), len(report.failed)
    lines.append(f"{checked - failed}/{checked} pack(s) passed")
    if failed:
        lines.append("failed: " + ", ".join(p.target.label for p in report.failed))
    return "\n".join(lines)


def format_markdown(report: CiReport) -> str:
    """A GitHub job-summary table — the at-a-glance view on the PR's Checks tab."""
    checked, failed = len(report.packs), len(report.failed)
    head = "✅ All policy packs passed" if report.ok else f"❌ {failed} policy pack(s) failed"
    lines = [
        "## Policy CI",
        "",
        f"{head} — {checked - failed}/{checked} passed.",
        "",
        "| Pack | Validate | Goldens | Coverage | Backtest |",
        "| --- | --- | --- | --- | --- |",
    ]
    for pack in report.packs:
        cells = []
        for name in (VALIDATE, GOLDENS, COVERAGE, BACKTEST):
            check = next((c for c in pack.checks if c.name == name), None)
            if check is None:
                cells.append("–")
            elif check.skipped:
                cells.append(f"➖ {check.detail}")
            else:
                cells.append(f"{'✅' if check.ok else '❌'} {check.detail}")
        lines.append(f"| `{pack.target.name}` | " + " | ".join(cells) + " |")

    if not report.ok:
        lines += ["", "### Failures", ""]
        for pack in report.failed:
            for check in pack.checks:
                for failure in check.failures:
                    lines.append(f"- **`{pack.target.name}` / {check.name}** — {failure}")
    return "\n".join(lines) + "\n"


def github_annotations(report: CiReport) -> list[str]:
    """`::error` workflow commands so failures land on the changed lines in the PR.

    Annotations are anchored to the pack's policy file rather than to the check
    that produced them: that is the file a reviewer edits, so it is where GitHub
    should point.
    """
    out: list[str] = []
    for pack in report.failed:
        target = pack.target
        anchor = target.layers[0] if target.layers else target.path
        with contextlib.suppress(ValueError):  # already relative, or outside the root
            anchor = anchor.relative_to(report.root)
        for check in pack.checks:
            for failure in check.failures:
                title = f"policy {check.name}: {target.name}"
                out.append(
                    f"::error file={anchor},title={_escape(title)}::{_escape(failure)}"
                )
    return out


def _escape(text: str) -> str:
    """Workflow-command escaping: newlines and separators must not break the line."""
    return (
        text.replace("%", "%25").replace("\r", "%0D")
        .replace("\n", "%0A").replace(",", "%2C").replace("::", "%3A%3A")
    )
