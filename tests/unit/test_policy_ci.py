"""The policy CI harness itself, against synthetic repos.

`test_goldens.py` proves the harness passes on the packs we ship. That is only
half the story: a checker that never fails is indistinguishable from one that
does nothing. These tests build deliberately broken repos and assert each check
*catches* its failure, plus the two properties CI depends on — that discovery is
intolerant (a broken pack fails the build rather than being skipped) and that
the command exits non-zero when it should.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_gateway.cli import main
from mcp_gateway.policy.ci import (
    BACKTEST,
    COVERAGE,
    GOLDENS,
    VALIDATE,
    check_target,
    discover_targets,
    format_markdown,
    format_text,
    github_annotations,
    run_policy_ci,
)

GOOD_POLICY = """\
schema_version: 1
name: {name}
default_action: block
tools:
  demo.ping:
    action: allow
    reason: harmless
"""

GOOD_TESTS = """\
tests:
  - name: ping allowed
    tool: demo.ping
    expect: {outcome: allow, action: allow}
  - name: unknown denied
    tool: demo.nope
    expect: {outcome: deny, action: block}
"""

TOOLS = """\
tools:
  demo.ping:
    risk: read
"""


def write_pack(
    root: Path,
    name: str,
    *,
    policy: str | None = None,
    tests: str | None = GOOD_TESTS,
    tools: str | None = None,
    manifest: str | None = None,
    roles: str | None = None,
) -> Path:
    pack = root / "connectors" / name
    pack.mkdir(parents=True)
    (pack / "manifest.yaml").write_text(
        manifest if manifest is not None else f"name: {name}\ndescription: test pack\n"
    )
    (pack / "policy.yaml").write_text(
        policy if policy is not None else GOOD_POLICY.format(name=name)
    )
    if tests is not None:
        (pack / "policy_tests.yaml").write_text(tests)
    if tools is not None:
        (pack / "tools.yaml").write_text(tools)
    if roles is not None:
        (pack / "roles.yaml").write_text(roles)
    return pack


def check_of(report, name):
    return next((c for c in report.checks if c.name == name), None)


def only_target(root: Path, name: str):
    targets = [t for t in discover_targets(root) if t.name == name]
    assert targets, f"{name} was not discovered"
    return targets[0]


# ----------------------------------------------------------------- discovery
def test_discovers_connectors_and_standalone_policies(tmp_path):
    write_pack(tmp_path, "alpha")
    policies = tmp_path / "policies"
    policies.mkdir()
    (policies / "loose.yaml").write_text(GOOD_POLICY.format(name="loose"))
    (policies / "loose.tests.yaml").write_text(GOOD_TESTS)

    found = {t.name: t for t in discover_targets(tmp_path)}
    assert found["alpha"].kind == "connector"
    assert found["loose"].kind == "policy"
    # A tests file is not itself a policy to check.
    assert "loose.tests" not in found
    assert found["loose"].tests == policies / "loose.tests.yaml"


def test_roles_layer_is_included_in_order(tmp_path):
    """The runtime order policy.yaml -> roles.yaml, applied centrally.

    Loading only the base layer makes role goldens fail closed on the base
    action and pass for the wrong reason; this is the regression guard.
    """
    write_pack(tmp_path, "alpha", roles="schema_version: 1\nroles: {}\n")
    layers = [p.name for p in only_target(tmp_path, "alpha").layers]
    assert layers == ["policy.yaml", "roles.yaml"]


def test_directory_without_a_manifest_fails_rather_than_being_skipped(tmp_path):
    """Discovery is intolerant here, unlike registry.list_connectors().

    An operator listing packs benefits from skipping a broken one; CI must not,
    or the pack nobody can load is also the pack nobody notices.
    """
    stray = tmp_path / "connectors" / "stray"
    stray.mkdir(parents=True)
    (stray / "README.md").write_text("no manifest here\n")

    report = run_policy_ci(tmp_path)
    assert not report.ok
    assert "missing manifest.yaml" in check_of(report.packs[0], VALIDATE).failures[0]


def test_private_directories_are_ignored(tmp_path):
    for name in (".cache", "_templates"):
        (tmp_path / "connectors" / name).mkdir(parents=True)
    write_pack(tmp_path, "alpha")
    assert [t.name for t in discover_targets(tmp_path)] == ["alpha"]


# -------------------------------------------------------------------- checks
def test_happy_pack_passes_every_check(tmp_path):
    write_pack(tmp_path, "alpha", tools=TOOLS)
    report = check_target(only_target(tmp_path, "alpha"))
    assert report.ok
    assert {c.name for c in report.checks} == {VALIDATE, GOLDENS, COVERAGE, BACKTEST}


def test_unparseable_policy_fails_validate_and_short_circuits(tmp_path):
    write_pack(tmp_path, "alpha", policy="schema_version: 1\ndefault_action: sideways\n")
    report = check_target(only_target(tmp_path, "alpha"))
    assert not report.ok
    # Running goldens against a policy that does not compile would report the
    # same root cause four times; validate gates the rest.
    assert [c.name for c in report.checks] == [VALIDATE]


def test_layers_valid_alone_but_broken_merged_fails(tmp_path):
    """The merged result is its own artifact and gets its own check."""
    write_pack(
        tmp_path, "alpha",
        roles="schema_version: 1\ntools:\n  demo.ping:\n    action: teleport\n",
    )
    report = check_target(only_target(tmp_path, "alpha"))
    assert not report.ok
    assert check_of(report, VALIDATE).failures


def test_failing_golden_is_reported_with_its_case_name(tmp_path):
    write_pack(tmp_path, "alpha", tests=GOOD_TESTS.replace("outcome: deny", "outcome: allow"))
    report = check_target(only_target(tmp_path, "alpha"))
    assert not report.ok
    assert "unknown denied" in check_of(report, GOLDENS).failures[0]


def test_connector_without_goldens_fails(tmp_path):
    write_pack(tmp_path, "alpha", tests=None)
    report = check_target(only_target(tmp_path, "alpha"))
    assert not report.ok
    assert "policy_tests.yaml" in check_of(report, GOLDENS).failures[0]


def test_standalone_policy_without_goldens_is_skipped_not_failed(tmp_path):
    """A loose policy file may legitimately be an override layer, not a pack."""
    policies = tmp_path / "policies"
    policies.mkdir()
    (policies / "loose.yaml").write_text(GOOD_POLICY.format(name="loose"))
    report = check_target(only_target(tmp_path, "loose"))
    assert report.ok
    assert check_of(report, GOLDENS).skipped


def test_min_goldens_rejects_a_token_suite(tmp_path):
    write_pack(tmp_path, "alpha")
    report = check_target(only_target(tmp_path, "alpha"), min_goldens=5)
    assert not report.ok
    assert "at least 5" in check_of(report, GOLDENS).failures[0]


def test_inventoried_tool_without_a_rule_fails_coverage(tmp_path):
    """Default-deny keeps it safe; unreviewed is still a finding."""
    write_pack(tmp_path, "alpha", tools=TOOLS + "  demo.unrated:\n    risk: write\n")
    report = check_target(only_target(tmp_path, "alpha"))
    assert not report.ok
    failure = check_of(report, COVERAGE).failures[0]
    assert "demo.unrated" in failure and "default_action" in failure


def test_coverage_is_skipped_without_an_inventory(tmp_path):
    write_pack(tmp_path, "alpha")
    report = check_target(only_target(tmp_path, "alpha"))
    assert check_of(report, COVERAGE).skipped


def test_backtest_replays_every_tool_across_every_role_view(tmp_path):
    """One recorded call per (tool, role): the surface the replay must agree on."""
    write_pack(
        tmp_path, "alpha", tools=TOOLS,
        roles=(
            "schema_version: 1\n"
            "tools:\n"
            "  demo.ping:\n"
            "    action: allow\n"
            "    roles:\n"
            "      auditor: {action: block, reason: read-only role}\n"
        ),
    )
    report = check_target(only_target(tmp_path, "alpha"))
    assert report.ok
    # 1 tool x (no-role + auditor) = 2 replayed calls.
    assert "2 replayed call(s) across 2 role view(s)" in check_of(report, BACKTEST).detail


def test_backtest_can_be_disabled(tmp_path):
    write_pack(tmp_path, "alpha")
    report = check_target(only_target(tmp_path, "alpha"), backtest=False)
    assert BACKTEST not in {c.name for c in report.checks}


# ---------------------------------------------------------------------- run
def test_only_with_an_unknown_name_fails(tmp_path):
    """A typo in a workflow must not quietly reduce CI to checking nothing."""
    write_pack(tmp_path, "alpha")
    report = run_policy_ci(tmp_path, only=["alpha", "typo"])
    assert not report.ok
    assert [p.target.name for p in report.failed] == ["typo"]


def test_only_restricts_the_run(tmp_path):
    write_pack(tmp_path, "alpha")
    write_pack(tmp_path, "beta")
    report = run_policy_ci(tmp_path, only=["beta"])
    assert [p.target.name for p in report.packs] == ["beta"]
    assert report.ok


# --------------------------------------------------------------- formatting
def test_text_output_names_the_failing_pack(tmp_path):
    write_pack(tmp_path, "alpha")
    write_pack(tmp_path, "beta", tests=None)
    text = format_text(run_policy_ci(tmp_path))
    assert "PASS  connector:alpha" in text
    assert "FAIL  connector:beta" in text
    assert "1/2 pack(s) passed" in text


def test_markdown_summary_has_a_row_per_pack(tmp_path):
    write_pack(tmp_path, "alpha", tools=TOOLS)
    markdown = format_markdown(run_policy_ci(tmp_path))
    assert "## Policy CI" in markdown
    assert "| `alpha` |" in markdown
    assert "All policy packs passed" in markdown


def test_annotations_anchor_to_the_policy_file_and_escape_separators(tmp_path):
    """Workflow commands are comma/newline delimited — an unescaped message
    would truncate the annotation or spill into a bogus parameter."""
    write_pack(tmp_path, "alpha", tests=GOOD_TESTS.replace("outcome: deny", "outcome: allow"))
    annotations = github_annotations(run_policy_ci(tmp_path))
    assert annotations
    line = annotations[0]
    assert line.startswith("::error file=connectors/alpha/policy.yaml,")
    body = line.split("::", 2)[2]
    assert "," not in body and "\n" not in body


@pytest.mark.parametrize("raw,expected", [
    ("a,b", "a%2Cb"), ("a\nb", "a%0Ab"), ("50%", "50%25"), ("a::b", "a%3A%3Ab"),
])
def test_annotation_escaping(raw, expected):
    from mcp_gateway.policy.ci import _escape

    assert _escape(raw) == expected


# ---------------------------------------------------------------------- CLI
def test_cli_exits_zero_on_a_healthy_repo(tmp_path, capsys):
    write_pack(tmp_path, "alpha")
    assert main(["policy", "ci", "--root", str(tmp_path)]) == 0
    assert "1/1 pack(s) passed" in capsys.readouterr().out


def test_cli_exits_nonzero_on_a_broken_pack(tmp_path, capsys):
    """`policy ci` is a gate, unlike `policy backtest` which only reports."""
    write_pack(tmp_path, "alpha", tests=None)
    assert main(["policy", "ci", "--root", str(tmp_path)]) == 1
    assert "0/1 pack(s) passed" in capsys.readouterr().out


def test_cli_json_output_is_machine_readable(tmp_path, capsys):
    write_pack(tmp_path, "alpha", tools=TOOLS)
    main(["policy", "ci", "--root", str(tmp_path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["packs_checked"] == 1
    assert [c["check"] for c in payload["packs"][0]["checks"]] == [
        VALIDATE, GOLDENS, COVERAGE, BACKTEST
    ]


def test_cli_github_mode_writes_annotations_and_the_job_summary(
    tmp_path, capsys, monkeypatch
):
    write_pack(tmp_path, "alpha", tests=None)
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))

    assert main(["policy", "ci", "--root", str(tmp_path), "--github"]) == 1
    assert "::error file=connectors/alpha/policy.yaml" in capsys.readouterr().out
    assert "policy pack(s) failed" in summary.read_text()


def test_cli_github_mode_survives_an_unwritable_summary(tmp_path, capsys, monkeypatch):
    """The summary is reporting, never the gate — losing it must not change
    the verdict or crash the job."""
    write_pack(tmp_path, "alpha")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "nope" / "summary.md"))

    assert main(["policy", "ci", "--root", str(tmp_path), "--github"]) == 0
    assert "could not write job summary" in capsys.readouterr().err
