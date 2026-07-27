"""The policy differ: does it rank a change the way a security reviewer would?

The differ's whole value is that it reads a policy change more carefully than a
human skimming YAML. These tests pin the judgments that make that true — chiefly
that `block` -> `require_approval` is a *loosening* (wire an approver and the
tool opens up) even though both sides refuse a bare gateway, and that a role
overlay change is visible at all.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_gateway.cli import main
from mcp_gateway.policy.diff import (
    ADDED,
    CHANGED_KIND,
    COMMENT_MARKER,
    LOOSENED,
    REMOVED,
    TIGHTENED,
    UNCHANGED,
    classify,
    diff_roots,
    format_markdown,
    format_text,
)

MANIFEST = "name: {name}\n"
TOOLS = "tools:\n  demo.read: {risk: read}\n  demo.write: {risk: write}\n"


def policy(read="redact", write="require_approval", extra=""):
    return (
        "schema_version: 1\n"
        "default_action: block\n"
        "tools:\n"
        f"  demo.read: {{action: {read}, reason: r}}\n"
        f"  demo.write: {{action: {write}, reason: w}}\n"
        f"{extra}"
    )


def make_repo(root: Path, packs: dict[str, str], *, roles: dict[str, str] | None = None):
    """Build a repo tree holding one policy.yaml per named pack."""
    for name, text in packs.items():
        pack = root / "connectors" / name
        pack.mkdir(parents=True)
        (pack / "manifest.yaml").write_text(MANIFEST.format(name=name))
        (pack / "policy.yaml").write_text(text)
        (pack / "tools.yaml").write_text(TOOLS)
        if roles and name in roles:
            (pack / "roles.yaml").write_text(roles[name])
    return root


def two_repos(tmp_path, base_packs, head_packs, *, base_roles=None, head_roles=None):
    base = make_repo(tmp_path / "base", base_packs, roles=base_roles)
    head = make_repo(tmp_path / "head", head_packs, roles=head_roles)
    return diff_roots(base, head)


def changes(diff, pack="demo"):
    return {(c.tool, c.role): c for c in _pack(diff, pack).changed}


def _pack(diff, name):
    return next(p for p in diff.packs if p.name == name)


# ------------------------------------------------------------- the ladder
@pytest.mark.parametrize("base,head,expected", [
    # The judgment that matters most: both refuse a bare gateway, but wiring an
    # approver opens the tool up. A binary allowed/blocked model calls this a
    # no-op, which is how a write quietly becomes reachable.
    ("block", "require_approval", LOOSENED),
    ("require_approval", "block", TIGHTENED),
    ("require_approval", "allow", LOOSENED),
    ("allow", "require_approval", TIGHTENED),
    ("redact", "allow", LOOSENED),
    ("allow", "redact", TIGHTENED),
    ("quarantine", "redact", LOOSENED),
    ("redact", "quarantine", TIGHTENED),
    # Same rung, different treatment — real, but not a direction.
    ("rewrite", "redact", CHANGED_KIND),
])
def test_classify_ranks_on_the_least_privilege_ladder(base, head, expected):
    assert classify(base, head) == expected


def test_unrankable_action_does_not_guess_a_direction():
    assert classify("allow", "some_future_action") == CHANGED_KIND


# ---------------------------------------------------------------- the diff
def test_identical_policies_are_clean(tmp_path):
    diff = two_repos(tmp_path, {"demo": policy()}, {"demo": policy()})
    assert diff.clean
    assert _pack(diff, "demo").state == UNCHANGED


def test_loosening_is_reported_with_its_direction(tmp_path):
    diff = two_repos(tmp_path, {"demo": policy(read="redact")}, {"demo": policy(read="allow")})
    change = changes(diff)[("demo.read", None)]
    assert change.kind == LOOSENED
    assert (change.base_action, change.head_action) == ("redact", "allow")
    assert diff.loosened == 1 and diff.tightened == 0


def test_crossing_the_deny_boundary_is_flagged_separately(tmp_path):
    """Loosening and going un-gated are different claims; both are reported."""
    diff = two_repos(
        tmp_path,
        {"demo": policy(write="require_approval")},
        {"demo": policy(write="allow")},
    )
    change = changes(diff)[("demo.write", None)]
    assert change.kind == LOOSENED and change.crosses_deny_boundary
    assert diff.newly_allowed == 1


def test_loosening_within_the_allowed_side_does_not_cross(tmp_path):
    """redact -> allow weakens the control but was never a refusal."""
    diff = two_repos(tmp_path, {"demo": policy(read="redact")}, {"demo": policy(read="allow")})
    assert diff.loosened == 1
    assert diff.newly_allowed == 0


def test_redact_is_not_mistaken_for_a_denial(tmp_path):
    """A service-backed redact lets the call through; scoring it as a denial
    would make every read rule look like a lockout."""
    diff = two_repos(tmp_path, {"demo": policy(read="block")}, {"demo": policy(read="redact")})
    assert changes(diff)[("demo.read", None)].crosses_deny_boundary


def test_role_overlay_changes_are_visible(tmp_path):
    """A policy is one decision table per role; a diff that only checks the
    default view misses an edit that only moves an overlay."""
    base_roles = {"demo": (
        "schema_version: 1\ntools:\n  demo.write:\n    action: require_approval\n"
        "    roles:\n      bot: {action: block, reason: no approver exists}\n"
    )}
    head_roles = {"demo": (
        "schema_version: 1\ntools:\n  demo.write:\n    action: require_approval\n"
        "    roles:\n      bot: {action: allow, reason: TEST loosened}\n"
    )}
    diff = two_repos(
        tmp_path, {"demo": policy()}, {"demo": policy()},
        base_roles=base_roles, head_roles=head_roles,
    )
    change = changes(diff)[("demo.write", "bot")]
    assert change.kind == LOOSENED and change.crosses_deny_boundary
    # The default view is untouched — only the overlay moved.
    assert ("demo.write", None) not in changes(diff)


def test_deleting_a_rule_surfaces_the_fallthrough(tmp_path):
    """The tool stays in the inventory, so default_action is diffed, not missed."""
    head = (
        "schema_version: 1\ndefault_action: block\n"
        "tools:\n  demo.write: {action: allow, reason: w}\n"
    )
    diff = two_repos(tmp_path, {"demo": policy(read="allow")}, {"demo": head})
    change = changes(diff)[("demo.read", None)]
    assert change.kind == TIGHTENED and change.head_action == "block"


def test_added_pack_is_reported_as_new_coverage_not_as_loosening(tmp_path):
    """A pack that appeared adds enforcement where this repo had none; calling
    every one of its rules 'loosened' would bury the real findings."""
    diff = two_repos(tmp_path, {"demo": policy()}, {"demo": policy(), "fresh": policy()})
    fresh = _pack(diff, "fresh")
    assert fresh.state == ADDED
    assert fresh.changed == []
    assert fresh.action_summary == {"redact": 1, "require_approval": 1}
    assert diff.loosened == 0
    assert not diff.clean


def test_removed_pack_is_reported_with_what_it_enforced(tmp_path):
    diff = two_repos(tmp_path, {"demo": policy(), "gone": policy()}, {"demo": policy()})
    gone = _pack(diff, "gone")
    assert gone.state == REMOVED
    assert gone.decisions_examined == 2
    assert "🚨 pack removed" in format_markdown(diff)


def test_broken_head_policy_is_reported_not_crashed(tmp_path):
    diff = two_repos(
        tmp_path, {"demo": policy()},
        {"demo": "schema_version: 1\ndefault_action: sideways\n"},
    )
    pack = _pack(diff, "demo")
    assert pack.state == "broken" and pack.error
    assert "could not diff" in format_text(diff)


def test_glob_rules_are_diffed_through_concrete_tools(tmp_path):
    base = (
        "schema_version: 1\ndefault_action: block\n"
        "tools:\n  'demo.*': {action: redact, reason: catch-all}\n"
    )
    head = (
        "schema_version: 1\ndefault_action: block\n"
        "tools:\n  'demo.*': {action: allow, reason: TEST loosened}\n"
    )
    # Neither policy names a literal tool; the inventory supplies the surface.
    diff = two_repos(tmp_path, {"demo": base}, {"demo": head})
    assert {t for t, _ in changes(diff)} == {"demo.read", "demo.write"}


# ---------------------------------------------------------------- rendering
def test_markdown_leads_with_the_deny_crossing(tmp_path):
    diff = two_repos(tmp_path, {"demo": policy()}, {"demo": policy(write="allow")})
    markdown = format_markdown(diff)
    assert markdown.startswith(COMMENT_MARKER)  # CI finds its own comment by this
    assert "[!CAUTION]" in markdown
    assert "cross the deny boundary" in markdown
    assert "| 🚨 | `demo.write` |" in markdown


def test_markdown_warns_on_loosening_that_stays_gated(tmp_path):
    diff = two_repos(tmp_path, {"demo": policy(read="quarantine")}, {"demo": policy(read="redact")})
    markdown = format_markdown(diff)
    assert "[!WARNING]" in markdown and "[!CAUTION]" not in markdown


def test_markdown_on_a_clean_diff_says_so_without_alarm(tmp_path):
    markdown = format_markdown(two_repos(tmp_path, {"demo": policy()}, {"demo": policy()}))
    assert "No policy decision changes" in markdown
    assert "[!CAUTION]" not in markdown and "[!WARNING]" not in markdown


def test_rendered_output_always_states_what_is_not_replayed(tmp_path):
    """A green 'no changes' must not imply constraints or taint were checked."""
    diff = two_repos(tmp_path, {"demo": policy()}, {"demo": policy()})
    for rendered in (format_text(diff), format_markdown(diff)):
        assert "taint/sequence gating" in rendered


# --------------------------------------------------------------------- CLI
def test_cli_diff_reports_without_gating_by_default(tmp_path, capsys):
    make_repo(tmp_path / "base", {"demo": policy()})
    make_repo(tmp_path / "head", {"demo": policy(write="allow")})
    assert main([
        "policy", "diff", "--base", str(tmp_path / "base"), "--head", str(tmp_path / "head")
    ]) == 0
    assert "loosened" in capsys.readouterr().out


def test_cli_fail_on_crossing_is_an_opt_in_gate(tmp_path, capsys):
    make_repo(tmp_path / "base", {"demo": policy()})
    make_repo(tmp_path / "head", {"demo": policy(write="allow")})
    args = ["policy", "diff", "--base", str(tmp_path / "base"), "--head", str(tmp_path / "head")]
    assert main([*args, "--fail-on-crossing"]) == 1
    assert "go through un-gated" in capsys.readouterr().err


def test_cli_fail_on_crossing_passes_a_tightening(tmp_path):
    make_repo(tmp_path / "base", {"demo": policy(write="allow")})
    make_repo(tmp_path / "head", {"demo": policy()})
    assert main([
        "policy", "diff", "--base", str(tmp_path / "base"),
        "--head", str(tmp_path / "head"), "--fail-on-crossing",
    ]) == 0


def test_cli_json_output(tmp_path, capsys):
    make_repo(tmp_path / "base", {"demo": policy()})
    make_repo(tmp_path / "head", {"demo": policy(write="allow")})
    main([
        "policy", "diff", "--base", str(tmp_path / "base"),
        "--head", str(tmp_path / "head"), "--json",
    ])
    payload = json.loads(capsys.readouterr().out)
    assert payload["clean"] is False
    assert payload["summary"]["newly_allowed"] == 1
    assert payload["packs"][0]["changed"][0]["tool"] == "demo.write"
