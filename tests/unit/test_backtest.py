"""Policy backtest: replay recorded calls, diff decisions against a new policy."""

from __future__ import annotations

import json

from mcp_gateway.policy.backtest import backtest_policy, format_report
from mcp_gateway.policy.engine import PolicyEngine


def _spool(path, events):
    with path.open("wb") as fh:
        for ev in events:
            fh.write((json.dumps(ev) + "\n").encode("utf-8"))


def _engine(rules, default="allow"):
    doc = {"schema_version": 1, "default_action": default, "tools": rules}
    return PolicyEngine.from_documents([(doc, "candidate")])


def _log():
    # crm.get was allowed; web.fetch was allowed; http.post was blocked.
    return [
        {"schema_version": 1, "event": "tool_call_allowed",
         "session_id": "s1", "tool": "crm.get", "action": "allow", "rule": "r"},
        {"schema_version": 1, "event": "tool_call_allowed",
         "session_id": "s1", "tool": "crm.get", "action": "allow", "rule": "r"},
        {"schema_version": 1, "event": "tool_call_allowed",
         "session_id": "s1", "tool": "web.fetch", "action": "allow", "rule": "r"},
        {"schema_version": 1, "event": "tool_call_blocked",
         "session_id": "s1", "tool": "http.post", "stage": "action", "reason": "no"},
    ]


def test_newly_blocked_is_flagged(tmp_path):
    spool = tmp_path / "audit.log"
    _spool(spool, _log())
    # New policy blocks crm.get.
    engine = _engine({"crm.get": {"action": "block"}})
    report = backtest_policy(spool, engine)
    assert report.newly_blocked == 1
    blocked = [c for c in report.changed if c.change_kind == "newly_blocked"]
    assert blocked[0].tool == "crm.get"
    assert blocked[0].count == 2  # both crm.get calls collapse into one row


def test_newly_allowed_is_flagged(tmp_path):
    spool = tmp_path / "audit.log"
    _spool(spool, _log())
    # New policy allows http.post (which was blocked). Default allow covers it.
    engine = _engine({"crm.get": {"action": "allow"}})
    report = backtest_policy(spool, engine)
    kinds = {c.tool: c.change_kind for c in report.changed}
    assert kinds.get("http.post") == "newly_allowed"
    # The blocked call records the stage it was stopped at (honesty flag).
    http = [c for c in report.changed if c.tool == "http.post"][0]
    assert http.old_stage == "action"


def test_action_changed_is_flagged(tmp_path):
    spool = tmp_path / "audit.log"
    _spool(spool, _log())
    # crm.get stays allowed-ish but becomes a redact — a non-denying action,
    # so pass a deny_set that treats redact as allowed (service wired).
    engine = _engine({"crm.get": {"action": "redact"}})
    report = backtest_policy(spool, engine, deny_set=frozenset({"block", "require_approval"}))
    changed = {c.tool: c for c in report.changed}
    assert changed["crm.get"].change_kind == "action_changed"
    assert changed["crm.get"].new_action == "redact"


def test_unchanged_policy_reports_no_changes(tmp_path):
    spool = tmp_path / "audit.log"
    _spool(spool, _log())
    # http.post default-allowed would flip (was blocked) — give it an explicit
    # block so nothing changes.
    engine = _engine({"http.post": {"action": "block"}})
    report = backtest_policy(spool, engine)
    assert report.changed == []
    assert report.unchanged == report.distinct_calls


def test_role_is_replayed(tmp_path):
    spool = tmp_path / "audit.log"
    _spool(spool, [
        {"schema_version": 1, "event": "tool_call_allowed", "session_id": "s1",
         "tool": "crm.get", "action": "allow", "rule": "r", "role": "admin"},
    ])
    # Base blocks; admin overlay allows. Replaying with role=admin stays allowed.
    engine = _engine({
        "crm.get": {"action": "block", "roles": {"admin": {"action": "allow"}}}
    })
    report = backtest_policy(spool, engine)
    assert report.changed == []


def test_counts_and_bad_lines(tmp_path):
    spool = tmp_path / "audit.log"
    with spool.open("wb") as fh:
        for ev in _log():
            fh.write((json.dumps(ev) + "\n").encode())
        fh.write(b"{garbage\n")
    engine = _engine({})
    report = backtest_policy(spool, engine)
    assert report.calls_examined == 4
    assert report.bad_lines == 1
    # format_report renders without error.
    text = format_report(report)
    assert "examined" in text and "note:" in text
