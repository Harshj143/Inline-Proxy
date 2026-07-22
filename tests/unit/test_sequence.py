"""Taint tracking and sequence rules."""

from mcp_gateway.core.session import Session
from mcp_gateway.sequence.policy import SequencePolicy


def make_policy():
    return SequencePolicy(
        taint_sources=["web.fetch"],
        taint_sinks=["http.post", "db.execute_sql"],
        sequence_rules=[{"after": "crm.get_customer", "forbid": "http.post",
                         "reason": "no POST after reading PII"}],
    )


# ------------------------------------------------------------------ taint
def test_clean_session_allows_sink():
    p = make_policy()
    assert p.check("http.post", Session.new()) is None


def test_tainted_session_blocks_sink():
    p = make_policy()
    s = Session.new()
    s.mark_tainted("web.fetch")
    reason = p.check("http.post", s)
    assert reason is not None and "tainted" in reason and "web.fetch" in reason


def test_tainted_session_still_allows_non_sink():
    p = make_policy()
    s = Session.new()
    s.mark_tainted("web.fetch")
    assert p.check("search.docs", s) is None


def test_is_taint_source():
    p = make_policy()
    assert p.is_taint_source("web.fetch")
    assert not p.is_taint_source("search.docs")


def test_mark_tainted_is_idempotent_first_only():
    s = Session.new()
    assert s.mark_tainted("web.fetch") is True    # first taint
    assert s.mark_tainted("other") is False       # already tainted
    assert s.taint_origin == "web.fetch"          # origin unchanged


# --------------------------------------------------------------- sequence
def test_sequence_rule_fires_after_trigger():
    p = make_policy()
    s = Session.new()
    assert p.check("http.post", s) is None        # no trigger yet
    s.record_call("crm.get_customer")
    reason = p.check("http.post", s)
    assert reason == "no POST after reading PII"


def test_glob_patterns_in_taint_sinks():
    p = SequencePolicy(taint_sources=["web.*"], taint_sinks=["github.*"])
    s = Session.new()
    assert p.is_taint_source("web.fetch")
    s.mark_tainted("web.fetch")
    assert p.check("github.push_files", s) is not None
    assert p.check("search.docs", s) is None


def test_inactive_policy_never_blocks():
    p = SequencePolicy()
    assert not p.active
    s = Session.new()
    s.mark_tainted("x")
    assert p.check("anything", s) is None
