"""Risk scoring: weights, thresholds, auto-suspend."""

from mcp_gateway.core.session import Session
from mcp_gateway.risk.scoring import (
    BLOCKED_TOOL,
    CONSTRAINT_VIOLATION,
    LEVEL_ELEVATED,
    LEVEL_NORMAL,
    LEVEL_SUSPENDED,
    RiskEngine,
)


def test_score_accumulates_and_levels_up():
    eng = RiskEngine()
    s = Session.new()
    assert eng.level(0) == LEVEL_NORMAL

    u1 = eng.record(s, BLOCKED_TOOL)         # 25
    assert u1.score == 25 and u1.level == LEVEL_NORMAL and not u1.suspended_now

    u2 = eng.record(s, BLOCKED_TOOL)         # 50 -> elevated
    assert u2.score == 50 and u2.level == LEVEL_ELEVATED


def test_auto_suspend_at_threshold():
    eng = RiskEngine()
    s = Session.new()
    eng.record(s, BLOCKED_TOOL)              # 25
    eng.record(s, BLOCKED_TOOL)              # 50
    u = eng.record(s, CONSTRAINT_VIOLATION)  # 70
    assert not u.suspended_now and not s.suspended
    u = eng.record(s, BLOCKED_TOOL)          # 95 -> suspended
    assert u.level == LEVEL_SUSPENDED
    assert u.suspended_now is True and s.suspended is True


def test_suspended_now_only_fires_on_transition():
    eng = RiskEngine()
    s = Session.new()
    for _ in range(4):
        eng.record(s, BLOCKED_TOOL)          # 25,50,75,100
    # Already suspended; further events accrue but don't re-fire the transition.
    u = eng.record(s, BLOCKED_TOOL)
    assert s.suspended and u.suspended_now is False


def test_custom_weights_and_thresholds():
    eng = RiskEngine(weights={BLOCKED_TOOL: 100}, suspend_at=100)
    s = Session.new()
    u = eng.record(s, BLOCKED_TOOL)
    assert u.suspended_now and s.suspended


def test_unknown_event_scores_zero():
    eng = RiskEngine()
    s = Session.new()
    u = eng.record(s, "nonexistent_event")
    assert u.weight == 0 and u.score == 0


def test_audit_fields_shape():
    eng = RiskEngine()
    s = Session.new()
    fields = eng.record(s, BLOCKED_TOOL).audit_fields()
    assert fields == {
        "risk_event": BLOCKED_TOOL, "risk_delta": 25,
        "session_score": 25, "session_level": LEVEL_NORMAL,
    }
