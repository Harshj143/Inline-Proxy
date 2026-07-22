"""Anomaly monitor: heuristic patterns, debounce, and graceful Claude fallback."""

import asyncio

import pytest

from mcp_gateway.anomaly import AnomalyMonitor, SessionTrace, build_monitor
from mcp_gateway.anomaly.base import AnomalyBackend, Verdict
from mcp_gateway.anomaly.heuristic import HeuristicBackend


def assess(backend, trace):
    return asyncio.run(backend.assess(trace))


# ---------------------------------------------------------------- heuristic
def test_read_then_exfiltrate_flagged():
    v = assess(HeuristicBackend(), SessionTrace(
        history=["crm.get_customer"], last_tool="http.post",
    ))
    assert v.anomalous and v.severity == "medium"
    assert "exfiltration" in v.rationale


def test_read_then_exfiltrate_is_high_when_tainted():
    v = assess(HeuristicBackend(), SessionTrace(
        history=["web.fetch", "crm.get_customer"], last_tool="http.post", tainted=True,
    ))
    assert v.anomalous and v.severity == "high"


def test_recon_sprawl_flagged():
    v = assess(HeuristicBackend(), SessionTrace(
        history=["a.x", "b.y", "c.z"], last_tool="d.w", blocked_count=2,
    ))
    assert v.anomalous and v.severity == "medium"
    assert "probing" in v.rationale


def test_benign_session_not_flagged():
    assert assess(HeuristicBackend(), SessionTrace(
        history=["search.docs", "search.docs"], last_tool="search.docs",
    )) is None


def test_outbound_without_prior_read_not_flagged():
    # An outbound call with no sensitive read earlier is not the exfil shape.
    assert assess(HeuristicBackend(), SessionTrace(
        history=["search.docs"], last_tool="http.post",
    )) is None


# ------------------------------------------------------------------ monitor
class CountingBackend(AnomalyBackend):
    name = "counting"

    def __init__(self):
        self.calls = 0

    async def assess(self, trace):
        self.calls += 1
        return None


def test_debounce_samples_calls():
    backend = CountingBackend()
    mon = AnomalyMonitor(backend, debounce=3)
    for _ in range(5):
        asyncio.run(mon.observe(SessionTrace()))
    assert backend.calls == 1  # assessed on the 3rd call only (5 // 3)


def test_force_bypasses_debounce():
    backend = CountingBackend()
    mon = AnomalyMonitor(backend, debounce=100)
    asyncio.run(mon.observe(SessionTrace(), force=True))
    assert backend.calls == 1


def test_debounce_one_assesses_every_call():
    backend = CountingBackend()
    mon = AnomalyMonitor(backend, debounce=1)
    for _ in range(3):
        asyncio.run(mon.observe(SessionTrace()))
    assert backend.calls == 3


# ------------------------------------------------------------- build_monitor
def test_off_returns_no_monitor():
    assert build_monitor("off") is None


def test_heuristic_monitor():
    mon = build_monitor("heuristic")
    assert mon is not None and mon.backend_name == "heuristic"


def test_claude_falls_back_to_heuristic_without_key(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    mon = build_monitor("claude")
    # No key -> Claude backend unavailable -> heuristic, with a stderr note.
    assert mon.backend_name == "heuristic"
    assert "falling back to the heuristic" in capsys.readouterr().err


def test_unknown_mode_raises():
    with pytest.raises(ValueError, match="unknown anomaly mode"):
        build_monitor("psychic")


def test_verdict_severity_maps_to_risk_event_name():
    # The gateway records f"anomaly_{severity}" — the RiskEngine has weights for
    # exactly low/medium/high, so the severity vocabulary must line up.
    from mcp_gateway.risk.scoring import DEFAULT_WEIGHTS

    for sev in ("low", "medium", "high"):
        assert f"anomaly_{sev}" in DEFAULT_WEIGHTS
    assert Verdict(True, "high", "x").severity == "high"
