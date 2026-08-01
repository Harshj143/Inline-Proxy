"""The metrics registry, the audit→metrics sink, and the health checks.

The registry is hand-rolled, so its Prometheus text format and its cardinality
guard need pinning; the sink has to map the right events to the right counters;
and the health checks encode the liveness-vs-readiness distinction that keeps a
SIEM outage from getting the process killed. Each is tested in isolation against
a fresh `Registry` so counts are deterministic (the process-wide default registry
is monotonic and shared, which is correct for production and wrong for a test).
"""

from __future__ import annotations

import asyncio

import pytest

from mcp_gateway.observability import health
from mcp_gateway.observability.audit_metrics import MetricsAuditSink
from mcp_gateway.observability.metrics import Registry


# ----------------------------------------------------------------- registry
def test_counter_accumulates_per_label_set():
    reg = Registry()
    c = reg.counter("calls_total", "help", ["outcome"])
    c.inc(outcome="allow")
    c.inc(2, outcome="allow")
    c.inc(outcome="deny")
    text = reg.render()
    assert 'calls_total{outcome="allow"} 3' in text
    assert 'calls_total{outcome="deny"} 1' in text


def test_render_emits_help_and_type():
    reg = Registry()
    reg.counter("widgets_total", "Total widgets.", [])
    text = reg.render()
    assert "# HELP widgets_total Total widgets." in text
    assert "# TYPE widgets_total counter" in text
    assert "widgets_total 0" in text          # unlabeled + no samples reads as 0


def test_gauge_goes_up_and_down():
    reg = Registry()
    g = reg.gauge("live_sessions", "Live sessions.", [])
    g.inc()
    g.inc()
    g.dec()
    assert "live_sessions 1" in reg.render()
    g.set(10)
    assert "live_sessions 10" in reg.render()


def test_a_counter_cannot_decrease():
    c = Registry().counter("c_total", "h", [])
    with pytest.raises(ValueError, match="cannot decrease"):
        c.inc(-1)


def test_wrong_label_set_is_rejected():
    c = Registry().counter("c_total", "h", ["a"])
    with pytest.raises(ValueError, match="expects labels"):
        c.inc(b="x")


def test_reregistering_the_same_metric_is_idempotent():
    reg = Registry()
    a = reg.counter("dup_total", "h", ["x"])
    b = reg.counter("dup_total", "h", ["x"])   # same shape → same instance
    a.inc(x="1")
    b.inc(x="1")
    assert 'dup_total{x="1"} 2' in reg.render()


def test_reregistering_with_a_different_shape_raises():
    reg = Registry()
    reg.counter("m_total", "h", ["x"])
    with pytest.raises(ValueError, match="different shape"):
        reg.gauge("m_total", "h", ["x"])


def test_label_values_are_escaped():
    reg = Registry()
    reg.counter("e_total", "h", ["k"]).inc(k='a"b\\c')
    assert r'e_total{k="a\"b\\c"} 1' in reg.render()


# -------------------------------------------------------------- audit sink
def _emit(sink, *events):
    async def run():
        for e in events:
            await sink.emit({"event": e})
    asyncio.run(run())


def test_audit_sink_counts_events_calls_and_signals():
    reg = Registry()
    sink = MetricsAuditSink(reg)
    _emit(sink, "tool_call_allowed", "tool_call_allowed", "tool_call_blocked",
          "session_tainted", "tool_result_redacted")
    text = reg.render()
    assert 'mcpgw_audit_events_total{event="tool_call_allowed"} 2' in text
    assert 'mcpgw_tool_calls_total{outcome="allow"} 2' in text
    assert 'mcpgw_tool_calls_total{outcome="deny"} 1' in text
    assert 'mcpgw_security_signals_total{signal="session_tainted"} 1' in text
    assert 'mcpgw_security_signals_total{signal="tool_result_redacted"} 1' in text


def test_suspended_denial_counts_as_deny():
    reg = Registry()
    sink = MetricsAuditSink(reg)
    _emit(sink, "tool_call_denied_session_suspended")
    assert 'mcpgw_tool_calls_total{outcome="deny"} 1' in reg.render()


def test_non_call_events_do_not_touch_the_calls_counter():
    reg = Registry()
    sink = MetricsAuditSink(reg)
    _emit(sink, "gateway_start", "passthrough_request")
    text = reg.render()
    # counted in the universal events total, but not as a tool-call outcome
    assert 'mcpgw_audit_events_total{event="gateway_start"} 1' in text
    assert "mcpgw_tool_calls_total{" not in text


def test_audit_sink_ignores_an_event_without_a_name():
    reg = Registry()
    sink = MetricsAuditSink(reg)
    asyncio.run(sink.emit({"no_event_key": True}))
    assert "mcpgw_tool_calls_total{" not in reg.render()


# ------------------------------------------------------------------ health
def test_liveness_never_depends_on_a_downstream():
    # There is nothing to assert about a downstream here — that's the point.
    # Liveness is the trivial predicate; readiness carries the dependencies.
    report = health.evaluate({})
    assert report.ready is True and report.checks == []


def test_readiness_passes_when_every_check_passes(tmp_path):
    report = health.evaluate({
        "spool": health.spool_writable_check(tmp_path / "audit.log"),
        "upstreams": health.upstreams_configured_check(3),
    })
    assert report.ready
    assert report.to_dict()["status"] == "ready"


def test_readiness_fails_if_the_spool_dir_is_unwritable():
    report = health.evaluate({
        "spool": health.spool_writable_check("/does/not/exist/audit.log"),
    })
    assert not report.ready
    assert "not writable" in report.to_dict()["checks"]["spool"]["detail"]


def test_readiness_fails_with_no_upstreams():
    report = health.evaluate({"upstreams": health.upstreams_configured_check(0)})
    assert not report.ready


def test_a_raising_check_is_a_failing_check():
    def boom() -> tuple[bool, str]:
        raise RuntimeError("kaboom")
    report = health.evaluate({"x": boom})
    assert not report.ready
    assert "kaboom" in report.checks[0].detail
