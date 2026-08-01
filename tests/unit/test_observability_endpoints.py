"""The ops endpoints over the real ASGI apps: /healthz, /readyz, /metrics.

These prove the wiring — that mount_ops_endpoints reaches the central and
single-upstream apps, that readiness reflects a failing check with a 503, and
that a policed decision actually shows up on /metrics. Metric *values* are
asserted only as ">= 1" because the process-wide default registry is monotonic
and shared across the suite; exact counts are pinned in test_metrics.py against
an isolated registry.
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

# Reuse the transport test's fakes.
from tests.unit.test_streamable_http import (  # noqa: E402
    FakeUpstream,
    MemSink,
    _rpc,
)

from mcp_gateway.observability.health import upstreams_configured_check  # noqa: E402
from mcp_gateway.policy.engine import PolicyEngine  # noqa: E402
from mcp_gateway.transports.streamable_http import (  # noqa: E402
    StreamableHttpGateway,
    build_session_parts,
    create_central_app,
    create_streamable_http_app,
)

POLICY = {"schema_version": 1, "default_action": "allow",
          "tools": {"danger.tool": {"action": "block", "reason": "off limits"}}}


def _hub(readiness=None):
    engine = PolicyEngine.from_documents([(POLICY, "test")])
    parts = build_session_parts(
        engine=engine, spool=MemSink(),
        upstream_factory=lambda _sid: FakeUpstream(),
        annotate={"transport": "streamable_http"},
    )
    return StreamableHttpGateway(parts, response_timeout=5.0)


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw")


def test_healthz_is_always_ok():
    async def scenario():
        app = create_streamable_http_app(_hub())
        async with _client(app) as c:
            r = await c.get("/healthz")
            assert r.status_code == 200 and r.json() == {"status": "ok"}
    asyncio.run(scenario())


def test_readyz_reports_200_when_ready():
    async def scenario():
        app = create_streamable_http_app(
            _hub(), readiness={"upstreams": upstreams_configured_check(1)}
        )
        async with _client(app) as c:
            r = await c.get("/readyz")
            assert r.status_code == 200
            assert r.json()["status"] == "ready"
            assert r.json()["checks"]["upstreams"]["ok"] is True
    asyncio.run(scenario())


def test_readyz_reports_503_when_a_check_fails():
    async def scenario():
        app = create_streamable_http_app(
            _hub(), readiness={"upstreams": upstreams_configured_check(0)}
        )
        async with _client(app) as c:
            r = await c.get("/readyz")
            assert r.status_code == 503
            assert r.json()["status"] == "not ready"
    asyncio.run(scenario())


def test_metrics_is_prometheus_text():
    async def scenario():
        app = create_streamable_http_app(_hub())
        async with _client(app) as c:
            r = await c.get("/metrics")
            assert r.status_code == 200
            assert r.headers["content-type"].startswith("text/plain")
            assert "# TYPE mcpgw_audit_events_total counter" in r.text
    asyncio.run(scenario())


def test_a_blocked_call_increments_the_deny_counter():
    async def scenario():
        app = create_streamable_http_app(_hub())
        async with _client(app) as c:
            sid = (await c.post("/mcp", json=_rpc("initialize", mid=0))).headers["mcp-session-id"]
            await c.post("/mcp", headers={"Mcp-Session-Id": sid},
                         json=_rpc("tools/call", mid=1, name="danger.tool", arguments={}))
            text = (await c.get("/metrics")).text
        deny = [ln for ln in text.splitlines()
                if ln.startswith("mcpgw_tool_calls_total") and 'outcome="deny"' in ln]
        assert deny, "expected a deny sample after a blocked call"
        assert float(deny[0].rsplit(" ", 1)[1]) >= 1
    asyncio.run(scenario())


def test_central_app_exposes_ops_endpoints_alongside_servers():
    async def scenario():
        hubs = {"a": _hub(), "b": _hub()}
        app = create_central_app(hubs, readiness={"upstreams": upstreams_configured_check(2)})
        async with _client(app) as c:
            assert (await c.get("/healthz")).status_code == 200
            assert (await c.get("/readyz")).status_code == 200
            assert "mcpgw_" in (await c.get("/metrics")).text
            # ops endpoints don't shadow the MCP routing
            servers = (await c.get("/servers")).json()
            assert set(servers["servers"]) == {"a", "b"}
    asyncio.run(scenario())


def test_ops_endpoints_are_not_in_the_openapi_schema():
    async def scenario():
        app = create_streamable_http_app(_hub())
        async with _client(app) as c:
            paths = (await c.get("/openapi.json")).json().get("paths", {})
            assert "/healthz" not in paths and "/metrics" not in paths
    asyncio.run(scenario())
