"""Streamable HTTP transport (5a): session lifecycle + policing over ASGI.

Driven in-process with httpx.ASGITransport and an in-memory fake upstream — no
subprocess, no sockets. Gated on the [server] extra.
"""

from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from mcp_gateway.policy.engine import PolicyEngine  # noqa: E402
from mcp_gateway.transports.streamable_http import (  # noqa: E402
    StreamableHttpGateway,
    build_session_parts,
    create_streamable_http_app,
)


class FakeUpstream:
    """An in-process MCP server: answers initialize/tools/list/tools/call."""

    def __init__(self):
        self.received: list[dict] = []
        self._on_line = None

    async def start(self, on_line, on_exit):
        self._on_line = on_line

    async def send(self, line: str) -> None:
        msg = json.loads(line)
        self.received.append(msg)
        mid, method = msg.get("id"), msg.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2025-03-26", "serverInfo": {"name": "fake"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "safe.tool"}, {"name": "danger.tool"}]}
        elif method == "tools/call":
            result = {"content": [{"type": "text", "text": "UPSTREAM-RESULT"}]}
        elif mid is not None:
            result = {}
        else:
            return  # client notification: no response
        await self._on_line(json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}))

    async def shutdown(self):
        return 0


class MemSink:
    def __init__(self):
        self.events = []

    async def emit(self, event):
        self.events.append(event)


def _make_app(policy_doc):
    engine = PolicyEngine.from_documents([(policy_doc, "test")])
    upstreams: list[FakeUpstream] = []

    def upstream_factory(_session_id):
        up = FakeUpstream()
        upstreams.append(up)
        return up

    parts = build_session_parts(
        engine=engine, spool=MemSink(), upstream_factory=upstream_factory,
        annotate={"transport": "streamable_http"},
    )
    hub = StreamableHttpGateway(parts, response_timeout=5.0)
    app = create_streamable_http_app(hub)
    return app, upstreams, hub


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw")


def _rpc(method, mid=1, **params):
    msg = {"jsonrpc": "2.0", "method": method}
    if mid is not None:
        msg["id"] = mid
    if params:
        msg["params"] = params
    return msg


ALLOW_POLICY = {"schema_version": 1, "default_action": "allow",
                "tools": {"danger.tool": {"action": "block", "reason": "too risky"}}}


def test_initialize_mints_session_id():
    async def scenario():
        app, upstreams, _ = _make_app(ALLOW_POLICY)
        async with _client(app) as c:
            r = await c.post("/mcp", json=_rpc("initialize", mid=0))
            assert r.status_code == 200
            sid = r.headers.get("mcp-session-id")
            assert sid
            assert r.json()["result"]["serverInfo"]["name"] == "fake"
            # The upstream saw the initialize forwarded by the gateway.
            assert upstreams[0].received[0]["method"] == "initialize"

    asyncio.run(scenario())


def test_allowed_tool_call_reaches_upstream():
    async def scenario():
        app, upstreams, _ = _make_app(ALLOW_POLICY)
        async with _client(app) as c:
            sid = (await c.post("/mcp", json=_rpc("initialize", mid=0))).headers["mcp-session-id"]
            r = await c.post("/mcp", headers={"Mcp-Session-Id": sid},
                             json=_rpc("tools/call", mid=1, name="safe.tool", arguments={}))
            assert r.status_code == 200
            assert r.json()["result"]["content"][0]["text"] == "UPSTREAM-RESULT"
            methods = [m.get("method") for m in upstreams[0].received]
            assert "tools/call" in methods

    asyncio.run(scenario())


def test_blocked_tool_call_never_reaches_upstream():
    async def scenario():
        app, upstreams, _ = _make_app(ALLOW_POLICY)
        async with _client(app) as c:
            sid = (await c.post("/mcp", json=_rpc("initialize", mid=0))).headers["mcp-session-id"]
            r = await c.post("/mcp", headers={"Mcp-Session-Id": sid},
                             json=_rpc("tools/call", mid=2, name="danger.tool", arguments={}))
            assert r.status_code == 200
            err = r.json()["error"]
            assert err["code"] == -32001  # policy-denied
            assert "denied by security gateway" in err["message"]
            # The dangerous call was stopped at the gateway.
            call_names = [
                m["params"]["name"] for m in upstreams[0].received
                if m.get("method") == "tools/call"
            ]
            assert "danger.tool" not in call_names

    asyncio.run(scenario())


def test_tools_list_is_filtered_by_policy():
    # danger.tool can only ever deny → hidden from a filtered tools/list.
    async def scenario():
        app, upstreams, _ = _make_app(ALLOW_POLICY)
        async with _client(app) as c:
            sid = (await c.post("/mcp", json=_rpc("initialize", mid=0))).headers["mcp-session-id"]
            r = await c.post("/mcp", headers={"Mcp-Session-Id": sid},
                             json=_rpc("tools/list", mid=3))
            names = [t["name"] for t in r.json()["result"]["tools"]]
            assert "safe.tool" in names
            assert "danger.tool" not in names

    asyncio.run(scenario())


def test_unknown_session_is_404():
    async def scenario():
        app, _, _ = _make_app(ALLOW_POLICY)
        async with _client(app) as c:
            r = await c.post("/mcp", headers={"Mcp-Session-Id": "nope"},
                             json=_rpc("tools/call", mid=1, name="safe.tool"))
            assert r.status_code == 404
            assert r.json()["error"]["code"] == -32001

    asyncio.run(scenario())


def test_request_without_session_is_400():
    async def scenario():
        app, _, _ = _make_app(ALLOW_POLICY)
        async with _client(app) as c:
            r = await c.post("/mcp", json=_rpc("tools/list", mid=1))
            assert r.status_code == 400

    asyncio.run(scenario())


def test_notification_returns_202():
    async def scenario():
        app, upstreams, _ = _make_app(ALLOW_POLICY)
        async with _client(app) as c:
            sid = (await c.post("/mcp", json=_rpc("initialize", mid=0))).headers["mcp-session-id"]
            r = await c.post("/mcp", headers={"Mcp-Session-Id": sid},
                             json=_rpc("notifications/initialized", mid=None))
            assert r.status_code == 202
            # Forwarded to the upstream as a passthrough notification.
            assert any(m.get("method") == "notifications/initialized"
                       for m in upstreams[0].received)

    asyncio.run(scenario())


def test_delete_terminates_session():
    async def scenario():
        app, _, hub = _make_app(ALLOW_POLICY)
        async with _client(app) as c:
            sid = (await c.post("/mcp", json=_rpc("initialize", mid=0))).headers["mcp-session-id"]
            assert hub.get(sid) is not None
            r = await c.request("DELETE", "/mcp", headers={"Mcp-Session-Id": sid})
            assert r.status_code == 204
            assert hub.get(sid) is None
            # A call on the terminated session is now unknown.
            r2 = await c.post("/mcp", headers={"Mcp-Session-Id": sid},
                              json=_rpc("tools/list", mid=9))
            assert r2.status_code == 404

    asyncio.run(scenario())


def test_sessions_are_isolated():
    async def scenario():
        app, upstreams, _ = _make_app(ALLOW_POLICY)
        async with _client(app) as c:
            sid_a = (await c.post("/mcp", json=_rpc("initialize", mid=0))).headers["mcp-session-id"]
            sid_b = (await c.post("/mcp", json=_rpc("initialize", mid=0))).headers["mcp-session-id"]
            assert sid_a != sid_b
            assert len(upstreams) == 2  # each session got its own upstream

    asyncio.run(scenario())


def test_gateway_timeout_returns_rpc_error():
    # An upstream that never replies → the gateway deadline fires, fail-closed
    # with a JSON-RPC error rather than hanging.
    class SilentUpstream(FakeUpstream):
        async def send(self, line):
            msg = json.loads(line)
            self.received.append(msg)
            if msg.get("method") == "initialize":
                await self._on_line(json.dumps(
                    {"jsonrpc": "2.0", "id": msg.get("id"), "result": {}}))
            # tools/call: swallow — never respond.

    async def scenario():
        engine = PolicyEngine.from_documents([(ALLOW_POLICY, "t")])
        ups: list[SilentUpstream] = []

        def factory(_sid):
            u = SilentUpstream()
            ups.append(u)
            return u

        parts = build_session_parts(engine=engine, spool=MemSink(), upstream_factory=factory)
        hub = StreamableHttpGateway(parts, response_timeout=0.3)
        app = create_streamable_http_app(hub)
        async with _client(app) as c:
            sid = (await c.post("/mcp", json=_rpc("initialize", mid=0))).headers["mcp-session-id"]
            r = await c.post("/mcp", headers={"Mcp-Session-Id": sid},
                             json=_rpc("tools/call", mid=1, name="safe.tool"))
            assert r.status_code == 200
            assert r.json()["error"]["code"] == -32002  # gateway timeout

    asyncio.run(scenario())
