"""Phase 5b: multi-upstream routing + gateway.yaml config load/validate/assembly."""

from __future__ import annotations

import asyncio
import json

import pytest

from mcp_gateway.central.config import (
    GatewayConfig,
    UpstreamConfig,
    load_gateway_config,
)
from mcp_gateway.core.errors import GatewayError

fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from tests.unit.test_streamable_http import FakeUpstream, MemSink, _rpc  # noqa: E402

from mcp_gateway.central.config import build_central_app  # noqa: E402
from mcp_gateway.policy.engine import PolicyEngine  # noqa: E402
from mcp_gateway.transports.streamable_http import (  # noqa: E402
    StreamableHttpGateway,
    build_session_parts,
    create_central_app,
)


# ------------------------------------------------------------- config loader
def _write(tmp_path, body, name="gateway.yaml"):
    p = tmp_path / name
    p.write_text(body)
    return p


def test_load_valid_config(tmp_path):
    cfg = _write(tmp_path, """
audit:
  spool: /var/audit.log
state:
  backend: memory
upstreams:
  - name: filesystem
    command: ["python", "srv.py"]
    policy: ["p1.yaml", "p2.yaml"]
  - name: github
    command: ["gh-mcp"]
    policy: gh.yaml
""")
    config = load_gateway_config(cfg)
    assert config.spool_path == "/var/audit.log"
    assert config.state_backend == "memory"
    assert config.names == {"filesystem", "github"}
    fs = config.upstreams[0]
    assert fs.name == "filesystem" and fs.command == ["python", "srv.py"]
    assert fs.policy == ["p1.yaml", "p2.yaml"]
    # A scalar policy is normalised to a one-element list.
    assert config.upstreams[1].policy == ["gh.yaml"]


def test_defaults_when_optional_sections_absent(tmp_path):
    cfg = _write(tmp_path, """
upstreams:
  - name: only
    command: ["x"]
    policy: ["p.yaml"]
""")
    config = load_gateway_config(cfg)
    assert config.spool_path == "audit.log"
    assert config.state_backend == "memory"


def test_json_config(tmp_path):
    body = json.dumps({"upstreams": [
        {"name": "a", "command": ["x"], "policy": ["p.yaml"]}]})
    config = load_gateway_config(_write(tmp_path, body, name="gateway.json"))
    assert config.names == {"a"}


@pytest.mark.parametrize("body, match", [
    ("upstreams: []", "non-empty list"),
    ("state:\n  backend: elasticsearch\nupstreams:\n  - {name: a, command: [x], policy: [p]}",
     "not supported"),
    ("state:\n  backend: redis\nupstreams:\n  - {name: a, command: [x], policy: [p]}",
     "requires state.url"),
    ("upstreams:\n  - {command: [x], policy: [p]}", "'name' is required"),
    ("upstreams:\n  - {name: a, policy: [p]}", "'command'"),
    ("upstreams:\n  - {name: a, command: [x]}", "'policy'"),
    ("upstreams:\n  - {name: a, command: [x], policy: [p]}\n"
     "  - {name: a, command: [y], policy: [q]}",
     "duplicate upstream name"),
])
def test_invalid_configs_fail_closed(tmp_path, body, match):
    with pytest.raises(GatewayError, match=match):
        load_gateway_config(_write(tmp_path, body))


def test_missing_file_fails(tmp_path):
    with pytest.raises(GatewayError, match="cannot read config"):
        load_gateway_config(tmp_path / "nope.yaml")


# ------------------------------------------------------- multi-upstream routing
def _hub(policy_doc, upstreams_out):
    engine = PolicyEngine.from_documents([(policy_doc, "t")])

    def factory(_sid):
        up = FakeUpstream()
        upstreams_out.append(up)
        return up

    parts = build_session_parts(engine=engine, spool=MemSink(), upstream_factory=factory)
    return StreamableHttpGateway(parts, response_timeout=5.0)


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw")


def test_central_routes_each_upstream_to_its_policy():
    # 'alpha' blocks danger.tool; 'beta' allows everything.
    async def scenario():
        a_ups, b_ups = [], []
        hubs = {
            "alpha": _hub({"schema_version": 1, "default_action": "allow",
                           "tools": {"danger.tool": {"action": "block"}}}, a_ups),
            "beta": _hub({"schema_version": 1, "default_action": "allow"}, b_ups),
        }
        app = create_central_app(hubs)
        async with _client(app) as c:
            # list_servers
            assert (await c.get("/servers")).json()["servers"] == ["alpha", "beta"]

            sid_a = (await c.post("/servers/alpha/mcp",
                     json=_rpc("initialize", mid=0))).headers["mcp-session-id"]
            sid_b = (await c.post("/servers/beta/mcp",
                     json=_rpc("initialize", mid=0))).headers["mcp-session-id"]

            # danger.tool is blocked on alpha...
            ra = await c.post("/servers/alpha/mcp", headers={"Mcp-Session-Id": sid_a},
                              json=_rpc("tools/call", mid=1, name="danger.tool"))
            assert ra.json()["error"]["code"] == -32001
            # ...but allowed on beta.
            rb = await c.post("/servers/beta/mcp", headers={"Mcp-Session-Id": sid_b},
                              json=_rpc("tools/call", mid=1, name="danger.tool"))
            assert rb.json()["result"]["content"][0]["text"] == "UPSTREAM-RESULT"

    asyncio.run(scenario())


def test_sessions_are_isolated_across_upstreams():
    async def scenario():
        hubs = {
            "alpha": _hub({"schema_version": 1, "default_action": "allow"}, []),
            "beta": _hub({"schema_version": 1, "default_action": "allow"}, []),
        }
        app = create_central_app(hubs)
        async with _client(app) as c:
            sid_a = (await c.post("/servers/alpha/mcp",
                     json=_rpc("initialize", mid=0))).headers["mcp-session-id"]
            # alpha's session id is unknown to beta → 404.
            r = await c.post("/servers/beta/mcp", headers={"Mcp-Session-Id": sid_a},
                             json=_rpc("tools/list", mid=1))
            assert r.status_code == 404

    asyncio.run(scenario())


def test_unknown_upstream_is_404():
    async def scenario():
        app = create_central_app({"alpha": _hub(
            {"schema_version": 1, "default_action": "allow"}, [])})
        async with _client(app) as c:
            r = await c.post("/servers/ghost/mcp", json=_rpc("initialize", mid=0))
            assert r.status_code == 404
            assert r.json()["error"]["code"] == -32004

    asyncio.run(scenario())


def test_build_central_app_from_config(tmp_path):
    # Assemble from a real config (real policy file) but inject fake upstreams so
    # no subprocess is spawned; prove the wiring polices correctly end to end.
    policy = tmp_path / "p.yaml"
    policy.write_text(
        "schema_version: 1\ndefault_action: allow\n"
        "tools:\n  danger.tool:\n    action: block\n"
    )
    cfg = GatewayConfig(
        upstreams=[UpstreamConfig("svc", ["unused"], [str(policy)])],
        spool_path=str(tmp_path / "audit.log"),
        names=frozenset({"svc"}),
    )
    made = []

    def fake_factory(name, command):
        up = FakeUpstream()
        made.append((name, command, up))
        return up

    app, spool = build_central_app(cfg, upstream_factory=fake_factory)

    async def scenario():
        async with _client(app) as c:
            sid = (await c.post("/servers/svc/mcp",
                   json=_rpc("initialize", mid=0))).headers["mcp-session-id"]
            r = await c.post("/servers/svc/mcp", headers={"Mcp-Session-Id": sid},
                             json=_rpc("tools/call", mid=1, name="danger.tool"))
            assert r.json()["error"]["code"] == -32001  # policed by the config's policy

    asyncio.run(scenario())
    assert made and made[0][0] == "svc"
    asyncio.run(spool.close())
