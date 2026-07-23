"""Phase 5c: Redis-backed session store — shared taint/risk across replicas.

Uses fakeredis (in-process, no server). Skipped cleanly when it is absent.
"""

from __future__ import annotations

import asyncio

import pytest

fakeredis = pytest.importorskip("fakeredis")

from mcp_gateway.approvals.broker import build_broker  # noqa: E402
from mcp_gateway.audit.recorder import AuditRecorder  # noqa: E402
from mcp_gateway.core.gateway import SecurityGateway  # noqa: E402
from mcp_gateway.core.pipeline import default_pipeline  # noqa: E402
from mcp_gateway.core.session import Session  # noqa: E402
from mcp_gateway.policy.engine import PolicyEngine  # noqa: E402
from mcp_gateway.state.redis import RedisSessionStore  # noqa: E402


def _store(client, **kw):
    return RedisSessionStore(client, **kw)


class _FakeTransport:
    def __init__(self):
        self.to_client, self.to_upstream = [], []

    async def send_client(self, line):
        self.to_client.append(line)

    async def send_upstream(self, line):
        self.to_upstream.append(line)


class _Sink:
    async def emit(self, event):
        pass


def test_session_dict_roundtrip():
    s = Session.new(session_id="abc")
    s.mark_tainted("web.fetch")
    s.record_call("crm.get")
    s.risk_score = 42
    s.risk_events.append({"event": "blocked_tool", "weight": 20})
    s.suspended = True
    restored = Session.from_dict(s.to_dict())
    assert restored.id == "abc"
    assert restored.tainted and restored.taint_origin == "web.fetch"
    assert restored.history == ["crm.get"]
    assert restored.risk_score == 42
    assert restored.suspended is True
    # pending is intentionally not serialised.
    assert restored.pending == {}


def test_get_or_create_persists():
    client = fakeredis.FakeStrictRedis()
    store = _store(client)
    s = store.get_or_create("sess1")
    assert s.id == "sess1"
    # A second get returns an equivalent (reloaded) session, not None.
    again = store.get("sess1")
    assert again is not None and again.id == "sess1"


def test_get_unknown_is_none():
    store = _store(fakeredis.FakeStrictRedis())
    assert store.get("nope") is None


def test_two_replicas_share_taint_and_suspension():
    # Two stores over ONE Redis = two gateway replicas sharing state.
    shared = fakeredis.FakeStrictRedis()
    replica_a = _store(shared)
    replica_b = _store(shared)

    # Replica A taints + suspends the session and saves (as the gateway does
    # after handling a message).
    s_a = replica_a.get_or_create("shared-session")
    s_a.mark_tainted("web.fetch")
    s_a.risk_score = 80
    s_a.suspended = True
    replica_a.save(s_a)

    # Replica B, handling the next call for the same id, sees the taint + suspension.
    s_b = replica_b.get("shared-session")
    assert s_b is not None
    assert s_b.tainted is True
    assert s_b.taint_origin == "web.fetch"
    assert s_b.suspended is True
    assert s_b.risk_score == 80


def test_save_refreshes_and_updates():
    client = fakeredis.FakeStrictRedis()
    store = _store(client)
    s = store.get_or_create("s")
    s.risk_score = 10
    store.save(s)
    assert store.get("s").risk_score == 10
    s.risk_score = 25
    store.save(s)
    assert store.get("s").risk_score == 25


def test_corrupt_blob_is_treated_as_absent():
    client = fakeredis.FakeStrictRedis()
    store = _store(client)
    client.set("mcpg:session:bad", b"{not json")
    assert store.get("bad") is None


def test_ttl_is_set_when_configured():
    client = fakeredis.FakeStrictRedis()
    store = _store(client, ttl_seconds=100)
    store.get_or_create("ttl")
    assert 0 < client.ttl("mcpg:session:ttl") <= 100


def test_gateway_persists_taint_to_shared_store():
    # Exit criterion: replica A tainting a session is seen by replica B.
    shared = fakeredis.FakeStrictRedis()
    doc = {"schema_version": 1, "default_action": "allow",
           "tools": {"web.fetch": {"action": "allow"}},
           "taint_sources": ["web.fetch"]}
    engine = PolicyEngine.from_documents([(doc, "t")])

    def _gateway(store):
        gw = SecurityGateway(
            pipeline=default_pipeline(engine, None, build_broker("deny")),
            audit=AuditRecorder([_Sink()]),
            policy=engine, store=store, session_id="shared-id",
        )
        gw.bind_transport(_FakeTransport())
        return gw

    # Replica A processes a taint-source call → taints + persists to Redis.
    gw_a = _gateway(RedisSessionStore(shared))
    assert gw_a.session.tainted is False
    fetch = ('{"jsonrpc":"2.0","id":1,"method":"tools/call",'
             '"params":{"name":"web.fetch","arguments":{}}}')
    asyncio.run(gw_a.on_client_line(fetch))
    assert gw_a.session.tainted is True

    # Replica B binds the same Mcp-Session-Id and resumes the tainted state.
    gw_b = _gateway(RedisSessionStore(shared))
    assert gw_b.session.tainted is True
    assert gw_b.session.taint_origin == "web.fetch"
