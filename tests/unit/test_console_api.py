"""Console REST API, SSE resume, approvals round-trip, and role gating.

Gated behind the [server] extra — the suite still passes without FastAPI
installed (mirrors how the Presidio tests skip when the extra is absent).
"""

from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from mcp_gateway.console.app import create_app  # noqa: E402
from mcp_gateway.console.auth import CookieSigner, LocalUsers  # noqa: E402
from mcp_gateway.policy.engine import PolicyEngine  # noqa: E402


def _spool(path, events):
    with path.open("wb") as fh:
        for ev in events:
            fh.write((json.dumps(ev) + "\n").encode("utf-8"))


def _events():
    return [
        {"schema_version": 1, "ts": "t1", "event": "gateway_start", "session_id": "s1"},
        {"schema_version": 1, "ts": "t2", "event": "tool_call_allowed",
         "session_id": "s1", "tool": "crm.get", "action": "allow", "rule": "r", "id": 1},
        {"schema_version": 1, "ts": "t3", "event": "tool_call_blocked",
         "session_id": "s1", "tool": "http.post", "stage": "action", "reason": "no", "id": 2},
    ]


def _app(tmp_path, *, policy=None, users=None):
    spool = tmp_path / "audit.log"
    _spool(spool, _events())
    engine = None
    if policy is not None:
        engine = PolicyEngine.from_documents([(policy, "test")])
    user_recs = users or [
        {"username": "alice", "role": "approver", "password": "pw"},
        {"username": "bob", "role": "viewer", "password": "pw"},
    ]
    return create_app(
        index_path=str(tmp_path / "audit.db"),
        spool_path=str(spool),
        users=LocalUsers(user_recs),
        signer=CookieSigner(b"test-secret"),
        policy_engine=engine,
        approval_timeout=1.0,
    )


def _login(client, username="alice", password="pw"):
    resp = client.post("/api/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp


# --------------------------------------------------------------------- authn
def test_unauthenticated_read_is_401(tmp_path):
    client = TestClient(_app(tmp_path))
    assert client.get("/api/sessions").status_code == 401


def test_login_bad_credentials(tmp_path):
    client = TestClient(_app(tmp_path))
    resp = client.post("/api/login", json={"username": "alice", "password": "no"})
    assert resp.status_code == 401


def test_login_sets_cookie_and_me(tmp_path):
    client = TestClient(_app(tmp_path))
    _login(client)
    me = client.get("/api/me").json()
    assert me == {"username": "alice", "role": "approver"}


# ----------------------------------------------------------------- read model
def test_sessions_and_detail(tmp_path):
    client = TestClient(_app(tmp_path))
    _login(client)
    sessions = client.get("/api/sessions").json()["sessions"]
    assert sessions[0]["session_id"] == "s1"
    assert sessions[0]["allowed_count"] == 1
    assert sessions[0]["blocked_count"] == 1

    detail = client.get("/api/sessions/s1").json()
    names = [e["event"] for e in detail["events"]]
    assert names == ["gateway_start", "tool_call_allowed", "tool_call_blocked"]
    assert client.get("/api/sessions/missing").status_code == 404


def test_events_filter(tmp_path):
    client = TestClient(_app(tmp_path))
    _login(client)
    blocked = client.get("/api/events", params={"event": "tool_call_blocked"}).json()
    assert len(blocked["events"]) == 1
    assert blocked["events"][0]["tool"] == "http.post"
    assert blocked["latest_offset"] > 0


def test_stats(tmp_path):
    client = TestClient(_app(tmp_path))
    _login(client)
    counts = client.get("/api/stats").json()["counts_by_event"]
    assert counts["tool_call_allowed"] == 1


def test_policy_view(tmp_path):
    policy = {"schema_version": 1, "default_action": "block",
              "tools": {"crm.get": {"action": "allow"}}}
    client = TestClient(_app(tmp_path, policy=policy))
    _login(client)
    desc = client.get("/api/policy").json()
    assert desc["default_action"] == "block"
    assert any(r["pattern"] == "crm.get" for r in desc["rules"])


def test_policy_view_404_without_policy(tmp_path):
    client = TestClient(_app(tmp_path))
    _login(client)
    assert client.get("/api/policy").status_code == 404


def test_home_serves_the_spa(tmp_path):
    client = TestClient(_app(tmp_path))
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Security Ops Console" in resp.text


def test_static_assets_served(tmp_path):
    client = TestClient(_app(tmp_path))
    js = client.get("/static/app.js")
    assert js.status_code == 200
    assert "EventSource" in js.text
    css = client.get("/static/style.css")
    assert css.status_code == 200


def test_static_dir_can_be_disabled(tmp_path):
    # Passing an empty/missing static dir yields an API-only app (no "/" route).
    spool = tmp_path / "audit.log"
    _spool(spool, _events())
    app = create_app(
        index_path=str(tmp_path / "audit.db"), spool_path=str(spool),
        users=LocalUsers([{"username": "a", "role": "viewer", "password": "p"}]),
        signer=CookieSigner(b"s"), static_dir=tmp_path / "no-such-dir",
    )
    assert TestClient(app).get("/").status_code == 404


def test_openapi_covers_the_surface(tmp_path):
    client = TestClient(_app(tmp_path))
    spec = client.get("/openapi.json").json()
    paths = spec["paths"]
    for p in ["/api/login", "/api/sessions", "/api/events", "/api/stream",
              "/api/approvals", "/api/approvals/pending", "/api/backtest"]:
        assert p in paths, f"missing {p} in OpenAPI"


# ------------------------------------------------------------------ backtest
def test_backtest_endpoint(tmp_path):
    client = TestClient(_app(tmp_path))
    _login(client)
    body = {"policy": {"schema_version": 1, "default_action": "allow",
                       "tools": {"crm.get": {"action": "block"}}}}
    report = client.post("/api/backtest", json=body).json()
    assert report["summary"]["newly_blocked"] == 1


def test_backtest_invalid_policy_is_400(tmp_path):
    client = TestClient(_app(tmp_path))
    _login(client)
    resp = client.post("/api/backtest", json={"policy": {"nonsense": True}})
    assert resp.status_code == 400


# ---------------------------------------------------------------- live feed
def test_stream_once_replays_all(tmp_path):
    client = TestClient(_app(tmp_path))
    _login(client)
    with client.stream("GET", "/api/stream", params={"once": True}) as resp:
        body = "".join(resp.iter_text())
    ids = [ln.split("id: ")[1] for ln in body.splitlines() if ln.startswith("id: ")]
    assert len(ids) == 3
    assert ids == sorted(ids, key=int)


def test_stream_resume_is_exclusive(tmp_path):
    client = TestClient(_app(tmp_path))
    _login(client)
    with client.stream("GET", "/api/stream", params={"once": True}) as resp:
        first = "".join(resp.iter_text())
    ids = [int(ln.split("id: ")[1]) for ln in first.splitlines() if ln.startswith("id: ")]
    # Resume after the first event: only the remaining two, none repeated.
    with client.stream("GET", "/api/stream",
                       params={"once": True, "last_event_id": ids[0]}) as resp:
        resumed = "".join(resp.iter_text())
    resumed_ids = [int(ln.split("id: ")[1]) for ln in resumed.splitlines()
                   if ln.startswith("id: ")]
    assert resumed_ids == ids[1:]


def test_stream_resume_via_header(tmp_path):
    client = TestClient(_app(tmp_path))
    _login(client)
    with client.stream("GET", "/api/stream", params={"once": True}) as resp:
        first = "".join(resp.iter_text())
    ids = [int(ln.split("id: ")[1]) for ln in first.splitlines() if ln.startswith("id: ")]
    with client.stream("GET", "/api/stream", params={"once": True},
                       headers={"Last-Event-ID": str(ids[0])}) as resp:
        resumed = "".join(resp.iter_text())
    resumed_ids = [int(ln.split("id: ")[1]) for ln in resumed.splitlines()
                   if ln.startswith("id: ")]
    assert resumed_ids == ids[1:]


# ------------------------------------------------------------- approvals flow
def test_approval_roundtrip_blocks_until_resolved(tmp_path):
    # The blocking contract must be exercised on ONE event loop (as uvicorn
    # runs it): the gateway POST parks and awaits while a concurrent resolver
    # completes it. TestClient serialises requests through a single portal and
    # would deadlock, so drive the ASGI app with httpx.AsyncClient directly.
    app = _app(tmp_path)

    async def scenario():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            r = await client.post("/api/login", json={"username": "alice", "password": "pw"})
            assert r.status_code == 200  # alice = approver

            wire = {"request_id": 7, "session_id": "s1", "tool": "admin.delete",
                    "arguments": {"id": "1"}, "principal": "alice", "reason": "destructive"}
            submit_task = asyncio.create_task(client.post("/api/approvals", json=wire))

            approval_id = None
            for _ in range(200):
                pend = (await client.get("/api/approvals/pending")).json()["pending"]
                if pend:
                    approval_id = pend[0]["approval_id"]
                    assert pend[0]["tool"] == "admin.delete"
                    break
                await asyncio.sleep(0.01)
            assert approval_id is not None, "approval never appeared in the queue"

            resolve = await client.post(
                f"/api/approvals/{approval_id}/resolve",
                json={"approved": True, "note": "looks fine"},
            )
            assert resolve.status_code == 200

            resp = await submit_task
            decision = resp.json()
            assert decision == {"approved": True, "approver": "alice", "note": "looks fine"}

    asyncio.run(scenario())


def test_viewer_cannot_resolve(tmp_path):
    client = TestClient(_app(tmp_path))
    _login(client, username="bob")  # bob = viewer
    resp = client.post("/api/approvals/whatever/resolve", json={"approved": True})
    assert resp.status_code == 403


def test_resolve_unknown_is_404(tmp_path):
    client = TestClient(_app(tmp_path))
    _login(client)  # approver
    resp = client.post("/api/approvals/does-not-exist/resolve", json={"approved": True})
    assert resp.status_code == 404


def test_approval_gateway_token_enforced(tmp_path):
    spool = tmp_path / "audit.log"
    _spool(spool, _events())
    app = create_app(
        index_path=str(tmp_path / "audit.db"), spool_path=str(spool),
        users=LocalUsers([{"username": "a", "role": "approver", "password": "p"}]),
        signer=CookieSigner(b"s"), approval_timeout=0.2, gateway_token="sekret",
    )
    client = TestClient(app)
    wire = {"tool": "x", "request_id": 1, "session_id": "s"}
    assert client.post("/api/approvals", json=wire).status_code == 401
    # Correct token: no resolver, so it fails closed on timeout (still 200 body).
    resp = client.post("/api/approvals", json=wire, headers={"X-Gateway-Token": "sekret"})
    assert resp.status_code == 200
    assert resp.json()["approved"] is False
