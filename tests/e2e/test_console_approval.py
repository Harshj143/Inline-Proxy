"""End-to-end: the real gateway approval path against a running console.

The phase's headline criterion is that a `require_approval` tool call blocks in
the gateway until a human clicks approve in the console. This test wires the
ACTUAL gateway pieces — `ApprovalBroker` + `HttpChannel` (the same code the
`wrap --approvals http` CLI builds) — to a real uvicorn-served console and
resolves the request through the console's approver API, proving the two halves
of the contract meet.

Gated on the [server] extra; skipped when it (or uvicorn) is absent.
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
import urllib.request

import pytest

pytest.importorskip("fastapi")
uvicorn = pytest.importorskip("uvicorn")

from mcp_gateway.approvals.broker import ApprovalBroker  # noqa: E402
from mcp_gateway.approvals.channels.http import HttpChannel  # noqa: E402
from mcp_gateway.approvals.models import ApprovalRequest  # noqa: E402
from mcp_gateway.console.app import create_app  # noqa: E402
from mcp_gateway.console.auth import CookieSigner, LocalUsers  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_server(tmp_path, port):
    spool = tmp_path / "audit.log"
    spool.write_text("")
    app = create_app(
        index_path=str(tmp_path / "audit.db"),
        spool_path=str(spool),
        users=LocalUsers([{"username": "alice", "role": "approver", "password": "pw"}]),
        signer=CookieSigner(b"e2e-secret"),
        approval_timeout=10.0,
    )
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    return uvicorn.Server(config)


def _console_opener(base):
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
    opener.open(urllib.request.Request(
        f"{base}/api/login",
        data=json.dumps({"username": "alice", "password": "pw"}).encode(),
        headers={"Content-Type": "application/json"},
    ))
    return opener


def test_gateway_httpchannel_blocks_until_console_approves(tmp_path):
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    server = _make_server(tmp_path, port)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 10
        while not server.started and time.time() < deadline:
            time.sleep(0.02)
        assert server.started, "console server did not start"

        async def scenario():
            # The real gateway broker + HTTP channel, exactly as `wrap` builds them.
            broker = ApprovalBroker(HttpChannel(base))
            req = ApprovalRequest(
                request_id=99, session_id="s1", tool="admin.delete_user",
                arguments={"id": "8842"}, principal="alice", reason="destructive",
            )
            task = asyncio.create_task(broker.request(req))

            # An approver resolves it through the console API.
            opener = await asyncio.to_thread(_console_opener, base)

            approval_id = None
            for _ in range(200):
                pend = json.loads(
                    await asyncio.to_thread(
                        lambda: opener.open(f"{base}/api/approvals/pending").read()
                    )
                )["pending"]
                if pend:
                    approval_id = pend[0]["approval_id"]
                    assert pend[0]["tool"] == "admin.delete_user"
                    break
                await asyncio.sleep(0.02)
            assert approval_id is not None, "approval never reached the console"

            await asyncio.to_thread(lambda: opener.open(urllib.request.Request(
                f"{base}/api/approvals/{approval_id}/resolve",
                data=json.dumps({"approved": True, "note": "ok via console"}).encode(),
                headers={"Content-Type": "application/json"},
            )))

            resolution = await task
            assert resolution.approved is True
            assert resolution.approver == "alice"
            assert resolution.note == "ok via console"

        asyncio.run(scenario())
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_gateway_httpchannel_fails_closed_on_console_timeout(tmp_path):
    # If nobody resolves, the console times out and the gateway broker sees a
    # denial — the fail-closed direction for an unanswered approval.
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    spool = tmp_path / "audit.log"
    spool.write_text("")
    app = create_app(
        index_path=str(tmp_path / "audit.db"), spool_path=str(spool),
        users=LocalUsers([{"username": "a", "role": "approver", "password": "p"}]),
        signer=CookieSigner(b"s"), approval_timeout=0.3,
    )
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 10
        while not server.started and time.time() < deadline:
            time.sleep(0.02)
        assert server.started

        async def scenario():
            broker = ApprovalBroker(HttpChannel(base))
            req = ApprovalRequest(request_id=1, session_id="s", tool="x",
                                  arguments={}, principal="p", reason="r")
            resolution = await broker.request(req)
            assert resolution.approved is False

        asyncio.run(scenario())
    finally:
        server.should_exit = True
        thread.join(timeout=5)
