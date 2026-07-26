"""MCP Streamable HTTP transport — central mode, single upstream (Phase 5a).

Sidecar mode is one gateway, one client, one upstream, over stdio. Central mode
is one long-lived HTTP service fronting *many* clients. This module bridges the
gap without changing the gateway: each MCP session (keyed by `Mcp-Session-Id`)
gets its **own** `SecurityGateway` and its own upstream, and a per-session
object plays the gateway's `Transport` role.

The impedance mismatch to solve: the gateway is written for a bidirectional
pipe (`send_client` may push a line at any time), but Streamable HTTP is
request/response with an optional server→client SSE channel. A `_Session`
resolves it:

  * `send_upstream(line)` → write to that session's upstream.
  * `send_client(line)` → if the line is a response whose id matches an
    in-flight POST, hand it to that POST's future; otherwise it is a
    server-initiated request/notification and goes on the session's SSE queue
    (delivered over `GET /mcp`).

HTTP surface (single upstream at `/mcp`):
  * `POST /mcp` — a JSON-RPC message. No session + `initialize` mints a session
    and returns `Mcp-Session-Id`. A request (has id) is policed and its
    correlated response is awaited and returned as JSON. A notification (no id)
    returns 202. An unknown session id is 404 (fail closed).
  * `GET /mcp` — SSE stream of server-initiated messages for the session.
  * `DELETE /mcp` — terminate the session (tears down its upstream).

Fail-closed throughout: unknown/missing session where one is required is a 4xx,
never a silent new session; a response that never arrives times out into a
JSON-RPC error rather than hanging forever.

Like the console app, this module imports FastAPI at import time and does NOT
use `from __future__ import annotations`: FastAPI resolves route annotations at
decoration time, and stringised annotations make it misread `request: Request`
as a query param. That is safe because the HTTP transport lives behind the
`[server]` extra — every importer (the CLI's `serve`, the tests) guards on it.
"""

import asyncio
import uuid
from collections.abc import Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from mcp_gateway.audit.recorder import AuditRecorder, AuditSink
from mcp_gateway.core.gateway import SecurityGateway
from mcp_gateway.protocol.jsonrpc import decode_line, encode, error_response
from mcp_gateway.protocol.mcp import METHOD_INITIALIZE
from mcp_gateway.transports.upstream import Upstream

SESSION_HEADER = "mcp-session-id"
# JSON-RPC implementation-defined error for a gateway-side timeout.
ERROR_GATEWAY_TIMEOUT = -32002


class _NonClosingSink:
    """Wrap a shared audit sink so a per-session recorder can't close it.

    Every session gets its own recorder (so its events carry its own
    `session_id` — a shared recorder's `default_fields` would bleed the first
    session's id onto all of them), but they all write to ONE spool. The real
    spool is closed once at app shutdown, never when a single session ends.
    """

    def __init__(self, inner: AuditSink):
        self._inner = inner

    async def emit(self, event: dict[str, Any]) -> None:
        await self._inner.emit(event)

    async def close(self) -> None:  # no-op: the shared spool outlives the session
        return None


class _Session:
    """One MCP session: its gateway, its upstream, and the client-side plumbing.

    Implements the gateway's `Transport` protocol (`send_client`/`send_upstream`).
    """

    def __init__(
        self,
        session_id: str,
        gateway: SecurityGateway,
        upstream: Upstream,
        response_timeout: float,
    ):
        self.id = session_id
        self.gateway = gateway
        self.upstream = upstream
        self.response_timeout = response_timeout
        self._pending: dict[Any, asyncio.Future] = {}
        self._sse: asyncio.Queue[str] = asyncio.Queue()
        self._closed = False

    # ---- gateway Transport interface --------------------------------------
    async def send_upstream(self, line: str) -> None:
        await self.upstream.send(line)

    async def send_client(self, line: str) -> None:
        msg = decode_line(line)
        if msg is not None and msg.is_response and msg.id in self._pending:
            future = self._pending.pop(msg.id)
            if not future.done():
                future.set_result(line)
            return
        # Server-initiated request/notification (sampling, roots, progress, …):
        # deliver over the SSE channel.
        await self._sse.put(line)

    # ---- client-facing request/response -----------------------------------
    async def handle_request(self, raw: dict[str, Any], request_id: Any) -> str:
        """Feed a client request to the gateway and await its correlated reply."""
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        self._pending[request_id] = future
        await self.gateway.on_client_line(encode(raw))
        try:
            return await asyncio.wait_for(future, self.response_timeout)
        except TimeoutError:
            self._pending.pop(request_id, None)
            return encode(error_response(
                request_id, ERROR_GATEWAY_TIMEOUT,
                "upstream did not respond within the gateway deadline",
            ))

    async def handle_notification(self, raw: dict[str, Any]) -> None:
        await self.gateway.on_client_line(encode(raw))

    async def sse_events(self):
        """Yield SSE frames of server-initiated messages until the session closes."""
        while not self._closed:
            try:
                line = await asyncio.wait_for(self._sse.get(), timeout=15.0)
            except TimeoutError:
                yield ": keep-alive\n\n"
                continue
            yield f"data: {line}\n\n"

    async def _on_upstream_exit(self, returncode: int | None) -> None:
        """The upstream ended on its own (EOF/crash/overrun). Mark the session
        dead — further requests fail closed — and record the exit."""
        self._closed = True
        await self.gateway.on_upstream_exit(returncode)

    async def close(self) -> int | None:
        self._closed = True
        for fut in self._pending.values():
            if not fut.done():
                fut.cancel()
        self._pending.clear()
        returncode = await self.upstream.shutdown()
        await self.gateway.on_upstream_exit(returncode)
        await self.gateway.on_stop()
        return returncode


# Builds (gateway, upstream) for a new session id. Injected so tests can supply
# an in-process fake upstream instead of a subprocess.
SessionParts = Callable[[str], "tuple[SecurityGateway, Upstream]"]


class StreamableHttpGateway:
    """Owns the live sessions for one upstream and their lifecycle."""

    def __init__(self, session_parts: SessionParts, *, response_timeout: float = 30.0):
        self._session_parts = session_parts
        self._response_timeout = response_timeout
        self._sessions: dict[str, _Session] = {}
        self._lock = asyncio.Lock()

    async def create(self) -> _Session:
        session_id = uuid.uuid4().hex
        gateway, upstream = self._session_parts(session_id)
        session = _Session(session_id, gateway, upstream, self._response_timeout)
        gateway.bind_transport(session)
        await gateway.on_start(getattr(upstream, "command", ["<upstream>"]))
        await upstream.start(gateway.on_upstream_line, session._on_upstream_exit)
        async with self._lock:
            self._sessions[session_id] = session
        return session

    def get(self, session_id: str) -> _Session | None:
        return self._sessions.get(session_id)

    async def terminate(self, session_id: str) -> bool:
        async with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        await session.close()
        return True

    async def shutdown_all(self) -> None:
        async with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            await session.close()


def build_session_parts(
    *,
    engine,
    spool: AuditSink,
    upstream_factory: Callable[[str], Upstream],
    principal=None,
    redaction=None,
    broker=None,
    anomaly=None,
    store=None,
    annotate: dict[str, Any] | None = None,
) -> SessionParts:
    """A default `SessionParts` builder: each session shares the policy engine,
    redaction service, broker, spool, and (optionally) a shared session store,
    but gets its own gateway + recorder + upstream. The gateway is bound to the
    session id so its audit events carry the client's `Mcp-Session-Id`, and a
    shared store (Redis) lets replicas resume the same session state."""
    from mcp_gateway.core.context import Principal
    from mcp_gateway.core.pipeline import default_pipeline

    principal = principal or Principal()

    def make(session_id: str) -> tuple[SecurityGateway, Upstream]:
        recorder = AuditRecorder([_NonClosingSink(spool)])
        gateway = SecurityGateway(
            pipeline=default_pipeline(engine, redaction, broker),
            audit=recorder,
            principal=principal,
            policy=engine,
            redaction=redaction,
            anomaly=anomaly,
            store=store,
            session_id=session_id,
        )
        if annotate:
            gateway.annotate(**annotate)
        return gateway, upstream_factory(session_id)

    return make


def _json_line(line: str, headers: dict[str, str] | None = None) -> JSONResponse:
    import json as _json

    return JSONResponse(content=_json.loads(line), headers=headers or {})


def _rpc_error(request_id: Any, code: int, message: str, status: int) -> JSONResponse:
    return JSONResponse(
        content=error_response(request_id, code, message), status_code=status
    )


async def _handle_post(hub: StreamableHttpGateway, request: Request):
    """POST semantics for one upstream hub. Shared by single- and multi-upstream
    apps so routing is the only thing that differs between them."""
    try:
        raw = await request.json()
    except Exception:  # noqa: BLE001
        return _rpc_error(None, -32700, "parse error: body is not JSON", 400)
    if not isinstance(raw, dict):
        return _rpc_error(None, -32600, "invalid request: expected one JSON-RPC object", 400)

    msg = decode_line(encode(raw))
    assert msg is not None
    session_id = request.headers.get(SESSION_HEADER)

    # initialize with no session → mint one on this hub.
    if session_id is None and msg.method == METHOD_INITIALIZE:
        session = await hub.create()
        body = await session.handle_request(raw, msg.id)
        return _json_line(body, headers={SESSION_HEADER.title(): session.id})

    if session_id is None:
        return _rpc_error(msg.id, -32600, "missing Mcp-Session-Id header", 400)
    session = hub.get(session_id)
    if session is None:
        return _rpc_error(msg.id, -32001, "unknown or expired session", 404)

    if msg.is_request:
        body = await session.handle_request(raw, msg.id)
        return _json_line(body)
    # Notification / response from client → forward, no reply expected.
    await session.handle_notification(raw)
    return Response(status_code=202)


async def _handle_get(hub: StreamableHttpGateway, request: Request):
    session_id = request.headers.get(SESSION_HEADER)
    session = hub.get(session_id) if session_id else None
    if session is None:
        return _rpc_error(None, -32001, "unknown or expired session", 404)
    return StreamingResponse(session.sse_events(), media_type="text/event-stream")


async def _handle_delete(hub: StreamableHttpGateway, request: Request):
    session_id = request.headers.get(SESSION_HEADER)
    if not session_id or not await hub.terminate(session_id):
        return Response(status_code=404)
    return Response(status_code=204)


def create_streamable_http_app(gateway: StreamableHttpGateway, *, path: str = "/mcp"):
    """Build a FastAPI app exposing ONE upstream over MCP Streamable HTTP."""

    @asynccontextmanager
    async def lifespan(_app):
        yield
        await gateway.shutdown_all()  # tear down every live upstream on shutdown

    app = FastAPI(
        title="MCP Security Gateway — Streamable HTTP", version="1", lifespan=lifespan
    )

    @app.post(path)
    async def post(request: Request):
        return await _handle_post(gateway, request)

    @app.get(path)
    async def get(request: Request):
        return await _handle_get(gateway, request)

    @app.delete(path)
    async def delete(request: Request):
        return await _handle_delete(gateway, request)

    return app


def create_central_app(hubs: dict[str, StreamableHttpGateway]):
    """Build a FastAPI app routing many upstreams at `/servers/<name>/mcp`.

    Each named upstream has its own hub (policy pack + session registry), so a
    session id minted for one upstream is unknown to another — per-endpoint
    isolation keeps policy attribution and `tools/list` filtering trivial
    (docs/ARCHITECTURE.md §1). An unknown upstream name is a 404 (fail closed).
    """

    @asynccontextmanager
    async def lifespan(_app):
        yield
        for hub in hubs.values():
            await hub.shutdown_all()

    app = FastAPI(
        title="MCP Security Gateway — Central", version="1", lifespan=lifespan
    )

    def _hub(name: str) -> StreamableHttpGateway | None:
        return hubs.get(name)

    @app.post("/servers/{name}/mcp")
    async def post(name: str, request: Request):
        hub = _hub(name)
        if hub is None:
            return _rpc_error(None, -32004, f"unknown upstream {name!r}", 404)
        return await _handle_post(hub, request)

    @app.get("/servers/{name}/mcp")
    async def get(name: str, request: Request):
        hub = _hub(name)
        if hub is None:
            return _rpc_error(None, -32004, f"unknown upstream {name!r}", 404)
        return await _handle_get(hub, request)

    @app.delete("/servers/{name}/mcp")
    async def delete(name: str, request: Request):
        hub = _hub(name)
        if hub is None:
            return Response(status_code=404)
        return await _handle_delete(hub, request)

    @app.get("/servers")
    async def list_servers() -> dict[str, Any]:
        return {"servers": sorted(hubs)}

    return app
