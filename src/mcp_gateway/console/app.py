"""FastAPI app for the Security Ops Console (Phase 4b).

REST + automatic OpenAPI over the Phase 4a audit index, an SSE live feed that
tails the JSONL spool with `Last-Event-ID` resume, and the approvals endpoint
the gateway's `HttpChannel` blocks on. Everything read-side goes through the
index (`audit/index.py`); the live feed reads the spool directly so it is
always current even between index catch-ups.

Design notes:
  * **The index is refreshed on demand.** Each read request opens the SQLite
    index, catches it up from the spool watermark (cheap — only new bytes), and
    closes it. No background loop to supervise, and every response reflects the
    spool as of that request. The live SSE feed doesn't need the index at all.
  * **Auth is a signed cookie** (`console/auth.py`); `viewer` reads, `approver`
    additionally resolves approvals. The gateway-facing `POST /api/approvals`
    is machine-to-machine (no browser cookie) and is instead guarded by an
    optional shared token — localhost-only otherwise.
  * **Fail closed:** an unauthenticated read is 401, a non-approver resolve is
    403, an approval that times out is a denial, a malformed backtest policy is
    a 400 — never a 500 that a caller might read as success.

Unlike the rest of the package, this module imports FastAPI/Pydantic at import
time and does NOT use `from __future__ import annotations`: FastAPI resolves
route annotations at decoration time, and stringised/late-bound annotations
make it misread body params as query params. That is safe because this module
lives behind the `[server]` extra — every importer (the CLI's `console serve`,
the tests) guards on the extra being installed.
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from mcp_gateway.audit.index import AuditIndex
from mcp_gateway.audit.reader import read_spool
from mcp_gateway.console.approvals import ApprovalQueue
from mcp_gateway.console.auth import COOKIE_NAME, CookieSigner, LocalUsers, User


class LoginBody(BaseModel):
    username: str
    password: str


class ResolveBody(BaseModel):
    approved: bool
    note: str = ""


class BacktestBody(BaseModel):
    policy: dict[str, Any] | None = None
    deny_set: list[str] | None = None


def create_app(
    *,
    index_path: str | Path,
    spool_path: str | Path,
    users: LocalUsers,
    signer: CookieSigner,
    policy_engine: Any | None = None,
    approval_queue: ApprovalQueue | None = None,
    approval_timeout: float = 300.0,
    gateway_token: str | None = None,
    poll_interval: float = 0.5,
) -> FastAPI:
    """Build the console FastAPI app over an audit index + spool."""
    spool_path = str(spool_path)
    index_path = str(index_path)
    queue = approval_queue or ApprovalQueue()

    app = FastAPI(
        title="MCP Security Gateway — Console",
        version="1",
        description="Read model, live feed, and human approvals over the audit spool.",
    )

    # ---------------------------------------------------------- dependencies
    def get_index():
        index = AuditIndex(index_path)
        index.catch_up(spool_path)
        try:
            yield index
        finally:
            index.close()

    def current_user(request: Request) -> User:
        token = request.cookies.get(COOKIE_NAME)
        user = signer.verify(token) if token else None
        if user is None:
            raise HTTPException(status_code=401, detail="authentication required")
        return user

    def require_approver(user: User = Depends(current_user)) -> User:
        if not user.can_approve:
            raise HTTPException(status_code=403, detail="approver role required")
        return user

    # ------------------------------------------------------------------ authn
    @app.post("/api/login")
    def login(body: LoginBody, response: Response) -> dict[str, Any]:
        user = users.authenticate(body.username, body.password)
        if user is None:
            raise HTTPException(status_code=401, detail="invalid credentials")
        response.set_cookie(
            COOKIE_NAME, signer.mint(user),
            httponly=True, samesite="lax", path="/",
        )
        return {"username": user.username, "role": user.role}

    @app.post("/api/logout")
    def logout(response: Response) -> dict[str, bool]:
        response.delete_cookie(COOKIE_NAME, path="/")
        return {"ok": True}

    @app.get("/api/me")
    def me(user: User = Depends(current_user)) -> dict[str, Any]:
        return {"username": user.username, "role": user.role}

    # ----------------------------------------------------------- read model
    @app.get("/api/sessions")
    def list_sessions(
        limit: int = Query(100, ge=1, le=1000),
        user: User = Depends(current_user),
        index: AuditIndex = Depends(get_index),
    ) -> dict[str, Any]:
        return {"sessions": index.list_sessions(limit=limit)}

    @app.get("/api/sessions/{session_id}")
    def session_detail(
        session_id: str,
        limit: int = Query(500, ge=1, le=1000),
        user: User = Depends(current_user),
        index: AuditIndex = Depends(get_index),
    ) -> dict[str, Any]:
        detail = index.session_detail(session_id, limit=limit)
        if detail is None:
            raise HTTPException(status_code=404, detail="no such session")
        return detail

    @app.get("/api/events")
    def events(
        session_id: str | None = None,
        event: str | None = None,
        tool: str | None = None,
        after: int | None = None,
        limit: int = Query(100, ge=1, le=1000),
        user: User = Depends(current_user),
        index: AuditIndex = Depends(get_index),
    ) -> dict[str, Any]:
        rows = index.query_events(
            session_id=session_id, event=event, tool=tool, after=after, limit=limit
        )
        return {"events": rows, "latest_offset": index.latest_offset()}

    @app.get("/api/stats")
    def stats(
        user: User = Depends(current_user),
        index: AuditIndex = Depends(get_index),
    ) -> dict[str, Any]:
        return {"counts_by_event": index.counts_by_event()}

    @app.get("/api/policy")
    def policy(user: User = Depends(current_user)) -> dict[str, Any]:
        if policy_engine is None:
            raise HTTPException(status_code=404, detail="no policy loaded")
        return policy_engine.describe()

    @app.post("/api/backtest")
    def backtest(body: BacktestBody, user: User = Depends(current_user)) -> dict[str, Any]:
        from mcp_gateway.core.errors import GatewayError
        from mcp_gateway.policy.backtest import backtest_policy
        from mcp_gateway.policy.engine import PolicyEngine

        if body.policy is not None:
            try:
                engine = PolicyEngine.from_documents([(body.policy, "candidate")])
            except GatewayError as exc:
                raise HTTPException(status_code=400, detail=f"invalid policy: {exc}") from None
        elif policy_engine is not None:
            engine = policy_engine
        else:
            raise HTTPException(status_code=400, detail="no policy to backtest")
        deny = frozenset(body.deny_set) if body.deny_set is not None else None
        report = backtest_policy(spool_path, engine, deny_set=deny)
        return report.to_dict()

    # ------------------------------------------------------------ live feed
    async def _event_stream(request: Request, after: "int | None", once: bool):
        # `after` is an EXCLUSIVE cursor (the id of the last event the client
        # already has); None means start from the beginning. The event id is
        # the line-start byte offset, so reading from byte `after` re-reads that
        # last-delivered line — we skip it on the first pass and everything the
        # loop reads afterwards is strictly newer.
        byte_pos = 0 if after is None else after
        first = True
        while True:
            if await request.is_disconnected():
                return
            result = read_spool(spool_path, start=byte_pos)
            for rec in result.records:
                if first and after is not None and rec.offset <= after:
                    continue
                data = json.dumps(rec.event, separators=(",", ":"), default=str)
                yield f"id: {rec.offset}\ndata: {data}\n\n"
            byte_pos = result.next_offset
            first = False
            if once:
                return
            yield ": keep-alive\n\n"
            await asyncio.sleep(poll_interval)

    @app.get("/api/stream")
    async def stream(
        request: Request,
        last_event_id: int | None = None,
        once: bool = False,
        user: User = Depends(current_user),
    ):
        after = last_event_id
        if after is None:
            header = request.headers.get("last-event-id")
            if header is not None and header.lstrip("-").isdigit():
                after = int(header)
        return StreamingResponse(
            _event_stream(request, after, once),
            media_type="text/event-stream",
        )

    # ------------------------------------------------------------- approvals
    @app.post("/api/approvals")
    async def submit_approval(request: Request) -> dict[str, Any]:
        """Gateway contract: block until a human decides. Returns
        {approved, approver, note}. Machine-to-machine — no browser cookie; an
        optional shared token guards it when the console isn't localhost-only."""
        if gateway_token is not None and request.headers.get("x-gateway-token") != gateway_token:
            raise HTTPException(status_code=401, detail="bad gateway token")
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            raise HTTPException(status_code=400, detail="expected JSON body") from None
        if not isinstance(payload, dict) or "tool" not in payload:
            raise HTTPException(status_code=400, detail="not an ApprovalRequest")
        item = await queue.submit(payload, now=time.time())
        return await queue.wait(item, timeout=approval_timeout)

    @app.get("/api/approvals/pending")
    async def pending_approvals(user: User = Depends(current_user)) -> dict[str, Any]:
        return {"pending": await queue.pending()}

    @app.post("/api/approvals/{approval_id}/resolve")
    async def resolve_approval(
        approval_id: str,
        body: ResolveBody,
        user: User = Depends(require_approver),
    ) -> dict[str, Any]:
        ok = await queue.resolve(
            approval_id, approved=body.approved, approver=user.username, note=body.note
        )
        if not ok:
            raise HTTPException(status_code=404, detail="unknown or already-resolved approval")
        return {"resolved": True, "approval_id": approval_id, "approved": body.approved}

    return app
