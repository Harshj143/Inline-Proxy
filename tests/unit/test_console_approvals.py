"""Live approval queue: submit parks a future, resolve unblocks, timeout denies."""

from __future__ import annotations

import asyncio

from mcp_gateway.console.approvals import ApprovalQueue


def _req(request_id=1, tool="admin.delete"):
    return {"request_id": request_id, "session_id": "s1", "tool": tool,
            "arguments": {"id": "8842"}, "principal": "alice", "reason": "destructive"}


def test_submit_then_resolve_unblocks():
    async def scenario():
        queue = ApprovalQueue()
        item = await queue.submit(_req(), now=0.0)
        assert await queue.count() == 1
        pending = await queue.pending()
        assert pending[0]["tool"] == "admin.delete"

        # A concurrent resolver approves; wait() returns that decision.
        async def resolver():
            await asyncio.sleep(0.01)
            ok = await queue.resolve(item.approval_id, approved=True,
                                     approver="carol", note="ok")
            assert ok

        waiter = asyncio.create_task(queue.wait(item, timeout=5))
        await resolver()
        result = await waiter
        assert result == {"approved": True, "approver": "carol", "note": "ok"}
        assert await queue.count() == 0  # cleared after resolution

    asyncio.run(scenario())


def test_timeout_fails_closed():
    async def scenario():
        queue = ApprovalQueue()
        item = await queue.submit(_req(), now=0.0)
        result = await queue.wait(item, timeout=0.02)
        assert result["approved"] is False
        assert "timed out" in result["note"]
        assert await queue.count() == 0

    asyncio.run(scenario())


def test_resolve_unknown_is_noop():
    async def scenario():
        queue = ApprovalQueue()
        assert await queue.resolve("nope", approved=True, approver="x") is False

    asyncio.run(scenario())


def test_double_resolve_is_idempotent():
    async def scenario():
        queue = ApprovalQueue()
        item = await queue.submit(_req(), now=0.0)
        waiter = asyncio.create_task(queue.wait(item, timeout=5))
        await asyncio.sleep(0)
        assert await queue.resolve(item.approval_id, approved=False, approver="x") is True
        # second resolve after the first: item already gone/resolved.
        assert await queue.resolve(item.approval_id, approved=True, approver="y") is False
        result = await waiter
        assert result["approved"] is False

    asyncio.run(scenario())
