"""Approval broker, channels, and fail-closed semantics."""

import asyncio

import pytest

from mcp_gateway.approvals import ApprovalRequest, Resolution, build_broker
from mcp_gateway.approvals.broker import ApprovalBroker
from mcp_gateway.approvals.channels import AllowChannel, DenyChannel
from mcp_gateway.approvals.channels.base import ApprovalChannel


def make_request():
    return ApprovalRequest(
        request_id=1, session_id="s", tool="admin.delete_user",
        arguments={"id": "8842"}, principal="alice", reason="destructive",
    )


def resolve(broker):
    return asyncio.run(broker.request(make_request()))


# ---------------------------------------------------------------- channels
def test_deny_channel_denies_and_cannot_approve():
    r = resolve(ApprovalBroker(DenyChannel()))
    assert r.approved is False
    assert DenyChannel.can_approve is False


def test_allow_channel_approves():
    r = resolve(ApprovalBroker(AllowChannel()))
    assert r.approved is True and r.approver == "auto"


# ------------------------------------------------------------- fail-closed
def test_broker_fail_closed_on_channel_error():
    class Broken(ApprovalChannel):
        name = "broken"

        async def request(self, req):
            raise RuntimeError("approver crashed")

    r = resolve(ApprovalBroker(Broken()))
    assert r.approved is False and "fail-closed" in r.note


def test_broker_fail_closed_on_timeout():
    class Slow(ApprovalChannel):
        name = "slow"

        async def request(self, req):
            await asyncio.sleep(10)
            return Resolution(True, "late")

    r = resolve(ApprovalBroker(Slow(), deadline=0.05))
    assert r.approved is False and "fail-closed" in r.note


# ----------------------------------------------------------------- factory
def test_build_broker_modes():
    assert build_broker("deny").mode == "deny"
    assert build_broker("allow").mode == "allow"
    assert build_broker("http", "http://localhost:8000").mode == "http"


def test_build_broker_http_needs_url():
    with pytest.raises(ValueError, match="requires --approvals-url"):
        build_broker("http")


def test_build_broker_unknown_mode():
    with pytest.raises(ValueError, match="unknown approvals mode"):
        build_broker("maybe")
