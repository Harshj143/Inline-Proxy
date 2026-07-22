"""Failure posture: parsing, defaults, validation, and the always-closed line."""

import asyncio

import pytest

from mcp_gateway.approvals import ApprovalRequest
from mcp_gateway.approvals.broker import ApprovalBroker
from mcp_gateway.approvals.channels.base import ApprovalChannel
from mcp_gateway.core.errors import PolicyError
from mcp_gateway.core.failure import FailMode
from mcp_gateway.policy.engine import PolicyEngine


def engine(on_failure=None):
    doc = {"schema_version": 1, "default_action": "block", "tools": {}}
    if on_failure is not None:
        doc["on_failure"] = on_failure
    return PolicyEngine.from_documents([(doc, "t")])


# ---------------------------------------------------------------- defaults
def test_default_is_fail_closed():
    p = engine().posture
    assert p.pipeline is FailMode.CLOSED
    assert p.redaction is FailMode.CLOSED
    assert p.approval is FailMode.CLOSED
    assert not p.any_open


def test_global_open_sets_all():
    p = engine("open").posture
    assert p.pipeline is p.redaction is p.approval is FailMode.OPEN
    assert set(p.open_categories()) == {"pipeline", "redaction", "approval"}


def test_per_category_with_default():
    p = engine({"default": "closed", "redaction": "open"}).posture
    assert p.redaction is FailMode.OPEN
    assert p.pipeline is FailMode.CLOSED
    assert p.open_categories() == ["redaction"]


def test_per_category_default_open_with_one_closed():
    p = engine({"default": "open", "approval": "closed"}).posture
    assert p.pipeline is FailMode.OPEN and p.redaction is FailMode.OPEN
    assert p.approval is FailMode.CLOSED


# -------------------------------------------------------------- validation
def test_invalid_mode_rejected_at_load():
    with pytest.raises(PolicyError, match="must be 'open' or 'closed'"):
        engine("maybe")


def test_unknown_category_rejected():
    with pytest.raises(PolicyError, match="unknown on_failure field"):
        engine({"pipelin": "open"})


def test_on_failure_merges_last_wins():
    base = {"schema_version": 1, "tools": {}, "on_failure": "open"}
    override = {"schema_version": 1, "on_failure": "closed"}
    eng = PolicyEngine.from_documents([(base, "base"), (override, "override")])
    assert not eng.posture.any_open   # override's closed wins


# ---------------------------------------------------- approval broker knob
def _resolve(broker):
    req = ApprovalRequest(1, "s", "t", {}, "p", "r")
    return asyncio.run(broker.request(req))


def test_broker_fail_closed_by_default_on_error():
    class Broken(ApprovalChannel):
        name = "broken"

        async def request(self, req):
            raise RuntimeError("down")

    assert _resolve(ApprovalBroker(Broken())).approved is False


def test_broker_fail_open_when_configured():
    class Broken(ApprovalChannel):
        name = "broken"

        async def request(self, req):
            raise RuntimeError("down")

    r = _resolve(ApprovalBroker(Broken(), fail_open=True))
    assert r.approved is True and "fail-open" in r.note
