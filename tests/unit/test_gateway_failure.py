"""Gateway behavior under the fail-open / fail-closed posture.

Drives the gateway directly (fake transport) to prove that an UNEXPECTED error
denies/withholds by default, and releases only when the customer opts in.
"""

import asyncio

from mcp_gateway.approvals.broker import build_broker
from mcp_gateway.audit.recorder import AuditRecorder
from mcp_gateway.core.gateway import SecurityGateway
from mcp_gateway.core.pipeline import (
    RequestPipeline,
    RequestStage,
    default_pipeline,
)
from mcp_gateway.policy.engine import PolicyEngine
from mcp_gateway.redaction.report import RedactionReport
from mcp_gateway.redaction.service import RedactionService


class FakeTransport:
    def __init__(self):
        self.to_client: list[str] = []
        self.to_upstream: list[str] = []

    async def send_client(self, line):
        self.to_client.append(line)

    async def send_upstream(self, line):
        self.to_upstream.append(line)


class ListSink:
    def __init__(self):
        self.events: list[dict] = []

    async def emit(self, event):
        self.events.append(event)


class BrokenOnResult(RedactionService):
    """Argument scrub succeeds (call 1); result scrub crashes (call 2)."""

    def __init__(self):
        super().__init__()
        self.calls = 0

    def redact(self, value, spec):
        self.calls += 1
        if self.calls == 1:
            return value, RedactionReport()
        raise RuntimeError("detector crashed")


class ExplodingStage(RequestStage):
    name = "boom"

    async def handle(self, ctx):
        raise RuntimeError("plugin bug")


def make_engine(on_failure, tools):
    doc = {"schema_version": 1, "default_action": "block", "tools": tools,
           "on_failure": on_failure}
    return PolicyEngine.from_documents([(doc, "t")])


def build_gateway(pipeline, engine, redaction=None):
    sink = ListSink()
    gw = SecurityGateway(
        pipeline=pipeline, audit=AuditRecorder([sink]),
        policy=engine, redaction=redaction,
    )
    gw.bind_transport(FakeTransport())
    return gw, sink


TOOL_CALL = ('{"jsonrpc":"2.0","id":5,"method":"tools/call",'
             '"params":{"name":"crm.get","arguments":{"id":"8842"}}}')
RESULT = ('{"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text",'
          '"text":"email ada.verne@example.com ssn 544-21-1290"}]}}')


def run_redaction_case(on_failure):
    engine = make_engine(on_failure, {"crm.get": {"action": "redact", "redaction": "standard"}})
    service = BrokenOnResult()
    pipeline = default_pipeline(engine, service, build_broker("deny"))
    gw, sink = build_gateway(pipeline, engine, redaction=service)

    async def drive():
        await gw.on_client_line(TOOL_CALL)      # forwarded upstream, disposition redact
        await gw.on_upstream_line(RESULT)       # result scrub crashes -> posture decides

    asyncio.run(drive())
    return gw.transport, sink


def test_redaction_error_fails_closed_by_default():
    transport, sink = run_redaction_case("closed")
    delivered = transport.to_client[-1]
    assert "ada.verne@example.com" not in delivered   # unscanned data withheld
    assert "WITHHELD" in delivered
    assert any(e["event"] == "tool_result_redaction_failed" for e in sink.events)


def test_redaction_error_fails_open_when_opted_in():
    transport, sink = run_redaction_case({"redaction": "open"})
    delivered = transport.to_client[-1]
    assert "ada.verne@example.com" in delivered       # raw result RELEASED (opt-in risk)
    assert any(e["event"] == "redaction_error_fail_open" for e in sink.events)


def run_pipeline_case(on_failure):
    engine = make_engine(on_failure, {"crm.get": {"action": "allow"}})
    # A pipeline whose only stage crashes — simulates a buggy plugin.
    gw, sink = build_gateway(RequestPipeline([ExplodingStage()]), engine)

    async def drive():
        await gw.on_client_line(TOOL_CALL)

    asyncio.run(drive())
    return gw.transport, sink


def test_pipeline_error_fails_closed_by_default():
    transport, sink = run_pipeline_case("closed")
    assert transport.to_upstream == []                # never forwarded
    assert "denied by security gateway" in transport.to_client[-1]


def test_pipeline_error_fails_open_when_opted_in():
    transport, sink = run_pipeline_case({"pipeline": "open"})
    assert len(transport.to_upstream) == 1            # forwarded despite the crash
    assert any(e["event"] == "stage_error_fail_open" for e in sink.events)


def test_legitimate_denial_is_never_failed_open():
    # A real policy block (default-deny) must NOT be forwarded even under a
    # global fail-open posture — fail-open governs errors, not enforcement.
    engine = make_engine("open", {})   # crm.get unmatched -> default block
    gw, sink = build_gateway(default_pipeline(engine, None, build_broker("deny")), engine)
    asyncio.run(gw.on_client_line(TOOL_CALL))
    assert gw.transport.to_upstream == []             # blocked, not forwarded
    assert "denied by security gateway" in gw.transport.to_client[-1]
