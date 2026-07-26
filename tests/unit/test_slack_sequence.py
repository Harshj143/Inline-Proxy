"""Slack pack: the session-state controls the golden harness cannot reach.

`policy test` runs policy → constraints → action. The sequence gate sits
between constraints and action and reads session history, so taint and
sequence_rules are invisible to goldens (policy/testing.py says as much).

The mock-crm pack covers that gap with an e2e that drives a real subprocess
gateway. This pack's upstream is a remote OAuth-gated service with no local
stand-in, so its taint model is asserted here instead — directly against the
SHIPPED policy file, not a fixture copy, so an edit to connectors/slack/
policy.yaml that weakens the exfiltration guard fails the build.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_gateway.core.session import Session
from mcp_gateway.policy.engine import PolicyEngine

PACK = Path(__file__).resolve().parents[2] / "connectors" / "slack"

# Every content read the pack treats as untrusted input.
CONTENT_READS = [
    "read_channel",
    "read_thread",
    "search_messages",
    "read_file",
    "read_canvas",
    "fetch_user_info",
    "search_users",
]

# Every tool that can carry bytes back out of the workspace.
EGRESS_SINKS = [
    "send_message",
    "draft_message",
    "create_conversation",
    "create_canvas",
    "update_canvas",
]


@pytest.fixture(scope="module")
def sequence():
    engine = PolicyEngine.load([PACK / "policy.yaml", PACK / "roles.yaml"])
    return engine.build_sequence_policy()


# ------------------------------------------------------------------- taint
@pytest.mark.parametrize("tool", CONTENT_READS)
def test_every_content_read_taints_the_session(sequence, tool):
    assert sequence.is_taint_source(tool), f"{tool} must be a taint source"


@pytest.mark.parametrize("tool", ["search_channels", "search_emoji", "list_channel_members"])
def test_metadata_reads_do_not_taint(sequence, tool):
    """Discovery stays untainted, or an agent could never do anything at all."""
    assert not sequence.is_taint_source(tool)


@pytest.mark.parametrize("sink", EGRESS_SINKS)
def test_clean_session_may_use_every_sink(sequence, sink):
    """The controls are conditional on session state, not a blanket ban."""
    assert sequence.check(sink, Session.new()) is None


@pytest.mark.parametrize("sink", EGRESS_SINKS)
def test_tainted_session_is_blocked_from_every_sink(sequence, sink):
    session = Session.new()
    session.mark_tainted("read_channel")
    reason = sequence.check(sink, session)
    assert reason is not None, f"{sink} must be blocked in a tainted session"
    assert "tainted" in reason


def test_reactions_survive_taint(sequence):
    """add_reaction is deliberately NOT a sink — too low-bandwidth to matter."""
    session = Session.new()
    session.mark_tainted("read_channel")
    assert sequence.check("add_reaction", session) is None


# ---------------------------------------------------------------- sequence
# Sequence rules restate the exfiltration paths independently of taint, so the
# guard survives a future edit that narrows taint_sources. These assertions use
# an UNTAINTED session precisely to prove the second control stands alone.
@pytest.mark.parametrize(
    "read",
    ["read_channel", "read_thread", "search_messages", "read_file", "read_canvas"],
)
def test_read_then_send_is_forbidden_by_sequence_rule_alone(sequence, read):
    session = Session.new()
    session.record_call(read)          # history only — no taint flag set
    reason = sequence.check("send_message", session)
    assert reason is not None, f"send_message must be forbidden after {read}"
    assert "tainted" not in reason, "this must be the sequence rule, not taint"


def test_search_then_new_dm_is_forbidden(sequence):
    """Opening a DM after a workspace-wide search manufactures an egress path."""
    session = Session.new()
    session.record_call("search_messages")
    assert sequence.check("create_conversation", session) is not None


def test_send_is_fine_after_only_metadata_reads(sequence):
    """The false-positive guard: discovery alone must not lock out messaging."""
    session = Session.new()
    session.record_call("search_channels")
    session.record_call("list_channel_members")
    assert sequence.check("send_message", session) is None
