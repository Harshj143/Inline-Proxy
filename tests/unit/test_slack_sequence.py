"""Slack pack: the session-state controls the golden harness cannot reach.

`policy test` runs policy → constraints → action. The sequence gate sits
between constraints and action and reads session history, so taint and
sequence_rules are invisible to goldens (policy/testing.py says as much).

The mock-crm pack covers that gap with an e2e that drives a real subprocess
gateway. This pack's taint model is asserted here instead — directly against the
SHIPPED policy file, not a fixture copy, so an edit to connectors/slack/
policy.yaml that weakens the exfiltration guard fails the build.

Tool names are korotovsky/slack-mcp-server's, verified from source (see the
pack README § "Why this server").
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_gateway.core.session import Session
from mcp_gateway.policy.engine import PolicyEngine

PACK = Path(__file__).resolve().parents[2] / "connectors" / "slack"

# Every content read the pack treats as untrusted input (a taint source).
CONTENT_READS = [
    "conversations_history",
    "conversations_replies",
    "conversations_search_messages",
    "conversations_unreads",
    "saved_list",
    "attachment_get_data",
    "users_search",
]

# Every tool that can carry bytes back out of the workspace (a taint sink).
EGRESS_SINKS = [
    "conversations_add_message",
    "usergroups_create",
    "usergroups_update",
]


@pytest.fixture(scope="module")
def sequence():
    engine = PolicyEngine.load([PACK / "policy.yaml", PACK / "roles.yaml"])
    return engine.build_sequence_policy()


# ------------------------------------------------------------------- taint
@pytest.mark.parametrize("tool", CONTENT_READS)
def test_every_content_read_taints_the_session(sequence, tool):
    assert sequence.is_taint_source(tool), f"{tool} must be a taint source"


@pytest.mark.parametrize("tool", ["channels_list", "channels_me", "usergroups_list"])
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
    session.mark_tainted("conversations_history")
    reason = sequence.check(sink, session)
    assert reason is not None, f"{sink} must be blocked in a tainted session"
    assert "tainted" in reason


def test_taint_blocks_send_after_a_source_with_no_explicit_sequence_rule(sequence):
    """users_search has no read→send sequence rule, but it IS a taint source, so
    the taint control alone must still block the send — proving the two controls
    are independent (a source can't slip through just because no rule names it)."""
    session = Session.new()
    session.mark_tainted("users_search")
    reason = sequence.check("conversations_add_message", session)
    assert reason is not None and "tainted" in reason


def test_reactions_survive_taint(sequence):
    """reactions_add is deliberately NOT a sink — too low-bandwidth to matter."""
    session = Session.new()
    session.mark_tainted("conversations_history")
    assert sequence.check("reactions_add", session) is None


# ---------------------------------------------------------------- sequence
# Sequence rules restate the exfiltration paths independently of taint, so the
# guard survives a future edit that narrows taint_sources. These assertions use
# an UNTAINTED session precisely to prove the second control stands alone.
@pytest.mark.parametrize(
    "read",
    ["conversations_history", "conversations_search_messages", "attachment_get_data"],
)
def test_read_then_send_is_forbidden_by_sequence_rule_alone(sequence, read):
    session = Session.new()
    session.record_call(read)          # history only — no taint flag set
    reason = sequence.check("conversations_add_message", session)
    assert reason is not None, f"send must be forbidden after {read}"
    assert "tainted" not in reason, "this must be the sequence rule, not taint"


def test_send_is_fine_after_only_metadata_reads(sequence):
    """The false-positive guard: discovery alone must not lock out messaging."""
    session = Session.new()
    session.record_call("channels_list")
    session.record_call("channels_me")
    assert sequence.check("conversations_add_message", session) is None
