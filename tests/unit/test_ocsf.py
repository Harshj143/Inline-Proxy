"""OCSF / ECS mapping: normalize for correlation without losing anything.

A SIEM can only build detections over a normalized schema, so the mapping has to
get the security-relevant fields right — a blocked call is a *failure*, an
allowed one a *success*, the principal is the actor. But an audit trail must not
lose fidelity to fit a schema, so the mapping also has to be lossless: the whole
original event survives verbatim. These tests pin both.
"""

from __future__ import annotations

from mcp_gateway.audit.ocsf import MAPPERS, to_ecs, to_ocsf

BLOCKED = {
    "event": "tool_call_blocked", "ts": "2026-07-31T14:00:00Z",
    "tool": "db.drop", "principal": "alice", "reason": "destructive",
    "session_id": "sess-1",
}
ALLOWED = {"event": "tool_call_allowed", "ts": "2026-07-31T14:00:01Z", "tool": "search"}


# ---------------------------------------------------------------- OCSF
def test_ocsf_maps_a_block_to_a_failure_activity():
    r = to_ocsf(BLOCKED)
    assert r["class_uid"] == 6006 and r["class_name"] == "Application Activity"
    assert r["activity_name"] == "Deny"
    assert r["status"] == "Failure" and r["status_id"] == 2
    assert r["severity_id"] == 3                       # medium for a denial


def test_ocsf_maps_an_allow_to_a_success():
    r = to_ocsf(ALLOWED)
    assert r["activity_name"] == "Allow"
    assert r["status"] == "Success" and r["severity_id"] == 1


def test_ocsf_carries_actor_app_time_and_correlation():
    r = to_ocsf(BLOCKED)
    assert r["actor"]["user"]["name"] == "alice"
    assert r["app"]["name"] == "db.drop"
    assert r["time"] == "2026-07-31T14:00:00Z"
    assert r["message"] == "destructive"
    assert r["metadata"]["correlation_uid"] == "sess-1"


def test_ocsf_is_lossless():
    """The whole original event survives under `unmapped` — no field dropped."""
    assert to_ocsf(BLOCKED)["unmapped"] == BLOCKED


def test_ocsf_handles_an_unknown_event_name():
    r = to_ocsf({"event": "some_future_event", "ts": "t"})
    assert r["activity_name"] == "Unknown" and r["status"] == "Success"
    assert r["unmapped"]["event"] == "some_future_event"


# ----------------------------------------------------------------- ECS
def test_ecs_maps_outcome_and_action():
    d = to_ecs(BLOCKED)
    assert d["event"]["action"] == "tool_call_blocked"
    assert d["event"]["outcome"] == "failure"
    assert d["event"]["module"] == "mcp_gateway"
    assert d["user"]["name"] == "alice"
    assert d["@timestamp"] == "2026-07-31T14:00:00Z"


def test_ecs_labels_preserve_the_event_fields():
    d = to_ecs(BLOCKED)
    assert d["labels"]["tool"] == "db.drop" and d["labels"]["event"] == "tool_call_blocked"


def test_ecs_policy_events_are_configuration_category():
    d = to_ecs({"event": "policy_bundle_rejected", "reason": "bad sig"})
    assert d["event"]["category"] == ["configuration"]
    assert d["event"]["outcome"] == "failure"


# --------------------------------------------------------------- registry
def test_mappers_registry_has_the_cli_formats():
    assert MAPPERS["raw"] is None                      # identity: ship verbatim
    assert MAPPERS["ocsf"] is to_ocsf and MAPPERS["ecs"] is to_ecs
