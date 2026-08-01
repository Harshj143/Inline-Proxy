"""Map our audit events to OCSF and ECS — the schemas SIEMs already understand.

Our audit events are shaped for us (`audit/events.py`): `event`, `ts`, `tool`,
`principal`, count fields. A SIEM would happily store them raw, but it can only
*correlate* — build dashboards, alerts, and detections — over a normalized
schema. Two dominate:

  * **OCSF** (Open Cybersecurity Schema Framework) — the vendor-neutral schema
    Splunk, AWS Security Lake, and others converge on. We map tool calls to the
    **Application Activity** class (`class_uid` 6006): a tool call is an app doing
    a thing, with an actor, an activity, and a status. A blocked/denied call maps
    to activity `Deny` and a Failure status; an allowed one to `Allow`/Success.

  * **ECS** (Elastic Common Schema) — the Elastic/OpenSearch equivalent, mapped
    to `event.*`, `user.*`, `labels.*`.

Both mappings are deliberately **lossless-in-spirit**: the normalized fields are
added for correlation, and the whole original event is preserved verbatim under
`unmapped` (OCSF) / a raw label (ECS), so nothing an investigator might need is
thrown away just because our schema had a field OCSF doesn't name. Counts-only is
respected — we never invent a payload the audit event didn't carry.

Pure stdlib. No dependency, no network — just a dict-to-dict function the
forwarder applies before handing a batch to a sink.
"""

from __future__ import annotations

from typing import Any

# OCSF Application Activity (6006). activity_id: 1 Create, 3 Read, 4 Update, …;
# we use the security-relevant subset plus a catch-all.
_OCSF_CLASS_UID = 6006
_OCSF_CATEGORY_UID = 6  # Application Activity category

# Our event name → (OCSF activity_id, activity_name, is_denial).
_ACTIVITY = {
    "tool_call_allowed": (3, "Allow", False),
    "tool_call_blocked": (4, "Deny", True),
    "tool_call_denied_session_suspended": (4, "Deny", True),
    "tool_result_redacted": (3, "Redact", False),
    "tool_result_quarantined": (4, "Quarantine", True),
    "tool_result_redaction_failed": (4, "Deny", True),
    "session_tainted": (4, "Taint", True),
    "session_suspended": (4, "Suspend", True),
    "anomaly_detected": (4, "Anomaly", True),
    "approval_requested": (2, "Approve", False),
    "policy_bundle_rejected": (4, "Reject", True),
}

# Status: 1 Success, 2 Failure. A denial is a Failure from the *caller's* view.
_STATUS_SUCCESS = 1
_STATUS_FAILURE = 2

# Coarse severity for a denial vs an allow (OCSF severity_id: 1 Info … 6 Fatal).
_SEV_INFO = 1
_SEV_MEDIUM = 3


def to_ocsf(event: dict[str, Any]) -> dict[str, Any]:
    """One audit event → an OCSF Application Activity record."""
    name = event.get("event", "unknown")
    activity_id, activity_name, denial = _ACTIVITY.get(name, (0, "Unknown", False))
    status_id = _STATUS_FAILURE if denial else _STATUS_SUCCESS

    record: dict[str, Any] = {
        "class_uid": _OCSF_CLASS_UID,
        "class_name": "Application Activity",
        "category_uid": _OCSF_CATEGORY_UID,
        "activity_id": activity_id,
        "activity_name": activity_name,
        "type_uid": _OCSF_CLASS_UID * 100 + activity_id,
        "severity_id": _SEV_MEDIUM if denial else _SEV_INFO,
        "status_id": status_id,
        "status": "Failure" if denial else "Success",
        "metadata": {
            "product": {"name": "MCP Security Gateway", "vendor_name": "mcp-gateway"},
            "version": "1.4.0",
            "event_code": name,
        },
        "unmapped": event,      # preserve everything, lossless
    }
    if "ts" in event:
        record["time"] = event["ts"]
    principal = event.get("principal")
    if principal is not None:
        record["actor"] = {"user": {"name": str(principal)}}
    if event.get("tool"):
        record["app"] = {"name": event["tool"]}
    if event.get("session_id"):
        record.setdefault("metadata", {})["correlation_uid"] = event["session_id"]
    if event.get("reason"):
        record["message"] = str(event["reason"])
    return record


def to_ecs(event: dict[str, Any]) -> dict[str, Any]:
    """One audit event → an Elastic Common Schema document."""
    name = event.get("event", "unknown")
    _, action, denial = _ACTIVITY.get(name, (0, "unknown", False))

    category = ["configuration"] if name.startswith("policy_") else ["intrusion_detection"]
    doc: dict[str, Any] = {
        "event": {
            "kind": "event",
            "category": category,
            "action": name,
            "outcome": "failure" if denial else "success",
            "module": "mcp_gateway",
        },
        "labels": {k: v for k, v in event.items() if k not in ("ts", "principal")},
    }
    if "ts" in event:
        doc["@timestamp"] = event["ts"]
    if event.get("principal"):
        doc["user"] = {"name": str(event["principal"])}
    if event.get("reason"):
        doc["message"] = str(event["reason"])
    return doc


# Name → mapper, for the CLI's --format.
MAPPERS = {
    "raw": None,             # identity: ship the event verbatim
    "ocsf": to_ocsf,
    "ecs": to_ecs,
}
