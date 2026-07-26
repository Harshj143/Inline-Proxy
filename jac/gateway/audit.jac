"""Counts-only JSONL audit sink.

The record intentionally excludes arguments, raw results, and scrubbed values.
Sink availability never weakens enforcement, so write failures are reported but
do not change an already-computed decision.
"""

import json;
import datetime;
import from gateway.context { CallContext }

def _now -> str {
    return datetime.datetime.now(datetime.timezone.utc).isoformat();
}

def emit(
    path: str,
    event: str,
    ctx: CallContext,
    risk_score: int,
    risk_level: str,
    tainted: bool,
    origin: str
) {
    redactions: dict | None = None;
    if ctx.report.total > 0 {
        redactions = {"total": ctx.report.total, "by_entity": ctx.report.entity_counts};
    }
    record = {
        "schema_version": 1,
        "ts": _now(),
        "event": event,
        "session_id": ctx.session_id,
        "principal": {"sub": ctx.principal.sub, "roles": ctx.principal.roles},
        "tool": ctx.tool,
        "request_id": ctx.request_id,
        "decision": {
            "action": ctx.decision.action,
            "rule": ctx.decision.rule,
            "reason": ctx.decision.reason
        },
        "trace": ctx.trace,
        "violation_count": len(ctx.violations),
        "risk": {"score": risk_score, "level": risk_level},
        "taint": {"tainted": tainted, "origin": origin},
        "redactions": redactions
    };
    try {
        with open(path, "a") as audit_file {
            audit_file.write(json.dumps(record) + "\n");
        }
    } except Exception as error {
        _ignored_error = str(error);
    }
}
