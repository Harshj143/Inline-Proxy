"""Jac Object-Spatial enforcement pipeline.

Pipeline stages are graph nodes and CallWalker is the mobile enforcement
procedure. Stage abilities live on the walker so `disengage` can halt traversal
immediately. Session state is graph-persistent; policies and calls remain plain
typed objects. The engine decides and mutates security state, but never executes
an upstream tool.
"""

import from gateway.context { Principal, Decision, CallContext, Violation }
import from gateway.policy { Policy, Rule, match, check_constraints, apply_rewrites }
import from gateway.redaction { redact_text }
import from gateway.audit { emit }

glob APPROVALS_MODE: str = "deny";

node Session {
    has sid: str,
        roles: list[str] = [],
        tainted: bool = False,
        taint_origin: str = "",
        risk_score: int = 0,
        risk_level: str = "NORMAL",
        suspended: bool = False,
        history: list[str] = [];
}

node SessionGate {}
node PolicyMatch {}
node ConstraintGate {}
node SequenceGate {}
node ActionStage {}

def get_session(wanted_sid: str, roles: list[str]) -> Session {
    matches = [root-->[?:Session, sid==wanted_sid]];
    if matches {
        session = matches[0];
        if roles {
            session.roles = roles;
        }
        return session;
    }
    created = root ++> Session(sid=wanted_sid, roles=roles);
    return created[0];
}

def _default_weights -> dict[str, int] {
    return {
        "policy_block": 10,
        "constraint_violation": 15,
        "taint_block": 25,
        "sequence_block": 25,
        "approval_denied": 20,
        "heavy_redaction": 5
    };
}

def _add_risk(session: Session, policy: Policy, event: str) {
    weights = _default_weights();
    for (name, weight) in policy.risk.weights.items() {
        weights[name] = weight;
    }
    session.risk_score += weights.get(event, 0);
    if session.risk_score >= policy.risk.suspended {
        session.risk_level = "SUSPENDED";
        session.suspended = True;
    } elif session.risk_score >= policy.risk.elevated {
        session.risk_level = "ELEVATED";
    } else {
        session.risk_level = "NORMAL";
    }
}

walker CallWalker {
    has ctx: CallContext,
        policy: Policy,
        session: Session,
        rule: Rule = Rule(tool="");

    can begin with Root entry {
        visit [root-->[?:SessionGate]];
    }

    can check_session with SessionGate entry {
        self.ctx.trace.append("session_gate");
        if self.session.suspended {
            self.ctx.decision = Decision(
                action="block",
                rule="session.suspended",
                reason="session is suspended (risk threshold exceeded)"
            );
            disengage;
        }
        visit [here-->];
    }

    can resolve_policy with PolicyMatch entry {
        self.ctx.trace.append("policy");
        role = self.ctx.principal.roles[0] if self.ctx.principal.roles else "";
        self.rule = match(self.policy, self.ctx.tool, role);
        self.ctx.decision = Decision(
            action=self.rule.action,
            rule=self.policy.name,
            reason=self.rule.reason,
            redaction=self.rule.redaction,
            then=self.rule.then
        );
        self.ctx.is_source = self.ctx.tool in self.policy.taint_sources;
        self.ctx.is_sink = self.ctx.tool in self.policy.taint_sinks;
        if self.rule.action not in [
            "allow",
            "block",
            "redact",
            "rewrite",
            "quarantine",
            "require_approval"
        ] {
            self.ctx.decision = Decision(
                action="block",
                rule="policy.invalid_action",
                reason="unsupported policy action (fail-closed)"
            );
            _add_risk(self.session, self.policy, "policy_block");
            disengage;
        }
        if self.rule.action == "block" {
            _add_risk(self.session, self.policy, "policy_block");
            disengage;
        }
        visit [here-->];
    }

    can enforce_constraints with ConstraintGate entry {
        self.ctx.trace.append("constraints");
        failures = check_constraints(self.rule, self.ctx.args);
        if failures {
            for reason in failures {
                self.ctx.violations.append(Violation(arg="", reason=reason));
            }
            self.ctx.decision = Decision(
                action="block", rule="constraint", reason=failures[0]
            );
            _add_risk(self.session, self.policy, "constraint_violation");
            disengage;
        }
        self.ctx.args = apply_rewrites(self.rule, self.ctx.args);
        visit [here-->];
    }

    can enforce_sequence with SequenceGate entry {
        self.ctx.trace.append("sequence");
        if self.session.tainted and self.ctx.is_sink {
            self.ctx.decision = Decision(
                action="block",
                rule="taint",
                reason=(
                    "tainted session may not reach an outbound/mutating " + "sink (origin: " + self.session.taint_origin + ")"
                )
            );
            _add_risk(self.session, self.policy, "taint_block");
            disengage;
        }
        for sequence in self.policy.sequence_rules {
            if (
                sequence.after in self.session.history
                and sequence.forbid == self.ctx.tool
            ) {
                self.ctx.decision = Decision(
                    action="block", rule="sequence", reason=sequence.reason
                );
                _add_risk(self.session, self.policy, "sequence_block");
                disengage;
            }
        }
        visit [here-->];
    }

    can choose_action with ActionStage entry {
        self.ctx.trace.append("action");
        if (
            self.ctx.decision.action == "require_approval" and APPROVALS_MODE == "deny"
        ) {
            self.ctx.decision = Decision(
                action="block",
                rule="approval",
                reason=(
                    "human approval required and no approver is " + "configured (fail-closed)"
                )
            );
            _add_risk(self.session, self.policy, "approval_denied");
            disengage;
        }
        if self.ctx.decision.action == "require_approval" {
            self.ctx.decision.action = self.rule.then or "allow";
        }
        if self.ctx.is_source {
            self.session.tainted = True;
            self.session.taint_origin = self.ctx.tool;
        }
        self.session.history.append(self.ctx.tool);
    }
}

def build_pipeline -> None {
    if [root-->[?:SessionGate]] {
        return;
    }
    session_gate = root ++> SessionGate();
    policy_match = session_gate[0] ++> PolicyMatch();
    constraint_gate = policy_match[0] ++> ConstraintGate();
    sequence_gate = constraint_gate[0] ++> SequenceGate();
    sequence_gate[0] ++> ActionStage();
}

def police_request(
    session: Session,
    policy: Policy,
    tool: str,
    args: dict[str, any],
    roles: list[str],
    request_id: int
) -> CallContext {
    build_pipeline();
    ctx = CallContext(
        session_id=session.sid,
        principal=Principal(sub="agent", roles=roles),
        tool=tool,
        args=args,
        request_id=request_id,
        decision=Decision()
    );
    root spawn CallWalker(ctx=ctx, policy=policy, session=session);
    return ctx;
}

def handle_response(
    ctx: CallContext,
    policy: Policy,
    session: Session,
    result_text: str,
    audit_path: str
) -> str {
    action = ctx.decision.action;
    delivered = result_text;
    event = "tool_result_delivered";
    try {
        if action == "quarantine" {
            delivered = (
                "[QUARANTINED] result withheld from the model and " + "flagged for review: " + ctx.decision.reason
            );
            event = "tool_result_quarantined";
        } elif action == "redact" {
            profile = ctx.decision.redaction or "standard";
            ctx.report = redact_text(result_text, profile);
            delivered = ctx.report.scrubbed;
            event = "tool_result_redacted";
            if ctx.report.total >= 3 {
                _add_risk(session, policy, "heavy_redaction");
            }
        }
    } except Exception as error {
        delivered = (
            "[QUARANTINED] redaction failed; result withheld " + "(fail-closed)"
        );
        event = "tool_result_redaction_failed";
        _ignored_error = str(error);
    }
    ctx.result_text = delivered;
    emit(
        audit_path,
        event,
        ctx,
        session.risk_score,
        session.risk_level,
        session.tainted,
        session.taint_origin
    );
    return delivered;
}

def audit_request(ctx: CallContext, session: Session, audit_path: str) {
    event = (
        "tool_call_allowed"
            if ctx.decision.action in ["allow", "redact", "rewrite", "quarantine"]
            else "tool_call_blocked"
    );
    emit(
        audit_path,
        event,
        ctx,
        session.risk_score,
        session.risk_level,
        session.tainted,
        session.taint_origin
    );
}
