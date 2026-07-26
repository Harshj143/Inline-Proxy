"""Policy loading, matching, constraints, and safe argument rewrites.

The policy engine computes an effective rule but never executes the tool call.
Matching preserves the product contract: exact rules beat the most-specific
glob, and unmatched tools use the fail-closed default.
"""

import re;
import fnmatch;
import yaml;

obj Constraint {
    has arg: str,
        must_match: str = "",
        must_not_match: str = "",
        flags: str = "",
        reason: str = "constraint violated";
}

obj Rewrite {
    has arg: str,
        set_to: str = "",
        append: str = "",
        unless_match: str = "",
        flags: str = "";
}

obj SequenceRule {
    has after: str,
        forbid: str,
        reason: str = "forbidden tool sequence";
}

obj RiskConfig {
    has elevated: int = 30,
        suspended: int = 60,
        weights: dict[str, int] = {};
}

obj Rule {
    has tool: str,
        action: str = "block",
        reason: str = "",
        redaction: str = "",
        then: str = "",
        constraints: list[Constraint] = [],
        rewrites: list[Rewrite] = [],
        roles: dict[str, dict] = {};
}

obj Policy {
    has name: str = "unnamed",
        default_action: str = "block",
        rules: dict[str, Rule] = {},
        taint_sources: list[str] = [],
        taint_sinks: list[str] = [],
        sequence_rules: list[SequenceRule] = [],
        risk: RiskConfig = RiskConfig();
}

def _flags(spec: str) -> int {
    return (re.IGNORECASE as int) if "i" in spec else 0;
}

def _build_rule(tool: str, raw: dict[str, any]) -> Rule {
    built = Rule(tool=tool);
    built.action = str(raw.get("action", "block"));
    built.reason = str(raw.get("reason", ""));
    built.redaction = str(raw.get("redaction", "")) if raw.get("redaction") else "";
    built.then = str(raw.get("then", ""));
    raw_constraints = raw.get("constraints", []) as list[dict[str, any]];
    for raw_constraint in raw_constraints {
        built.constraints.append(
            Constraint(
                arg=str(raw_constraint.get("arg", "")),
                must_match=str(raw_constraint.get("must_match", "")),
                must_not_match=str(raw_constraint.get("must_not_match", "")),
                flags=str(raw_constraint.get("flags", "")),
                reason=str(raw_constraint.get("reason", "constraint violated"))
            )
        );
    }
    raw_rewrites = raw.get("rewrites", []) as list[dict[str, any]];
    for raw_rewrite in raw_rewrites {
        built.rewrites.append(
            Rewrite(
                arg=str(raw_rewrite.get("arg", "")),
                set_to=str(raw_rewrite.get("set", "")),
                append=str(raw_rewrite.get("append", "")),
                unless_match=str(raw_rewrite.get("unless_match", "")),
                flags=str(raw_rewrite.get("flags", ""))
            )
        );
    }
    built.roles = raw.get("roles", {}) as dict[str, dict[str, any]];
    return built;
}

def load_policy(path: str) -> Policy {
    with open(path) as policy_file {
        document = yaml.safe_load(policy_file.read()) as dict[str, any];
    }
    policy = Policy(
        name=str(document.get("name", "unnamed")),
        default_action=str(document.get("default_action", "block"))
    );
    policy.taint_sources = document.get("taint_sources", []) as list[str];
    policy.taint_sinks = document.get("taint_sinks", []) as list[str];
    raw_sequences = document.get("sequence_rules", []) as list[dict[str, any]];
    for raw_sequence in raw_sequences {
        policy.sequence_rules.append(
            SequenceRule(
                after=str(raw_sequence.get("after", "")),
                forbid=str(raw_sequence.get("forbid", "")),
                reason=str(raw_sequence.get("reason", "forbidden tool sequence"))
            )
        );
    }
    risk = document.get("risk", {}) as dict[str, any];
    policy.risk = RiskConfig(
        elevated=int(risk.get("elevated", 30)),
        suspended=int(risk.get("suspended", 60)),
        weights=risk.get("weights", {}) as dict[str, int]
    );
    tools = document.get("tools", {}) as dict[str, dict[str, any]];
    for (tool, raw_rule) in tools.items() {
        policy.rules[tool] = _build_rule(tool, raw_rule);
    }
    return policy;
}

def _specificity(pattern: str) -> int {
    count = 0;
    for character in pattern {
        if character not in ["*", "?", "["] {
            count += 1;
        }
    }
    return count;
}

def match(policy: Policy, tool: str, role: str) -> Rule {
    chosen: Rule | None = None;
    if tool in policy.rules {
        chosen = policy.rules[tool];
    } else {
        best = -1;
        for (pattern, candidate) in policy.rules.items() {
            if ("*" in pattern or "?" in pattern) and fnmatch.fnmatch(tool, pattern) {
                specificity = _specificity(pattern);
                if specificity > best {
                    best = specificity;
                    chosen = candidate;
                }
            }
        }
    }
    if chosen is None {
        return Rule(
            tool=tool,
            action=policy.default_action,
            reason="default action (no matching rule)"
        );
    }
    effective = chosen;
    if role and role in chosen.roles {
        overlay = chosen.roles[role];
        effective = Rule(
            tool=tool,
            action=str(overlay.get("action", chosen.action)),
            reason=str(overlay.get("reason", chosen.reason)),
            redaction=str(overlay.get("redaction", chosen.redaction)),
            then=str(overlay.get("then", chosen.then)),
            constraints=chosen.constraints,
            rewrites=chosen.rewrites,
            roles=chosen.roles
        );
    }
    return effective;
}

def check_constraints(rule: Rule, args: dict[str, any]) -> list[str] {
    failures: list[str] = [];
    for constraint in rule.constraints {
        value = str(args.get(constraint.arg, ""));
        if constraint.must_match
        and not re.search(constraint.must_match, value, _flags(constraint.flags)) {
            failures.append(constraint.reason);
        }
        if constraint.must_not_match
        and re.search(constraint.must_not_match, value, _flags(constraint.flags)) {
            failures.append(constraint.reason);
        }
    }
    return failures;
}

def apply_rewrites(rule: Rule, args: dict[str, any]) -> dict[str, any] {
    output: dict[str, any] = dict(args);
    for rewrite in rule.rewrites {
        value = str(output.get(rewrite.arg, ""));
        if rewrite.unless_match
        and re.search(rewrite.unless_match, value, _flags(rewrite.flags)) {
            continue;
        }
        if rewrite.set_to {
            output[rewrite.arg] = rewrite.set_to;
        }
        if rewrite.append {
            output[rewrite.arg] = value + rewrite.append;
        }
    }
    return output;
}
