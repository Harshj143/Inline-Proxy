"""Policy engine for the MCP security gateway.

Evaluates every tools/call request against a JSON policy file and returns a
decision. The action vocabulary mirrors (in miniature) a Formal-style
multi-action pipeline:

  allow             pass the call through untouched
  block             deny at the gateway with a JSON-RPC error
  redact            allow, but scrub PII from args/response
  rewrite           allow, but first REWRITE the arguments to a safe form
                    (e.g. force a SQL LIMIT, pin read_only=true)
  quarantine        allow the call upstream, but WITHHOLD the result from the
                    LLM (replace it with a notice) and flag it for review
  require_approval  pause and ask a human; on approval fall through to `then`
                    (default allow), on denial block

Policy is also ROLE-AWARE. The gateway is launched for one caller identity
(--role), e.g. `admin` or `analyst`, and a tool rule may override its action
per role. Same tool, different treatment: an admin sees raw customer data,
an analyst sees it redacted.

Policy file shape (policies.json):
{
  "default_action": "block",
  "tools": {
    "crm.get_customer": {
      "action": "redact",
      "roles": {"admin": {"action": "allow"}, "analyst": {"action": "redact"}}
    },
    "search.docs":      {"action": "allow"},
    "db.execute_sql":   {"action": "rewrite",
                         "rewrites": [{"arg": "sql", "append": " LIMIT 1000",
                                       "unless_match": "\\blimit\\b", "flags": "i"}]}
  },
  "redact_entities": ["EMAIL", "PHONE", "SSN", "CREDIT_CARD", "IP_ADDRESS"]
}

This mirrors (in miniature) Formal-style request-stage enforcement: the
decision happens before anything reaches the upstream MCP server.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import re

ALLOW = "allow"
BLOCK = "block"
REDACT = "redact"
REWRITE = "rewrite"
QUARANTINE = "quarantine"
REQUIRE_APPROVAL = "require_approval"

VALID_ACTIONS = {ALLOW, BLOCK, REDACT, REWRITE, QUARANTINE, REQUIRE_APPROVAL}


@dataclass
class Decision:
    action: str
    tool: str
    reason: str
    constraint_violation: bool = False
    rewrites: list = field(default_factory=list)
    then_action: str = ALLOW  # for require_approval: the action once approved
    role: str | None = None

    @property
    def blocked(self) -> bool:
        return self.action == BLOCK

    @property
    def needs_redaction(self) -> bool:
        return self.action == REDACT

    @property
    def needs_rewrite(self) -> bool:
        return self.action == REWRITE

    @property
    def is_quarantine(self) -> bool:
        return self.action == QUARANTINE

    @property
    def needs_approval(self) -> bool:
        return self.action == REQUIRE_APPROVAL


def apply_rewrites(arguments: dict, rewrites: list[dict]) -> tuple[dict, list[dict]]:
    """Return (new_args, changes). Two supported operations:

      {"arg": "read_only", "set": true}
          force the argument to a fixed value.
      {"arg": "sql", "append": " LIMIT 1000", "unless_match": "\\blimit\\b",
       "flags": "i"}
          append a string to a string argument, unless a regex already matches
          (so we don't double-append a LIMIT that is already there).
    """
    new_args = dict(arguments)
    changes: list[dict] = []
    for r in rewrites:
        arg = r["arg"]
        if "set" in r:
            if new_args.get(arg) != r["set"]:
                changes.append({"arg": arg, "op": "set", "to": r["set"]})
                new_args[arg] = r["set"]
        elif "append" in r:
            value = str(new_args.get(arg, ""))
            flags = re.IGNORECASE if "i" in r.get("flags", "") else 0
            guard = r.get("unless_match")
            if guard and re.search(guard, value, flags):
                continue  # already satisfied, leave it alone
            new_args[arg] = value + r["append"]
            changes.append({"arg": arg, "op": "append", "added": r["append"]})
    return new_args, changes


class PolicyEngine:
    def __init__(self, policy_path: str | Path):
        raw = json.loads(Path(policy_path).read_text())
        self.default_action: str = raw.get("default_action", BLOCK)
        if self.default_action not in VALID_ACTIONS:
            raise ValueError(f"invalid default_action: {self.default_action}")

        self.tools: dict[str, dict] = raw.get("tools", {})
        for name, rule in self.tools.items():
            self._validate_rule(name, rule)
            for role_name, override in rule.get("roles", {}).items():
                self._validate_rule(f"{name}[role={role_name}]", override)

        self.redact_entities: list[str] = raw.get(
            "redact_entities",
            ["EMAIL", "PHONE", "SSN", "CREDIT_CARD", "IP_ADDRESS"],
        )

        # Session-state controls, consumed by gateway.sequence.SequencePolicy.
        self.taint_sources: list[str] = raw.get("taint_sources", [])
        self.taint_sinks: list[str] = raw.get("taint_sinks", [])
        self.sequence_rules: list[dict] = raw.get("sequence_rules", [])

    @staticmethod
    def _validate_rule(name: str, rule: dict) -> None:
        action = rule.get("action")
        if action is not None and action not in VALID_ACTIONS:
            raise ValueError(f"invalid action for tool {name!r}: {action!r}")
        then = rule.get("then", ALLOW)
        if then not in VALID_ACTIONS:
            raise ValueError(f"invalid 'then' action for tool {name!r}: {then!r}")

    def evaluate(
        self, tool_name: str, arguments: dict | None = None, role: str | None = None
    ) -> Decision:
        rule = self.tools.get(tool_name)
        if rule is None:
            return Decision(
                action=self.default_action,
                tool=tool_name,
                reason="tool not on allowlist; default policy applied",
                role=role,
            )

        # Role override: the base rule is a starting point; a matching role
        # entry replaces the fields it specifies (action, reason, constraints,
        # rewrites, then). This is how one tool gets different treatment for
        # different caller identities.
        eff = dict(rule)
        role_override = rule.get("roles", {}).get(role) if role else None
        if role_override:
            eff.update(role_override)

        # Argument-level constraints: an allowed tool can still be denied if
        # its arguments violate a rule, e.g. db.execute_sql restricted to
        # read-only SELECT statements. Request-stage inspection of WHAT the
        # agent is doing, not just WHICH tool it is calling.
        violation = self._check_constraints(eff, arguments or {})
        if violation:
            return Decision(action=BLOCK, tool=tool_name, reason=violation,
                            constraint_violation=True, role=role)

        return Decision(
            action=eff["action"],
            tool=tool_name,
            reason=eff.get("reason", "explicit tool rule"),
            rewrites=eff.get("rewrites", []),
            then_action=eff.get("then", ALLOW),
            role=role,
        )

    @staticmethod
    def _check_constraints(rule: dict, arguments: dict) -> str | None:
        """Return a violation reason, or None if all constraints pass.

        Constraint shape:
          {"arg": "sql", "must_match": "^\\s*SELECT\\b", "flags": "i",
           "reason": "only read-only SELECT statements are permitted"}
        """
        for c in rule.get("constraints", []):
            value = str(arguments.get(c["arg"], ""))
            flags = re.IGNORECASE if "i" in c.get("flags", "") else 0
            if not re.search(c["must_match"], value, flags):
                return c.get(
                    "reason",
                    f"argument '{c['arg']}' violates constraint {c['must_match']!r}",
                )
        return None
