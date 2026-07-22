"""Policy document loading and structural validation.

Accepts YAML and JSON (a JSON document is valid YAML, but .json files get
the JSON parser for exact error positions). Every document must declare
`schema_version: 1` — schema evolution is explicit, never guessed.

Validation philosophy: a typo in policy is a security bug, so anything the
build cannot enforce is a load-time PolicyError with the exact location —
unknown fields, unknown actions, invalid regexes, malformed constraints.
A single file may be a partial layer (e.g. a company override that only
changes fields of a pack's rule); completeness (every merged rule has an
action) is checked after merge, not per file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_gateway.core.errors import PolicyError
from mcp_gateway.policy.actions import ACTION_VOCABULARY
from mcp_gateway.policy.actions.rewrite import validate_rewrite
from mcp_gateway.policy.constraints import build_constraint
from mcp_gateway.redaction.profiles import list_profiles

SCHEMA_VERSION = 1

_TOP_LEVEL_FIELDS = {
    "schema_version", "name", "default_action", "tools",
    "taint_sources", "taint_sinks", "sequence_rules", "risk", "on_failure",
}
_RISK_FIELDS = {"weights", "elevated_at", "suspend_at"}
_FAILURE_FIELDS = {"default", "pipeline", "redaction", "approval"}
_FAIL_MODES = {"open", "closed"}
_RULE_FIELDS = {
    "action", "reason", "constraints", "rewrites", "redaction", "roles", "then", "replace"
}
_OVERLAY_FIELDS = _RULE_FIELDS - {"roles", "replace"}
_REDACTION_FIELDS = {"profile", "exclude_keys", "allowlist", "denylist", "context_words"}


@dataclass(slots=True)
class PolicyLayer:
    """One validated policy document, before merging."""

    name: str
    source: str
    default_action: str | None
    rules: dict[str, dict[str, Any]] = field(default_factory=dict)
    taint_sources: list[str] = field(default_factory=list)
    taint_sinks: list[str] = field(default_factory=list)
    sequence_rules: list[dict[str, Any]] = field(default_factory=list)
    risk: dict[str, Any] | None = None
    on_failure: Any = None


def load_policy_file(path: str | Path) -> PolicyLayer:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise PolicyError(f"policy file not found: {path}") from None

    if path.suffix == ".json":
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyError(f"{path}: not valid JSON ({exc})") from None
    else:
        try:
            import yaml
        except ImportError:
            raise PolicyError(
                f"{path}: YAML policies need pyyaml (pip install pyyaml)"
            ) from None
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise PolicyError(f"{path}: not valid YAML ({exc})") from None

    return parse_document(document, source=str(path), fallback_name=path.stem)


def parse_document(
    document: Any, source: str, fallback_name: str = "policy"
) -> PolicyLayer:
    if not isinstance(document, dict):
        raise PolicyError(f"{source}: policy document must be a mapping")

    version = document.get("schema_version")
    if version is None:
        raise PolicyError(
            f"{source}: missing schema_version (add `schema_version: 1`)"
        )
    if version != SCHEMA_VERSION:
        raise PolicyError(
            f"{source}: unsupported schema_version {version!r}; this build "
            f"supports {SCHEMA_VERSION}"
        )

    unknown = set(document) - _TOP_LEVEL_FIELDS
    if unknown:
        raise PolicyError(f"{source}: unknown top-level field(s) {sorted(unknown)}")

    default_action = document.get("default_action")
    if default_action is not None and default_action not in ("allow", "block"):
        raise PolicyError(
            f"{source}: default_action must be 'allow' or 'block', got {default_action!r}"
        )

    name = document.get("name", fallback_name)
    if not isinstance(name, str) or not name:
        raise PolicyError(f"{source}: 'name' must be a non-empty string")

    tools = document.get("tools", {})
    if not isinstance(tools, dict):
        raise PolicyError(f"{source}: 'tools' must be a mapping")

    rules: dict[str, dict[str, Any]] = {}
    for pattern, rule in tools.items():
        if not isinstance(pattern, str) or not pattern:
            raise PolicyError(f"{source}: tool pattern must be a non-empty string")
        where = f"{source}: tools[{pattern!r}]"
        rules[pattern] = _validate_rule(rule, where, allowed=_RULE_FIELDS)

    return PolicyLayer(
        name=name, source=source, default_action=default_action, rules=rules,
        taint_sources=_validate_str_list(document.get("taint_sources"), source, "taint_sources"),
        taint_sinks=_validate_str_list(document.get("taint_sinks"), source, "taint_sinks"),
        sequence_rules=_validate_sequence_rules(document.get("sequence_rules"), source),
        risk=_validate_risk(document.get("risk"), source),
        on_failure=_validate_on_failure(document.get("on_failure"), source),
    )


def _validate_on_failure(value: Any, source: str) -> Any:
    """`on_failure` is a mode string ('open'/'closed') or a mapping with an
    optional `default` plus per-category (pipeline/redaction/approval) modes."""
    if value is None:
        return None
    if isinstance(value, str):
        if value not in _FAIL_MODES:
            raise PolicyError(
                f"{source}: on_failure must be 'open' or 'closed', got {value!r}"
            )
        return value
    if not isinstance(value, dict):
        raise PolicyError(f"{source}: on_failure must be a string or a mapping")
    unknown = set(value) - _FAILURE_FIELDS
    if unknown:
        raise PolicyError(f"{source}: unknown on_failure field(s) {sorted(unknown)}")
    for key, mode in value.items():
        if mode not in _FAIL_MODES:
            raise PolicyError(
                f"{source}: on_failure.{key} must be 'open' or 'closed', got {mode!r}"
            )
    return value


def _validate_str_list(value: Any, source: str, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyError(f"{source}: '{field_name}' must be a list of strings")
    return list(value)


def _validate_sequence_rules(value: Any, source: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PolicyError(f"{source}: 'sequence_rules' must be a list")
    for i, rule in enumerate(value):
        where = f"{source}: sequence_rules[{i}]"
        if not isinstance(rule, dict):
            raise PolicyError(f"{where}: must be a mapping")
        unknown = set(rule) - {"after", "forbid", "reason"}
        if unknown:
            raise PolicyError(f"{where}: unknown field(s) {sorted(unknown)}")
        for req in ("after", "forbid"):
            if not isinstance(rule.get(req), str) or not rule[req]:
                raise PolicyError(f"{where}: '{req}' must be a non-empty string")
    return list(value)


def _validate_risk(value: Any, source: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise PolicyError(f"{source}: 'risk' must be a mapping")
    unknown = set(value) - _RISK_FIELDS
    if unknown:
        raise PolicyError(f"{source}: unknown risk field(s) {sorted(unknown)}")
    weights = value.get("weights")
    if weights is not None and (
        not isinstance(weights, dict)
        or not all(isinstance(k, str) and isinstance(v, int) for k, v in weights.items())
    ):
        raise PolicyError(f"{source}: risk.weights must map event names to integers")
    for threshold in ("elevated_at", "suspend_at"):
        if threshold in value and not isinstance(value[threshold], int):
            raise PolicyError(f"{source}: risk.{threshold} must be an integer")
    return value


def _validate_rule(rule: Any, where: str, allowed: set[str]) -> dict[str, Any]:
    if not isinstance(rule, dict):
        raise PolicyError(f"{where}: rule must be a mapping")

    unknown = set(rule) - allowed
    if unknown:
        raise PolicyError(f"{where}: unknown field(s) {sorted(unknown)}")

    action = rule.get("action")
    if action is not None and action not in ACTION_VOCABULARY:
        raise PolicyError(
            f"{where}: invalid action {action!r}; valid: {sorted(ACTION_VOCABULARY)}"
        )

    if "reason" in rule and not isinstance(rule["reason"], str):
        raise PolicyError(f"{where}: 'reason' must be a string")

    if "replace" in rule and not isinstance(rule["replace"], bool):
        raise PolicyError(f"{where}: 'replace' must be a boolean")

    then = rule.get("then")
    if then is not None and then not in ACTION_VOCABULARY:
        raise PolicyError(
            f"{where}: invalid 'then' action {then!r}; valid: {sorted(ACTION_VOCABULARY)}"
        )

    constraints = rule.get("constraints")
    if constraints is not None:
        if not isinstance(constraints, list):
            raise PolicyError(f"{where}: 'constraints' must be a list")
        for i, config in enumerate(constraints):
            build_constraint(config, f"{where}.constraints[{i}]")  # validate + discard

    rewrites = rule.get("rewrites")
    if rewrites is not None:
        if not isinstance(rewrites, list):
            raise PolicyError(f"{where}: 'rewrites' must be a list")
        for i, config in enumerate(rewrites):
            validate_rewrite(config, f"{where}.rewrites[{i}]")

    if "redaction" in rule:
        _validate_redaction(rule["redaction"], f"{where}.redaction")

    roles = rule.get("roles")
    if roles is not None:
        if not isinstance(roles, dict):
            raise PolicyError(f"{where}: 'roles' must be a mapping")
        for role_name, overlay in roles.items():
            if not isinstance(role_name, str) or not role_name:
                raise PolicyError(f"{where}: role names must be non-empty strings")
            _validate_rule(
                overlay, f"{where}.roles[{role_name!r}]", allowed=_OVERLAY_FIELDS
            )

    return dict(rule)


def _validate_redaction(config: object, where: str) -> None:
    """A `redaction` value is a profile name, or a mapping refining one."""
    if isinstance(config, str):
        profile, extras = config, {}
    elif isinstance(config, dict):
        profile = config.get("profile", "standard")
        unknown = set(config) - _REDACTION_FIELDS
        if unknown:
            raise PolicyError(f"{where}: unknown redaction field(s) {sorted(unknown)}")
        if not isinstance(profile, str):
            raise PolicyError(f"{where}: 'profile' must be a string")
        for list_field in ("exclude_keys", "allowlist", "denylist", "context_words"):
            value = config.get(list_field)
            if value is not None and not (
                isinstance(value, list) and all(isinstance(v, str) for v in value)
            ):
                raise PolicyError(f"{where}: '{list_field}' must be a list of strings")
        extras = config
    else:
        raise PolicyError(f"{where}: must be a profile name or a mapping")

    if profile not in list_profiles():
        raise PolicyError(
            f"{where}: unknown redaction profile {profile!r}; "
            f"available: {sorted(list_profiles())}"
        )
    _ = extras  # structure already validated above
