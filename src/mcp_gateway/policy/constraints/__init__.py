"""Constraint plugin registry.

A constraint inspects a call's arguments and returns a violation reason or
None. Phase 1 ships the regex constraint; connector packs register richer
types (JQL scoping, branch protection, …) by adding entries here via
`register_constraint_type` — no engine changes.
"""

from __future__ import annotations

from typing import Any

from mcp_gateway.core.errors import PolicyError
from mcp_gateway.policy.constraints.base import Constraint
from mcp_gateway.policy.constraints.regex import RegexConstraint

_CONSTRAINT_TYPES: dict[str, type[Constraint]] = {
    RegexConstraint.type_name: RegexConstraint,
}


def register_constraint_type(cls: type[Constraint]) -> None:
    _CONSTRAINT_TYPES[cls.type_name] = cls


def build_constraint(config: Any, where: str) -> Constraint:
    """Validate one constraint config and return a compiled instance.

    `where` is a human-readable location ("tools['db.*'].constraints[0]")
    used in every error so a policy author can find the line to fix.
    """
    if not isinstance(config, dict):
        raise PolicyError(f"{where}: constraint must be an object")
    type_name = config.get("type", RegexConstraint.type_name)
    cls = _CONSTRAINT_TYPES.get(type_name)
    if cls is None:
        raise PolicyError(
            f"{where}: unknown constraint type {type_name!r}; "
            f"available: {sorted(_CONSTRAINT_TYPES)}"
        )
    return cls.from_config(config, where)


__all__ = ["Constraint", "RegexConstraint", "build_constraint", "register_constraint_type"]
