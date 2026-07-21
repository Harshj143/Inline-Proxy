"""Layered policy merge: base < connector pack < company override.

Layers are given in ascending precedence (CLI order). Merge semantics,
chosen for safe overriding (docs/ARCHITECTURE.md §5):

* Rules for the same pattern merge FIELD-LEVEL: a later layer replaces only
  the fields it names. An override that says `action: block` keeps the
  pack's constraints — dropping them silently would be fail-open. A later
  rule with `replace: true` discards the earlier fields and starts fresh.
* `roles` maps merge per-role: a later layer's overlay for role X replaces
  the earlier overlay for X entirely, other roles survive.
* `default_action`: the last layer that sets one wins; otherwise "block".

Provenance (which layers shaped each rule) is kept for audit attribution
and `policy show`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_gateway.policy.loader import PolicyLayer


@dataclass(slots=True)
class MergedPolicy:
    default_action: str
    # pattern -> merged raw rule fields, in first-declaration order
    rules: dict[str, dict[str, Any]] = field(default_factory=dict)
    # pattern -> names of layers that contributed, in application order
    provenance: dict[str, list[str]] = field(default_factory=dict)
    layer_names: list[str] = field(default_factory=list)


def merge_layers(layers: list[PolicyLayer]) -> MergedPolicy:
    merged = MergedPolicy(default_action="block")
    for layer in layers:
        merged.layer_names.append(layer.name)
        if layer.default_action is not None:
            merged.default_action = layer.default_action

        for pattern, rule in layer.rules.items():
            incoming = {k: v for k, v in rule.items() if k != "replace"}
            existing = merged.rules.get(pattern)

            if existing is None or rule.get("replace"):
                merged.rules[pattern] = dict(incoming)
                merged.provenance[pattern] = [layer.name]
                continue

            roles = incoming.pop("roles", None)
            existing.update(incoming)
            if roles is not None:
                existing_roles = existing.setdefault("roles", {})
                existing_roles.update(roles)  # per-role replace
            merged.provenance[pattern].append(layer.name)

    return merged
