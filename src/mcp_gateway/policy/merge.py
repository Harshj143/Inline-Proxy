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
    # Session-state controls: taint lists UNION across layers (a company adds
    # sources/sinks), sequence rules CONCATENATE (all apply), risk config is
    # last-layer-wins per key.
    taint_sources: list[str] = field(default_factory=list)
    taint_sinks: list[str] = field(default_factory=list)
    sequence_rules: list[dict[str, Any]] = field(default_factory=list)
    risk: dict[str, Any] = field(default_factory=dict)
    # Failure posture: the last layer that sets `on_failure` wins entirely
    # (a customer override restates the posture it wants).
    on_failure: Any = None


def merge_layers(layers: list[PolicyLayer]) -> MergedPolicy:
    merged = MergedPolicy(default_action="block")
    taint_sources: dict[str, None] = {}  # ordered set
    taint_sinks: dict[str, None] = {}
    for layer in layers:
        merged.layer_names.append(layer.name)
        if layer.default_action is not None:
            merged.default_action = layer.default_action

        for s in layer.taint_sources:
            taint_sources.setdefault(s, None)
        for s in layer.taint_sinks:
            taint_sinks.setdefault(s, None)
        merged.sequence_rules.extend(layer.sequence_rules)
        if layer.risk:
            weights = {**merged.risk.get("weights", {}), **layer.risk.get("weights", {})}
            merged.risk = {**merged.risk, **layer.risk}
            if weights:
                merged.risk["weights"] = weights
        if layer.on_failure is not None:
            merged.on_failure = layer.on_failure

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

    merged.taint_sources = list(taint_sources)
    merged.taint_sinks = list(taint_sinks)
    return merged
