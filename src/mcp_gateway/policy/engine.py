"""Policy engine v2: layered packs, glob matching, role overlays.

Pipeline of responsibilities (each in its own module):

    loader.py   parse + structurally validate each document (layer)
    merge.py    fold layers into one MergedPolicy (field-level, provenance)
    matcher.py  exact > glob > default tool-name matching
    engine.py   compile merged rules (constraints/overlays) and evaluate

Compilation happens once at load: constraints become compiled objects, role
overlays become precomputed effective rules. `evaluate()` on the hot path is
a match + dict lookup — microseconds, no regex compilation, no allocation
beyond the Decision.

The engine decides WHAT the policy says; it never executes actions. The
action registry (policy.actions) is consulted only for vocabulary and for
visibility (which actions can only deny in this build).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_gateway.core.context import Decision
from mcp_gateway.core.errors import PolicyError
from mcp_gateway.core.failure import FailurePosture
from mcp_gateway.policy.actions import denying_actions
from mcp_gateway.policy.constraints import Constraint, build_constraint
from mcp_gateway.policy.loader import PolicyLayer, load_policy_file, parse_document
from mcp_gateway.policy.matcher import RuleMatcher
from mcp_gateway.policy.merge import MergedPolicy, merge_layers
from mcp_gateway.redaction.spec import RedactionSpec


@dataclass(slots=True)
class EffectiveRule:
    """One fully-resolved rule variant (base, or base+role overlay)."""

    action: str
    reason: str
    source: str
    constraints: list[Constraint] = field(default_factory=list)
    rewrites: list[dict[str, Any]] = field(default_factory=list)
    redaction: RedactionSpec | None = None
    then_action: str = "allow"


@dataclass(slots=True)
class CompiledRule:
    pattern: str
    base: EffectiveRule
    overlays: dict[str, EffectiveRule] = field(default_factory=dict)

    def for_role(self, role: str | None) -> EffectiveRule:
        if role is not None and role in self.overlays:
            return self.overlays[role]
        return self.base


class PolicyEngine:
    def __init__(self, layers: list[PolicyLayer]):
        if not layers:
            raise PolicyError("at least one policy layer is required")
        self._merged: MergedPolicy = merge_layers(layers)
        self.default_action = self._merged.default_action
        self.layer_names = list(self._merged.layer_names)
        self.source = " + ".join(self.layer_names)

        # Session-state controls, consumed by the gateway to build the
        # SequencePolicy and RiskEngine.
        self.taint_sources = self._merged.taint_sources
        self.taint_sinks = self._merged.taint_sinks
        self.sequence_rules = self._merged.sequence_rules
        self.risk = self._merged.risk
        # Failure posture (fail-closed default). Consumed by the pipeline,
        # gateway redaction path, and approval broker.
        self.posture = FailurePosture.from_config(self._merged.on_failure)

        self._rules: dict[str, CompiledRule] = {}
        for pattern, raw in self._merged.rules.items():
            self._rules[pattern] = self._compile(pattern, raw)
        self._matcher = RuleMatcher(list(self._rules))

    # ------------------------------------------------------------ constructors
    @classmethod
    def load(cls, paths: list[str | Path]) -> PolicyEngine:
        return cls([load_policy_file(p) for p in paths])

    @classmethod
    def from_documents(cls, documents: list[tuple[dict[str, Any], str]]) -> PolicyEngine:
        """For tests and embedding: [(document_dict, source_name), …]."""
        return cls([parse_document(doc, source=name, fallback_name=name)
                    for doc, name in documents])

    # -------------------------------------------------------------- compilation
    def _compile(self, pattern: str, raw: dict[str, Any]) -> CompiledRule:
        provenance = "+".join(self._merged.provenance.get(pattern, ["?"]))
        where = f"{provenance}: tools[{pattern!r}]"

        if "action" not in raw:
            raise PolicyError(
                f"{where}: no 'action' after merging all layers — an override "
                f"exists but nothing defines the rule's action"
            )

        base = self._compile_fields(raw, source=f"{provenance}:{pattern}", where=where)

        overlays: dict[str, EffectiveRule] = {}
        for role, overlay in raw.get("roles", {}).items():
            merged_fields = {k: v for k, v in raw.items() if k != "roles"}
            merged_fields.update(overlay)
            overlays[role] = self._compile_fields(
                merged_fields,
                source=f"{provenance}:{pattern}+role:{role}",
                where=f"{where}.roles[{role!r}]",
            )
        return CompiledRule(pattern=pattern, base=base, overlays=overlays)

    @staticmethod
    def _compile_fields(fields_: dict[str, Any], source: str, where: str) -> EffectiveRule:
        redaction = None
        if fields_.get("action") == "redact" or "redaction" in fields_:
            redaction = RedactionSpec.from_config(fields_.get("redaction"))
        return EffectiveRule(
            action=fields_["action"],
            reason=fields_.get("reason", "explicit tool rule"),
            source=source,
            constraints=[
                build_constraint(c, f"{where}.constraints[{i}]")
                for i, c in enumerate(fields_.get("constraints", []))
            ],
            rewrites=list(fields_.get("rewrites", [])),
            redaction=redaction,
            then_action=fields_.get("then", "allow"),
        )

    # --------------------------------------------------------------- evaluation
    def evaluate(
        self, tool: str, arguments: dict[str, Any], role: str | None = None
    ) -> Decision:
        pattern = self._matcher.match(tool)
        if pattern is None:
            return Decision(
                action=self.default_action,
                tool=tool,
                reason="no rule for this tool; default policy applied",
                rule="default",
                role=role,
            )

        effective = self._rules[pattern].for_role(role)
        return Decision(
            action=effective.action,
            tool=tool,
            reason=effective.reason,
            rule=effective.source,
            role=role,
            constraints=effective.constraints,
            rewrites=effective.rewrites,
            redaction=effective.redaction,
            then_action=effective.then_action,
        )

    def build_sequence_policy(self):
        """Construct the SequencePolicy from this policy's taint/sequence config."""
        from mcp_gateway.sequence.policy import SequencePolicy

        return SequencePolicy(
            taint_sources=self.taint_sources,
            taint_sinks=self.taint_sinks,
            sequence_rules=self.sequence_rules,
        )

    def build_risk_engine(self):
        """Construct the RiskEngine from this policy's risk config."""
        from mcp_gateway.risk.scoring import (
            DEFAULT_ELEVATED_AT,
            DEFAULT_SUSPEND_AT,
            RiskEngine,
        )

        return RiskEngine(
            weights=self.risk.get("weights"),
            elevated_at=self.risk.get("elevated_at", DEFAULT_ELEVATED_AT),
            suspend_at=self.risk.get("suspend_at", DEFAULT_SUSPEND_AT),
        )

    def is_visible(
        self, tool: str, role: str | None = None, denying: frozenset[str] | None = None
    ) -> bool:
        """Should this tool appear in a filtered tools/list?

        Hidden when its effective action can only deny — the model gains
        nothing from seeing a tool every call to which fails. `denying` is the
        set of deny-only actions for THIS gateway (a gateway with redaction
        enabled excludes 'redact'); it defaults to the global registry's set.
        Constraints don't affect visibility (they depend on arguments).
        """
        deny_set = denying if denying is not None else denying_actions()
        return self.evaluate(tool, {}, role=role).action not in deny_set

    # -------------------------------------------------------------- description
    def describe(self) -> dict[str, Any]:
        """JSON-safe summary for `policy show --effective` and the console."""
        rules = []
        for pattern, compiled in self._rules.items():
            entry: dict[str, Any] = {
                "pattern": pattern,
                "action": compiled.base.action,
                "reason": compiled.base.reason,
                "source": compiled.base.source,
            }
            if compiled.base.constraints:
                entry["constraints"] = [c.describe() for c in compiled.base.constraints]
            if compiled.base.rewrites:
                entry["rewrites"] = compiled.base.rewrites
            if compiled.base.redaction is not None:
                entry["redaction"] = compiled.base.redaction.describe()
            if compiled.base.action == "require_approval":
                entry["then"] = compiled.base.then_action
            if compiled.overlays:
                entry["roles"] = {
                    role: {"action": eff.action, "reason": eff.reason}
                    for role, eff in compiled.overlays.items()
                }
            rules.append(entry)
        return {
            "layers": self.layer_names,
            "default_action": self.default_action,
            "rules": rules,
        }
