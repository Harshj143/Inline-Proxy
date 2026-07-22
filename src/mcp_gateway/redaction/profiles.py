"""Named redaction profiles.

A profile bundles detectors + per-entity operators + a confidence threshold
into a name a policy rule can reference (`redaction: strict`) instead of
spelling out the machinery inline. Three built-ins span the common needs:

    secrets-only  credentials only (API keys, tokens, private keys). Cheapest;
                  the right default for surfaces where PII is expected but
                  leaked secrets are the real risk (CI logs, code).
    standard      secrets + validated PII, masked. The general default.
    strict        standard + higher recall. Cards partial-masked (keep last 4);
                  when the Presidio tier is installed (Phase 2c) it joins here
                  for names/locations. Degrades gracefully without it.

Profiles are data, not code — Phase 2c lets a deployment define its own in
redaction.yaml. `build_engine` is the single constructor everything uses.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mcp_gateway.redaction.detectors import get_detector_type
from mcp_gateway.redaction.detectors.base import Detector
from mcp_gateway.redaction.engine import RedactionEngine
from mcp_gateway.redaction.operators.base import Operator


@dataclass(frozen=True, slots=True)
class Profile:
    name: str
    detectors: tuple[str, ...]
    default_operator: str = "mask"
    operator_by_entity: dict[str, str] = field(default_factory=dict)
    min_confidence: float = 0.4


_PROFILES: dict[str, Profile] = {
    "secrets-only": Profile(
        name="secrets-only",
        detectors=("secrets",),
        # Secrets are noisier via the entropy heuristic; lift the floor so only
        # high-confidence provider tokens and validated shapes redact here.
        min_confidence=0.6,
    ),
    "standard": Profile(
        name="standard",
        detectors=("regex_pii", "secrets"),
        min_confidence=0.6,  # keeps validated PII, drops the noisiest phone-only hits
    ),
    "strict": Profile(
        name="strict",
        detectors=("regex_pii", "secrets"),  # + "presidio" auto-appended if available
        operator_by_entity={"CREDIT_CARD": "partial_mask"},
        min_confidence=0.4,  # lower floor = higher recall, more false positives
    ),
    "reversible": Profile(
        name="reversible",
        detectors=("regex_pii", "secrets"),
        # PII is tokenized (recoverable by an authorized operator via the
        # vault); secrets are still one-way hashed — a leaked credential must
        # be rotated, never restored.
        default_operator="hash",
        operator_by_entity={
            "EMAIL": "tokenize", "PHONE": "tokenize", "SSN": "tokenize",
            "CREDIT_CARD": "tokenize", "IP_ADDRESS": "tokenize",
        },
        min_confidence=0.6,
    ),
}


def list_profiles() -> frozenset[str]:
    return frozenset(_PROFILES)


def get_profile(name: str) -> Profile | None:
    return _PROFILES.get(name)


def build_engine(
    profile: str,
    operators: dict[str, Operator] | None = None,
    extra_detectors: list[Detector] | None = None,
) -> RedactionEngine:
    """Build the engine for a profile.

    `operators` overrides operator instances by name (the service injects a
    vault-backed tokenize operator this way). `extra_detectors` appends custom
    company recognizers after the profile's built-in tiers.
    """
    spec = _PROFILES.get(profile)
    if spec is None:
        raise ValueError(
            f"unknown redaction profile {profile!r}; available: {sorted(_PROFILES)}"
        )
    detectors: list[Detector] = []
    for det_name in spec.detectors:
        det_cls = get_detector_type(det_name)
        if det_cls is not None:
            detectors.append(det_cls())

    # The strict profile opportunistically uses Presidio when installed
    # (Phase 2c-ii registers it); absence is not an error, just lower recall.
    if profile == "strict":
        presidio_cls = get_detector_type("presidio")
        if presidio_cls is not None:
            instance = presidio_cls()
            if instance.available:
                detectors.append(instance)

    detectors.extend(extra_detectors or [])

    return RedactionEngine(
        detectors=detectors,
        operator_by_entity=spec.operator_by_entity,
        default_operator=spec.default_operator,
        min_confidence=spec.min_confidence,
        operators=operators,
    )
