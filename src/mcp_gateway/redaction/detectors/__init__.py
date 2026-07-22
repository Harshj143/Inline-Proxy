"""Detector registry.

Detectors are looked up by name so profiles and (later) config can compose
them. Phase 2a ships the always-available, zero-dependency tiers; Phase 2c
adds the optional Presidio detector and config-driven custom recognizers,
which register here the same way.
"""

from __future__ import annotations

from mcp_gateway.redaction.detectors.base import DetectionContext, Detector
from mcp_gateway.redaction.detectors.presidio import PresidioDetector
from mcp_gateway.redaction.detectors.regex_pii import RegexPiiDetector
from mcp_gateway.redaction.detectors.secrets import SecretsDetector

# PresidioDetector is registered unconditionally; its `available` property
# reports False (and profiles skip it) when the optional dependency or model
# is absent. Construction is cheap — the spaCy load is lazy and cached.
_DETECTORS: dict[str, type[Detector]] = {
    RegexPiiDetector.name: RegexPiiDetector,
    SecretsDetector.name: SecretsDetector,
    PresidioDetector.name: PresidioDetector,
}


def register_detector(cls: type[Detector]) -> None:
    _DETECTORS[cls.name] = cls


def get_detector_type(name: str) -> type[Detector] | None:
    return _DETECTORS.get(name)


def available_detectors() -> frozenset[str]:
    return frozenset(_DETECTORS)


__all__ = [
    "DetectionContext",
    "Detector",
    "PresidioDetector",
    "RegexPiiDetector",
    "SecretsDetector",
    "available_detectors",
    "get_detector_type",
    "register_detector",
]
