"""Config-driven custom recognizers.

Every company has sensitive identifiers no generic detector knows: employee
ids (`EMP-48213`), internal hostnames (`db17.corp.internal`), project
codenames, account-number formats. A custom recognizer is a named entity plus
a regex plus a confidence, loaded from deployment config — the extension point
that lets the redaction subsystem cover an organization's own data without a
code change.

Each config entry auto-registers its entity name in the CUSTOM category, so a
report and audit can attribute a hit to `EMPLOYEE_ID` just like a built-in
`EMAIL`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from mcp_gateway.redaction import entities
from mcp_gateway.redaction.detectors.base import DetectionContext, Detector
from mcp_gateway.redaction.spans import Span

_ALLOWED_FIELDS = {"entity", "pattern", "confidence", "flags"}


@dataclass(frozen=True, slots=True)
class Recognizer:
    entity: str
    pattern: re.Pattern
    confidence: float


def load_recognizers(configs: list[dict[str, Any]]) -> list[Recognizer]:
    """Validate + compile recognizer configs (raises ValueError on bad config)."""
    recognizers: list[Recognizer] = []
    for i, config in enumerate(configs):
        where = f"recognizer[{i}]"
        if not isinstance(config, dict):
            raise ValueError(f"{where}: must be a mapping")
        unknown = set(config) - _ALLOWED_FIELDS
        if unknown:
            raise ValueError(f"{where}: unknown field(s) {sorted(unknown)}")

        entity = config.get("entity")
        if not isinstance(entity, str) or not entity:
            raise ValueError(f"{where}: 'entity' must be a non-empty string")
        pattern = config.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise ValueError(f"{where}: 'pattern' must be a non-empty string")

        flags_spec = config.get("flags", "")
        if not isinstance(flags_spec, str) or set(flags_spec) - {"i"}:
            raise ValueError(f"{where}: 'flags' supports only 'i'")
        flags = re.IGNORECASE if "i" in flags_spec else 0
        try:
            compiled = re.compile(pattern, flags)
        except re.error as exc:
            raise ValueError(f"{where}: invalid regex ({exc})") from None

        confidence = config.get("confidence", 0.9)
        if not isinstance(confidence, int | float) or not 0.0 <= confidence <= 1.0:
            raise ValueError(f"{where}: 'confidence' must be a number in [0,1]")

        # Register the entity so reports/audit can name it (CUSTOM category).
        if entities.get(entity) is None:
            entities.register(entity, entities.Category.CUSTOM, "Custom recognizer")
        recognizers.append(Recognizer(entity, compiled, float(confidence)))
    return recognizers


class CustomDetector(Detector):
    name = "custom"

    def __init__(self, recognizers: list[Recognizer]):
        self.recognizers = recognizers

    def detect(self, text: str, ctx: DetectionContext) -> list[Span]:
        spans: list[Span] = []
        for rec in self.recognizers:
            for m in rec.pattern.finditer(text):
                if m.group() in ctx.allowlist:
                    continue
                spans.append(Span(
                    rec.entity, m.start(), m.end(), rec.confidence, self.name, m.group()
                ))
        return spans
