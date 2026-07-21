"""PII detection and redaction.

Uses Microsoft Presidio when installed (pip install presidio-analyzer
presidio-anonymizer), and falls back to a regex engine otherwise so the
gateway works with zero dependencies.

Redaction is applied recursively to any JSON value: every string inside a
tool call's arguments or a tool result's content is scanned, and detected
entities are replaced with [REDACTED:<TYPE>].

This is the response-stage control: PII is stripped BEFORE the tool result
reaches the LLM, so sensitive data never enters the model's context window.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------- regex tier

# Deliberately conservative patterns; tune for your data. Order matters:
# more specific patterns (SSN, credit card) run before generic ones (phone).
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    # No leading \b: word boundaries never match before "(", so "(415) 555-0142"
    # would slip through. A real-world lesson in PII regex formatting variants.
    ("PHONE", re.compile(r"(?<![\w.-])(?:\+?1[ .-]?)?(?:\(\d{3}\)\s?|\d{3}[ .-])\d{3}[ .-]?\d{4}\b")),
    ("IP_ADDRESS", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]

# Map our generic entity names to Presidio's entity names.
_PRESIDIO_ENTITIES = {
    "EMAIL": "EMAIL_ADDRESS",
    "PHONE": "PHONE_NUMBER",
    "SSN": "US_SSN",
    "CREDIT_CARD": "CREDIT_CARD",
    "IP_ADDRESS": "IP_ADDRESS",
    "PERSON": "PERSON",
}


@dataclass
class RedactionReport:
    """Counts of entities redacted in one pass, e.g. {"EMAIL": 2}."""

    counts: dict[str, int] = field(default_factory=dict)

    def add(self, entity: str, n: int = 1) -> None:
        self.counts[entity] = self.counts.get(entity, 0) + n

    @property
    def total(self) -> int:
        return sum(self.counts.values())


class Redactor:
    def __init__(self, entities: list[str]):
        self.entities = entities
        self._presidio = self._try_load_presidio()
        self.backend = "presidio" if self._presidio else "regex"

    # -------------------------------------------------------------- presidio
    def _try_load_presidio(self):
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_anonymizer import AnonymizerEngine

            return {
                "analyzer": AnalyzerEngine(),
                "anonymizer": AnonymizerEngine(),
            }
        except Exception:
            return None

    def _redact_text_presidio(self, text: str, report: RedactionReport) -> str:
        from presidio_anonymizer.entities import OperatorConfig

        wanted = [_PRESIDIO_ENTITIES[e] for e in self.entities if e in _PRESIDIO_ENTITIES]
        results = self._presidio["analyzer"].analyze(
            text=text, entities=wanted, language="en"
        )
        if not results:
            return text
        reverse = {v: k for k, v in _PRESIDIO_ENTITIES.items()}
        for r in results:
            report.add(reverse.get(r.entity_type, r.entity_type))
        anonymized = self._presidio["anonymizer"].anonymize(
            text=text,
            analyzer_results=results,
            operators={
                "DEFAULT": OperatorConfig(
                    "custom", {"lambda": lambda _t, e=None: "[REDACTED]"}
                )
            },
        )
        return anonymized.text

    # ----------------------------------------------------------------- regex
    def _redact_text_regex(self, text: str, report: RedactionReport) -> str:
        for entity, pattern in _PATTERNS:
            if entity not in self.entities:
                continue
            text, n = pattern.subn(f"[REDACTED:{entity}]", text)
            if n:
                report.add(entity, n)
        return text

    # ------------------------------------------------------------ public API
    def redact_text(self, text: str, report: RedactionReport) -> str:
        if self._presidio:
            return self._redact_text_presidio(text, report)
        return self._redact_text_regex(text, report)

    def redact_json(self, value, report: RedactionReport):
        """Recursively redact every string inside a JSON-like structure."""
        if isinstance(value, str):
            return self.redact_text(value, report)
        if isinstance(value, list):
            return [self.redact_json(v, report) for v in value]
        if isinstance(value, dict):
            return {k: self.redact_json(v, report) for k, v in value.items()}
        return value
