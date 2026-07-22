"""The redaction engine: orchestrates detection, resolution, and operators.

One pass over a string:
    1. every configured detector scans the text -> candidate spans
    2. drop spans below `min_confidence`
    3. resolve overlaps -> one non-overlapping covering (spans.resolve_overlaps)
    4. apply each span's operator, right-to-left so offsets stay valid
    5. record counts (never values) in the report

`redact_json` walks any JSON-like value and redacts every string, returning a
new structure (never mutating the input) and a merged report. Structured
targeting (redact this field, skip that one; key-name hints) is layered on in
Phase 2b (structured.py); this engine is the primitive it builds on.

Operator selection is per entity, with a default — that mapping is what a
profile configures. An entity with no mapping and no default falls back to the
mask operator: an unmapped sensitive entity must still be removed, never
emitted in the clear (fail closed).
"""

from __future__ import annotations

from dataclasses import replace

from mcp_gateway.redaction import entities
from mcp_gateway.redaction.detectors.base import DetectionContext, Detector
from mcp_gateway.redaction.operators import get_operator
from mcp_gateway.redaction.operators.base import Operator
from mcp_gateway.redaction.operators.mask import MaskOperator
from mcp_gateway.redaction.report import RedactionReport
from mcp_gateway.redaction.spans import Span, resolve_overlaps
from mcp_gateway.redaction.structured import StructuredPolicy

_FALLBACK_OPERATOR = MaskOperator()


class RedactionBudgetExceeded(Exception):
    """A payload was too large to scan within budget; the caller must fail closed."""


class RedactionEngine:
    def __init__(
        self,
        detectors: list[Detector],
        operator_by_entity: dict[str, str] | None = None,
        default_operator: str = "mask",
        min_confidence: float = 0.4,
        operators: dict[str, Operator] | None = None,
        max_bytes: int = 4 * 1024 * 1024,
    ):
        self.detectors = detectors
        self.min_confidence = min_confidence
        # `max_bytes`: a single string larger than this is refused rather than
        # scanned — scanning cost is linear in size and an unbounded payload is
        # both a DoS vector and (for the NER tier) a latency cliff. The gateway
        # catches the raised error and withholds the result (fail closed).
        self.max_bytes = max_bytes
        # Instance operator overrides (e.g. a vault-backed tokenize op) take
        # precedence over the global registry, resolved by name.
        self._operator_overrides = operators or {}
        self._default_operator: Operator = self._resolve_operator(default_operator) or (
            _FALLBACK_OPERATOR
        )
        self._operator_by_entity: dict[str, Operator] = {}
        for entity, op_name in (operator_by_entity or {}).items():
            op = self._resolve_operator(op_name)
            if op is None:
                raise ValueError(f"unknown operator {op_name!r} for entity {entity!r}")
            self._operator_by_entity[entity] = op

    def _resolve_operator(self, name: str) -> Operator | None:
        return self._operator_overrides.get(name) or get_operator(name)

    # ------------------------------------------------------------------ text
    def detect_spans(self, text: str, ctx: DetectionContext | None = None) -> list[Span]:
        """The detection half: run all tiers and return the resolved,
        non-overlapping spans (positions included). Exposed for evaluation and
        debugging; `redact_text` applies operators on top of this.
        """
        if not text:
            return []
        if len(text) > self.max_bytes:
            raise RedactionBudgetExceeded(
                f"text of {len(text)} bytes exceeds redaction budget "
                f"({self.max_bytes}); refusing to scan"
            )
        ctx = ctx or DetectionContext()

        spans: list[Span] = []
        for detector in self.detectors:
            if detector.available:
                spans.extend(detector.detect(text, ctx))

        # Context words can lift a borderline detection over the threshold
        # BEFORE filtering — that is the whole point (a bare number near "SSN:"
        # becomes credible). Applied to detector spans only.
        if ctx.context_words:
            spans = [_apply_context_boost(s, text, ctx) for s in spans]
        spans = [s for s in spans if s.confidence >= self.min_confidence]

        # Denylisted literals are always redacted (confidence 1.0), regardless
        # of what the detectors think — this is explicit deployment intent.
        spans.extend(_denylist_spans(text, ctx.denylist))

        return resolve_overlaps(spans)

    def redact_text(
        self, text: str, ctx: DetectionContext | None = None
    ) -> tuple[str, RedactionReport]:
        report = RedactionReport()
        chosen = self.detect_spans(text, ctx)
        if not chosen:
            return text, report

        # Apply right-to-left: replacing a later span never shifts the offsets
        # of an earlier one.
        out = text
        for span in sorted(chosen, key=lambda s: s.start, reverse=True):
            operator = self._operator_for(span.entity)
            out = out[: span.start] + operator.apply(span) + out[span.end :]
            report.record(span.entity, span.detector, operator.name, span.confidence)
        return out, report

    # ------------------------------------------------------------------ json
    def redact_json(
        self,
        value: object,
        ctx: DetectionContext | None = None,
        structured: StructuredPolicy | None = None,
    ) -> tuple[object, RedactionReport]:
        report = RedactionReport()
        redacted = self._walk(value, ctx or DetectionContext(), structured, report)
        return redacted, report

    def _walk(
        self,
        value: object,
        ctx: DetectionContext,
        structured: StructuredPolicy | None,
        report: RedactionReport,
    ) -> object:
        if isinstance(value, str):
            out, sub = self.redact_text(value, ctx)
            report.extend(sub)
            return out
        if isinstance(value, list):
            return [self._walk(v, ctx, structured, report) for v in value]
        if isinstance(value, dict):
            return {
                k: self._walk_field(k, v, ctx, structured, report)
                for k, v in value.items()
            }
        return value  # numbers, bools, None: nothing to scan

    def _walk_field(
        self,
        key: str,
        value: object,
        ctx: DetectionContext,
        structured: StructuredPolicy | None,
        report: RedactionReport,
    ) -> object:
        if structured is not None and isinstance(key, str):
            if structured.key_is_excluded(key):
                return value  # protected field: never touch its subtree
            if structured.key_is_sensitive(key) and isinstance(value, str) and value:
                # The key name marks this sensitive; redact the whole value
                # even if no content pattern would recognize it.
                op = self._operator_for(entities.SENSITIVE_FIELD)
                span = Span(entities.SENSITIVE_FIELD, 0, len(value), 1.0, "structured", value)
                report.record(entities.SENSITIVE_FIELD, "structured", op.name, 1.0)
                return op.apply(span)
        return self._walk(value, ctx, structured, report)

    # --------------------------------------------------------------- helpers
    def _operator_for(self, entity: str) -> Operator:
        return self._operator_by_entity.get(entity, self._default_operator)


def _apply_context_boost(span: Span, text: str, ctx: DetectionContext) -> Span:
    """Raise a span's confidence if a context word precedes it within the window."""
    window = text[max(0, span.start - ctx.context_window): span.start].lower()
    if any(word.lower() in window for word in ctx.context_words):
        boosted = min(1.0, span.confidence + ctx.context_boost)
        if boosted != span.confidence:
            return replace(span, confidence=boosted)
    return span


def _denylist_spans(text: str, denylist: frozenset[str]) -> list[Span]:
    spans: list[Span] = []
    for term in denylist:
        if not term:
            continue
        start = text.find(term)
        while start != -1:
            spans.append(
                Span(entities.CUSTOM_TERM, start, start + len(term), 1.0, "denylist", term)
            )
            start = text.find(term, start + len(term))
    return spans
