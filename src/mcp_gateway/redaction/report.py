"""Redaction report — what happened, in COUNTS not values.

Critical privacy rule: the report never stores the matched text. The report
feeds the audit trail, and an audit record that echoed the PII it redacted
would turn the security log into the very leak it exists to prevent. So a
finding records the entity, the detector that found it, the operator applied,
and the confidence — never the value.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Finding:
    entity: str
    detector: str
    operator: str
    confidence: float


@dataclass(slots=True)
class RedactionReport:
    findings: list[Finding] = field(default_factory=list)

    def record(self, entity: str, detector: str, operator: str, confidence: float) -> None:
        self.findings.append(Finding(entity, detector, operator, confidence))

    def extend(self, other: RedactionReport) -> None:
        self.findings.extend(other.findings)

    @property
    def total(self) -> int:
        return len(self.findings)

    def counts_by_entity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.entity] = out.get(f.entity, 0) + 1
        return out

    def counts_by_detector(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.detector] = out.get(f.detector, 0) + 1
        return out

    def summary(self) -> dict[str, object]:
        """JSON-safe summary for audit events."""
        return {
            "total": self.total,
            "by_entity": self.counts_by_entity(),
            "by_detector": self.counts_by_detector(),
        }
