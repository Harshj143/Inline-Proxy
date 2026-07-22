"""Detected spans and overlap resolution.

A Span is one detector's claim that `text[start:end]` is a sensitive entity,
with a confidence. Multiple detectors (and multiple patterns within one) can
claim overlapping regions of the same text — e.g. a credit-card pattern and a
generic high-entropy pattern both firing on the same digits. `resolve_overlaps`
picks a single, non-overlapping set so each character is redacted at most once
and by the most credible detector.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Span:
    entity: str          # our entity name, e.g. "EMAIL", "AWS_ACCESS_KEY_ID"
    start: int           # inclusive
    end: int             # exclusive
    confidence: float    # 0.0 .. 1.0
    detector: str        # which detector produced this span
    text: str = ""       # the matched substring (needed by hash/tokenize ops)

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise ValueError(f"invalid span bounds: [{self.start}, {self.end})")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence out of range: {self.confidence}")

    @property
    def length(self) -> int:
        return self.end - self.start

    def overlaps(self, other: Span) -> bool:
        return self.start < other.end and other.start < self.end


def resolve_overlaps(spans: list[Span]) -> list[Span]:
    """Return a non-overlapping subset, in document order.

    Greedy by priority: highest confidence wins; ties break to the longer
    span (more of the secret covered), then to the earlier start (stable,
    deterministic). This is the classic weighted interval selection done
    greedily — correct here because a redaction only needs *a* good covering,
    not a provably maximum-weight one, and greedy-by-confidence is what a
    reviewer expects ("the better detector won").
    """
    if len(spans) <= 1:
        return list(spans)

    ordered = sorted(spans, key=lambda s: (-s.confidence, -s.length, s.start))
    chosen: list[Span] = []
    for span in ordered:
        if not any(span.overlaps(kept) for kept in chosen):
            chosen.append(span)
    chosen.sort(key=lambda s: s.start)
    return chosen
