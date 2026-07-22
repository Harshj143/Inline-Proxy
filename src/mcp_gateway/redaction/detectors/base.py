"""The Detector interface and detection context.

A detector scans text and returns Spans it believes are sensitive. Detectors
are pure and stateless with respect to a call: no I/O on the hot path (the
Presidio tier, which loads models, does its loading at construction, not per
scan). Confidence is mandatory and meaningful — the engine filters and
resolves overlaps by it, so a detector must not label a weak guess 0.99.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from mcp_gateway.redaction.spans import Span


@dataclass(frozen=True, slots=True)
class DetectionContext:
    """Signals that tune detection for one scan.

    `allowlist` — literal strings that must never be treated as sensitive
    (test fixtures, the company's own public domains).
    `denylist` — literal strings that must ALWAYS be redacted even though no
    detector recognizes them (an internal codename, a VIP's name). The engine
    scans for these directly.
    `context_words` — words whose presence just before a detection raises its
    confidence, so a borderline hit near "SSN:" or "api key:" clears the
    threshold it would otherwise miss.
    """

    allowlist: frozenset[str] = field(default_factory=frozenset)
    denylist: frozenset[str] = field(default_factory=frozenset)
    context_words: frozenset[str] = field(default_factory=frozenset)
    context_boost: float = 0.3
    context_window: int = 40
    locale: str = "en"


class Detector(ABC):
    #: Unique registry name.
    name: str
    #: True if this detector needs an optional dependency that may be absent.
    optional: bool = False

    @abstractmethod
    def detect(self, text: str, ctx: DetectionContext) -> list[Span]:
        """Return sensitive spans in `text`. Never raises for ordinary input."""

    @property
    def available(self) -> bool:
        """False when an optional dependency is missing (Presidio, Phase 2c)."""
        return True
