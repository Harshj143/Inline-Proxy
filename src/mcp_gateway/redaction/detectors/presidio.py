"""Presidio NER tier — higher recall for UNSTRUCTURED PII (names, locations).

This is the one detector the regex tier fundamentally cannot replace: person
names and locations have no syntactic shape to match. It runs Microsoft
Presidio (spaCy NER underneath) and is strictly optional — the `[presidio]`
extra plus a spaCy model. When either is absent the detector reports itself
unavailable and the engine simply runs without it (lower recall, not an
error). That graceful-degradation contract is why the core install stays
dependency-free (docs/SYSTEM_DESIGN.md §3, §11).

Design choices that matter:
  * Presidio types never leak out — results are mapped to OUR entity names, so
    policies and audit only ever speak "PERSON", never Presidio's internals.
  * We ask Presidio ONLY for entities the regex tier misses (PERSON/LOCATION/
    NRP). Emails, SSNs, cards are already handled with validators; running NER
    for them would be slower and less precise.
  * The analyzer is loaded once, lazily, and cached process-wide — construction
    stays cheap so building an engine never pays the ~1s spaCy load unless the
    tier is actually used.
  * spaCy pipelines are not thread-safe; a lock serializes analyze() calls (the
    gateway runs redaction in a worker thread, so this guards concurrency).
  * Large text is chunked at whitespace so NER cost stays bounded per call and
    a single huge blob can't stall the pipeline.
"""

from __future__ import annotations

import threading

from mcp_gateway.redaction import entities
from mcp_gateway.redaction.detectors.base import DetectionContext, Detector
from mcp_gateway.redaction.spans import Span

# Presidio entity type -> our entity name. Only NER entities; the regex tier
# owns the structured ones.
_ENTITY_MAP = {
    "PERSON": entities.PERSON,
    "LOCATION": entities.LOCATION,
    "NRP": entities.NRP,
}
_WANTED = list(_ENTITY_MAP)

# Preferred spaCy models, best first; the small model is the low-footprint
# fallback that still exercises the full path.
_MODELS = ("en_core_web_lg", "en_core_web_sm")
_CHUNK_BYTES = 100_000

_analyzer_lock = threading.Lock()
_analyzer_loaded = False
_analyzer = None  # the AnalyzerEngine, or None if unavailable


def _load_analyzer():
    """Build the Presidio analyzer once; cache the result (or the failure)."""
    global _analyzer_loaded, _analyzer
    if _analyzer_loaded:
        return _analyzer
    _analyzer_loaded = True
    try:
        import spacy
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        model = next((m for m in _MODELS if spacy.util.is_package(m)), None)
        if model is None:
            _analyzer = None
            return None
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": model}],
        })
        _analyzer = AnalyzerEngine(
            nlp_engine=provider.create_engine(), supported_languages=["en"]
        )
    except Exception:  # noqa: BLE001 — any failure = tier unavailable, never fatal
        _analyzer = None
    return _analyzer


def reset_analyzer_cache() -> None:
    """Test hook: forget the cached analyzer so availability can be re-evaluated."""
    global _analyzer_loaded, _analyzer
    with _analyzer_lock:
        _analyzer_loaded = False
        _analyzer = None


class PresidioDetector(Detector):
    name = "presidio"
    optional = True

    @property
    def available(self) -> bool:
        with _analyzer_lock:
            return _load_analyzer() is not None

    def detect(self, text: str, ctx: DetectionContext) -> list[Span]:
        with _analyzer_lock:
            analyzer = _load_analyzer()
            if analyzer is None:
                return []
            spans: list[Span] = []
            for offset, chunk in _chunks(text):
                for r in analyzer.analyze(text=chunk, entities=_WANTED, language="en"):
                    entity = _ENTITY_MAP.get(r.entity_type)
                    if entity is None:
                        continue
                    matched = chunk[r.start:r.end]
                    if matched in ctx.allowlist:
                        continue
                    spans.append(Span(
                        entity, offset + r.start, offset + r.end,
                        float(r.score), self.name, matched,
                    ))
            return spans


def _chunks(text: str):
    """Yield (offset, chunk) splitting large text at whitespace boundaries."""
    if len(text) <= _CHUNK_BYTES:
        yield 0, text
        return
    start = 0
    n = len(text)
    while start < n:
        end = min(start + _CHUNK_BYTES, n)
        if end < n:
            # Back up to the last whitespace so a name isn't split mid-token.
            ws = text.rfind(" ", start, end)
            if ws > start:
                end = ws
        yield start, text[start:end]
        start = end
