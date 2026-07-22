"""Presidio NER tier: graceful degradation (always) + real detection (if present).

The absent-path tests run everywhere — they are the contract that the core
install works without the [presidio] extra. The present-path tests skip unless
Presidio and a spaCy model are actually installed.
"""

import pytest

from mcp_gateway.redaction import build_engine, entities
from mcp_gateway.redaction.detectors import presidio as presidio_mod
from mcp_gateway.redaction.detectors.base import DetectionContext
from mcp_gateway.redaction.detectors.presidio import PresidioDetector

HAVE_PRESIDIO = PresidioDetector().available


# ------------------------------------------------------ graceful degradation
def test_unavailable_detector_returns_no_spans(monkeypatch):
    # Simulate the extra/model being absent: the detector must report itself
    # unavailable and produce nothing, never raise.
    monkeypatch.setattr(presidio_mod, "_analyzer_loaded", True)
    monkeypatch.setattr(presidio_mod, "_analyzer", None)
    det = PresidioDetector()
    assert det.available is False
    assert det.detect("Ada Verne lives in Portland", DetectionContext()) == []


def test_engine_runs_without_presidio(monkeypatch):
    # An engine whose Presidio tier is unavailable still redacts everything the
    # regex/secrets tiers cover — lower recall on names, not a failure.
    monkeypatch.setattr(presidio_mod, "_analyzer_loaded", True)
    monkeypatch.setattr(presidio_mod, "_analyzer", None)
    engine = build_engine("strict")
    out, report = engine.redact_text("Ada Verne, ada.verne@example.com")
    assert "ada.verne@example.com" not in out          # regex tier still works
    assert entities.EMAIL in report.counts_by_entity()


def test_presidio_is_optional_metadata():
    assert PresidioDetector.optional is True


# --------------------------------------------------------- real detection
@pytest.mark.skipif(not HAVE_PRESIDIO, reason="presidio + spaCy model not installed")
def test_detects_person_and_location():
    det = PresidioDetector()
    spans = det.detect("Please email Ada Verne in Portland today", DetectionContext())
    found = {s.entity for s in spans}
    assert entities.PERSON in found
    assert entities.LOCATION in found
    # Presidio types never leak: we only ever see OUR entity names.
    assert all(s.entity in entities.all_names() for s in spans)


@pytest.mark.skipif(not HAVE_PRESIDIO, reason="presidio + spaCy model not installed")
def test_strict_profile_redacts_names():
    out, report = build_engine("strict").redact_text(
        "Contact Ada Verne in Portland"
    )
    assert "Ada Verne" not in out
    assert "Portland" not in out
    assert report.counts_by_entity().get(entities.PERSON) == 1


@pytest.mark.skipif(not HAVE_PRESIDIO, reason="presidio + spaCy model not installed")
def test_allowlist_suppresses_a_name():
    det = PresidioDetector()
    ctx = DetectionContext(allowlist=frozenset({"Ada Verne"}))
    spans = det.detect("Ada Verne in Portland", ctx)
    assert all(s.text != "Ada Verne" for s in spans)


@pytest.mark.skipif(not HAVE_PRESIDIO, reason="presidio + spaCy model not installed")
def test_chunking_preserves_offsets():
    # Force chunking with a tiny threshold and assert spans still point at the
    # right text after offset adjustment.
    from mcp_gateway.redaction.detectors import presidio as mod

    original = mod._CHUNK_BYTES
    mod._CHUNK_BYTES = 30
    try:
        text = "Alice met Bob in Paris. " * 4
        for s in PresidioDetector().detect(text, DetectionContext()):
            assert text[s.start:s.end] == s.text
    finally:
        mod._CHUNK_BYTES = original
