"""Span-level accuracy gate (NER tier).

Runs everywhere for the entities the always-on tiers cover; asserts PERSON /
LOCATION recall only when Presidio is installed. Span scoring is the metric
that can tell a name from a location — count scoring cannot.
"""

from mcp_gateway.redaction import build_engine
from mcp_gateway.redaction.detectors.presidio import PresidioDetector
from mcp_gateway.redaction.eval import evaluate_spans, format_report

HAVE_PRESIDIO = PresidioDetector().available


def test_detect_spans_positions_are_correct():
    # detect_spans (which the eval relies on) must return spans whose offsets
    # actually point at the matched substring.
    engine = build_engine("standard")
    text = "email alice@example.com and ssn 123-45-6789"
    for s in engine.detect_spans(text):
        assert text[s.start:s.end] == s.text


def test_span_eval_meets_bar():
    overall, by_entity = evaluate_spans(build_engine("strict"))
    print("\n" + format_report(overall, by_entity))

    if HAVE_PRESIDIO:
        # Full corpus including names/locations must be caught with high recall.
        assert overall.recall >= 0.9
        assert by_entity["PERSON"].recall >= 0.9
        assert by_entity["LOCATION"].recall >= 0.9
    else:
        # Without the NER tier, the structured entities (EMAIL) still score;
        # names/locations are expected misses, so gate only the covered ones.
        assert by_entity.get("EMAIL", overall).recall >= 0.9
