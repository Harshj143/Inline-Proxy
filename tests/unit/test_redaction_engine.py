"""Engine: overlap resolution, thresholds, recursion, report privacy."""

from mcp_gateway.redaction import build_engine, entities
from mcp_gateway.redaction.detectors.base import DetectionContext, Detector
from mcp_gateway.redaction.engine import RedactionEngine
from mcp_gateway.redaction.spans import Span, resolve_overlaps


# ------------------------------------------------------- overlap resolution
def test_resolve_overlaps_prefers_confidence():
    weak = Span("GENERIC_SECRET", 0, 20, 0.55, "secrets")
    strong = Span("CREDIT_CARD", 0, 16, 0.95, "regex_pii")
    (winner,) = resolve_overlaps([weak, strong])
    assert winner.entity == "CREDIT_CARD"


def test_resolve_overlaps_keeps_disjoint():
    a = Span("EMAIL", 0, 5, 0.9, "d")
    b = Span("SSN", 10, 15, 0.95, "d")
    assert len(resolve_overlaps([a, b])) == 2


def test_resolve_overlaps_tiebreaks_to_longer():
    short = Span("A", 0, 4, 0.9, "d")
    long = Span("B", 0, 8, 0.9, "d")
    (winner,) = resolve_overlaps([short, long])
    assert winner.entity == "B"


# --------------------------------------------------- engine over real text
def test_redacts_and_reports():
    engine = build_engine("standard")
    out, report = engine.redact_text("Reach alice@example.com or 123-45-6789")
    assert "alice@example.com" not in out
    assert "123-45-6789" not in out
    assert report.counts_by_entity() == {entities.EMAIL: 1, entities.SSN: 1}


def test_multiple_entities_preserve_surrounding_text():
    engine = build_engine("standard")
    out, _ = engine.redact_text("A alice@example.com B 10.0.0.5 C")
    # Right-to-left application must not corrupt the interleaved literals.
    assert out.startswith("A [REDACTED:EMAIL] B ")
    assert out.endswith(" C")


def test_min_confidence_filters_weak_hits():
    # Phone is 0.60; raise the floor above it and it survives in the clear.
    strict_floor = RedactionEngine(
        detectors=build_engine("standard").detectors, min_confidence=0.7
    )
    out, report = strict_floor.redact_text("call (415) 555-0142")
    assert "(415) 555-0142" in out
    assert report.total == 0


def test_redact_json_walks_nested_structures():
    engine = build_engine("standard")
    payload = {
        "user": {"email": "alice@example.com", "age": 30},
        "contacts": ["bob@example.com", "not-an-email"],
        "active": True,
    }
    out, report = engine.redact_json(payload)
    assert out["user"]["email"] == "[REDACTED:EMAIL]"
    assert out["user"]["age"] == 30          # non-strings untouched
    assert out["contacts"][0] == "[REDACTED:EMAIL]"
    assert out["contacts"][1] == "not-an-email"
    assert out["active"] is True
    assert report.counts_by_entity()[entities.EMAIL] == 2


def test_redact_json_does_not_mutate_input():
    engine = build_engine("standard")
    payload = {"email": "alice@example.com"}
    engine.redact_json(payload)
    assert payload["email"] == "alice@example.com"  # original intact


def test_secrets_only_profile_ignores_pii():
    engine = build_engine("secrets-only")
    out, report = engine.redact_text("alice@example.com AKIAIOSFODNN7EXAMPLE")
    assert "alice@example.com" in out                 # PII left alone
    assert "AKIAIOSFODNN7EXAMPLE" not in out           # secret removed
    assert report.counts_by_entity() == {entities.AWS_ACCESS_KEY_ID: 1}


def test_strict_profile_partial_masks_cards():
    engine = build_engine("strict")
    out, _ = engine.redact_text("card 4111111111111111 on file")
    assert out == "card ************1111 on file"


def test_report_never_stores_the_raw_value():
    # The audit trail must not become a PII sink: findings carry entity/
    # detector/operator/confidence, never the matched text.
    engine = build_engine("standard")
    _, report = engine.redact_text("ssn 123-45-6789")
    blob = str(report.summary()) + str([f.__dict__ if hasattr(f, "__dict__") else f
                                        for f in report.findings])
    assert "123-45-6789" not in blob


def test_unmapped_entity_still_masked_fail_closed():
    # An entity with no operator mapping must never be emitted in the clear.
    class TagDetector(Detector):
        name = "tagger"

        def detect(self, text, ctx):
            return [Span("MYSTERY", 0, 6, 0.9, self.name, text[:6])]

    engine = RedactionEngine(detectors=[TagDetector()], operator_by_entity={})
    out, _ = engine.redact_text("secret payload")
    assert out.startswith("[REDACTED:MYSTERY]")


def test_detector_context_allowlist_flows_through_json():
    engine = build_engine("standard")
    ctx = DetectionContext(allowlist=frozenset({"alice@example.com"}))
    out, report = engine.redact_json({"to": "alice@example.com"}, ctx)
    assert out["to"] == "alice@example.com"
    assert report.total == 0
