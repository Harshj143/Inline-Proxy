"""Context-word confidence boosting."""

from mcp_gateway.redaction import build_engine
from mcp_gateway.redaction.detectors.base import DetectionContext


def test_context_word_promotes_borderline_hit():
    # A 32-char, entropy-4.0 token scores GENERIC_SECRET at 0.55; the standard
    # profile's floor is 0.6, so alone it is NOT redacted...
    token = "0123456789abcdef0123456789abcdef"
    engine = build_engine("standard")
    out, _ = engine.redact_text(f"value {token} end")
    assert token in out  # below threshold, survives

    # ...but with "key" as a context word just before it, the boost clears the
    # threshold and it is redacted.
    ctx = DetectionContext(context_words=frozenset({"key"}))
    out2, report = engine.redact_text(f"api key {token} end", ctx)
    assert token not in out2
    assert report.total == 1


def test_context_word_only_applies_within_window():
    token = "0123456789abcdef0123456789abcdef"
    engine = build_engine("standard")
    # The context word is far away (beyond the default 40-char window).
    far = "key " + ("x" * 60) + f" {token}"
    ctx = DetectionContext(context_words=frozenset({"key"}))
    out, _ = engine.redact_text(far, ctx)
    assert token in out  # too far to boost


def test_no_context_words_is_a_noop():
    engine = build_engine("standard")
    out, _ = engine.redact_text("email alice@example.com", DetectionContext())
    assert out == "email [REDACTED:EMAIL]"
