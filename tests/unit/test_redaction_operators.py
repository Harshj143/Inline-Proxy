"""Operators: replacement shapes, partial-mask safety, hash determinism."""

from mcp_gateway.redaction.operators.drop import DropOperator
from mcp_gateway.redaction.operators.hash import HashOperator
from mcp_gateway.redaction.operators.mask import MaskOperator, PartialMaskOperator
from mcp_gateway.redaction.spans import Span


def span(entity="EMAIL", text="alice@example.com"):
    return Span(entity=entity, start=0, end=len(text), confidence=0.9,
                detector="t", text=text)


def test_mask_uses_typed_placeholder():
    assert MaskOperator().apply(span()) == "[REDACTED:EMAIL]"


def test_partial_mask_keeps_last_four():
    out = PartialMaskOperator(keep_last=4).apply(
        span("CREDIT_CARD", "4111111111111111")
    )
    assert out == "************1111"
    assert out.endswith("1111") and out.count("*") == 12


def test_partial_mask_falls_back_for_short_values():
    # Never reveal a majority of a short secret — fall back to a full mask.
    out = PartialMaskOperator(keep_last=4).apply(span("PIN", "1234"))
    assert out == "[REDACTED:PIN]"


def test_hash_is_deterministic_and_keyed():
    key = b"fixed-key-for-test"
    op1, op2 = HashOperator(key=key), HashOperator(key=key)
    s = span()
    # Same key + same value -> same token (enables correlation without exposure).
    assert op1.apply(s) == op2.apply(s)
    # Different value -> different token.
    assert op1.apply(s) != op1.apply(span(text="bob@example.com"))
    # Different key -> different token (keyed, not a bare hash).
    assert op1.apply(s) != HashOperator(key=b"other-key").apply(s)


def test_hash_format():
    out = HashOperator(key=b"k", length=8).apply(span())
    assert out.startswith("[EMAIL:") and out.endswith("]")
    assert len(out) == len("[EMAIL:") + 8 + 1


def test_drop_leaves_no_value_or_length():
    out = DropOperator().apply(span("SSN", "123-45-6789"))
    assert "123" not in out and out == "███"
