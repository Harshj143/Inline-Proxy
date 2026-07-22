"""Masking operators.

MaskOperator replaces the whole value with a typed placeholder,
`[REDACTED:ENTITY]` — the model learns an entity was there and of what kind,
but not its value. This is the safe default.

PartialMaskOperator keeps the last few characters, e.g. a card as
`************1111` — enough for a human or the model to disambiguate "which
card" in a support flow without exposing the number. Never keeps enough to
reconstruct the secret.
"""

from __future__ import annotations

from mcp_gateway.redaction.operators.base import Operator
from mcp_gateway.redaction.spans import Span


class MaskOperator(Operator):
    name = "mask"

    def apply(self, span: Span) -> str:
        return f"[REDACTED:{span.entity}]"


class PartialMaskOperator(Operator):
    name = "partial_mask"

    def __init__(self, keep_last: int = 4, mask_char: str = "*"):
        self.keep_last = keep_last
        self.mask_char = mask_char

    def apply(self, span: Span) -> str:
        value = span.text
        # If we don't clearly have more characters than we'd reveal, fall back
        # to a full typed mask — never expose a majority of a short secret.
        if len(value) <= self.keep_last * 2:
            return f"[REDACTED:{span.entity}]"
        return self.mask_char * (len(value) - self.keep_last) + value[-self.keep_last :]
