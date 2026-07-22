"""Operator registry.

An operator decides what a detected span becomes in the output. Profiles and
policy pick an operator per entity (mask an email, but partial-mask a card so
the last four survive for support workflows). Phase 2a ships mask, partial
mask, hash, and drop; the reversible `tokenize` operator (needs a vault) lands
in Phase 2c and registers here the same way.
"""

from __future__ import annotations

from mcp_gateway.redaction.operators.base import Operator
from mcp_gateway.redaction.operators.drop import DropOperator
from mcp_gateway.redaction.operators.hash import HashOperator
from mcp_gateway.redaction.operators.mask import MaskOperator, PartialMaskOperator
from mcp_gateway.redaction.operators.tokenize import TokenizeOperator

# The default tokenize operator uses a non-persistent in-memory vault; the
# gateway's RedactionService injects a shared (optionally encrypted) vault.
_OPERATORS: dict[str, Operator] = {
    op.name: op
    for op in (
        MaskOperator(), PartialMaskOperator(), HashOperator(),
        DropOperator(), TokenizeOperator(),
    )
}


def get_operator(name: str) -> Operator | None:
    return _OPERATORS.get(name)


def register_operator(op: Operator) -> None:
    _OPERATORS[op.name] = op


def available_operators() -> frozenset[str]:
    return frozenset(_OPERATORS)


__all__ = [
    "DropOperator",
    "HashOperator",
    "MaskOperator",
    "Operator",
    "PartialMaskOperator",
    "TokenizeOperator",
    "available_operators",
    "get_operator",
    "register_operator",
]
