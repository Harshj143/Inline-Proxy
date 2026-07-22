"""Tokenize operator — reversible redaction backed by a vault.

Replaces a value with `[ENTITY:tok_<id>]` and stores value↔token in a vault so
an authorized operator can reverse it later (with audit). Unlike mask (lossy)
and hash (one-way), tokenize preserves recoverability for legitimate downstream
needs — a support agent detokenizing a card's last-four, a fraud review pulling
the real value under a break-glass audit — without ever exposing the value to
the model.

The operator holds a vault; which vault (in-memory vs encrypted SQLite) is a
deployment choice made when the service is constructed, not the model's concern.
"""

from __future__ import annotations

from mcp_gateway.redaction.operators.base import Operator
from mcp_gateway.redaction.spans import Span
from mcp_gateway.redaction.vault import InMemoryVault, TokenVault


class TokenizeOperator(Operator):
    name = "tokenize"

    def __init__(self, vault: TokenVault | None = None):
        # Default to a non-persistent in-memory vault so the operator is usable
        # out of the box; production wires an EncryptedSqliteVault.
        self.vault = vault or InMemoryVault()

    def apply(self, span: Span) -> str:
        return self.vault.tokenize(span.entity, span.text)
