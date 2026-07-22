"""Deterministic pseudonymization via keyed hashing.

Replaces a value with `[ENTITY:<8 hex>]` where the hex is an HMAC-SHA256 of
the value under a secret key. Because it is deterministic, the same email
appearing twice in a result becomes the same token both times — so the model
can still reason "these two records are the same customer" without ever seeing
the customer. Because it is keyed (HMAC, not a bare hash), an attacker who
sees the tokens cannot brute-force the small space of, say, US SSNs back to
values without the key.

The key must be stable for correlation to hold across a session, and secret
for the brute-force resistance to hold. Phase 2c sources it from config/KMS;
here it is injected at construction. A random per-process key (the default)
gives correlation within a run and forward secrecy across runs.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from mcp_gateway.redaction.operators.base import Operator
from mcp_gateway.redaction.spans import Span


class HashOperator(Operator):
    name = "hash"

    def __init__(self, key: bytes | None = None, length: int = 8):
        # Default: a fresh random key per process. Deterministic *within* a
        # run (correlation works), unlinkable *across* runs (no stable
        # rainbow surface). Supply a fixed key via config for cross-run
        # correlation when a deployment needs it.
        self.key = key if key is not None else os.urandom(32)
        self.length = length

    def apply(self, span: Span) -> str:
        digest = hmac.new(self.key, span.text.encode("utf-8"), hashlib.sha256)
        return f"[{span.entity}:{digest.hexdigest()[: self.length]}]"
