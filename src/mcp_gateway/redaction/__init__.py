"""Redaction subsystem: detect and remove PII and secrets from text and JSON.

This is a dedicated subsystem, not a helper module — the prototype's 125-line
regex `redact.py` is deliberately replaced by a tiered detector architecture
(docs/PLAN.md Phase 2). The pieces:

    spans.py       Span type + overlap resolution
    entities.py    the entity registry (names, categories, defaults)
    detectors/     tiers that FIND sensitive spans (regex+validators, secrets,
                   later Presidio/custom)
    operators/     what to DO with a found span (mask, hash, drop, later
                   tokenize)
    engine.py      orchestrator: text -> detect -> resolve -> operate -> report
    profiles.py    named bundles (secrets-only / standard / strict) a policy
                   rule references by name
    report.py      per-pass findings, COUNTS ONLY (never the matched values —
                   the audit trail must not itself become a PII sink)

Phase 2a (this module set) is the standalone engine. Phase 2b wires it into
the gateway's redact action and response path; Phase 2c adds the Presidio
tier, the tokenization vault, and the precision/recall eval corpus.
"""

from mcp_gateway.redaction.engine import RedactionEngine
from mcp_gateway.redaction.profiles import build_engine, list_profiles
from mcp_gateway.redaction.report import RedactionReport

__all__ = ["RedactionEngine", "RedactionReport", "build_engine", "list_profiles"]
