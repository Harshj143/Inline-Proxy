"""Redaction size budget: oversized payloads are refused (caller fails closed)."""

import pytest

from mcp_gateway.redaction import build_engine
from mcp_gateway.redaction.engine import RedactionBudgetExceeded
from mcp_gateway.redaction.service import RedactionService
from mcp_gateway.redaction.spec import RedactionSpec


def test_engine_refuses_oversized_text():
    engine = build_engine("standard")
    engine.max_bytes = 100
    with pytest.raises(RedactionBudgetExceeded):
        engine.redact_text("x" * 101)


def test_under_budget_is_fine():
    engine = build_engine("standard")
    engine.max_bytes = 100
    out, _ = engine.redact_text("email alice@example.com")
    assert "[REDACTED:EMAIL]" in out


def test_service_propagates_budget_error_for_gateway_to_fail_closed():
    # The gateway catches this and withholds the result (never releases it
    # unscanned) — proven end-to-end elsewhere; here we assert it propagates.
    svc = RedactionService()
    engine = svc.engine_for("standard")
    engine.max_bytes = 10
    with pytest.raises(RedactionBudgetExceeded):
        svc.redact({"big": "x" * 50}, RedactionSpec("standard"))
