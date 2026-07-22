"""Tokenize operator + the reversible profile + service round-trip."""

from mcp_gateway.redaction import build_engine, entities
from mcp_gateway.redaction.operators.tokenize import TokenizeOperator
from mcp_gateway.redaction.service import RedactionService
from mcp_gateway.redaction.spec import RedactionSpec
from mcp_gateway.redaction.vault import InMemoryVault


def test_operator_tokenizes_and_reverses():
    vault = InMemoryVault(key=b"k" * 32)
    op = TokenizeOperator(vault)
    from mcp_gateway.redaction.spans import Span

    span = Span("EMAIL", 0, 17, 0.9, "regex_pii", "alice@example.com")
    token = op.apply(span)
    assert token.startswith("[EMAIL:tok_")
    assert vault.detokenize(token) == "alice@example.com"


def test_reversible_profile_tokenizes_pii_hashes_secrets():
    # Standalone engine uses the registry's default (in-memory) tokenize vault.
    engine = build_engine("reversible")
    out, report = engine.redact_text(
        "email alice@example.com key AKIAIOSFODNN7EXAMPLE"
    )
    assert "[EMAIL:tok_" in out                     # PII tokenized (reversible)
    assert "[AWS_ACCESS_KEY_ID:" in out             # secret hashed (one-way)
    assert "tok_" not in out.split("AWS_ACCESS_KEY_ID")[1]  # secret is not a token
    entities_seen = report.counts_by_entity()
    assert entities_seen[entities.EMAIL] == 1
    assert entities_seen[entities.AWS_ACCESS_KEY_ID] == 1


def test_service_shares_one_vault_across_engines():
    svc = RedactionService()
    out, _ = svc.redact({"email": "alice@example.com"}, RedactionSpec("reversible"))
    token = out["email"]
    assert token.startswith("[EMAIL:tok_")
    # The gateway can reverse any token it produced, through the service.
    assert svc.detokenize(token) == "alice@example.com"


def test_same_value_tokenizes_consistently_within_service():
    svc = RedactionService()
    a, _ = svc.redact({"x": "alice@example.com"}, RedactionSpec("reversible"))
    b, _ = svc.redact({"y": "alice@example.com"}, RedactionSpec("reversible"))
    assert a["x"] == b["y"]   # correlation preserved without exposing the value
