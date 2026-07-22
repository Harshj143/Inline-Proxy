"""Structured (key-aware) redaction and denylist literals."""

from mcp_gateway.redaction import build_engine, entities
from mcp_gateway.redaction.detectors.base import DetectionContext
from mcp_gateway.redaction.structured import StructuredPolicy


# ------------------------------------------------------- key classification
def test_sensitive_key_tokenization():
    p = StructuredPolicy()
    assert p.key_is_sensitive("password")
    assert p.key_is_sensitive("aws_secret_access_key")   # token "secret"
    assert p.key_is_sensitive("apiKey")                  # joined "apikey"
    assert p.key_is_sensitive("clientSecret")


def test_ambiguous_keys_are_not_sensitive():
    # These are why token matching beats substring matching.
    p = StructuredPolicy()
    assert not p.key_is_sensitive("token_count")     # LLM field, not a credential
    assert not p.key_is_sensitive("authorized_users")  # contains "auth", not a token
    assert not p.key_is_sensitive("public_key")      # a key, but not secret
    assert not p.key_is_sensitive("file_path")


def test_excluded_key():
    p = StructuredPolicy(exclude_keys=frozenset({"file_path"}))
    assert p.key_is_excluded("file_path")
    assert p.key_is_excluded("FILE_PATH")   # case-insensitive
    assert not p.key_is_excluded("note")


# ----------------------------------------------------- engine integration
def test_password_field_redacted_by_key_name():
    # "hunter2" matches no content pattern; only the KEY name reveals it.
    engine = build_engine("standard")
    out, report = engine.redact_json({"password": "hunter2", "id": "42"},
                                     structured=StructuredPolicy())
    assert out["password"] == "[REDACTED:SENSITIVE_FIELD]"
    assert out["id"] == "42"
    assert report.counts_by_entity()[entities.SENSITIVE_FIELD] == 1


def test_excluded_key_protects_subtree():
    engine = build_engine("standard")
    # file_path would otherwise be scanned; excluding it leaves it untouched
    # even though it contains an email-shaped substring.
    payload = {"file_path": "/home/alice@example.com/x", "note": "ping bob@example.com"}
    out, _ = engine.redact_json(
        payload, structured=StructuredPolicy(exclude_keys=frozenset({"file_path"}))
    )
    assert out["file_path"] == "/home/alice@example.com/x"   # protected
    assert out["note"] == "ping [REDACTED:EMAIL]"            # still scanned


def test_exclude_wins_over_sensitive_name():
    engine = build_engine("standard")
    # A key that is both sensitive-named and excluded: exclusion wins.
    out, _ = engine.redact_json(
        {"secret": "keep-me"},
        structured=StructuredPolicy(exclude_keys=frozenset({"secret"})),
    )
    assert out["secret"] == "keep-me"


# ---------------------------------------------------------------- denylist
def test_denylist_literal_always_redacted():
    engine = build_engine("standard")
    ctx = DetectionContext(denylist=frozenset({"Project-Bluebird"}))
    out, report = engine.redact_text("Launch of Project-Bluebird is confidential", ctx)
    assert "Project-Bluebird" not in out
    assert report.counts_by_entity()[entities.CUSTOM_TERM] == 1


def test_denylist_and_detectors_combine():
    engine = build_engine("standard")
    ctx = DetectionContext(denylist=frozenset({"Bluebird"}))
    out, report = engine.redact_text("Bluebird owner alice@example.com", ctx)
    assert "Bluebird" not in out and "alice@example.com" not in out
    assert report.total == 2
