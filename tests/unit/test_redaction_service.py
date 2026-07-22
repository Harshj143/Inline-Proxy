"""RedactionService: spec-driven redaction and engine caching."""

from mcp_gateway.redaction import entities
from mcp_gateway.redaction.service import RedactionService
from mcp_gateway.redaction.spec import RedactionSpec


def test_redacts_json_per_profile():
    svc = RedactionService()
    out, report = svc.redact(
        {"email": "alice@example.com"}, RedactionSpec(profile="standard")
    )
    assert out["email"] == "[REDACTED:EMAIL]"
    assert report.counts_by_entity()[entities.EMAIL] == 1


def test_spec_exclude_keys_flow_through():
    svc = RedactionService()
    spec = RedactionSpec(profile="standard", exclude_keys=frozenset({"path"}))
    out, _ = svc.redact({"path": "alice@example.com", "x": "bob@example.com"}, spec)
    assert out["path"] == "alice@example.com"       # excluded
    assert out["x"] == "[REDACTED:EMAIL]"


def test_spec_allowlist_and_denylist():
    svc = RedactionService()
    allow = RedactionSpec(profile="standard", allowlist=frozenset({"alice@example.com"}))
    out, _ = svc.redact({"to": "alice@example.com"}, allow)
    assert out["to"] == "alice@example.com"

    deny = RedactionSpec(profile="secrets-only", denylist=frozenset({"Bluebird"}))
    out, report = svc.redact({"note": "Bluebird ships Friday"}, deny)
    assert "Bluebird" not in out["note"]
    assert report.counts_by_entity()[entities.CUSTOM_TERM] == 1


def test_engine_is_cached_per_profile():
    svc = RedactionService()
    assert svc.engine_for("standard") is svc.engine_for("standard")
    assert svc.engine_for("standard") is not svc.engine_for("strict")


def test_unknown_profile_raises():
    svc = RedactionService()
    try:
        svc.redact({}, RedactionSpec(profile="nope"))
    except ValueError as exc:
        assert "unknown redaction profile" in str(exc)
    else:
        raise AssertionError("expected ValueError for unknown profile")
