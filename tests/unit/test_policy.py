"""Policy engine v2: loading, validation, merging, matching, role overlays."""

import pytest

from mcp_gateway.core.errors import PolicyError
from mcp_gateway.policy.engine import PolicyEngine
from mcp_gateway.policy.loader import load_policy_file, parse_document


def engine(*docs):
    return PolicyEngine.from_documents(
        [(doc, f"layer{i}") for i, doc in enumerate(docs)]
    )


def doc(tools=None, default_action="block", **extra):
    return {"schema_version": 1, "default_action": default_action,
            "tools": tools or {}, **extra}


# ------------------------------------------------------------------- loading
def test_schema_version_is_required():
    with pytest.raises(PolicyError, match="schema_version"):
        parse_document({"default_action": "block"}, source="test")


def test_wrong_schema_version_rejected():
    with pytest.raises(PolicyError, match="unsupported schema_version"):
        parse_document({"schema_version": 2}, source="test")


def test_unknown_top_level_field_rejected():
    with pytest.raises(PolicyError, match="unknown top-level"):
        parse_document({"schema_version": 1, "not_a_real_field": []}, source="test")


def test_invalid_action_is_load_time_error():
    with pytest.raises(PolicyError, match="invalid action"):
        engine(doc({"t": {"action": "alow"}}))  # typo must not reach runtime


def test_unknown_rule_field_is_load_time_error():
    with pytest.raises(PolicyError, match="unknown field"):
        engine(doc({"t": {"action": "allow", "consraints": []}}))


def test_invalid_constraint_regex_is_load_time_error():
    with pytest.raises(PolicyError, match="invalid regex"):
        engine(doc({"t": {"action": "allow",
                          "constraints": [{"arg": "q", "must_match": "("}]}}))


def test_rewrite_needs_exactly_one_operation():
    with pytest.raises(PolicyError, match="exactly one"):
        engine(doc({"t": {"action": "rewrite",
                          "rewrites": [{"arg": "sql", "set": 1, "append": "x"}]}}))


def test_yaml_and_json_files_load(tmp_path):
    yaml_file = tmp_path / "p.yaml"
    yaml_file.write_text(
        "schema_version: 1\ndefault_action: allow\ntools:\n  a.b: {action: block}\n"
    )
    layer = load_policy_file(yaml_file)
    assert layer.default_action == "allow"
    assert layer.rules["a.b"]["action"] == "block"
    assert layer.name == "p"  # falls back to file stem

    json_file = tmp_path / "p.json"
    json_file.write_text('{"schema_version": 1, "tools": {"a.b": {"action": "allow"}}}')
    assert load_policy_file(json_file).rules["a.b"]["action"] == "allow"


# ------------------------------------------------------------------ matching
def test_exact_beats_glob():
    eng = engine(doc({
        "github.*": {"action": "block"},
        "github.get_issue": {"action": "allow"},
    }))
    assert eng.evaluate("github.get_issue", {}).action == "allow"
    assert eng.evaluate("github.push_files", {}).action == "block"


def test_more_specific_glob_beats_less_specific():
    eng = engine(doc({
        "github.*": {"action": "block"},
        "github.repos.*": {"action": "allow"},
    }))
    assert eng.evaluate("github.repos.get", {}).action == "allow"
    assert eng.evaluate("github.issues.get", {}).action == "block"


def test_no_match_gets_default_action():
    eng = engine(doc({}, default_action="block"))
    decision = eng.evaluate("anything", {})
    assert decision.action == "block" and decision.rule == "default"


# ------------------------------------------------------------------- merging
def test_later_layer_overrides_field_level():
    base = doc({"db.query": {
        "action": "allow",
        "constraints": [{"arg": "sql", "must_match": "^SELECT"}],
    }})
    override = {"schema_version": 1,
                "tools": {"db.query": {"action": "block"}}}
    eng = engine(base, override)
    decision = eng.evaluate("db.query", {})
    # Override changed the action but the base constraints SURVIVE —
    # dropping them silently would be fail-open.
    assert decision.action == "block"
    assert len(decision.constraints) == 1


def test_replace_discards_lower_layer_fields():
    base = doc({"db.query": {
        "action": "allow",
        "constraints": [{"arg": "sql", "must_match": "^SELECT"}],
    }})
    override = {"schema_version": 1, "tools": {
        "db.query": {"action": "allow", "replace": True},
    }}
    decision = engine(base, override).evaluate("db.query", {})
    assert decision.action == "allow"
    assert decision.constraints == []


def test_default_action_last_layer_wins():
    eng = engine(doc({}, default_action="block"),
                 {"schema_version": 1, "default_action": "allow"})
    assert eng.evaluate("x", {}).action == "allow"


def test_override_only_layer_needs_base_action():
    # A lone override with no action anywhere must fail at load, not runtime.
    with pytest.raises(PolicyError, match="no 'action' after merging"):
        engine({"schema_version": 1, "tools": {"t": {"reason": "tighten later"}}})


def test_roles_merge_per_role():
    base = doc({"t": {"action": "block",
                      "roles": {"admin": {"action": "allow"},
                                "analyst": {"action": "block"}}}})
    override = {"schema_version": 1, "tools": {
        "t": {"roles": {"analyst": {"action": "allow"}}},
    }}
    eng = engine(base, override)
    assert eng.evaluate("t", {}, role="admin").action == "allow"      # survives
    assert eng.evaluate("t", {}, role="analyst").action == "allow"   # replaced
    assert eng.evaluate("t", {}).action == "block"                   # base intact


# ------------------------------------------------------------- role overlays
def test_role_overlay_replaces_only_named_fields():
    eng = engine(doc({"crm.get": {
        "action": "redact",
        "reason": "base reason",
        "roles": {"admin": {"action": "allow"}},
    }}))
    base = eng.evaluate("crm.get", {})
    assert base.action == "redact" and base.reason == "base reason"

    admin = eng.evaluate("crm.get", {}, role="admin")
    assert admin.action == "allow"
    assert admin.rule.endswith("+role:admin")

    stranger = eng.evaluate("crm.get", {}, role="intern")
    assert stranger.action == "redact"  # unknown role gets the base rule


def test_overlay_inherits_base_constraints():
    eng = engine(doc({"db.query": {
        "action": "block",
        "constraints": [{"arg": "sql", "must_match": "^SELECT"}],
        "roles": {"analyst": {"action": "allow"}},
    }}))
    analyst = eng.evaluate("db.query", {}, role="analyst")
    assert analyst.action == "allow"
    assert len(analyst.constraints) == 1  # constraints follow into the overlay


# ---------------------------------------------------------------- visibility
def test_visibility_tracks_denying_actions():
    eng = engine(doc({
        "a": {"action": "allow"},
        "b": {"action": "block"},
        "r": {"action": "redact"},          # terminal deny until Phase 2
        "q": {"action": "quarantine"},
        "vip": {"action": "block", "roles": {"admin": {"action": "allow"}}},
    }))
    assert eng.is_visible("a") and eng.is_visible("q")
    assert not eng.is_visible("b")
    assert not eng.is_visible("r")
    assert not eng.is_visible("unknown.tool")     # default block
    assert not eng.is_visible("vip")
    assert eng.is_visible("vip", role="admin")    # per-role visibility


# ---------------------------------------------------------------- redaction
def test_redaction_field_compiles_to_spec():
    eng = engine(doc({"crm.get": {"action": "redact", "redaction": "strict"}}))
    decision = eng.evaluate("crm.get", {})
    assert decision.action == "redact"
    assert decision.redaction is not None
    assert decision.redaction.profile == "strict"


def test_redaction_defaults_to_standard_for_redact_action():
    eng = engine(doc({"crm.get": {"action": "redact"}}))
    assert eng.evaluate("crm.get", {}).redaction.profile == "standard"


def test_redaction_object_form_with_targeting():
    eng = engine(doc({"crm.get": {
        "action": "redact",
        "redaction": {"profile": "standard", "exclude_keys": ["id"],
                      "denylist": ["Bluebird"]},
    }}))
    spec = eng.evaluate("crm.get", {}).redaction
    assert spec.exclude_keys == frozenset({"id"})
    assert spec.denylist == frozenset({"Bluebird"})


def test_unknown_profile_rejected_at_load():
    with pytest.raises(PolicyError, match="unknown redaction profile"):
        engine(doc({"crm.get": {"action": "redact", "redaction": "ultra"}}))


def test_role_overlay_can_change_redaction_profile():
    eng = engine(doc({"crm.get": {
        "action": "redact", "redaction": "secrets-only",
        "roles": {"analyst": {"redaction": "strict"}},
    }}))
    assert eng.evaluate("crm.get", {}).redaction.profile == "secrets-only"
    assert eng.evaluate("crm.get", {}, role="analyst").redaction.profile == "strict"


# --------------------------------------------------------------- description
def test_describe_summarizes_rules():
    eng = engine(doc({"db.query": {
        "action": "rewrite",
        "rewrites": [{"arg": "sql", "append": " LIMIT 10"}],
        "constraints": [{"arg": "sql", "must_match": "^SELECT"}],
        "roles": {"admin": {"action": "allow"}},
    }}))
    description = eng.describe()
    (rule,) = description["rules"]
    assert rule["pattern"] == "db.query"
    assert rule["roles"]["admin"]["action"] == "allow"
    assert len(rule["constraints"]) == 1
