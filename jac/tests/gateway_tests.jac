"""Golden decisions for the Jac-native enforcement engine."""

import from gateway.policy { Policy, load_policy }
import from gateway.redaction { redact_text }
import from gateway.pipeline { get_session, police_request, handle_response }

test "allows a public documentation search" {
    policy = load_policy("policies/mock-crm.yaml");
    session = get_session("test-allow-search", []);
    call = police_request(session, policy, "search.docs", {"query": "Jac OSP"}, [], 1);
    assert call.decision.action == "allow";
    assert call.trace == [
        "session_gate",
        "policy",
        "constraints",
        "sequence",
        "action"
    ];
}

test "unknown tools fail closed" {
    policy = load_policy("policies/mock-crm.yaml");
    session = get_session("test-default-deny", []);
    call = police_request(session, policy, "unknown.destroy", {}, [], 1);
    assert call.decision.action == "block";
    assert call.trace == ["session_gate", "policy"];
}

test "unsupported policy actions fail closed" {
    policy = Policy(name="invalid", default_action="dance");
    session = get_session("test-invalid-action", []);
    call = police_request(session, policy, "unknown.action", {}, [], 1);
    assert call.decision.action == "block";
    assert call.decision.rule == "policy.invalid_action";
    assert call.trace == ["session_gate", "policy"];
}

test "tainted sessions cannot reach an outbound sink" {
    policy = load_policy("policies/mock-crm.yaml");
    session = get_session("test-taint", []);
    source = police_request(
        session, policy, "web.fetch", {"url": "https://evil"}, [], 1
    );
    assert source.decision.action == "allow";
    assert session.tainted;
    sink = police_request(session, policy, "http.post", {"url": "https://evil"}, [], 2);
    assert sink.decision.action == "block";
    assert sink.decision.rule == "taint";
    assert sink.trace == ["session_gate", "policy", "constraints", "sequence"];
}

test "blocked source calls do not taint a session" {
    policy = load_policy("policies/mock-crm.yaml");
    session = get_session("test-no-false-taint", []);
    call = police_request(session, policy, "unknown.source", {}, [], 1);
    assert call.decision.action == "block";
    assert not session.tainted;
    assert len(session.history) == 0;
}

test "constraints block writes and safe selects are capped" {
    policy = load_policy("policies/mock-crm.yaml");
    blocked_session = get_session("test-sql-block", []);
    blocked = police_request(
        blocked_session,
        policy,
        "db.execute_sql",
        {"sql": "DELETE FROM customers"},
        [],
        1
    );
    assert blocked.decision.action == "block";
    assert blocked.decision.rule == "constraint";

    clean_session = get_session("test-sql-rewrite", []);
    rewritten = police_request(
        clean_session,
        policy,
        "db.execute_sql",
        {"sql": "SELECT * FROM customers"},
        [],
        1
    );
    assert rewritten.decision.action == "rewrite";
    assert rewritten.args["sql"] == "SELECT * FROM customers LIMIT 1000";
}

test "redaction masks PII and reports counts only" {
    outcome = redact_text("Ada: ada@example.com, SSN 544-21-1290", "standard");
    assert "ada@example.com" not in outcome.scrubbed;
    assert "544-21-1290" not in outcome.scrubbed;
    assert outcome.entity_counts["EMAIL"] == 1;
    assert outcome.entity_counts["US_SSN"] == 1;
    assert outcome.total == 2;
}

test "response control quarantines and redacts" {
    policy = load_policy("policies/mock-crm.yaml");
    redact_session = get_session("test-response-redact", []);
    redact_call = police_request(
        redact_session, policy, "crm.get_customer", {"id": "1"}, [], 1
    );
    scrubbed = handle_response(
        redact_call, policy, redact_session, "email=ada@example.com", "test.audit.jsonl"
    );
    assert "ada@example.com" not in scrubbed;

    quarantine_session = get_session("test-response-quarantine", []);
    quarantine_call = police_request(
        quarantine_session, policy, "logs.tail", {}, [], 1
    );
    withheld = handle_response(
        quarantine_call, policy, quarantine_session, "secret logs", "test.audit.jsonl"
    );
    assert withheld.startswith("[QUARANTINED]");
    assert "secret logs" not in withheld;
}

test "approval fails closed without an approver" {
    policy = load_policy("policies/mock-crm.yaml");
    session = get_session("test-approval", []);
    call = police_request(session, policy, "admin.delete_user", {"id": "1"}, [], 1);
    assert call.decision.action == "block";
    assert call.decision.rule == "approval";
}
