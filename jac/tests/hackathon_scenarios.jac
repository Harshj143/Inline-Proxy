"""Golden tests for the GitHub and Slack hackathon attack chains."""

import uuid;
import from gateway.policy { load_policy }
import from gateway.redaction { redact_text }
import from gateway.pipeline { get_session, police_request }

def fresh(prefix: str) -> str {
    return prefix + "-" + str(uuid.uuid4());
}

test "github protected branches are blocked before forwarding" {
    policy = load_policy("policies/github-high.yaml");
    session = get_session(fresh("github-protected"), ["developer"]);
    call = police_request(
        session,
        policy,
        "push_files",
        {"owner_repo": "acme/payments", "branch": "main"},
        ["developer"],
        1
    );
    assert call.decision.action == "block";
    assert call.decision.rule == "constraint";
    assert call.trace == ["session_gate", "policy", "constraints"];
}

test "github clean changes are rewritten into draft pull requests" {
    policy = load_policy("policies/github-high.yaml");
    session = get_session(fresh("github-draft"), ["developer"]);
    call = police_request(
        session,
        policy,
        "create_pull_request",
        {
            "owner_repo": "acme/payments",
            "head": "agent/checkout-fix",
            "base": "main",
            "draft": "false"
        },
        ["developer"],
        1
    );
    assert call.decision.action == "rewrite";
    assert call.args["draft"] == "true";
}

test "github attacker content taints and blocks otherwise valid writes" {
    policy = load_policy("policies/github-high.yaml");
    session = get_session(fresh("github-taint"), ["developer"]);
    source = police_request(
        session,
        policy,
        "get_pull_request",
        {"owner_repo": "acme/payments", "number": 418},
        ["developer"],
        1
    );
    assert source.decision.action == "redact";
    assert session.tainted;

    sink = police_request(
        session,
        policy,
        "push_files",
        {"owner_repo": "acme/payments", "branch": "agent/checkout-fix"},
        ["developer"],
        2
    );
    assert sink.decision.action == "block";
    assert sink.decision.rule == "taint";
}

test "github log reads sequence-block workflow execution" {
    policy = load_policy("policies/github-high.yaml");
    session = get_session(fresh("github-sequence"), ["security-reviewer"]);
    logs = police_request(
        session,
        policy,
        "get_job_logs",
        {"owner_repo": "acme/payments", "run_id": 99184},
        ["security-reviewer"],
        1
    );
    assert logs.decision.action == "redact";

    workflow = police_request(
        session,
        policy,
        "run_workflow",
        {"owner_repo": "acme/payments", "workflow": "deploy.yml"},
        ["security-reviewer"],
        2
    );
    assert workflow.decision.action == "block";
    assert workflow.decision.rule == "sequence";
}

test "strict DLP recognizes github aws slack and identity secrets" {
    payload = (
        "email=ada@example.com " + "GITHUB_TOKEN=" + "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 " + "AWS_ACCESS_KEY_ID=" + "AKIA" + "1234567890ABCDEF " + "SLACK_TOKEN=" + "xoxb-" + "123456789012-abcdefghijklmnopqrstuvwxyz"
    );
    outcome = redact_text(payload, "strict");
    assert outcome.entity_counts["EMAIL"] == 1;
    assert outcome.entity_counts["GITHUB_PAT"] == 1;
    assert outcome.entity_counts["AWS_ACCESS_KEY_ID"] == 1;
    assert outcome.entity_counts["SLACK_TOKEN"] == 1;
    assert "ada@example.com" not in outcome.scrubbed;
}

test "slack sensitive channel ACL blocks reads" {
    policy = load_policy("policies/slack-critical.yaml");
    session = get_session(fresh("slack-acl"), ["support-agent"]);
    call = police_request(
        session, policy, "read_channel", {"channel": "#exec"}, ["support-agent"], 1
    );
    assert call.decision.action == "block";
    assert call.decision.rule == "constraint";
}

test "slack files quarantine while reactions stay useful after taint" {
    policy = load_policy("policies/slack-critical.yaml");
    session = get_session(fresh("slack-quarantine"), ["support-agent"]);
    file_call = police_request(
        session,
        policy,
        "read_file",
        {"file_id": "F-PRODUCTION-ENV"},
        ["support-agent"],
        1
    );
    assert file_call.decision.action == "quarantine";
    assert session.tainted;

    reaction = police_request(
        session,
        policy,
        "add_reaction",
        {"channel": "#customer-support", "emoji": "eyes"},
        ["support-agent"],
        2
    );
    assert reaction.decision.action == "allow";
}

test "slack multi-route exfiltration escalates to session suspension" {
    policy = load_policy("policies/slack-critical.yaml");
    session = get_session(fresh("slack-risk"), ["support-agent"]);
    police_request(
        session,
        policy,
        "read_channel",
        {"channel": "#customer-support"},
        ["support-agent"],
        1
    );
    acl_probe = police_request(
        session, policy, "read_channel", {"channel": "#exec"}, ["support-agent"], 2
    );
    assert acl_probe.decision.rule == "constraint";
    first_sink = police_request(
        session,
        policy,
        "send_message",
        {"channel": "@external-auditor", "text": "archive"},
        ["support-agent"],
        3
    );
    assert first_sink.decision.rule == "taint";

    second_sink = police_request(
        session,
        policy,
        "create_conversation",
        {"participants": ["external-auditor"]},
        ["support-agent"],
        4
    );
    assert second_sink.decision.rule == "taint";
    assert session.suspended;

    safe_read = police_request(
        session,
        policy,
        "search_channels",
        {"query": "engineering"},
        ["support-agent"],
        5
    );
    assert safe_read.decision.rule == "session.suspended";
    assert safe_read.trace == ["session_gate"];
}
