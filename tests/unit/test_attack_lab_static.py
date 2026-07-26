"""Static contract for the judge-facing Attack Lab frontend."""

import json
from html.parser import HTMLParser
from pathlib import Path

from dashboard import server

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "dashboard"


class _Ids(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()

    def handle_starttag(self, _tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name == "id" and value:
                self.ids.add(value)


def test_attack_lab_has_the_complete_explainability_surface() -> None:
    parser = _Ids()
    parser.feed((DASHBOARD / "index.html").read_text(encoding="utf-8"))

    assert {
        "view-lab",
        "lab-topology",
        "lab-gates",
        "lab-timeline",
        "lab-risk",
        "lab-trust",
        "lab-policy-name",
        "lab-policy-rule",
        "lab-proof-upstream",
        "lab-payload",
        "live-session-name",
        "live-session-detail",
    } <= parser.ids


def test_attack_lab_contains_both_verified_demo_stories() -> None:
    script = (DASHBOARD / "app.js").read_text(encoding="utf-8")

    assert "ATTACK_SCENARIOS" in script
    assert "GitHub supply-chain attack" in script
    assert "Slack data-exfiltration attack" in script
    assert "Protected-branch constraint" in script
    assert "Taint sink gate" in script
    assert "Automatic risk suspension" in script
    assert "Counts only:" in script
    assert "let labStep = -1" in script
    assert "scenario.steps.slice(0, labStep + 1)" in script
    assert "Waiting for the agent’s next action" in script


def test_dashboard_summarizes_nested_jac_audit_records(tmp_path, monkeypatch) -> None:
    records = [
        {
            "ts": "2026-07-26T20:00:00Z",
            "event": "tool_result_redacted",
            "session_id": "jac-demo",
            "principal": {"roles": ["support-agent"]},
            "risk": {"score": 5, "level": "NORMAL"},
            "taint": {"tainted": True, "origin": "search_messages"},
            "redactions": {"total": 5, "by_entity": {"EMAIL": 1}},
        },
        {
            "ts": "2026-07-26T20:00:01Z",
            "event": "tool_call_blocked",
            "session_id": "jac-demo",
            "principal": {"roles": ["support-agent"]},
            "risk": {"score": 70, "level": "SUSPENDED"},
            "taint": {"tainted": True, "origin": "read_file"},
            "redactions": None,
        },
    ]
    audit = tmp_path / "jac.audit.jsonl"
    audit.write_text(
        "\n".join(json.dumps(record) for record in records),
        encoding="utf-8",
    )
    monkeypatch.setattr(server, "AUDIT_PATH", audit)

    summary = server.session_summaries()[0]
    assert summary["role"] == "support-agent"
    assert summary["score"] == 70
    assert summary["level"] == "SUSPENDED"
    assert summary["tainted"] is True
    assert summary["redactions"] == 5
    assert summary["blocks"] == 1


def test_live_ops_selects_the_strongest_incident_not_trailing_clean_control() -> None:
    clean = {
        "id": "clean-control",
        "tainted": False,
        "score": 20,
        "redactions": 0,
        "blocks": 1,
    }
    compromised = {
        "id": "compromised",
        "tainted": True,
        "score": 70,
        "redactions": 5,
        "blocks": 4,
    }

    assert server.select_incident_summary([compromised, clean]) == compromised
