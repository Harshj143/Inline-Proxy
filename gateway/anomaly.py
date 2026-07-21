"""LLM-powered behavioral anomaly detection for agent sessions.

The rest of the gateway is a rulebook: static allowlists, taint flags, ordered
sequence rules. Those catch what you thought to write down. This module adds
the thing a rulebook can't do — look at the SHAPE of a session's behavior and
judge whether it *smells* like an attack, even when no single rule fired.

This is the miniature of Formal's "Real-Time AI Session Monitoring": an LLM
embedded in the proxy that watches the live tool-call trace and flags
suspicious patterns (recon sprawl, privilege probing, read-secrets-then-
exfiltrate) as they happen. A flag feeds the risk engine as extra points, so a
model verdict can escalate or suspend a session just like a hard rule.

Three backends, so the whole project still runs with zero dependencies:

  mode="off"        (default) no-op. Nothing is sent anywhere.
  mode="heuristic"  a local, dependency-free stand-in for the LLM. Same
                    interface, crude judgement. Lets the demo show the concept
                    with no API key.
  mode="claude"     the real thing: ask Claude (Haiku — cheapest/fastest, and
                    this is a classification task) whether the trace looks
                    malicious. Requires `pip install anthropic` and
                    ANTHROPIC_API_KEY; falls back to heuristic if unavailable.

NOTE: in a real proxy you would sample or debounce these calls (one LLM call
per tool call adds latency and cost). The demo assesses on every call for
clarity.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

# Haiku: cheapest + fastest current model, ideal for a yes/no classification.
_ANOMALY_MODEL = "claude-haiku-4-5"

_SYSTEM = (
    "You are a security monitor embedded in a proxy that sits between an AI "
    "agent and its tools. You are shown the sequence of tool calls the agent "
    "has made this session, plus whether the session is 'tainted' (it has "
    "ingested untrusted external content that may carry a prompt injection). "
    "Judge whether the recent behavior looks like an attack in progress: "
    "reconnaissance sprawl, privilege probing, or the classic pattern of "
    "reading sensitive data and then trying to send it outward. Benign, "
    "on-task tool use is NOT anomalous. Respond ONLY with the JSON object."
)

_SCHEMA = {
    "type": "object",
    "properties": {
        "anomalous": {"type": "boolean"},
        "severity": {"type": "string", "enum": ["low", "medium", "high"]},
        "rationale": {"type": "string"},
    },
    "required": ["anomalous", "severity", "rationale"],
    "additionalProperties": False,
}


@dataclass
class Verdict:
    anomalous: bool
    severity: str  # "low" | "medium" | "high"
    rationale: str


class AnomalyDetector:
    def __init__(self, mode: str = "off"):
        if mode not in {"off", "heuristic", "claude"}:
            raise ValueError(f"invalid anomaly mode: {mode!r}")
        self.mode = mode
        self._client = None
        if mode == "claude":
            self._client = self._try_load_claude()
            # Announce the effective backend so operators aren't surprised.
            self.backend = "claude" if self._client else "heuristic"
        else:
            self.backend = mode

    # ------------------------------------------------------------- backends
    def _try_load_claude(self):
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return None
        try:
            import anthropic

            return anthropic.Anthropic()
        except Exception:
            return None

    # ------------------------------------------------------------- public API
    def assess(
        self, history: list[str], last_tool: str, tainted: bool, blocked_count: int
    ) -> Verdict | None:
        """Judge the session so far. Returns a Verdict, or None if disabled or
        the detector abstains (nothing suspicious / not worth scoring)."""
        if self.backend == "off":
            return None
        if self.backend == "claude" and self._client is not None:
            verdict = self._assess_claude(history, last_tool, tainted, blocked_count)
            if verdict is not None:
                return verdict
            # fall through to heuristic if the API call failed
        return self._assess_heuristic(history, last_tool, tainted, blocked_count)

    # ----------------------------------------------------------------- claude
    def _assess_claude(
        self, history: list[str], last_tool: str, tainted: bool, blocked_count: int
    ) -> Verdict | None:
        trace = {
            "tool_call_history": history,
            "most_recent_call": last_tool,
            "session_tainted_by_untrusted_content": tainted,
            "policy_blocks_so_far": blocked_count,
        }
        try:
            resp = self._client.messages.create(
                model=_ANOMALY_MODEL,
                max_tokens=256,
                system=_SYSTEM,
                output_config={"format": {"type": "json_schema", "schema": _SCHEMA}},
                messages=[{"role": "user", "content": json.dumps(trace, indent=2)}],
            )
            text = next(b.text for b in resp.content if b.type == "text")
            data = json.loads(text)
            return Verdict(
                anomalous=bool(data["anomalous"]),
                severity=data["severity"],
                rationale=data["rationale"],
            )
        except Exception:
            return None

    # -------------------------------------------------------------- heuristic
    def _assess_heuristic(
        self, history: list[str], last_tool: str, tainted: bool, blocked_count: int
    ) -> Verdict | None:
        """A crude, local stand-in for the LLM so the demo runs with no API
        key. Flags the two patterns the real monitor cares about most."""
        # Read-then-exfiltrate shape: a sensitive read followed by an outbound
        # tool, especially in a tainted session.
        sensitive = {"crm.get_customer", "db.execute_sql", "secrets.dump",
                     "files.read_any"}
        outbound = {"http.post", "email.send", "web.fetch"}
        read_sensitive = any(t in sensitive for t in history)
        if read_sensitive and last_tool in outbound:
            return Verdict(
                anomalous=True,
                severity="high" if tainted else "medium",
                rationale=("sensitive data was read earlier this session and "
                           f"the agent is now calling '{last_tool}', an "
                           "outbound tool — classic exfiltration shape"),
            )
        # Recon sprawl: several distinct blocked probes in a short session.
        if blocked_count >= 2 and len(set(history)) >= 3:
            return Verdict(
                anomalous=True,
                severity="medium",
                rationale=("the agent is touching many distinct tools and "
                           f"accumulating blocks ({blocked_count}) — looks "
                           "like it is probing for what it can reach"),
            )
        return None
