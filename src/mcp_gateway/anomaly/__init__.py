"""Behavioral anomaly detection for agent sessions.

The rest of the gateway is a rulebook — static allowlists, taint flags, ordered
sequence rules. Those catch what you thought to write down. This adds the thing
a rulebook can't: it looks at the SHAPE of a session's behavior and judges
whether it *smells* like an attack, even when no single rule fired (recon
sprawl, privilege probing, read-secrets-then-exfiltrate). A flag feeds the risk
engine as severity-weighted points, so a model verdict can escalate or suspend
a session just like a hard rule.

Backends keep the core dependency-free:
  off        no-op (default).
  heuristic  local, zero-dependency stand-in — same interface, crude judgement.
  claude     Claude Haiku judges the trace (the `[anomaly]` extra + an API key);
             falls back to heuristic when unavailable.

The monitor is DEBOUNCED — one LLM call per tool call is expensive, so the
Claude backend is sampled, not run on every call.
"""

from mcp_gateway.anomaly.base import AnomalyBackend, SessionTrace, Verdict
from mcp_gateway.anomaly.monitor import AnomalyMonitor, build_monitor

__all__ = [
    "AnomalyBackend",
    "AnomalyMonitor",
    "SessionTrace",
    "Verdict",
    "build_monitor",
]
