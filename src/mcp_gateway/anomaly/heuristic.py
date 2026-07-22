"""Local, zero-dependency heuristic backend.

A crude stand-in for the LLM so the whole gateway runs with no API key. It
flags the two patterns the real monitor cares about most: the read-then-
exfiltrate shape, and recon sprawl (many distinct tools + accumulating blocks).
Tool-name sets are deliberately conservative defaults; a connector pack can
supply its own via config later.
"""

from __future__ import annotations

from mcp_gateway.anomaly.base import AnomalyBackend, SessionTrace, Verdict

_SENSITIVE_READS = frozenset({
    "crm.get_customer", "db.execute_sql", "secrets.dump", "files.read_any",
    "logs.tail", "vault.read", "get_file_contents",
})
_OUTBOUND = frozenset({
    "http.post", "email.send", "web.fetch", "create_gist", "push_files",
})


class HeuristicBackend(AnomalyBackend):
    name = "heuristic"

    async def assess(self, trace: SessionTrace) -> Verdict | None:
        # Read-then-exfiltrate: a sensitive read earlier this session, and the
        # agent is now reaching for an outbound tool. Worse if tainted.
        read_sensitive = any(t in _SENSITIVE_READS for t in trace.history)
        if read_sensitive and trace.last_tool in _OUTBOUND:
            return Verdict(
                anomalous=True,
                severity="high" if trace.tainted else "medium",
                rationale=(
                    f"sensitive data was read earlier this session and the agent "
                    f"is now calling '{trace.last_tool}', an outbound tool — "
                    f"classic exfiltration shape"
                ),
            )
        # Recon sprawl: several distinct tools touched while accumulating blocks.
        if trace.blocked_count >= 2 and len(set(trace.history)) >= 3:
            return Verdict(
                anomalous=True,
                severity="medium",
                rationale=(
                    f"the agent is touching many distinct tools and accumulating "
                    f"blocks ({trace.blocked_count}) — looks like it is probing "
                    f"for what it can reach"
                ),
            )
        return None
