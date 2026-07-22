"""The anomaly monitor: a backend plus debouncing.

Running the LLM on every single tool call is expensive and noisy, so the
monitor samples: it assesses at most once every `debounce` calls, but always
assesses immediately when `force=True` (the gateway forces it on a block or a
taint event — the moments most worth a look).
"""

from __future__ import annotations

import sys

from mcp_gateway.anomaly.base import AnomalyBackend, SessionTrace, Verdict


class AnomalyMonitor:
    def __init__(self, backend: AnomalyBackend, debounce: int = 1):
        self.backend = backend
        self.debounce = max(1, debounce)
        self._since_last = 0

    @property
    def backend_name(self) -> str:
        return self.backend.name

    async def observe(self, trace: SessionTrace, force: bool = False) -> Verdict | None:
        self._since_last += 1
        if not force and self._since_last < self.debounce:
            return None
        self._since_last = 0
        return await self.backend.assess(trace)


def build_monitor(mode: str, debounce: int = 1) -> AnomalyMonitor | None:
    """Construct a monitor for a CLI `--anomaly` mode, or None for 'off'.

    'claude' falls back to the heuristic (with a stderr note) when the extra or
    API key is missing — a monitor is never a hard dependency.
    """
    if mode == "off":
        return None
    if mode == "heuristic":
        from mcp_gateway.anomaly.heuristic import HeuristicBackend

        return AnomalyMonitor(HeuristicBackend(), debounce)
    if mode == "claude":
        from mcp_gateway.anomaly.claude import ClaudeBackend
        from mcp_gateway.anomaly.heuristic import HeuristicBackend

        claude = ClaudeBackend()
        if claude.available:
            return AnomalyMonitor(claude, debounce)
        print(
            "mcp-gateway: --anomaly claude unavailable (needs the [anomaly] extra "
            "and ANTHROPIC_API_KEY); falling back to the heuristic backend.",
            file=sys.stderr,
        )
        return AnomalyMonitor(HeuristicBackend(), debounce)
    raise ValueError(f"unknown anomaly mode {mode!r}; use off|heuristic|claude")
