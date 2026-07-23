"""`gateway.yaml` — the central-mode configuration model, loader, and assembly.

One document describes the whole service: which upstream MCP servers to front,
the policy pack bound to each, where audit goes, and which state backend holds
sessions/taint/risk. The loader validates fail-closed — a malformed or
ambiguous config is a hard error at startup, never a silently degraded service.

Shape (YAML or JSON):

    audit:
      spool: audit.log            # JSONL spool path (default: audit.log)
    state:
      backend: memory             # memory (sqlite/redis/postgres arrive in 5c)
    upstreams:
      - name: filesystem
        command: ["python", "demo/mock_server.py"]
        policy: ["policies/mock-crm.yaml"]   # one or more, layered in order
      - name: github
        command: ["github-mcp-server", "stdio"]
        policy: ["policies/github.yaml"]

Each upstream becomes a `/servers/<name>/mcp` endpoint policed by its own engine.
`build_central_app` wires it all; `upstream_factory` is injectable so tests use
in-process fakes instead of real subprocesses.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_gateway.core.errors import GatewayError

# State backends implemented so far. redis/postgres land in Phase 5c; naming one
# here now is a clear "not yet" rather than a confusing silent fallback.
_SUPPORTED_STATE = {"memory"}


@dataclass(frozen=True, slots=True)
class UpstreamConfig:
    name: str
    command: list[str]
    policy: list[str]


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    upstreams: list[UpstreamConfig]
    spool_path: str = "audit.log"
    state_backend: str = "memory"
    names: frozenset[str] = field(default_factory=frozenset)


def load_gateway_config(path: str | Path) -> GatewayConfig:
    """Parse and validate a gateway config file (YAML or JSON). Fail closed."""
    import yaml

    p = Path(path)
    try:
        text = p.read_text()
    except OSError as exc:
        raise GatewayError(f"cannot read config {path}: {exc}") from None
    document = json.loads(text) if p.suffix == ".json" else yaml.safe_load(text)
    if not isinstance(document, dict):
        raise GatewayError(f"{path}: expected a mapping at the top level")

    raw_upstreams = document.get("upstreams")
    if not isinstance(raw_upstreams, list) or not raw_upstreams:
        raise GatewayError(f"{path}: 'upstreams' must be a non-empty list")

    upstreams: list[UpstreamConfig] = []
    seen: set[str] = set()
    for i, entry in enumerate(raw_upstreams):
        where = f"{path}: upstreams[{i}]"
        if not isinstance(entry, dict):
            raise GatewayError(f"{where}: expected a mapping")
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            raise GatewayError(f"{where}: 'name' is required")
        if name in seen:
            raise GatewayError(f"{path}: duplicate upstream name {name!r}")
        seen.add(name)
        command = entry.get("command")
        if not isinstance(command, list) or not command or not all(
            isinstance(c, str) for c in command
        ):
            raise GatewayError(f"{where} ({name}): 'command' must be a non-empty list of strings")
        policy = entry.get("policy")
        if isinstance(policy, str):
            policy = [policy]
        if not isinstance(policy, list) or not policy or not all(
            isinstance(pth, str) for pth in policy
        ):
            raise GatewayError(f"{where} ({name}): 'policy' must be one or more file paths")
        upstreams.append(UpstreamConfig(name=name, command=list(command), policy=list(policy)))

    audit = document.get("audit") or {}
    spool_path = audit.get("spool", "audit.log") if isinstance(audit, dict) else "audit.log"

    state = document.get("state") or {}
    backend = state.get("backend", "memory") if isinstance(state, dict) else "memory"
    if backend not in _SUPPORTED_STATE:
        raise GatewayError(
            f"{path}: state.backend {backend!r} not supported yet "
            f"(available: {sorted(_SUPPORTED_STATE)}; redis/postgres arrive in Phase 5c)"
        )

    return GatewayConfig(
        upstreams=upstreams,
        spool_path=str(spool_path),
        state_backend=backend,
        names=frozenset(seen),
    )


def build_central_app(
    config: GatewayConfig,
    *,
    upstream_factory: Callable[[str, list[str]], Any] | None = None,
):
    """Assemble the central FastAPI app from a validated config.

    Returns `(app, spool)`. Each upstream gets its own `StreamableHttpGateway`
    over a `PolicyEngine` loaded from its policy pack, sharing one audit spool.
    `upstream_factory(name, command)` is injectable for tests; the default
    launches a real `SubprocessUpstream`.
    """
    from mcp_gateway.approvals import build_broker
    from mcp_gateway.audit.spool import JsonlSpool
    from mcp_gateway.policy.engine import PolicyEngine
    from mcp_gateway.redaction.service import RedactionService
    from mcp_gateway.transports.streamable_http import (
        StreamableHttpGateway,
        build_session_parts,
        create_central_app,
    )
    from mcp_gateway.transports.upstream import SubprocessUpstream

    if upstream_factory is None:
        def upstream_factory(name: str, command: list[str]):  # noqa: ARG001
            return SubprocessUpstream(command)

    spool = JsonlSpool(config.spool_path)
    hubs: dict[str, StreamableHttpGateway] = {}
    for up in config.upstreams:
        engine = PolicyEngine.load(up.policy)
        redaction = RedactionService()
        # Fail-closed approvals by default in central mode; an HTTP approver
        # (the console) can be wired per-deployment later.
        broker = build_broker("deny")
        parts = build_session_parts(
            engine=engine,
            spool=spool,
            upstream_factory=_bind_upstream(upstream_factory, up.name, up.command),
            redaction=redaction,
            broker=broker,
            annotate={"transport": "streamable_http", "upstream": up.name,
                      "policy_source": engine.source},
        )
        hubs[up.name] = StreamableHttpGateway(parts)

    return create_central_app(hubs), spool


def _bind_upstream(factory: Callable[[str, list[str]], Any], name: str, command: list[str]):
    """Freeze (name, command) so each hub's session factory builds its own
    upstream — avoids the classic late-binding-closure bug over the loop var."""
    def make(_session_id: str):
        return factory(name, command)

    return make
