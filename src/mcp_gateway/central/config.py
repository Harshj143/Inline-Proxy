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

# State backends implemented so far. `memory` = per-replica; `redis` = shared
# session state (taint/risk/suspension) across replicas (Phase 5c). Postgres is
# an audit-index backend, configured separately, not a session store.
_SUPPORTED_STATE = {"memory", "redis"}


@dataclass(frozen=True, slots=True)
class UpstreamConfig:
    name: str
    command: list[str]
    policy: list[str]


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    upstreams: list[UpstreamConfig]
    spool_path: str = "audit.log"
    spool_rotate_bytes: int | None = None   # None = unbounded (no rotation)
    spool_keep: int = 10
    state_backend: str = "memory"
    state_url: str | None = None  # e.g. redis://host:6379/0 when backend == redis
    names: frozenset[str] = field(default_factory=frozenset)
    # Path to an identity.yaml (OIDC + API keys). When set, every endpoint
    # requires an authenticated caller; when None, the service authenticates
    # nobody (a trusted-network deployment behind its own gateway).
    identity_path: str | None = None


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

    audit = document.get("audit") if isinstance(document.get("audit"), dict) else {}
    spool_path = audit.get("spool", "audit.log")
    rotate_bytes = audit.get("rotate_bytes")
    if rotate_bytes is not None and (not isinstance(rotate_bytes, int) or rotate_bytes <= 0):
        raise GatewayError(f"{path}: audit.rotate_bytes must be a positive integer")
    keep = audit.get("keep", 10)
    if not isinstance(keep, int) or keep < 1:
        raise GatewayError(f"{path}: audit.keep must be a positive integer")

    state = document.get("state") or {}
    if not isinstance(state, dict):
        state = {}
    backend = state.get("backend", "memory")
    if backend not in _SUPPORTED_STATE:
        raise GatewayError(
            f"{path}: state.backend {backend!r} not supported "
            f"(available: {sorted(_SUPPORTED_STATE)})"
        )
    state_url = state.get("url")
    if backend == "redis" and not state_url:
        raise GatewayError(f"{path}: state.backend 'redis' requires state.url")

    identity = document.get("identity") or {}
    if not isinstance(identity, dict):
        raise GatewayError(f"{path}: 'identity' must be a mapping")
    identity_ref = identity.get("config")
    identity_path = None
    if identity_ref:
        if not isinstance(identity_ref, str):
            raise GatewayError(f"{path}: identity.config must be a file path")
        # Resolve relative to the gateway config's own directory, so a deployment
        # can ship gateway.yaml + identity.yaml side by side.
        identity_path = str((p.parent / identity_ref).resolve())

    return GatewayConfig(
        upstreams=upstreams,
        spool_path=str(spool_path),
        spool_rotate_bytes=rotate_bytes,
        spool_keep=keep,
        state_backend=backend,
        state_url=state_url,
        names=frozenset(seen),
        identity_path=identity_path,
    )


def build_central_app(
    config: GatewayConfig,
    *,
    upstream_factory: Callable[[str, list[str]], Any] | None = None,
    resolver: Any | None = None,
):
    """Assemble the central FastAPI app from a validated config.

    Returns `(app, spool)`. Each upstream gets its own `StreamableHttpGateway`
    over a `PolicyEngine` loaded from its policy pack, sharing one audit spool.
    `upstream_factory(name, command)` is injectable for tests; the default
    launches a real `SubprocessUpstream`.

    `resolver` is an `IdentityResolver`; when omitted it is loaded from
    `config.identity_path` (if configured). Passing it directly lets tests inject
    an offline-JWKS resolver. When there is no resolver, endpoints authenticate
    nobody — the pre-Phase-9 behavior, for a trusted-network deployment.
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

    if resolver is None and config.identity_path:
        from mcp_gateway.identity import load_identity_config
        resolver = load_identity_config(config.identity_path)

    # One shared session store across every upstream + every replica when
    # backend == redis; the default (memory) gives each gateway its own store.
    store = _build_store(config)

    spool = JsonlSpool(
        config.spool_path,
        max_bytes=config.spool_rotate_bytes,
        keep=config.spool_keep,
    )
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
            store=store,
            annotate={"transport": "streamable_http", "upstream": up.name,
                      "policy_source": engine.source},
        )
        hubs[up.name] = StreamableHttpGateway(parts, resolver=resolver)

    from mcp_gateway.observability.health import (
        spool_writable_check,
        upstreams_configured_check,
    )
    readiness = {
        "audit_spool": spool_writable_check(config.spool_path),
        "upstreams": upstreams_configured_check(len(hubs)),
    }
    return create_central_app(hubs, readiness=readiness), spool


def _build_store(config: GatewayConfig):
    """Build the shared session store for the configured backend (or None for
    memory, where each gateway gets its own in-process store)."""
    if config.state_backend == "redis":
        from mcp_gateway.state.redis import RedisSessionStore

        assert config.state_url is not None  # enforced by the loader
        return RedisSessionStore.from_url(config.state_url)
    return None


def _bind_upstream(factory: Callable[[str, list[str]], Any], name: str, command: list[str]):
    """Freeze (name, command) so each hub's session factory builds its own
    upstream — avoids the classic late-binding-closure bug over the loop var."""
    def make(_session_id: str):
        return factory(name, command)

    return make
