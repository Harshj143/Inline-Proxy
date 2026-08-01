"""Mount `/healthz`, `/readyz`, `/metrics` on a FastAPI app.

One helper so every server surface (central multi-upstream, single-upstream
transport, ops console) exposes the same three operational endpoints the same
way. FastAPI is imported *inside* the function, not at module top, so this module
stays importable without the `[server]` extra — the caller is always
`[server]`-gated code that already has an `app`.

The endpoints are `include_in_schema=False`: they are infrastructure for an
orchestrator and a scraper, not part of the gateway's OpenAPI surface.
"""

from __future__ import annotations

from typing import Any

from mcp_gateway.observability.health import ReadinessCheck, evaluate
from mcp_gateway.observability.metrics import CONTENT_TYPE, REGISTRY, Registry


def mount_ops_endpoints(
    app: Any,
    *,
    readiness: dict[str, ReadinessCheck] | None = None,
    registry: Registry | None = None,
) -> None:
    from fastapi.responses import JSONResponse, PlainTextResponse

    reg = registry or REGISTRY
    checks = readiness or {}

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        # Liveness: prove the event loop turns. Never touches a downstream, so a
        # SIEM/upstream outage can't get this process killed and restarted.
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    async def readyz() -> JSONResponse:
        report = evaluate(checks)
        return JSONResponse(report.to_dict(), status_code=200 if report.ready else 503)

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> PlainTextResponse:
        return PlainTextResponse(reg.render(), media_type=CONTENT_TYPE)
