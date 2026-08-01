"""Liveness and readiness — the two questions an orchestrator actually asks.

Kubernetes (and every load balancer) distinguishes two things, and conflating
them is how a deployment either flaps or serves traffic it can't handle:

  * **Liveness** (`/healthz`) — "is this process wedged?" Answered by the fact
    that the HTTP handler ran at all. It must not depend on any downstream: if
    `/healthz` checked the SIEM or an upstream, a SIEM outage would get the
    gateway *killed and restarted*, turning a cosmetic problem into an outage.
    So liveness is deliberately trivial — a 200 that proves the event loop turns.

  * **Readiness** (`/readyz`) — "should traffic come here *now*?" This *may*
    depend on the things a request needs: the audit spool has to be writable
    (the gateway fails closed if it can't audit), and in central mode at least
    one upstream must be configured. A failing readiness check pulls the replica
    out of rotation without killing it, so it rejoins when the dependency
    recovers.

A `ReadinessCheck` is just a named predicate; `evaluate` runs them all and
reports which passed. Pure stdlib.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    ok: bool
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ReadinessReport:
    ready: bool
    checks: list[CheckResult]

    def to_dict(self) -> dict:
        status = "ready" if self.ready else "not ready"
        return {
            "status": status,
            "checks": {c.name: {"ok": c.ok, "detail": c.detail} for c in self.checks},
        }


# A readiness check: () -> (ok, detail). Raising counts as a failure.
ReadinessCheck = Callable[[], "tuple[bool, str]"]


def spool_writable_check(spool_path: str | os.PathLike) -> ReadinessCheck:
    """Ready only if the audit spool's directory is writable — the gateway fails
    closed when it cannot record a decision, so 'can't audit' means 'not ready'."""
    def check() -> tuple[bool, str]:
        directory = os.path.dirname(os.path.abspath(str(spool_path))) or "."
        if os.access(directory, os.W_OK):
            return True, str(spool_path)
        return False, f"audit spool dir not writable: {directory}"
    return check


def upstreams_configured_check(count: int) -> ReadinessCheck:
    """Central mode: ready only if at least one upstream is bound."""
    def check() -> tuple[bool, str]:
        return (count > 0, f"{count} upstream(s)")
    return check


def evaluate(checks: dict[str, ReadinessCheck]) -> ReadinessReport:
    results: list[CheckResult] = []
    for name, check in checks.items():
        try:
            ok, detail = check()
        except Exception as exc:  # noqa: BLE001 — a raising check is a failing check
            ok, detail = False, f"check raised: {exc}"
        results.append(CheckResult(name=name, ok=ok, detail=detail))
    return ReadinessReport(ready=all(c.ok for c in results), checks=results)
