"""Load test: gateway added latency on the regex enforcement path.

Phase 5 exit target (docs/PLAN.md): sustained 100 calls/sec with p99 added
latency < 50 ms on the regex path — i.e. policy match + argument constraints
(regex), NOT the NER/redaction tier. This script measures exactly that: it fires
tool calls through a real `SecurityGateway` whose policy has a regex constraint,
with a no-op transport, so the wall-clock per call is the enforcement decision
overhead the gateway adds in front of an upstream.

Run standalone:
    PYTHONPATH=src python scripts/loadtest.py --calls 20000 --assert-p99-ms 50

It prints throughput and p50/p95/p99 and exits non-zero if p99 exceeds the
threshold. `tests/unit/test_loadtest.py` runs a small sandbox smoke of the same
harness.
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import time

from mcp_gateway.approvals.broker import build_broker
from mcp_gateway.audit.recorder import AuditRecorder
from mcp_gateway.core.gateway import SecurityGateway
from mcp_gateway.core.pipeline import default_pipeline
from mcp_gateway.policy.engine import PolicyEngine

# A regex-constrained policy: every crm.get call runs a compiled regex over its
# argument — the "regex path" the latency target is about.
_POLICY = {
    "schema_version": 1,
    "default_action": "block",
    "tools": {
        "crm.get": {
            "action": "allow",
            "constraints": [
                {"type": "regex", "arg": "id", "must_match": r"^[0-9]{1,10}$"}
            ],
        }
    },
}

_CALL = ('{"jsonrpc":"2.0","id":%d,"method":"tools/call",'
         '"params":{"name":"crm.get","arguments":{"id":"8842"}}}')


class _NullTransport:
    async def send_client(self, line: str) -> None:  # noqa: ARG002
        pass

    async def send_upstream(self, line: str) -> None:  # noqa: ARG002
        pass


class _NullSink:
    async def emit(self, event: dict) -> None:  # noqa: ARG002
        pass


def _build_gateway() -> SecurityGateway:
    engine = PolicyEngine.from_documents([(_POLICY, "loadtest")])
    gw = SecurityGateway(
        pipeline=default_pipeline(engine, None, build_broker("deny")),
        audit=AuditRecorder([_NullSink()]),
        policy=engine,
    )
    gw.bind_transport(_NullTransport())
    return gw


async def run(calls: int) -> dict[str, float]:
    gw = _build_gateway()
    # Warm up (import/JIT-ish, first-call allocations) so the sample is steady.
    for i in range(200):
        await gw.on_client_line(_CALL % i)

    latencies: list[float] = []
    start = time.perf_counter()
    for i in range(calls):
        t0 = time.perf_counter()
        await gw.on_client_line(_CALL % i)
        latencies.append((time.perf_counter() - t0) * 1000.0)
    wall = time.perf_counter() - start

    latencies.sort()

    def pct(p: float) -> float:
        return latencies[min(len(latencies) - 1, int(p * len(latencies)))]

    return {
        "calls": calls,
        "wall_s": wall,
        "throughput_per_s": calls / wall if wall else float("inf"),
        "mean_ms": statistics.fmean(latencies),
        "p50_ms": pct(0.50),
        "p95_ms": pct(0.95),
        "p99_ms": pct(0.99),
        "max_ms": latencies[-1],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--calls", type=int, default=20000)
    ap.add_argument("--assert-p99-ms", type=float, default=None,
                    help="exit non-zero if p99 exceeds this many ms")
    ns = ap.parse_args()

    stats = asyncio.run(run(ns.calls))
    print(
        f"calls={stats['calls']}  "
        f"throughput={stats['throughput_per_s']:.0f}/s  "
        f"mean={stats['mean_ms']:.3f}ms  p50={stats['p50_ms']:.3f}ms  "
        f"p95={stats['p95_ms']:.3f}ms  p99={stats['p99_ms']:.3f}ms  "
        f"max={stats['max_ms']:.3f}ms"
    )
    if ns.assert_p99_ms is not None and stats["p99_ms"] > ns.assert_p99_ms:
        print(f"FAIL: p99 {stats['p99_ms']:.3f}ms exceeds {ns.assert_p99_ms}ms")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
