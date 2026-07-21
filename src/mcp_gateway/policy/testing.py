"""Golden decision tests for policies.

A policy pack ships a tests file asserting, for concrete calls, exactly what
the gateway will decide. The same harness runs in three places: `pytest`
(our packs), `mcp-gateway policy test` (authors, locally), and the CI/CD
pipeline (Phase 10) — one engine, no drift between what CI checks and what
production enforces.

Tests file shape (YAML or JSON):

    tests:
      - name: unbounded select gets capped
        tool: db.execute_sql
        role: analyst                      # optional
        arguments: {sql: "SELECT * FROM t"}
        expect:
          outcome: allow                   # allow | deny   (required)
          action: rewrite                  # optional: effective action
          stage: constraints               # optional: which stage denied
          reason_contains: "read-only"     # optional substring check
          disposition: quarantine          # optional response disposition
          rewritten:                       # optional final argument values
            sql: "SELECT * FROM t LIMIT 1000"
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_gateway.core.context import CallContext, Principal
from mcp_gateway.core.errors import PolicyError
from mcp_gateway.core.pipeline import (
    ActionStage,
    ConstraintsStage,
    PolicyStage,
    RequestPipeline,
)
from mcp_gateway.core.session import Session
from mcp_gateway.policy.engine import PolicyEngine
from mcp_gateway.protocol.jsonrpc import JsonRpcMessage

_EXPECT_FIELDS = {"outcome", "action", "stage", "reason_contains", "disposition", "rewritten"}


@dataclass(slots=True)
class GoldenResult:
    name: str
    failures: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.failures


def load_tests_file(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise PolicyError(f"tests file not found: {path}") from None
    if path.suffix == ".json":
        document = json.loads(text)
    else:
        import yaml

        document = yaml.safe_load(text)
    if not isinstance(document, dict) or not isinstance(document.get("tests"), list):
        raise PolicyError(f"{path}: expected a top-level 'tests' list")
    return document["tests"]


def run_policy_tests(
    policy_paths: list[str | Path], tests_path: str | Path
) -> list[GoldenResult]:
    engine = PolicyEngine.load(policy_paths)
    cases = load_tests_file(tests_path)
    return [_run_case(engine, i, case) for i, case in enumerate(cases)]


def _run_case(engine: PolicyEngine, index: int, case: Any) -> GoldenResult:
    name = case.get("name", f"case[{index}]") if isinstance(case, dict) else f"case[{index}]"
    result = GoldenResult(name=name)

    if not isinstance(case, dict) or "tool" not in case or "expect" not in case:
        result.failures.append("case must be a mapping with 'tool' and 'expect'")
        return result
    expect = case["expect"]
    if not isinstance(expect, dict) or "outcome" not in expect:
        result.failures.append("'expect' must be a mapping with 'outcome'")
        return result
    unknown = set(expect) - _EXPECT_FIELDS
    if unknown:
        result.failures.append(f"unknown expect field(s): {sorted(unknown)}")
        return result

    role = case.get("role")
    ctx = CallContext(
        session=Session.new(),
        message=JsonRpcMessage({
            "jsonrpc": "2.0", "id": 0, "method": "tools/call",
            "params": {"name": case["tool"], "arguments": case.get("arguments", {})},
        }),
        tool=case["tool"],
        arguments=case.get("arguments", {}),
        principal=Principal(id="golden", roles=(role,) if role else ()),
    )
    # The session gate is deliberately absent: goldens assert static policy,
    # not session state (risk/taint goldens arrive with Phase 3).
    pipeline = RequestPipeline([PolicyStage(engine), ConstraintsStage(), ActionStage()])
    outcome = asyncio.run(pipeline.run(ctx))

    actual_outcome = "deny" if outcome.denied else "allow"
    if actual_outcome != expect["outcome"]:
        reason = f" ({outcome.reason})" if outcome.denied else ""
        result.failures.append(
            f"outcome: expected {expect['outcome']}, got {actual_outcome}{reason}"
        )

    if "action" in expect:
        actual = ctx.decision.action if ctx.decision else None
        if actual != expect["action"]:
            result.failures.append(f"action: expected {expect['action']}, got {actual}")

    if "stage" in expect and outcome.stage != expect["stage"]:
        result.failures.append(f"stage: expected {expect['stage']}, got {outcome.stage!r}")

    if "reason_contains" in expect:
        haystack = outcome.reason if outcome.denied else (
            ctx.decision.reason if ctx.decision else ""
        )
        if expect["reason_contains"] not in haystack:
            result.failures.append(
                f"reason: expected substring {expect['reason_contains']!r} in {haystack!r}"
            )

    if "disposition" in expect and ctx.disposition != expect["disposition"]:
        result.failures.append(
            f"disposition: expected {expect['disposition']}, got {ctx.disposition!r}"
        )

    if "rewritten" in expect:
        for arg, expected_value in expect["rewritten"].items():
            actual_value = ctx.outbound_arguments.get(arg)
            if actual_value != expected_value:
                result.failures.append(
                    f"rewritten[{arg}]: expected {expected_value!r}, got {actual_value!r}"
                )

    return result
