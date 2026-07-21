"""The `mcp-gateway` command-line interface.

Phase 1 ships `wrap`, `version`, and the `policy` subcommands (validate,
show, test). `serve`, `init`, and `add` arrive in their phases
(docs/PLAN.md).

Usage:
    mcp-gateway wrap --policy base.yaml --policy override.yaml -- \
        npx -y @modelcontextprotocol/server-filesystem /data
    mcp-gateway policy validate policies/*.yaml
    mcp-gateway policy show --policy base.yaml --policy override.yaml
    mcp-gateway policy test --policy pack.yaml --tests pack.tests.yaml
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from mcp_gateway import __version__
from mcp_gateway.audit.recorder import AuditRecorder
from mcp_gateway.audit.spool import JsonlSpool
from mcp_gateway.core.context import Principal
from mcp_gateway.core.errors import GatewayError
from mcp_gateway.core.gateway import SecurityGateway
from mcp_gateway.core.pipeline import default_pipeline
from mcp_gateway.policy.engine import PolicyEngine
from mcp_gateway.policy.loader import load_policy_file
from mcp_gateway.policy.testing import run_policy_tests
from mcp_gateway.transports.stdio import StdioTransport


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-gateway",
        description="A transparent security gateway for MCP tool calls.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    wrap = sub.add_parser(
        "wrap",
        help="run as a stdio sidecar in front of one MCP server",
        description=(
            "Launch the real MCP server as a subprocess and police the "
            "JSON-RPC stream between it and the client that launched us. "
            "Everything after -- is the upstream server command."
        ),
    )
    wrap.add_argument(
        "--policy",
        action="append",
        required=True,
        metavar="FILE",
        help="policy file (YAML or JSON); repeat to layer, later files override",
    )
    wrap.add_argument("--audit", default="audit.log", help="audit spool path (JSONL)")
    wrap.add_argument(
        "--principal",
        default="local",
        help="caller identity recorded on every audit event (stdio has no "
        "per-request identity; OIDC arrives with the HTTP transport)",
    )
    wrap.add_argument("--role", default=None, help="role for role-aware policy overlays")
    wrap.add_argument(
        "upstream_cmd",
        nargs=argparse.REMAINDER,
        metavar="-- COMMAND ...",
        help="the real MCP server command, after --",
    )

    policy = sub.add_parser("policy", help="validate, inspect, and test policies")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)

    validate = policy_sub.add_parser(
        "validate",
        help="check policy files for structural and semantic errors",
        description=(
            "Validates each file, then the merged result of all files "
            "together (in the given order)."
        ),
    )
    validate.add_argument("files", nargs="+", metavar="FILE")

    show = policy_sub.add_parser(
        "show", help="print the effective merged policy"
    )
    show.add_argument("--policy", action="append", required=True, metavar="FILE")
    show.add_argument("--json", action="store_true", help="machine-readable output")

    test = policy_sub.add_parser(
        "test", help="run a golden decision tests file against a policy"
    )
    test.add_argument("--policy", action="append", required=True, metavar="FILE")
    test.add_argument("--tests", required=True, metavar="FILE")

    sub.add_parser("version", help="print the gateway version")
    return parser


# --------------------------------------------------------------------- wrap
def _run_wrap(ns: argparse.Namespace) -> int:
    upstream_cmd = ns.upstream_cmd
    if upstream_cmd and upstream_cmd[0] == "--":
        upstream_cmd = upstream_cmd[1:]
    if not upstream_cmd:
        print("mcp-gateway wrap: provide the upstream server command after --",
              file=sys.stderr)
        return 2

    engine = PolicyEngine.load(ns.policy)
    recorder = AuditRecorder([JsonlSpool(ns.audit)])
    roles = (ns.role,) if ns.role else ()
    gateway = SecurityGateway(
        pipeline=default_pipeline(engine),
        audit=recorder,
        principal=Principal(id=ns.principal, roles=roles),
        policy=engine,
    )
    gateway.annotate(
        policy_source=engine.source,
        default_action=engine.default_action,
        transport="stdio",
        gateway_version=__version__,
    )
    transport = StdioTransport(upstream_cmd, gateway)
    return asyncio.run(transport.run())


# ------------------------------------------------------------------- policy
def _run_policy_validate(ns: argparse.Namespace) -> int:
    layers = []
    failed = False
    for path in ns.files:
        try:
            layers.append(load_policy_file(path))
            print(f"ok       {path}")
        except GatewayError as exc:
            print(f"invalid  {exc}", file=sys.stderr)
            failed = True
    if failed:
        return 1
    if len(layers) >= 1:
        try:
            PolicyEngine(layers)
            if len(layers) > 1:
                print(f"ok       merged result of {len(layers)} layers")
        except GatewayError as exc:
            print(f"invalid  merged: {exc}", file=sys.stderr)
            return 1
    return 0


def _run_policy_show(ns: argparse.Namespace) -> int:
    engine = PolicyEngine.load(ns.policy)
    description = engine.describe()
    if ns.json:
        print(json.dumps(description, indent=2))
        return 0

    print(f"layers:         {' + '.join(description['layers'])}")
    print(f"default action: {description['default_action']}")
    print()
    width = max((len(r["pattern"]) for r in description["rules"]), default=10)
    for rule in description["rules"]:
        notes = []
        if "constraints" in rule:
            notes.append(f"{len(rule['constraints'])} constraint(s)")
        if "rewrites" in rule:
            notes.append(f"{len(rule['rewrites'])} rewrite(s)")
        if "then" in rule:
            notes.append(f"then={rule['then']}")
        if "roles" in rule:
            overrides = ", ".join(
                f"{role}→{o['action']}" for role, o in rule["roles"].items()
            )
            notes.append(f"roles: {overrides}")
        suffix = f"   [{'; '.join(notes)}]" if notes else ""
        print(f"  {rule['pattern']:<{width}}  {rule['action']:<16}{suffix}")
    return 0


def _run_policy_test(ns: argparse.Namespace) -> int:
    results = run_policy_tests(ns.policy, ns.tests)
    failed = [r for r in results if not r.passed]
    for r in results:
        print(f"{'PASS' if r.passed else 'FAIL'}  {r.name}")
        for failure in r.failures:
            print(f"      {failure}")
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    ns = _build_parser().parse_args(argv)
    try:
        if ns.command == "wrap":
            return _run_wrap(ns)
        if ns.command == "policy":
            if ns.policy_command == "validate":
                return _run_policy_validate(ns)
            if ns.policy_command == "show":
                return _run_policy_show(ns)
            if ns.policy_command == "test":
                return _run_policy_test(ns)
        if ns.command == "version":
            print(__version__)
            return 0
    except GatewayError as exc:
        print(f"mcp-gateway: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 2
