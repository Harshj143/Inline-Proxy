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
from pathlib import Path

from mcp_gateway import __version__
from mcp_gateway.anomaly import build_monitor
from mcp_gateway.approvals import build_broker
from mcp_gateway.audit import events
from mcp_gateway.audit.recorder import AuditRecorder
from mcp_gateway.audit.spool import JsonlSpool
from mcp_gateway.core.context import Principal
from mcp_gateway.core.errors import GatewayError
from mcp_gateway.core.gateway import SecurityGateway
from mcp_gateway.core.pipeline import default_pipeline
from mcp_gateway.policy.engine import PolicyEngine
from mcp_gateway.policy.loader import load_policy_file
from mcp_gateway.policy.testing import run_policy_tests
from mcp_gateway.redaction.detectors.custom import load_recognizers
from mcp_gateway.redaction.service import RedactionService
from mcp_gateway.redaction.vault import KEK_ENV_VAR as _KEK_ENV
from mcp_gateway.redaction.vault import (
    EncryptedSqliteVault,
    load_kek_from_env,
)
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
        "--vault",
        default=None,
        metavar="PATH",
        help=f"persistent encrypted token vault for reversible redaction; needs "
        f"a base64 KEK in ${{{_KEK_ENV}}}. Omit for a non-persistent in-memory vault.",
    )
    wrap.add_argument(
        "--recognizers",
        default=None,
        metavar="FILE",
        help="YAML/JSON file of custom redaction recognizers (entity + regex)",
    )
    wrap.add_argument(
        "--approvals",
        default="deny",
        choices=["deny", "allow", "http"],
        help="how require_approval calls are resolved (deny = fail-closed default; "
        "allow = auto-approve, DEV ONLY; http = ask an approver endpoint and block)",
    )
    wrap.add_argument(
        "--approvals-url",
        default=None,
        metavar="URL",
        help="approver base URL for --approvals http (e.g. http://localhost:8000)",
    )
    wrap.add_argument(
        "--anomaly",
        default="off",
        choices=["off", "heuristic", "claude"],
        help="behavioral anomaly monitor (heuristic = local; claude = Haiku, "
        "needs the [anomaly] extra + ANTHROPIC_API_KEY, falls back to heuristic)",
    )
    wrap.add_argument(
        "--anomaly-debounce",
        type=int,
        default=1,
        metavar="N",
        help="assess at most once every N tool calls (blocks force an assessment)",
    )
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

    redact = sub.add_parser(
        "redact",
        help="redact text/JSON through a profile, or print accuracy metrics",
        description=(
            "Pipe text or JSON on stdin (or pass FILE) to see how a redaction "
            "profile scrubs it. With --eval, print precision/recall over the "
            "built-in labeled corpus instead."
        ),
    )
    redact.add_argument("--profile", default="standard",
                        help="redaction profile (default: standard)")
    redact.add_argument("--json", action="store_true",
                        help="treat input as JSON and redact it structurally")
    redact.add_argument("--eval", action="store_true",
                        help="print corpus precision/recall for --profile and exit")
    redact.add_argument("file", nargs="?", metavar="FILE",
                        help="input file; omit to read stdin")

    detok = sub.add_parser(
        "detokenize",
        help="reverse a token from a persistent vault (authorized, audited)",
        description=(
            "Reverse a [ENTITY:tok_...] token produced by the tokenize operator "
            f"back to its value. Requires the vault path and a base64 KEK in "
            f"${{{_KEK_ENV}}}. The lookup is written to the audit log."
        ),
    )
    detok.add_argument("--vault", required=True, metavar="PATH")
    detok.add_argument("--audit", default="audit.log", metavar="FILE")
    detok.add_argument("--principal", default="local",
                       help="who is performing the detokenization (audited)")
    detok.add_argument("token", metavar="TOKEN")

    sub.add_parser("version", help="print the gateway version")
    return parser


def _load_config_file(path: str) -> list:
    import yaml

    text = Path(path).read_text()
    document = json.loads(text) if path.endswith(".json") else yaml.safe_load(text)
    if isinstance(document, dict) and "recognizers" in document:
        document = document["recognizers"]
    if not isinstance(document, list):
        raise GatewayError(f"{path}: expected a list of recognizers")
    return document


def _open_vault(path: str | None):
    if path is None:
        return None  # RedactionService defaults to a non-persistent in-memory vault
    kek = load_kek_from_env()
    if kek is None:
        raise GatewayError(
            f"--vault needs a base64 key in ${_KEK_ENV} (a persistent vault must "
            f"not use a random key). Generate one with: "
            f"python -c \"import os,base64;print(base64.b64encode(os.urandom(32)).decode())\""
        )
    return EncryptedSqliteVault(path, kek)


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

    # The redaction service makes the redact action executable; passing it to
    # the gateway also flips redact-ed tools from hidden to visible.
    vault = _open_vault(ns.vault)
    recognizers = (
        load_recognizers(_load_config_file(ns.recognizers)) if ns.recognizers else None
    )
    redaction = RedactionService(vault=vault, recognizers=recognizers)
    # The approval broker makes require_approval executable (fail-closed by
    # default); it likewise makes approval-gated tools visible in tools/list.
    # The policy's on_failure.approval decides what an unreachable approver does.
    from mcp_gateway.core.failure import FailMode

    approval_fail_open = engine.posture.approval is FailMode.OPEN
    try:
        broker = build_broker(ns.approvals, ns.approvals_url, fail_open=approval_fail_open)
    except ValueError as exc:
        raise GatewayError(str(exc)) from None
    monitor = build_monitor(ns.anomaly, debounce=ns.anomaly_debounce)
    gateway = SecurityGateway(
        pipeline=default_pipeline(engine, redaction, broker),
        audit=recorder,
        principal=Principal(id=ns.principal, roles=roles),
        policy=engine,
        redaction=redaction,
        anomaly=monitor,
    )
    gateway.annotate(
        policy_source=engine.source,
        default_action=engine.default_action,
        transport="stdio",
        approval_mode=broker.mode,
        anomaly_backend=monitor.backend_name if monitor else "off",
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


def _run_redact(ns: argparse.Namespace) -> int:
    from mcp_gateway.redaction import build_engine
    from mcp_gateway.redaction.eval import evaluate, format_report
    from mcp_gateway.redaction.spec import RedactionSpec

    try:
        engine = build_engine(ns.profile)
    except ValueError as exc:
        print(f"mcp-gateway redact: {exc}", file=sys.stderr)
        return 2

    if ns.eval:
        overall, by_entity = evaluate(engine)
        print(format_report(overall, by_entity))
        return 0

    raw = Path(ns.file).read_text() if ns.file else sys.stdin.read()
    service = RedactionService()
    spec = RedactionSpec(profile=ns.profile)
    if ns.json:
        redacted, report = service.redact(json.loads(raw), spec)
        print(json.dumps(redacted, indent=2))
    else:
        # Text mode: no structured targeting, just detector-driven redaction.
        redacted, report = engine.redact_text(raw)
        print(redacted, end="" if raw.endswith("\n") else "\n")
    print(f"\n[{report.total} redaction(s): {report.counts_by_entity()}]", file=sys.stderr)
    return 0


def _run_detokenize(ns: argparse.Namespace) -> int:
    kek = load_kek_from_env()
    if kek is None:
        raise GatewayError(f"detokenize needs a base64 key in ${_KEK_ENV}")
    vault = EncryptedSqliteVault(ns.vault, kek)
    value = vault.detokenize(ns.token)

    # Every reversal is audited — detokenization re-exposes a protected value
    # and must be accountable to a principal.
    async def _audit() -> None:
        recorder = AuditRecorder([JsonlSpool(ns.audit)])
        await recorder.emit(
            events.DETOKENIZE,
            principal=ns.principal,
            token=ns.token,
            found=value is not None,
        )
        await recorder.close()

    asyncio.run(_audit())

    if value is None:
        print(f"mcp-gateway: token not found in vault: {ns.token}", file=sys.stderr)
        return 1
    print(value)
    return 0


def main(argv: list[str] | None = None) -> int:
    ns = _build_parser().parse_args(argv)
    try:
        if ns.command == "wrap":
            return _run_wrap(ns)
        if ns.command == "detokenize":
            return _run_detokenize(ns)
        if ns.command == "policy":
            if ns.policy_command == "validate":
                return _run_policy_validate(ns)
            if ns.policy_command == "show":
                return _run_policy_show(ns)
            if ns.policy_command == "test":
                return _run_policy_test(ns)
        if ns.command == "redact":
            return _run_redact(ns)
        if ns.command == "version":
            print(__version__)
            return 0
    except GatewayError as exc:
        print(f"mcp-gateway: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 2
