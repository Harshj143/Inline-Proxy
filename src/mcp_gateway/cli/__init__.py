"""The `mcp-gateway` command-line interface.

Phase 1 ships `wrap`, `version`, and the `policy` subcommands (validate,
show, test). Phase 4a adds `policy backtest` and `audit reindex` (the console's
read model); Phase 10 adds `policy ci`. `init` and `add` arrive in their phases
(docs/PLAN.md).

Usage:
    mcp-gateway wrap --policy base.yaml --policy override.yaml -- \
        npx -y @modelcontextprotocol/server-filesystem /data
    mcp-gateway policy validate policies/*.yaml
    mcp-gateway policy show --policy base.yaml --policy override.yaml
    mcp-gateway policy test --policy pack.yaml --tests pack.tests.yaml
    mcp-gateway policy backtest --policy new.yaml --audit audit.log
    mcp-gateway policy ci --root . --github
    mcp-gateway policy diff --base /tmp/main-worktree --head . --markdown
    mcp-gateway audit reindex --audit audit.log --index audit.db
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
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
        "--connector",
        default=None,
        metavar="NAME",
        help="use a named connector pack's policy (see `connectors list`); "
        "layer extra files with --override, or use --policy instead",
    )
    wrap.add_argument(
        "--policy",
        action="append",
        metavar="FILE",
        help="policy file (YAML or JSON); repeat to layer, later files override. "
        "Required unless --connector is given",
    )
    wrap.add_argument(
        "--override",
        action="append",
        metavar="FILE",
        help="extra policy file layered on top of --connector/--policy "
        "(customize a pack without forking it); repeat to layer",
    )
    wrap.add_argument(
        "--bundle",
        default=None,
        metavar="FILE",
        help="load policy from a signed bundle file, verified before enforcing "
        "(needs --public-key); mutually exclusive with --connector/--policy",
    )
    wrap.add_argument(
        "--bundle-store",
        default=None,
        metavar="DIR",
        help="load the current bundle for --bundle-name from a bundle store, "
        "re-verified on read with fallback to last-known-good (needs --public-key)",
    )
    wrap.add_argument(
        "--bundle-name",
        default=None,
        metavar="NAME",
        help="which pack's current bundle to load from --bundle-store",
    )
    wrap.add_argument(
        "--public-key",
        default=None,
        metavar="FILE",
        help="Ed25519 public key PEM the gateway verifies a --bundle/--bundle-store "
        "against; without it a signed bundle is refused (fail closed)",
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

    backtest = policy_sub.add_parser(
        "backtest",
        help="replay recorded calls from an audit log through a policy (blast radius)",
        description=(
            "Re-evaluate every tool call recorded in an audit spool against a "
            "candidate policy and report what would be decided differently. "
            "Action-level: argument constraints, taint/sequence, and approvals "
            "are not replayed (the audit log is counts-only)."
        ),
    )
    backtest.add_argument("--policy", action="append", required=True, metavar="FILE")
    backtest.add_argument("--audit", required=True, metavar="FILE",
                          help="audit spool (JSONL) whose recorded calls are replayed")
    backtest.add_argument("--json", action="store_true", help="machine-readable output")

    ci = policy_sub.add_parser(
        "ci",
        help="validate + golden-test every policy pack in a repo (the CI entry point)",
        description=(
            "Discover every connector pack and standalone policy file under a "
            "repo and check each one: layers parse and merge, golden decisions "
            "hold, every inventoried tool has an explicit rule, and the backtest "
            "replay path agrees with the live matcher. Discovery means a new pack "
            "is covered without editing the pipeline. Exits non-zero on any "
            "failure."
        ),
    )
    ci.add_argument("--root", default=".", metavar="DIR",
                    help="repo root holding connectors/ and policies/ (default: .)")
    ci.add_argument("--only", action="append", metavar="NAME",
                    help="check only this pack/policy by name; repeatable")
    ci.add_argument("--min-goldens", type=int, default=1, metavar="N",
                    help="minimum golden cases a pack must ship (default: 1)")
    ci.add_argument("--no-backtest", action="store_true",
                    help="skip the backtest self-consistency check")
    ci.add_argument("--json", action="store_true", help="machine-readable output")
    ci.add_argument("--github", action="store_true",
                    help="emit GitHub Actions error annotations and append a job "
                         "summary to $GITHUB_STEP_SUMMARY")

    diff = policy_sub.add_parser(
        "diff",
        help="blast radius of a policy change: what two revisions decide differently",
        description=(
            "Compile every pack on both sides of a change and evaluate every "
            "tool across every role view, then rank each difference on the "
            "least-privilege ladder (allow < redact < quarantine < "
            "require_approval < block). Answers what a YAML diff cannot: layered "
            "merge, glob specificity, and role overlays mean a three-line edit "
            "can move a hundred decisions."
        ),
    )
    diff.add_argument("--base", required=True, metavar="DIR",
                      help="repo root BEFORE the change (e.g. a git worktree of main)")
    diff.add_argument("--head", default=".", metavar="DIR",
                      help="repo root AFTER the change (default: .)")
    diff.add_argument("--markdown", action="store_true",
                      help="render as a PR comment body")
    diff.add_argument("--json", action="store_true", help="machine-readable output")
    diff.add_argument("--fail-on-crossing", action="store_true",
                      help="exit non-zero if any decision that was refused would "
                           "now go through un-gated (opt-in gate; a diff only "
                           "reports by default)")

    # policy bundle <build|verify|show> — versioned, signed policy artifacts.
    bundle = policy_sub.add_parser(
        "bundle",
        help="build, sign, verify, and inspect versioned policy bundles",
        description=(
            "A bundle packages policy layers into one versioned, signed file the "
            "gateway can verify before enforcing. Integrity (sha256 over the "
            "payload) plus authenticity (Ed25519 signature over the manifest): a "
            "bundle that was altered after signing is refused."
        ),
    )
    bundle_sub = bundle.add_subparsers(dest="bundle_command", required=True)

    b_build = bundle_sub.add_parser(
        "build", help="package policy layers (or a connector) into a signed bundle"
    )
    b_build.add_argument("--connector", metavar="NAME",
                         help="bundle a named connector pack's layers")
    b_build.add_argument("--policy", action="append", metavar="FILE",
                         help="policy layer(s) to bundle; repeat to layer (or use --connector)")
    b_build.add_argument("--out", required=True, metavar="FILE",
                         help="write the bundle here")
    b_build.add_argument("--sign-key", metavar="FILE",
                         help="Ed25519 private key PEM to sign with (unsigned if omitted)")
    b_build.add_argument("--name", metavar="NAME",
                         help="bundle name (defaults to the first layer's policy name)")
    b_build.add_argument("--version", metavar="VERSION",
                         help="bundle version (defaults to a timestamp + content hash)")

    b_verify = bundle_sub.add_parser(
        "verify", help="check a bundle's hash and signature (exit non-zero if bad)"
    )
    b_verify.add_argument("bundle", metavar="FILE")
    b_verify.add_argument("--public-key", metavar="FILE",
                          help="Ed25519 public key PEM to verify against; without it, "
                               "only the content hash is checked (signature UNVERIFIED)")
    b_verify.add_argument("--json", action="store_true", help="machine-readable output")

    b_show = bundle_sub.add_parser(
        "show", help="print a bundle's manifest and layer inventory"
    )
    b_show.add_argument("bundle", metavar="FILE")
    b_show.add_argument("--json", action="store_true", help="machine-readable output")

    b_install = bundle_sub.add_parser(
        "install",
        help="verify a bundle and make it the current one in a store (atomic; "
             "keeps the prior as last-known-good)",
    )
    b_install.add_argument("bundle", metavar="FILE")
    b_install.add_argument("--store", required=True, metavar="DIR",
                           help="bundle store directory")
    b_install.add_argument("--public-key", required=True, metavar="FILE",
                           help="Ed25519 public key PEM to verify against")

    b_rollback = bundle_sub.add_parser(
        "rollback",
        help="promote a store's last-known-good bundle back to current",
    )
    b_rollback.add_argument("name", metavar="NAME", help="pack name to roll back")
    b_rollback.add_argument("--store", required=True, metavar="DIR")
    b_rollback.add_argument("--public-key", required=True, metavar="FILE")

    b_current = bundle_sub.add_parser(
        "current", help="show the current bundle version in a store"
    )
    b_current.add_argument("name", metavar="NAME")
    b_current.add_argument("--store", required=True, metavar="DIR")
    b_current.add_argument("--public-key", required=True, metavar="FILE")

    keygen = policy_sub.add_parser(
        "keygen",
        help="generate an Ed25519 keypair for signing policy bundles",
        description=(
            "The private key signs bundles (keep it in CI secrets or a KMS); the "
            "public key is what the gateway holds to verify. The gateway can never "
            "forge policy — it only ever has the public half."
        ),
    )
    keygen.add_argument("--out", required=True, metavar="PREFIX",
                        help="writes PREFIX.pem (private) and PREFIX.pub.pem (public)")
    keygen.add_argument("--force", action="store_true",
                        help="overwrite existing key files")

    audit = sub.add_parser("audit", help="build and inspect the audit index")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    reindex = audit_sub.add_parser(
        "reindex",
        help="rebuild the SQLite audit index from the JSONL spool",
        description=(
            "The index is a disposable read model derived from the spool (the "
            "source of truth). By default it rebuilds from scratch; --incremental "
            "only ingests spool records written since the last run."
        ),
    )
    reindex.add_argument("--audit", default="audit.log", metavar="FILE",
                         help="audit spool path (JSONL)")
    reindex.add_argument("--index", default="audit.db", metavar="FILE",
                         help="SQLite index path (created if absent)")
    reindex.add_argument("--incremental", action="store_true",
                         help="catch up from the stored watermark instead of a full rebuild")

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

    connectors = sub.add_parser(
        "connectors",
        help="list, inspect, and scaffold connector packs",
        description=(
            "A connector is a curated security pack for one MCP server. Packs are "
            "discovered by name across the connector search paths."
        ),
    )
    connectors_sub = connectors.add_subparsers(dest="connectors_command", required=True)
    connectors_sub.add_parser("list", help="list available connector packs")
    c_show = connectors_sub.add_parser("show", help="print a connector's manifest + inventory")
    c_show.add_argument("name", metavar="NAME")
    c_show.add_argument("--json", action="store_true", help="machine-readable output")
    c_new = connectors_sub.add_parser(
        "scaffold", help="generate a new connector skeleton to author from"
    )
    c_new.add_argument("name", metavar="NAME")
    c_new.add_argument("--dir", default="connectors", metavar="DIR",
                       help="parent directory for the new connector (default: connectors/)")
    c_new.add_argument("--force", action="store_true",
                       help="overwrite an existing non-empty connector directory")

    console = sub.add_parser(
        "console",
        help="run the Security Ops Console (needs the [server] extra)",
    )
    console_sub = console.add_subparsers(dest="console_command", required=True)
    serve = console_sub.add_parser(
        "serve",
        help="serve the console REST API + live feed over an audit index/spool",
    )
    serve.add_argument("--index", default="audit.db", metavar="FILE",
                       help="SQLite audit index (rebuilt on demand from the spool)")
    serve.add_argument("--audit", default="audit.log", metavar="FILE",
                       help="audit spool path (JSONL) — source of truth")
    serve.add_argument("--users", required=True, metavar="FILE",
                       help="YAML/JSON of console users (username, role, password_hash)")
    serve.add_argument("--policy", action="append", metavar="FILE",
                       help="policy file(s) to expose in the policy view + backtest")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--secret-env", default="MCPG_CONSOLE_SECRET", metavar="VAR",
                       help="env var holding the cookie-signing secret "
                       "(random per-process if unset — sessions won't survive restart)")
    serve.add_argument("--gateway-token-env", default=None, metavar="VAR",
                       help="env var holding a shared token required on POST /api/approvals")
    serve.add_argument("--allow-insecure-approvals", action="store_true",
                       help="permit the cookieless POST /api/approvals with no "
                       "--gateway-token-env on a non-loopback --host (use only when the "
                       "endpoint is already protected by an upstream proxy)")
    serve.add_argument("--approval-timeout", type=float, default=300.0, metavar="SECONDS")

    hashpw = console_sub.add_parser(
        "hash-password",
        help="print a PBKDF2 hash for a console user's password (reads stdin)",
    )
    hashpw.add_argument("--password", default=None,
                        help="password to hash; omit to read one line from stdin")

    serve = sub.add_parser(
        "serve",
        help="run the central multi-upstream HTTP gateway (needs the [server] extra)",
        description=(
            "Front many MCP servers over Streamable HTTP, each at "
            "/servers/<name>/mcp policed by its own policy pack, per a "
            "gateway.yaml config."
        ),
    )
    serve.add_argument("--config", required=True, metavar="FILE",
                       help="gateway config (YAML or JSON): upstreams, policies, audit, state")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)

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


def _build_wrap_engine(ns: argparse.Namespace) -> PolicyEngine:
    """Resolve --connector/--policy (+ --override) into one PolicyEngine.

    A connector contributes its policy layers first; --policy layers follow; then
    --override layers last, so a deployment tightens or relaxes a pack's rules
    without forking it. Requires at least one of --connector/--policy.
    """
    overrides = list(ns.override or [])
    if ns.connector:
        from mcp_gateway.connectors import find_connector

        connector = find_connector(ns.connector)  # ConnectorError if unknown/malformed
        layers = [*connector.policy_layers(), *(ns.policy or []), *overrides]
    elif ns.policy:
        layers = [*ns.policy, *overrides]
    else:
        raise GatewayError("wrap: provide --connector NAME or --policy FILE")
    return PolicyEngine.load(layers)


def _load_bundle_engine(
    ns: argparse.Namespace, recorder: AuditRecorder
) -> tuple[PolicyEngine, dict]:
    """Load, verify, and compile a policy bundle for `wrap`.

    Fail-closed and *audited*: a bundle that does not verify is refused with a
    `policy_bundle_rejected` event before the process exits, so the audit trail
    records that the gateway declined to enforce what was pushed — the exit
    criterion for tamper detection. Returns the engine plus a dict of annotations
    (version, signer, source) for `gateway_start`.
    """
    from mcp_gateway.policy.bundle import (
        engine_from_bundle,
        load_bundle,
        verify_bundle,
    )
    from mcp_gateway.policy.signing import load_verifying_key

    if ns.override or ns.policy or ns.connector:
        raise GatewayError(
            "wrap: --bundle/--bundle-store cannot be combined with "
            "--connector/--policy/--override (a bundle IS the policy)"
        )
    if not ns.public_key:
        # No key = no way to verify = fail closed. Do not silently trust.
        raise GatewayError(
            "wrap --bundle/--bundle-store requires --public-key to verify the "
            "signature; without it a signed bundle cannot be trusted"
        )
    verifying_key = load_verifying_key(ns.public_key)

    def _reject(name: str, version: str, reason: str) -> None:
        asyncio.run(recorder.emit(
            events.POLICY_BUNDLE_REJECTED, bundle=name, version=version, reason=reason
        ))
        asyncio.run(recorder.close())
        raise GatewayError(f"policy bundle rejected: {reason}")

    annotations: dict = {}
    if ns.bundle_store:
        if not ns.bundle_name:
            raise GatewayError("wrap --bundle-store requires --bundle-name NAME")
        from mcp_gateway.policy.bundle_store import BundleStore

        store = BundleStore(ns.bundle_store, verifying_key)
        resolved = store.current(ns.bundle_name)
        if resolved is None:
            _reject(ns.bundle_name, "", "no usable current or last-known-good bundle")
        bundle = resolved.bundle
        if resolved.fell_back:
            asyncio.run(recorder.emit(
                events.POLICY_BUNDLE_FALLBACK, bundle=bundle.name,
                version=bundle.version,
                reason="current bundle unusable; served last-known-good",
            ))
        annotations["bundle_source"] = resolved.source
    else:
        bundle = load_bundle(ns.bundle)
        result = verify_bundle(bundle, verifying_key)
        if not result.ok:
            reason = result.reasons[0] if result.reasons else result.summary
            _reject(bundle.name, bundle.version, reason)
        annotations["bundle_source"] = "file"

    engine = engine_from_bundle(bundle)
    asyncio.run(recorder.emit(
        events.POLICY_BUNDLE_LOADED, bundle=bundle.name, version=bundle.version,
        signer_key_id=bundle.signer_key_id, content_hash=bundle.content_hash,
    ))
    annotations.update(
        bundle_name=bundle.name, bundle_version=bundle.version,
        bundle_signer=bundle.signer_key_id,
    )
    return engine, annotations


# --------------------------------------------------------------------- wrap
def _run_wrap(ns: argparse.Namespace) -> int:
    upstream_cmd = ns.upstream_cmd
    if upstream_cmd and upstream_cmd[0] == "--":
        upstream_cmd = upstream_cmd[1:]
    if not upstream_cmd:
        print("mcp-gateway wrap: provide the upstream server command after --",
              file=sys.stderr)
        return 2

    recorder = AuditRecorder([JsonlSpool(ns.audit)])
    # Bundle mode verifies before enforcing and audits a rejection before exit,
    # so the recorder must exist first. Non-bundle mode is unchanged.
    bundle_annotations: dict = {}
    if ns.bundle or ns.bundle_store:
        engine, bundle_annotations = _load_bundle_engine(ns, recorder)
    else:
        engine = _build_wrap_engine(ns)
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
        **bundle_annotations,
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


def _run_policy_backtest(ns: argparse.Namespace) -> int:
    from mcp_gateway.policy.backtest import backtest_policy, format_report

    engine = PolicyEngine.load(ns.policy)
    report = backtest_policy(ns.audit, engine)
    if ns.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_report(report))
    # A backtest is a report, not a gate; exit 0 even when calls would flip.
    return 0


def _run_policy_ci(ns: argparse.Namespace) -> int:
    from mcp_gateway.policy.ci import (
        format_markdown,
        format_text,
        github_annotations,
        run_policy_ci,
    )

    report = run_policy_ci(
        ns.root,
        min_goldens=ns.min_goldens,
        backtest=not ns.no_backtest,
        only=ns.only,
    )
    if ns.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_text(report))

    if ns.github:
        # Annotations go to stdout (that is how workflow commands are read);
        # the summary is appended to the file Actions hands us, when present.
        for annotation in github_annotations(report):
            print(annotation)
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            try:
                with open(summary_path, "a", encoding="utf-8") as fh:
                    fh.write(format_markdown(report))
            except OSError as exc:  # a summary is reporting, never the gate
                print(f"warning: could not write job summary: {exc}", file=sys.stderr)

    # Unlike `backtest`, this IS a gate: a pack that fails its own goldens must
    # not merge.
    return 0 if report.ok else 1


def _run_policy_diff(ns: argparse.Namespace) -> int:
    from mcp_gateway.policy import diff as policy_diff

    result = policy_diff.diff_roots(ns.base, ns.head)
    if ns.json:
        print(json.dumps(result.to_dict(), indent=2))
    elif ns.markdown:
        print(policy_diff.format_markdown(result), end="")
    else:
        print(policy_diff.format_text(result))

    # A diff reports; gating on it is an opt-in a strict repo turns on.
    if ns.fail_on_crossing and result.newly_allowed:
        print(
            f"error: {result.newly_allowed} decision(s) that were refused would now "
            "go through un-gated",
            file=sys.stderr,
        )
        return 1
    return 0


def _run_policy_keygen(ns: argparse.Namespace) -> int:
    from mcp_gateway.policy.signing import (
        generate_keypair,
        private_key_to_pem,
        public_key_to_pem,
    )

    priv_path = Path(f"{ns.out}.pem")
    pub_path = Path(f"{ns.out}.pub.pem")
    if not ns.force:
        for p in (priv_path, pub_path):
            if p.exists():
                raise GatewayError(f"{p} exists (use --force to overwrite)")

    key = generate_keypair()
    # Private key gets 0600 — it can mint policy the whole fleet will enforce.
    priv_path.write_bytes(private_key_to_pem(key))
    os.chmod(priv_path, 0o600)
    pub_path.write_bytes(public_key_to_pem(key.public_raw))
    print(f"private key: {priv_path}  (keep secret; chmod 600)")
    print(f"public key:  {pub_path}")
    print(f"key id:      {key.key_id}")
    return 0


def _bundle_build_layers(ns: argparse.Namespace) -> list[Path]:
    """Resolve --connector / --policy into the ordered layer paths to bundle."""
    if ns.connector and ns.policy:
        raise GatewayError("bundle build: use --connector or --policy, not both")
    if ns.connector:
        from mcp_gateway.connectors import find_connector

        return list(find_connector(ns.connector).policy_layers())
    if ns.policy:
        return [Path(p) for p in ns.policy]
    raise GatewayError("bundle build: provide --connector NAME or --policy FILE")


def _run_policy_bundle_build(ns: argparse.Namespace) -> int:
    from mcp_gateway.policy.bundle import build_bundle, sign_bundle
    from mcp_gateway.policy.signing import load_signing_key

    layers = _bundle_build_layers(ns)
    bundle = build_bundle(layers, name=ns.name, version=ns.version)
    if ns.sign_key:
        bundle = sign_bundle(bundle, load_signing_key(ns.sign_key))
        signed = f"signed by {bundle.signer_key_id}"
    else:
        signed = "UNSIGNED (add --sign-key to sign)"
    bundle.write(ns.out)
    print(f"wrote {ns.out}")
    print(f"  name:    {bundle.name}")
    print(f"  version: {bundle.version}")
    print(f"  hash:    {bundle.content_hash}")
    print(f"  {signed}")
    return 0


def _run_policy_bundle_verify(ns: argparse.Namespace) -> int:
    from mcp_gateway.policy.bundle import load_bundle, verify_bundle
    from mcp_gateway.policy.signing import load_verifying_key

    bundle = load_bundle(ns.bundle)
    key = load_verifying_key(ns.public_key) if ns.public_key else None
    result = verify_bundle(bundle, key)

    if ns.json:
        print(json.dumps({
            "name": bundle.name, "version": bundle.version,
            "content_hash": bundle.content_hash,
            "ok": result.ok, "integrity_ok": result.integrity_ok,
            "signature_state": result.signature_state,
            "reasons": list(result.reasons),
        }, indent=2))
    else:
        print(f"bundle:  {bundle.name} {bundle.version}")
        print(f"result:  {result.summary}")
        for reason in result.reasons:
            print(f"  - {reason}")
        if key is None:
            print("  (no --public-key: signature was not checked — inspection only)")

    if key is None:
        # Integrity-only: report but do not pass/fail on authenticity. A torn
        # download is a failure; an unchecked signature is not this command's call.
        return 0 if result.integrity_ok else 1
    return 0 if result.ok else 1


def _run_policy_bundle_show(ns: argparse.Namespace) -> int:
    from mcp_gateway.policy.bundle import load_bundle, verify_bundle

    bundle = load_bundle(ns.bundle)
    integrity = verify_bundle(bundle)  # no key: hash only
    if ns.json:
        info = bundle.to_dict()["manifest"]
        info["integrity_ok"] = integrity.integrity_ok
        info["signed"] = bundle.signed
        print(json.dumps(info, indent=2))
        return 0

    print(f"name:         {bundle.name}")
    print(f"version:      {bundle.version}")
    print(f"created:      {bundle.created}")
    print(f"content hash: {bundle.content_hash}  "
          f"({'ok' if integrity.integrity_ok else 'MISMATCH'})")
    print(f"signed:       {'yes, by ' + bundle.signer_key_id if bundle.signed else 'no'}")
    print("layers:")
    for layer in bundle.layers:
        print(f"  - {layer.name}  ({len(layer.text)} bytes)")
    return 0


def _open_bundle_store(ns: argparse.Namespace):
    from mcp_gateway.policy.bundle_store import BundleStore
    from mcp_gateway.policy.signing import load_verifying_key

    return BundleStore(ns.store, load_verifying_key(ns.public_key))


def _run_policy_bundle_install(ns: argparse.Namespace) -> int:
    from mcp_gateway.policy.bundle import load_bundle

    store = _open_bundle_store(ns)
    result = store.install(load_bundle(ns.bundle))
    print(f"{'installed' if result.accepted else 'REJECTED'}  "
          f"{result.name} {result.version}: {result.reason}")
    if result.accepted and result.displaced_version:
        print(f"  last-known-good is now {result.displaced_version}")
    return 0 if result.accepted else 1


def _run_policy_bundle_rollback(ns: argparse.Namespace) -> int:
    store = _open_bundle_store(ns)
    result = store.rollback(ns.name)
    print(f"{'rolled back' if result.accepted else 'FAILED'}: {result.reason}")
    return 0 if result.accepted else 1


def _run_policy_bundle_current(ns: argparse.Namespace) -> int:
    store = _open_bundle_store(ns)
    resolved = store.current(ns.name)
    if resolved is None:
        print(f"{ns.name}: no usable bundle in {ns.store}", file=sys.stderr)
        return 1
    tag = " (last-known-good fallback)" if resolved.fell_back else ""
    print(f"{resolved.bundle.name} {resolved.bundle.version}{tag}")
    return 0


def _run_audit_reindex(ns: argparse.Namespace) -> int:
    from mcp_gateway.audit.index import AuditIndex

    with AuditIndex(ns.index) as index:
        stats = index.catch_up(ns.audit) if ns.incremental else index.rebuild(ns.audit)
    verb = "caught up" if ns.incremental else "rebuilt"
    print(
        f"{verb} {ns.index} from {ns.audit}: "
        f"{stats['inserted']} event(s) indexed, next_offset={stats['next_offset']}"
    )
    if stats["bad_lines"]:
        print(f"  warning: {stats['bad_lines']} unparseable line(s) skipped",
              file=sys.stderr)
    if stats["torn_tail"]:
        print("  note: a torn final line was skipped (writer still appending)",
              file=sys.stderr)
    return 0


def _load_users_file(path: str):
    from mcp_gateway.console.auth import LocalUsers

    document = _load_config_file_generic(path)
    if isinstance(document, dict) and "users" in document:
        document = document["users"]
    if not isinstance(document, list):
        raise GatewayError(f"{path}: expected a list of users (or a 'users:' key)")
    try:
        return LocalUsers(document)
    except ValueError as exc:
        raise GatewayError(f"{path}: {exc}") from None


def _load_config_file_generic(path: str):
    import yaml

    text = Path(path).read_text()
    return json.loads(text) if path.endswith(".json") else yaml.safe_load(text)


def _run_console_serve(ns: argparse.Namespace) -> int:
    import os

    try:
        import uvicorn

        from mcp_gateway.console.app import create_app
        from mcp_gateway.console.auth import CookieSigner, is_loopback_host
    except ModuleNotFoundError:
        raise GatewayError(
            "the console needs the [server] extra: pip install 'mcp-gateway[server]'"
        ) from None

    users = _load_users_file(ns.users)
    if len(users) == 0:
        raise GatewayError(f"{ns.users}: no users defined — the console would be unusable")

    # Fail closed on an exposed approvals endpoint. POST /api/approvals is the
    # gateway-facing, cookieless contract; without a shared token it is guarded
    # only by being unreachable. Binding a non-loopback host without a token (and
    # without an explicit override) would let anyone on the network flood the
    # approval queue, so refuse to start rather than open that quietly.
    gateway_token = os.environ.get(ns.gateway_token_env) if ns.gateway_token_env else None
    if (
        gateway_token is None
        and not is_loopback_host(ns.host)
        and not ns.allow_insecure_approvals
    ):
        raise GatewayError(
            f"console serve --host {ns.host} would expose the cookieless approvals "
            f"endpoint (POST /api/approvals) to the network with no shared token, so "
            f"anyone reachable could flood the approval queue. Set --gateway-token-env "
            f"NAME (with the token in $NAME), or pass --allow-insecure-approvals if the "
            f"endpoint is already protected by an upstream proxy."
        )

    secret = os.environ.get(ns.secret_env)
    if secret:
        signer = CookieSigner(secret.encode("utf-8"))
    else:
        import secrets as _secrets

        signer = CookieSigner(_secrets.token_bytes(32))
        print(
            f"mcp-gateway console: ${ns.secret_env} unset — using a random cookie "
            f"secret; sessions will not survive a restart.",
            file=sys.stderr,
        )

    engine = PolicyEngine.load(ns.policy) if ns.policy else None

    app = create_app(
        index_path=ns.index,
        spool_path=ns.audit,
        users=users,
        signer=signer,
        policy_engine=engine,
        approval_timeout=ns.approval_timeout,
        gateway_token=gateway_token,
    )
    uvicorn.run(app, host=ns.host, port=ns.port)
    return 0


def _run_serve(ns: argparse.Namespace) -> int:
    try:
        import uvicorn

        from mcp_gateway.central.config import build_central_app, load_gateway_config
    except ModuleNotFoundError:
        raise GatewayError(
            "the central gateway needs the [server] extra: pip install 'mcp-gateway[server]'"
        ) from None

    config = load_gateway_config(ns.config)
    app, _spool = build_central_app(config)
    names = ", ".join(sorted(config.names))
    print(
        f"mcp-gateway serve: {len(config.upstreams)} upstream(s) [{names}] on "
        f"http://{ns.host}:{ns.port}/servers/<name>/mcp "
        f"(audit → {config.spool_path}, state → {config.state_backend})",
        file=sys.stderr,
    )
    uvicorn.run(app, host=ns.host, port=ns.port)
    return 0


def _run_console_hash_password(ns: argparse.Namespace) -> int:
    from mcp_gateway.console.auth import hash_password

    password = ns.password if ns.password is not None else sys.stdin.readline().rstrip("\n")
    if not password:
        print("mcp-gateway: empty password", file=sys.stderr)
        return 2
    print(hash_password(password))
    return 0


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


# --------------------------------------------------------------- connectors
def _run_connectors_list(ns: argparse.Namespace) -> int:
    from mcp_gateway.connectors import list_connectors

    found = list_connectors()
    if not found:
        print("no connectors found", file=sys.stderr)
        return 0
    width = max(len(c.name) for c in found)
    for c in found:
        print(f"  {c.name:<{width}}  {c.description}")
    return 0


def _run_connectors_show(ns: argparse.Namespace) -> int:
    from mcp_gateway.connectors import find_connector

    connector = find_connector(ns.name)  # ConnectorError → exit 1
    description = connector.describe()
    if ns.json:
        print(json.dumps(description, indent=2))
        return 0
    print(f"name:        {description['name']}")
    print(f"description: {description['description']}")
    print(f"path:        {description['path']}")
    if description["upstream"]:
        print(f"upstream:    {description['upstream']}")
    if description["launch"]:
        print(f"launch:      {' '.join(description['launch'])}")
    print(f"tools:       {description['tool_count']} ({description['tools_by_risk']})")
    print(f"tests:       {'yes' if description['has_tests'] else 'no'}")
    return 0


def _run_connectors_scaffold(ns: argparse.Namespace) -> int:
    from mcp_gateway.connectors.scaffold import scaffold_connector

    target = scaffold_connector(ns.name, ns.dir, force=ns.force)
    print(f"created connector {ns.name!r} at {target}")
    print(f"  validate: mcp-gateway policy validate {target}/policy.yaml")
    print(f"  test:     mcp-gateway policy test --policy {target}/policy.yaml "
          f"--tests {target}/policy_tests.yaml")
    return 0


def main(argv: list[str] | None = None) -> int:
    ns = _build_parser().parse_args(argv)
    try:
        if ns.command == "wrap":
            return _run_wrap(ns)
        if ns.command == "connectors":
            if ns.connectors_command == "list":
                return _run_connectors_list(ns)
            if ns.connectors_command == "show":
                return _run_connectors_show(ns)
            if ns.connectors_command == "scaffold":
                return _run_connectors_scaffold(ns)
        if ns.command == "detokenize":
            return _run_detokenize(ns)
        if ns.command == "policy":
            if ns.policy_command == "validate":
                return _run_policy_validate(ns)
            if ns.policy_command == "show":
                return _run_policy_show(ns)
            if ns.policy_command == "test":
                return _run_policy_test(ns)
            if ns.policy_command == "backtest":
                return _run_policy_backtest(ns)
            if ns.policy_command == "ci":
                return _run_policy_ci(ns)
            if ns.policy_command == "diff":
                return _run_policy_diff(ns)
            if ns.policy_command == "keygen":
                return _run_policy_keygen(ns)
            if ns.policy_command == "bundle":
                if ns.bundle_command == "build":
                    return _run_policy_bundle_build(ns)
                if ns.bundle_command == "verify":
                    return _run_policy_bundle_verify(ns)
                if ns.bundle_command == "show":
                    return _run_policy_bundle_show(ns)
                if ns.bundle_command == "install":
                    return _run_policy_bundle_install(ns)
                if ns.bundle_command == "rollback":
                    return _run_policy_bundle_rollback(ns)
                if ns.bundle_command == "current":
                    return _run_policy_bundle_current(ns)
        if ns.command == "audit" and ns.audit_command == "reindex":
            return _run_audit_reindex(ns)
        if ns.command == "serve":
            return _run_serve(ns)
        if ns.command == "console":
            if ns.console_command == "serve":
                return _run_console_serve(ns)
            if ns.console_command == "hash-password":
                return _run_console_hash_password(ns)
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
