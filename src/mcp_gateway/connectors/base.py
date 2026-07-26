"""Connector packs — curated security bundles for one MCP server.

A connector is *not* an API client (the upstream MCP server already talks to
GitHub/Jira/Slack). It is a directory that bundles everything needed to police
one server safely, so a company adopts protection by name instead of authoring
a policy from scratch (docs/ARCHITECTURE.md §4):

    connectors/<name>/
    ├── manifest.yaml      # what this pack is: server, tested versions, launch template
    ├── policy.yaml        # the shipped default policy (schema_version 1)
    ├── roles.yaml         # OPTIONAL extra policy layer (role matrix), merged after policy.yaml
    ├── tools.yaml         # OPTIONAL tool inventory, risk-classified (documentation + review)
    ├── policy_tests.yaml  # golden decisions: call -> expected outcome
    └── README.md          # threat model, every rule explained, how to override

The framework's contract is deliberately thin. A connector resolves to an
ordered list of **policy layers** (`policy.yaml`, then `roles.yaml` if present),
and a deployment customizes it by appending its own override layers — which is
exactly what the Phase 1 layered merge already does. So `build_engine(overrides)`
is just `PolicyEngine.load([*pack_layers, *overrides])`: no new merge logic, and
a company never forks the pack to change one rule (docs/ARCHITECTURE.md §4).

Fail-closed: a directory missing its manifest or policy, or with an unparseable
or nameless manifest, raises `ConnectorError` rather than resolving to a partial
or empty policy that could silently under-enforce.

`constraints.py` / `detectors.py` (per-connector Python plugins) are named in
the layout for completeness but are NOT dynamically imported here — loading
arbitrary Python from a pack directory is a trust decision of its own. A pack's
policy.yaml uses the builtin, registered constraints/detectors (regex, etc.)
today; custom-plugin loading is a scoped follow-up.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mcp_gateway.core.errors import ConnectorError

if TYPE_CHECKING:
    from mcp_gateway.policy.engine import PolicyEngine

# Standard filenames inside a connector directory.
MANIFEST = "manifest.yaml"
POLICY = "policy.yaml"
ROLES = "roles.yaml"
TOOLS = "tools.yaml"
TESTS = "policy_tests.yaml"
README = "README.md"

# Risk classes a tools.yaml entry may carry (documentation + review signal).
RISK_CLASSES = ("read", "write", "destructive", "secret_adjacent")


def _load_yaml(path: Path) -> Any:
    import yaml

    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConnectorError(f"{path}: {exc}") from None


@dataclass(frozen=True, slots=True)
class Connector:
    """One loaded connector pack, resolved from a directory."""

    name: str
    path: Path
    manifest: dict[str, Any]

    # ------------------------------------------------------------- resolution
    def policy_layers(self) -> list[Path]:
        """Ordered policy layers: policy.yaml, then roles.yaml if it exists.

        Later layers override earlier ones (Phase 1 merge semantics), so a
        role matrix in roles.yaml refines the base policy without duplicating it.
        """
        layers = [self.path / POLICY]
        roles = self.path / ROLES
        if roles.is_file():
            layers.append(roles)
        return layers

    def tests_path(self) -> Path | None:
        p = self.path / TESTS
        return p if p.is_file() else None

    def tools(self) -> dict[str, Any]:
        """The tool inventory from tools.yaml, or {} if the pack ships none.

        Shape: {tool_name: {risk: <class>, description: ...}, ...}. Informational
        for now (review + docs); it does not drive enforcement, which is the
        policy's job.
        """
        p = self.path / TOOLS
        if not p.is_file():
            return {}
        doc = _load_yaml(p)
        if doc is None:
            return {}
        if isinstance(doc, dict) and "tools" in doc:
            doc = doc["tools"]
        if not isinstance(doc, dict):
            raise ConnectorError(f"{p}: expected a mapping of tool -> metadata")
        return doc

    def build_engine(self, overrides: list[str | Path] = ()) -> PolicyEngine:
        """Compile this connector's policy, with optional override layers on top.

        Overrides are ordinary policy files layered last, so a company tightens
        or loosens a shipped rule without forking the pack.
        """
        from mcp_gateway.policy.engine import PolicyEngine

        return PolicyEngine.load([*self.policy_layers(), *overrides])

    # -------------------------------------------------------------- accessors
    @property
    def description(self) -> str:
        return str(self.manifest.get("description", "")).strip()

    @property
    def upstream(self) -> dict[str, Any]:
        up = self.manifest.get("upstream", {})
        return up if isinstance(up, dict) else {}

    @property
    def launch(self) -> list[str]:
        """The template command to start the upstream server, or []."""
        cmd = self.manifest.get("launch", [])
        return [str(x) for x in cmd] if isinstance(cmd, list) else []

    def describe(self) -> dict[str, Any]:
        """JSON-safe summary for `connectors show` / `connectors list`."""
        inventory = self.tools()
        by_risk: dict[str, int] = {}
        for meta in inventory.values():
            risk = meta.get("risk", "unclassified") if isinstance(meta, dict) else "unclassified"
            by_risk[risk] = by_risk.get(risk, 0) + 1
        return {
            "name": self.name,
            "description": self.description,
            "path": str(self.path),
            "upstream": self.upstream,
            "launch": self.launch,
            "tool_count": len(inventory),
            "tools_by_risk": by_risk,
            "has_tests": self.tests_path() is not None,
        }


def load_connector(path: str | Path) -> Connector:
    """Load and validate the connector directory at `path`.

    Fail-closed: the directory must exist and contain a parseable manifest.yaml
    with a `name`, and a policy.yaml. Anything else raises ConnectorError so a
    malformed pack can never resolve to a partial policy.
    """
    path = Path(path)
    if not path.is_dir():
        raise ConnectorError(f"connector: not a directory: {path}")

    manifest_path = path / MANIFEST
    if not manifest_path.is_file():
        raise ConnectorError(f"connector {path.name!r}: missing {MANIFEST}")
    manifest = _load_yaml(manifest_path)
    if not isinstance(manifest, dict):
        raise ConnectorError(f"{manifest_path}: expected a mapping at the top level")

    name = manifest.get("name")
    if not name or not isinstance(name, str):
        raise ConnectorError(f"{manifest_path}: 'name' is required")
    if name != path.name:
        raise ConnectorError(
            f"{manifest_path}: name {name!r} does not match directory {path.name!r} "
            f"(a connector is resolved by its directory name)"
        )

    if not (path / POLICY).is_file():
        raise ConnectorError(f"connector {name!r}: missing {POLICY}")

    return Connector(name=name, path=path, manifest=manifest)
