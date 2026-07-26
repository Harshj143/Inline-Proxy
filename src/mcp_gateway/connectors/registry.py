"""Connector discovery: resolve a name to a pack across search paths.

Connectors are looked up by directory name across an ordered set of search
paths; the first match wins, so a site can shadow a bundled pack with its own
without editing it:

    1. $MCPG_CONNECTORS_DIR   (os.pathsep-separated; highest precedence)
    2. ~/.config/mcp-gateway/connectors   (per-user installs; honors $XDG_CONFIG_HOME)
    3. the repo's top-level connectors/   (bundled packs, alongside policies/)

`find_connector` fails closed: an unknown name is a `ConnectorError`, and a name
that resolves to a malformed directory surfaces the precise load error rather
than being silently skipped. `list_connectors` is tolerant — it skips
directories that are not connectors (no manifest) or fail to load, so one broken
pack can't hide the usable ones; use `show`/`find` to diagnose a specific pack.

Bundled-pack resolution is by path relative to the source tree, which covers the
git-clone / editable-install workflow connector authors use. Shipping bundled
packs inside the installed wheel is a packaging follow-up (docs/PLAN.md Phase 12).
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from mcp_gateway.connectors.base import MANIFEST, Connector, load_connector
from mcp_gateway.core.errors import ConnectorError

_ENV_VAR = "MCPG_CONNECTORS_DIR"


def _user_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "mcp-gateway" / "connectors"


def _bundled_dir() -> Path:
    # registry.py -> connectors -> mcp_gateway -> src -> <repo root>/connectors
    return Path(__file__).resolve().parents[3] / "connectors"


def search_paths() -> list[Path]:
    """The ordered connector search paths (highest precedence first)."""
    paths: list[Path] = []
    env = os.environ.get(_ENV_VAR)
    if env:
        paths.extend(Path(p) for p in env.split(os.pathsep) if p)
    paths.append(_user_dir())
    paths.append(_bundled_dir())
    return paths


def _candidate_dirs(paths: list[Path] | None) -> Iterator[tuple[str, Path]]:
    """Yield (name, dir) for every directory that looks like a connector,
    honoring precedence: a name seen in an earlier path shadows later ones."""
    seen: set[str] = set()
    for root in paths if paths is not None else search_paths():
        if not root.is_dir():
            continue
        for child in sorted(root.iterdir()):
            if not child.is_dir() or child.name in seen:
                continue
            if (child / MANIFEST).is_file():
                seen.add(child.name)
                yield child.name, child


def list_connectors(paths: list[Path] | None = None) -> list[Connector]:
    """Every loadable connector, one per name (precedence-resolved).

    Tolerant: a directory that fails to load is skipped so a single broken pack
    can't hide the rest. `find_connector` surfaces the error for a named pack.
    """
    out: list[Connector] = []
    for _name, path in _candidate_dirs(paths):
        try:
            out.append(load_connector(path))
        except ConnectorError:
            continue
    return sorted(out, key=lambda c: c.name)


def find_connector(name: str, paths: list[Path] | None = None) -> Connector:
    """Resolve `name` to a connector, or raise ConnectorError.

    A directory named `name` that fails validation raises the precise load error
    (not "unknown"), so a typo and a malformed pack are distinguishable.
    """
    for root in paths if paths is not None else search_paths():
        candidate = root / name
        if candidate.is_dir() and (candidate / MANIFEST).is_file():
            return load_connector(candidate)
    searched = ", ".join(str(p) for p in (paths if paths is not None else search_paths()))
    raise ConnectorError(f"unknown connector {name!r} (searched: {searched})")
