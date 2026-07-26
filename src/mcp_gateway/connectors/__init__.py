"""The connector framework: curated security packs, one per MCP server.

`base.py` defines what a connector *is* (a validated directory bundle) and how
it resolves to policy layers; `registry.py` finds connectors by name across
search paths; `scaffold.py` generates a new connector skeleton. Concrete packs
(github, slack, …) live in the repo's top-level `connectors/` directory,
authored purely from framework + policy primitives.
"""

from __future__ import annotations

from mcp_gateway.connectors.base import Connector, load_connector
from mcp_gateway.connectors.registry import (
    find_connector,
    list_connectors,
    search_paths,
)

__all__ = [
    "Connector",
    "load_connector",
    "find_connector",
    "list_connectors",
    "search_paths",
]
