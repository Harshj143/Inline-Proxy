"""Central mode: the multi-upstream HTTP gateway service (Phase 5).

Sidecar mode wraps one server from the command line; central mode runs one
long-lived service that fronts many MCP servers over Streamable HTTP, each bound
to its own policy pack. This package holds the config model and the assembly
that turns a `gateway.yaml` into a running app.

FastAPI/uvicorn live behind the `[server]` extra; import lazily.
"""

from __future__ import annotations
