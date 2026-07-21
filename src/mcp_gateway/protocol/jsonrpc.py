"""JSON-RPC 2.0 codec for newline-delimited MCP stdio framing.

The gateway is an interceptor, not a translator: it parses just enough of
each line to classify and route it, and anything it cannot parse is passed
through opaquely (misframed traffic is the upstream pair's problem to
resolve, not ours to judge — but it is audited).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

JSONRPC_VERSION = "2.0"

# JSON-RPC reserves -32000..-32099 for implementation-defined server errors.
ERROR_POLICY_DENIED = -32001


@dataclass(frozen=True, slots=True)
class JsonRpcMessage:
    """One parsed JSON-RPC message, wrapping the raw dict.

    The raw dict is kept verbatim: when the gateway forwards a message it
    re-encodes exactly what it received (minus any deliberate rewrite),
    never a lossy reconstruction.
    """

    raw: dict[str, Any]

    @property
    def id(self) -> Any:
        # None both for notifications and for `"id": null`; JSON-RPC treats
        # a null id as "no usable id" for correlation either way.
        return self.raw.get("id")

    @property
    def method(self) -> str | None:
        method = self.raw.get("method")
        return method if isinstance(method, str) else None

    @property
    def params(self) -> dict[str, Any]:
        params = self.raw.get("params")
        return params if isinstance(params, dict) else {}

    @property
    def is_request(self) -> bool:
        return self.method is not None and self.id is not None

    @property
    def is_notification(self) -> bool:
        return self.method is not None and self.id is None

    @property
    def is_response(self) -> bool:
        return self.method is None and ("result" in self.raw or "error" in self.raw)


def decode_line(line: str) -> JsonRpcMessage | None:
    """Parse one wire line. Returns None for anything that is not a JSON object."""
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(raw, dict):
        return None
    return JsonRpcMessage(raw)


def encode(payload: dict[str, Any]) -> str:
    """Compact single-line encoding; framing forbids embedded newlines."""
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def denied_response(request_id: Any, tool: str, reason: str) -> dict[str, Any]:
    """The error a client sees for a policy denial.

    Deliberately explicit that the *gateway* denied the call and the request
    never reached the server — an agent that understands why it was refused
    wastes fewer turns retrying, and a human reading the transcript sees
    exactly which control fired.
    """
    return error_response(
        request_id,
        ERROR_POLICY_DENIED,
        f"Tool call '{tool}' denied by security gateway policy ({reason}). "
        f"The request never reached the upstream server.",
    )
