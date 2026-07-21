"""MCP-specific protocol knowledge, kept out of the generic JSON-RPC codec."""

from __future__ import annotations

from typing import Any

from mcp_gateway.protocol.jsonrpc import JsonRpcMessage, encode

METHOD_INITIALIZE = "initialize"
METHOD_TOOLS_LIST = "tools/list"
METHOD_TOOLS_CALL = "tools/call"


def is_tool_call(msg: JsonRpcMessage) -> bool:
    return msg.method == METHOD_TOOLS_CALL and msg.is_request


def tool_call_parts(msg: JsonRpcMessage) -> tuple[str, dict[str, Any]]:
    """Extract (tool_name, arguments) from a tools/call request.

    Missing/malformed fields degrade to ("<unknown>", {}) rather than raising:
    a malformed call still flows through policy, where an unknown tool meets
    the default action — fail-closed by construction under default-deny.
    """
    params = msg.params
    name = params.get("name")
    args = params.get("arguments")
    return (
        name if isinstance(name, str) and name else "<unknown>",
        args if isinstance(args, dict) else {},
    )


def result_is_error(raw: dict[str, Any]) -> bool:
    """True for JSON-RPC error responses and for MCP tool-level errors.

    MCP distinguishes protocol errors (the JSON-RPC "error" member) from tool
    execution failures (result.isError). Audit wants to know about both.
    """
    if "error" in raw:
        return True
    result = raw.get("result")
    return isinstance(result, dict) and result.get("isError") is True


def result_size_bytes(raw: dict[str, Any]) -> int:
    """Encoded size of the result payload, for audit and (later) budget checks."""
    body = raw.get("result", raw.get("error"))
    if body is None:
        return 0
    return len(encode(body).encode("utf-8"))
