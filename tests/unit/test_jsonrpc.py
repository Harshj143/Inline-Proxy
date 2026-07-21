"""Codec behavior: classification, opaque handling, error shapes."""

import json

from mcp_gateway.protocol.jsonrpc import (
    ERROR_POLICY_DENIED,
    decode_line,
    denied_response,
    encode,
    error_response,
)


def test_decode_request():
    msg = decode_line('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t"}}')
    assert msg is not None
    assert msg.is_request and not msg.is_notification and not msg.is_response
    assert msg.id == 1
    assert msg.method == "tools/call"
    assert msg.params == {"name": "t"}


def test_decode_notification():
    msg = decode_line('{"jsonrpc":"2.0","method":"notifications/initialized"}')
    assert msg is not None
    assert msg.is_notification and not msg.is_request and not msg.is_response


def test_decode_response_result_and_error():
    ok = decode_line('{"jsonrpc":"2.0","id":7,"result":{}}')
    err = decode_line('{"jsonrpc":"2.0","id":8,"error":{"code":-1,"message":"x"}}')
    assert ok is not None and ok.is_response
    assert err is not None and err.is_response


def test_null_id_is_not_correlatable_request():
    # JSON-RPC: an explicit null id cannot be correlated; treat like a notification.
    msg = decode_line('{"jsonrpc":"2.0","id":null,"method":"m"}')
    assert msg is not None
    assert msg.is_notification and not msg.is_request


def test_decode_garbage_returns_none():
    assert decode_line("not json at all") is None
    assert decode_line('"a bare string"') is None
    assert decode_line("[1,2,3]") is None


def test_encode_is_single_line_and_lossless():
    raw = {"jsonrpc": "2.0", "id": "x", "params": {"text": "line1 ünïcode"}}
    encoded = encode(raw)
    assert "\n" not in encoded
    assert json.loads(encoded) == raw


def test_error_and_denied_response_shape():
    err = error_response(3, -32000, "boom")
    assert err["id"] == 3 and err["error"]["code"] == -32000

    denied = denied_response(4, "db.execute_sql", "raw SQL forbidden")
    assert denied["error"]["code"] == ERROR_POLICY_DENIED
    assert "db.execute_sql" in denied["error"]["message"]
    assert "never reached the upstream server" in denied["error"]["message"]
