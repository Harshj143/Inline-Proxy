"""Minimal MCP server whose tool result contains planted secrets + PII.

Used by test_wrap_redaction to prove the gateway scrubs a real GitHub PAT,
AWS key, email, and a password-named field out of a tool result before it
reaches the client. Stdlib only.
"""

import json
import sys

# A record a naive server would hand straight to the model: validated PII plus
# live credentials plus a value that only a key NAME reveals as sensitive.
RECORD = {
    "name": "Ada Verne",
    "email": "ada.verne@example.com",
    "ssn": "544-21-1290",
    "aws_key": "AKIAIOSFODNN7EXAMPLE",
    "github_token": "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
    "password": "hunter2-not-a-pattern",
    "file_path": "/vault/records/ada.json",
}

TOOLS = [{
    "name": "vault.read",
    "description": "Read a secret-bearing record",
    "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
}]


def handle(msg):
    method, mid = msg.get("method"), msg.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": "2025-03-26",
            "serverInfo": {"name": "redaction-mock", "version": "0.1.0"},
            "capabilities": {"tools": {}}}}
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "content": [{"type": "text", "text": json.dumps(RECORD)}]}}
    return {"jsonrpc": "2.0", "id": mid,
            "error": {"code": -32601, "message": f"unknown method {method}"}}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        reply = handle(json.loads(line))
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
