"""Single-flight stdio MCP proxy backed by the Jac enforcement graph.

The wrapper owns transport execution; gateway.pipeline only decides. Every
tools/call is checked before forwarding, and every textual result is processed
before delivery. A blocked call is never written to the upstream process.
"""

import sys;
import json;
import os;
import subprocess;
import from gateway.context { CallContext }
import from gateway.policy { Policy, load_policy, match }
import from gateway.pipeline {
    Session,
    get_session,
    police_request,
    handle_response,
    audit_request
}

def _write_message(message: dict[str, any]) {
    print(json.dumps(message), flush=True);
}

def _error_response(request_id: any, message: str) -> dict[str, any] {
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32001,
            "message": "denied by Jac security gateway: " + message
        }
    };
}

def _result_text(message: dict[str, any]) -> str {
    try {
        result = message.get("result", {}) as dict[str, any];
        content = result.get("content", []) as list[dict[str, any]];
        if content {
            return str(content[0].get("text", ""));
        }
    } except Exception {
        return "";
    }
    return "";
}

def _filter_tools(message: dict[str, any], policy: Policy, role: str) {
    try {
        result = message.get("result", {}) as dict[str, any];
        tools = result.get("tools", []) as list[dict[str, any]];
        visible: list[dict[str, any]] = [];
        for tool in tools {
            name = str(tool.get("name", ""));
            effective = match(policy, name, role);
            if effective.action not in ["block", "require_approval"] {
                visible.append(tool);
            }
        }
        result["tools"] = visible;
    } except Exception {
        # Filtering is a security boundary: an inspection failure exposes none.
        result = message.get("result", {}) as dict[str, any];
        result["tools"] = [];
    }
}

def _forward(upstream: any, message: dict[str, any]) -> dict[str, any] {
    upstream.stdin.write(json.dumps(message) + "\n");
    upstream.stdin.flush();
    response_line = upstream.stdout.readline();
    if not response_line {
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": {
                "code": -32603,
                "message": "upstream MCP server closed without a response"
            }
        };
    }
    return json.loads(response_line as str) as dict[str, any];
}

def _forward_notification(upstream: any, message: dict[str, any]) {
    upstream.stdin.write(json.dumps(message) + "\n");
    upstream.stdin.flush();
}

def _protect_response(
    response: dict[str, any],
    ctx: CallContext,
    policy: Policy,
    session: Session,
    audit_path: str
) {
    if "result" not in response {
        return;
    }
    result = response.get("result", {}) as dict[str, any];
    content = result.get("content", []) as list[dict[str, any]];

    if ctx.decision.action == "quarantine" {
        withheld = handle_response(ctx, policy, session, "", audit_path);
        result["content"] = [{"type": "text", "text": withheld}];
        return;
    }

    if ctx.decision.action == "redact" {
        for item in content {
            if str(item.get("type", "")) != "text" {
                ctx.decision.action = "quarantine";
                ctx.decision.reason = "non-text result cannot be safely redacted";
                withheld = handle_response(ctx, policy, session, "", audit_path);
                result["content"] = [{"type": "text", "text": withheld}];
                return;
            }
        }

        # Scan the complete MCP result, including structuredContent and metadata,
        # rather than assuming sensitive values live in the first text item.
        encoded = json.dumps(result);
        scrubbed_encoded = handle_response(ctx, policy, session, encoded, audit_path);
        try {
            scrubbed_result = json.loads(scrubbed_encoded) as dict[str, any];
            response["result"] = scrubbed_result;
        } except Exception {
            ctx.decision.action = "quarantine";
            ctx.decision.reason = "redacted result could not be safely reconstructed";
            withheld = handle_response(ctx, policy, session, "", audit_path);
            response["result"] = {"content": [{"type": "text", "text": withheld}]};
        }
        return;
    }

    # Allow/rewrite results are delivered unchanged, but still audited.
    handle_response(ctx, policy, session, _result_text(response), audit_path);
}

def _handle_tool_call(
    upstream: any,
    message: dict[str, any],
    policy: Policy,
    session: Session,
    audit_path: str,
    roles: list[str]
) -> dict[str, any] {
    params = message.get("params", {}) as dict[str, any];
    tool = str(params.get("name", ""));
    arguments = params.get("arguments", {}) as dict[str, any];
    request_id = message.get("id", 0);
    numeric_id = request_id if isinstance(request_id, int) else 0;
    ctx = police_request(session, policy, tool, arguments, roles, numeric_id);
    audit_request(ctx, session, audit_path);

    if ctx.decision.action == "block" {
        return _error_response(request_id, ctx.decision.reason);
    }

    params["arguments"] = ctx.args;
    response = _forward(upstream, message);
    _protect_response(response, ctx, policy, session, audit_path);
    return response;
}

with entry:__main__ {
    if len(sys.argv) < 5 or "--" not in sys.argv {
        raise ValueError("usage: wrap.jac <policy> <audit> -- <server command...>");
    }
    separator = sys.argv.index("--");
    policy_path = str(sys.argv[1]);
    audit_path = str(sys.argv[2]);
    server_command = sys.argv[separator + 1:] as list[str];
    policy = load_policy(policy_path);
    role = str(os.environ.get("JAC_GATEWAY_ROLE", ""));
    roles: list[str] = [role] if role else [];
    session_id = str(
        os.environ.get(
            "JAC_GATEWAY_SESSION_ID", "jac-wrap-" + str(os.getpid())
        )
    );
    session = get_session(session_id, roles);
    upstream = subprocess.Popen(
        server_command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1
    );

    try {
        for raw_line in sys.stdin {
            line = raw_line.strip();
            if not line {
                continue;
            }
            message = json.loads(line) as dict[str, any];
            method = str(message.get("method", ""));

            if method == "tools/call" {
                _write_message(
                    _handle_tool_call(
                        upstream, message, policy, session, audit_path, roles
                    )
                );
            } elif message.get("id") is None {
                _forward_notification(upstream, message);
            } else {
                response = _forward(upstream, message);
                if method == "tools/list" and "result" in response {
                    _filter_tools(response, policy, role);
                }
                _write_message(response);
            }
        }
    } finally {
        if upstream.stdin {
            upstream.stdin.close();
        }
        upstream.wait(timeout=5);
    }
}
