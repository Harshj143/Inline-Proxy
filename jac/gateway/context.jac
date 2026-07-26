"""Typed call state carried through the Jac enforcement graph.

The transport owns I/O, while this context is the single source of truth for
the engine's decision. Audit code may serialize decisions and redaction counts,
but must never serialize arguments, result text, or scrubbed values.
"""

obj Principal {
    has sub: str = "local",
        roles: list[str] = [];
}

obj Violation {
    has arg: str,
        reason: str;
}

obj RedactionReport {
    has total: int = 0,
        entity_counts: dict[str, int] = {},
        scrubbed: str = "";
}

obj Decision {
    has action: str = "block",
        rule: str = "default",
        reason: str = "no matching rule (default-deny)",
        redaction: str = "",
        then: str = "",
        risk_delta: int = 0;
}

obj CallContext {
    has session_id: str,
        principal: Principal,
        tool: str,
        args: dict[str, any] = {},
        request_id: int = 0,
        decision: Decision = Decision(),
        report: RedactionReport = RedactionReport(),
        violations: list[Violation] = [],
        is_source: bool = False,
        is_sink: bool = False,
        result_text: str = "",
        trace: list[str] = [];
}
