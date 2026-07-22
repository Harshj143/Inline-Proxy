"""Approval request/response value objects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    request_id: Any        # the JSON-RPC id of the tool call
    session_id: str
    tool: str
    arguments: dict[str, Any]
    principal: str
    reason: str

    def to_wire(self) -> dict[str, Any]:
        """The JSON an HTTP approver receives.

        Arguments are included so a human can judge the call; a deployment
        handling sensitive arguments should redact this preview before it
        leaves the trust boundary (a follow-up once the console is the
        approver — Phase 4).
        """
        return {
            "request_id": self.request_id,
            "session_id": self.session_id,
            "tool": self.tool,
            "arguments": self.arguments,
            "principal": self.principal,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class Resolution:
    approved: bool
    approver: str
    note: str = ""

    @classmethod
    def fail_closed(cls, note: str) -> Resolution:
        return cls(approved=False, approver="system", note=f"fail-closed: {note}")
