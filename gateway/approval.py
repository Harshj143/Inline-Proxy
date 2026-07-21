"""Human-in-the-loop approval for high-risk tool calls.

Some actions shouldn't be decided by static policy alone: a destructive admin
operation, a large data export, anything you'd want a human to sign off on in
the moment. The `require_approval` policy action routes such calls here.

This is the miniature of Formal's JIT-access / MFA actions: instead of a hard
allow/block, the gateway PAUSES and asks an approver. On approval the call
proceeds (as its `then` action); on denial it is blocked.

The broker is deliberately pluggable and FAIL-CLOSED:

  mode="deny"      (default) no approver is wired up, so every request is
                   denied. Safe default: a misconfigured gateway never
                   silently waves through a call meant for human review.
  mode="allow"     auto-approve everything (dev / testing only).
  mode="callback"  delegate to a caller-supplied function. A real deployment
                   would post to Slack / PagerDuty / an approvals UI and block
                   on the response; the demo injects a scripted approver here.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class ApprovalResult:
    approved: bool
    approver: str
    note: str = ""


# A callback takes (tool, arguments, role, reason) and returns an ApprovalResult.
ApprovalCallback = Callable[[str, dict, Optional[str], str], ApprovalResult]


class ApprovalBroker:
    def __init__(
        self,
        mode: str = "deny",
        callback: ApprovalCallback | None = None,
        url: str | None = None,
        timeout: float = 300.0,
        session_id: str | None = None,
    ):
        if mode not in {"deny", "allow", "callback", "http"}:
            raise ValueError(f"invalid approval mode: {mode!r}")
        if mode == "callback" and callback is None:
            raise ValueError("approval mode 'callback' requires a callback")
        if mode == "http" and not url:
            raise ValueError("approval mode 'http' requires --approvals-url")
        self.mode = mode
        self.callback = callback
        self.url = url
        self.timeout = timeout
        self.session_id = session_id  # set by the gateway after construction

    def request(
        self, tool: str, arguments: dict, role: str | None, reason: str
    ) -> ApprovalResult:
        if self.mode == "allow":
            return ApprovalResult(True, approver="auto-allow",
                                  note="approval mode=allow")
        if self.mode == "callback":
            return self.callback(tool, arguments, role, reason)
        if self.mode == "http":
            return self._request_http(tool, arguments, role, reason)
        # mode == "deny": fail closed.
        return ApprovalResult(
            False, approver="none",
            note="no human approver configured; failing closed",
        )

    def _request_http(
        self, tool: str, arguments: dict, role: str | None, reason: str
    ) -> ApprovalResult:
        """Post the pending call to the console and BLOCK until a human clicks
        Approve/Deny (the console holds the response open). Any failure —
        console down, timeout, bad response — fails CLOSED."""
        payload = json.dumps({
            "tool": tool, "arguments": arguments, "role": role,
            "reason": reason, "session_id": self.session_id,
        }).encode("utf-8")
        req = urllib.request.Request(
            self.url.rstrip("/") + "/api/approvals",
            data=payload, headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return ApprovalResult(
                approved=bool(data.get("approved")),
                approver=data.get("approver", "console"),
                note=data.get("note", ""),
            )
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return ApprovalResult(
                False, approver="none",
                note=f"console approval unavailable ({exc}); failing closed",
            )
