"""HTTP approval channel — POST the request, block for a human decision.

Contract: POST the request JSON (models.ApprovalRequest.to_wire) to the URL;
the approver holds the connection until a human decides, then responds with
`{"approved": bool, "approver": str, "note": str}`. The console (Phase 4)
implements this endpoint; any approvals UI or a Slack/PagerDuty bridge can too.

Uses stdlib urllib in a worker thread — no new dependency on the hot path. The
broker imposes the overall deadline and fail-closed conversion; this channel
just performs the round-trip and surfaces failures as exceptions.
"""

from __future__ import annotations

import asyncio
import json
import urllib.request

from mcp_gateway.approvals.channels.base import ApprovalChannel
from mcp_gateway.approvals.models import ApprovalRequest, Resolution


class HttpChannel(ApprovalChannel):
    name = "http"

    def __init__(self, url: str, timeout: float = 300.0):
        # Endpoint the tool-call approval is POSTed to.
        self.url = url.rstrip("/") + "/api/approvals"
        self.timeout = timeout

    async def request(self, req: ApprovalRequest) -> Resolution:
        data = await asyncio.to_thread(self._post, req.to_wire())
        return Resolution(
            approved=bool(data["approved"]),
            approver=str(data.get("approver", "console")),
            note=str(data.get("note", "")),
        )

    def _post(self, payload: dict) -> dict:
        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as resp:  # noqa: S310
            return json.loads(resp.read())
