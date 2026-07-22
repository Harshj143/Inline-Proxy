"""The ApprovalChannel interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mcp_gateway.approvals.models import ApprovalRequest, Resolution


class ApprovalChannel(ABC):
    #: Name for audit/logging.
    name: str
    #: Whether this channel can ever return an approval. False for the deny
    #: channel, which lets tools/list hide a tool that can only be refused.
    can_approve: bool = True

    @abstractmethod
    async def request(self, req: ApprovalRequest) -> Resolution:
        """Ask for a decision. May block awaiting a human; the broker imposes
        the deadline and converts any failure to a fail-closed denial."""
