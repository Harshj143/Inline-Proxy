"""Approval channels — where an approval request is sent for a decision."""

from mcp_gateway.approvals.channels.base import ApprovalChannel
from mcp_gateway.approvals.channels.http import HttpChannel
from mcp_gateway.approvals.channels.local import AllowChannel, DenyChannel

__all__ = ["AllowChannel", "ApprovalChannel", "DenyChannel", "HttpChannel"]
