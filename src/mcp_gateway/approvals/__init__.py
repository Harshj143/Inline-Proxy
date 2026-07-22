"""Human-in-the-loop approvals for high-risk tool calls.

Some actions shouldn't be decided by static policy alone — a destructive admin
operation, a large export, anything you'd want a human to sign off on in the
moment. The `require_approval` policy action routes such calls here: the
gateway PAUSES, asks an approver, and on approval proceeds as the rule's `then`
action; on denial it blocks (and scores risk).

The broker is pluggable and FAIL-CLOSED — a timeout, an unreachable approver,
or a malformed response all resolve to DENY, because a security control that
waves a call through when the approver is unavailable is worthless.
"""

from mcp_gateway.approvals.broker import ApprovalBroker, build_broker
from mcp_gateway.approvals.models import ApprovalRequest, Resolution

__all__ = ["ApprovalBroker", "ApprovalRequest", "Resolution", "build_broker"]
