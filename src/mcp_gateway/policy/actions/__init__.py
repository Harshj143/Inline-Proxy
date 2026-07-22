"""Action handler registry.

The action vocabulary IS this registry: the loader validates `action:`
values against it, the pipeline dispatches through it, and the tools/list
filter derives visibility from each handler's `terminal_deny`. One source
of truth; adding an action means adding a handler file and registering it.
"""

from __future__ import annotations

from mcp_gateway.policy.actions.allow import AllowHandler
from mcp_gateway.policy.actions.approval import RequireApprovalHandler
from mcp_gateway.policy.actions.base import ActionHandler
from mcp_gateway.policy.actions.block import BlockHandler
from mcp_gateway.policy.actions.quarantine import QuarantineHandler
from mcp_gateway.policy.actions.redact import RedactHandler
from mcp_gateway.policy.actions.rewrite import RewriteHandler

ACTIONS: dict[str, ActionHandler] = {
    handler.name: handler
    for handler in (
        AllowHandler(),
        BlockHandler(),
        RedactHandler(),
        RewriteHandler(),
        QuarantineHandler(),
        RequireApprovalHandler(),
    )
}

ACTION_VOCABULARY = frozenset(ACTIONS)


def register_action(handler: ActionHandler) -> None:
    ACTIONS[handler.name] = handler


def denying_actions() -> frozenset[str]:
    """Actions that can only refuse a call with the default (stub) registry.

    A gateway that enables a service-backed redact handler computes its own
    narrower set (see gateway tools/list filtering); this global default is
    the fail-closed baseline.
    """
    return frozenset(name for name, h in ACTIONS.items() if h.terminal_deny)


__all__ = [
    "ACTIONS",
    "ACTION_VOCABULARY",
    "ActionHandler",
    "denying_actions",
    "register_action",
]
