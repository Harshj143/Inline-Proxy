"""The ActionHandler interface.

An action is what the gateway DOES with a call the matcher selected: pass it,
refuse it, transform it, or change how its response is treated. Handlers are
looked up by name from the registry in `policy.actions`; adding an action is
adding a file, not editing the engine.

`terminal_deny` marks handlers that (in the current build) always refuse the
call — `block` permanently; `redact`/`require_approval` until their phases
land. The tools/list filter uses it: a tool whose action can only deny is
hidden from the model entirely.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from mcp_gateway.core.context import CallContext, Decision
from mcp_gateway.core.outcome import StageOutcome


class ActionHandler(ABC):
    #: The policy `action:` value this handler executes.
    name: str
    #: True if this handler can only deny in the current build (see module docstring).
    terminal_deny: bool = False

    @abstractmethod
    async def on_request(self, ctx: CallContext, decision: Decision) -> StageOutcome:
        """Execute the action's request-stage behavior."""
