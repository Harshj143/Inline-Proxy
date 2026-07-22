"""Drop operator: remove the value entirely, leaving a minimal marker.

Use when even the presence/shape of the placeholder is more than the model
should see. Leaves a short typed marker so the surrounding text stays readable
rather than silently losing content.
"""

from __future__ import annotations

from mcp_gateway.redaction.operators.base import Operator
from mcp_gateway.redaction.spans import Span


class DropOperator(Operator):
    name = "drop"

    def apply(self, span: Span) -> str:
        return "█" * 3  # ███ — visibly removed, no value, no length leak
