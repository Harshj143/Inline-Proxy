"""rewrite — allow the call, but first rewrite its arguments to a safe form.

Two operations, mirroring the proven prototype semantics:

    rewrites:
      - arg: read_only
        set: true                      # force a fixed value
      - arg: sql
        append: " LIMIT 1000"          # append to a string argument…
        unless_match: "\\blimit\\b"    # …unless this regex already matches
        flags: i

Rewrites run AFTER constraints (a rewrite must never launder a call past a
constraint) and the changes are recorded on the context for audit.
"""

from __future__ import annotations

import re
from typing import Any

from mcp_gateway.core.context import CallContext, Decision
from mcp_gateway.core.errors import PolicyError
from mcp_gateway.core.outcome import StageOutcome, proceed
from mcp_gateway.policy.actions.base import ActionHandler

_ALLOWED_FIELDS = {"arg", "set", "append", "unless_match", "flags"}


def validate_rewrite(config: Any, where: str) -> None:
    """Load-time validation; typos in policy must not reach runtime."""
    if not isinstance(config, dict):
        raise PolicyError(f"{where}: rewrite must be an object")
    unknown = set(config) - _ALLOWED_FIELDS
    if unknown:
        raise PolicyError(f"{where}: unknown rewrite field(s) {sorted(unknown)}")
    if not isinstance(config.get("arg"), str) or not config["arg"]:
        raise PolicyError(f"{where}: rewrite requires a non-empty 'arg'")
    has_set, has_append = "set" in config, "append" in config
    if has_set == has_append:  # neither, or both
        raise PolicyError(f"{where}: rewrite requires exactly one of 'set' or 'append'")
    if "unless_match" in config:
        if not has_append:
            raise PolicyError(f"{where}: 'unless_match' only applies to 'append'")
        try:
            re.compile(config["unless_match"])
        except re.error as exc:
            raise PolicyError(f"{where}: invalid unless_match regex: {exc}") from None
    flags = config.get("flags", "")
    if not isinstance(flags, str) or set(flags) - {"i"}:
        raise PolicyError(f"{where}: 'flags' supports only 'i', got {flags!r}")


def apply_rewrites(
    arguments: dict[str, Any], rewrites: list[dict[str, Any]]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return (new_arguments, changes). Pure function; never mutates input."""
    new_args = dict(arguments)
    changes: list[dict[str, Any]] = []
    for r in rewrites:
        arg = r["arg"]
        if "set" in r:
            if new_args.get(arg) != r["set"]:
                changes.append({"arg": arg, "op": "set", "to": r["set"]})
                new_args[arg] = r["set"]
        else:  # append
            value = str(new_args.get(arg, ""))
            guard = r.get("unless_match")
            flags = re.IGNORECASE if "i" in r.get("flags", "") else 0
            if guard and re.search(guard, value, flags):
                continue  # requirement already satisfied; leave it alone
            new_args[arg] = value + r["append"]
            changes.append({"arg": arg, "op": "append", "added": r["append"]})
    return new_args, changes


class RewriteHandler(ActionHandler):
    name = "rewrite"

    async def on_request(self, ctx: CallContext, decision: Decision) -> StageOutcome:
        new_args, changes = apply_rewrites(ctx.arguments, decision.rewrites)
        if changes:
            ctx.effective_arguments = new_args
            ctx.argument_changes = changes
        return proceed()
