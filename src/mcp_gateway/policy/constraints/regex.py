"""The built-in regex constraint.

Config shape (inside a tool rule):

    constraints:
      - arg: sql                      # type: regex is the default
        must_match: "^\\s*SELECT\\b"  # call denied unless this matches
        flags: i
        reason: only read-only SELECT statements are permitted
      - arg: url
        must_not_match: "\\.internal\\."   # call denied if this matches

At least one of must_match / must_not_match is required; both may be given.
A missing argument is checked as the empty string, so a `must_match`
constraint also denies calls that omit the argument entirely (fail closed —
an absent value cannot satisfy a positive requirement).
"""

from __future__ import annotations

import re
from typing import Any

from mcp_gateway.core.errors import PolicyError
from mcp_gateway.policy.constraints.base import Constraint

_ALLOWED_FIELDS = {"type", "arg", "must_match", "must_not_match", "flags", "reason"}


class RegexConstraint(Constraint):
    type_name = "regex"

    def __init__(
        self,
        arg: str,
        must_match: re.Pattern | None,
        must_not_match: re.Pattern | None,
        reason: str | None,
    ):
        self.arg = arg
        self.must_match = must_match
        self.must_not_match = must_not_match
        self.reason = reason

    @classmethod
    def from_config(cls, config: dict[str, Any], where: str) -> RegexConstraint:
        unknown = set(config) - _ALLOWED_FIELDS
        if unknown:
            raise PolicyError(f"{where}: unknown constraint field(s) {sorted(unknown)}")

        arg = config.get("arg")
        if not isinstance(arg, str) or not arg:
            raise PolicyError(f"{where}: constraint requires a non-empty 'arg'")

        if "must_match" not in config and "must_not_match" not in config:
            raise PolicyError(
                f"{where}: constraint requires 'must_match' and/or 'must_not_match'"
            )

        flags_spec = config.get("flags", "")
        if not isinstance(flags_spec, str) or set(flags_spec) - {"i"}:
            raise PolicyError(f"{where}: 'flags' supports only 'i', got {flags_spec!r}")
        flags = re.IGNORECASE if "i" in flags_spec else 0

        def compile_pattern(key: str) -> re.Pattern | None:
            raw = config.get(key)
            if raw is None:
                return None
            if not isinstance(raw, str):
                raise PolicyError(f"{where}: {key} must be a string")
            try:
                return re.compile(raw, flags)
            except re.error as exc:
                raise PolicyError(f"{where}: invalid regex for {key}: {exc}") from None

        return cls(
            arg=arg,
            must_match=compile_pattern("must_match"),
            must_not_match=compile_pattern("must_not_match"),
            reason=config.get("reason"),
        )

    def check(self, arguments: dict[str, Any]) -> str | None:
        value = str(arguments.get(self.arg, ""))
        if self.must_match is not None and not self.must_match.search(value):
            return self.reason or (
                f"argument '{self.arg}' does not satisfy required pattern "
                f"{self.must_match.pattern!r}"
            )
        if self.must_not_match is not None and self.must_not_match.search(value):
            return self.reason or (
                f"argument '{self.arg}' matches forbidden pattern "
                f"{self.must_not_match.pattern!r}"
            )
        return None

    def describe(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": self.type_name, "arg": self.arg}
        if self.must_match is not None:
            out["must_match"] = self.must_match.pattern
        if self.must_not_match is not None:
            out["must_not_match"] = self.must_not_match.pattern
        if self.reason:
            out["reason"] = self.reason
        return out
