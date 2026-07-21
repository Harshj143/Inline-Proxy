"""Tool-name matching: exact > glob > default.

Precedence, in order:
  1. An exact rule (no wildcard characters) always beats any glob.
  2. Among matching globs, the most SPECIFIC pattern wins — specificity is
     the count of literal (non-wildcard) characters, so `github.repos.*`
     beats `github.*`.
  3. On equal specificity, the later-merged pattern wins, which makes a
     company override that restates a pack's glob deterministically take
     effect.

Glob syntax is fnmatch (`*`, `?`, `[seq]`), case-sensitive.
"""

from __future__ import annotations

import fnmatch
import re

_WILDCARD = set("*?[")


def is_glob(pattern: str) -> bool:
    return any(ch in _WILDCARD for ch in pattern)


def specificity(pattern: str) -> int:
    return sum(1 for ch in pattern if ch not in _WILDCARD)


class RuleMatcher:
    def __init__(self, patterns: list[str]):
        """`patterns` in merged declaration order (order breaks specificity ties)."""
        self._exact: set[str] = set()
        self._globs: list[tuple[str, re.Pattern, int, int]] = []
        for index, pattern in enumerate(patterns):
            if is_glob(pattern):
                self._globs.append(
                    (pattern, re.compile(fnmatch.translate(pattern)),
                     specificity(pattern), index)
                )
            else:
                self._exact.add(pattern)

    def match(self, tool: str) -> str | None:
        """Return the winning pattern for this tool, or None (→ default action)."""
        if tool in self._exact:
            return tool
        best: tuple[int, int, str] | None = None
        for pattern, regex, spec, index in self._globs:
            if regex.match(tool) and (best is None or (spec, index) > best[:2]):
                best = (spec, index, pattern)
        return best[2] if best else None
