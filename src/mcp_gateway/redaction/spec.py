"""RedactionSpec — the per-rule redaction configuration a policy carries.

A tool rule with `action: redact` selects a profile and, optionally, refines
it: keys to never touch, literal values to always/never redact. This is the
bridge object between the policy engine (which produces it from YAML) and the
redaction service (which executes it) — kept in its own dependency-free module
so neither side imports the other.

Policy shapes accepted (validated in policy.loader):

    redaction: standard                 # just a profile name
    redaction:                          # or a refined form
      profile: strict
      exclude_keys: [id, file_path]     # never redact values under these keys
      allowlist: [example.com]          # never treat these literals as sensitive
      denylist: [Project-Bluebird]      # always redact these literals
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

DEFAULT_PROFILE = "standard"


@dataclass(frozen=True, slots=True)
class RedactionSpec:
    profile: str = DEFAULT_PROFILE
    exclude_keys: frozenset[str] = field(default_factory=frozenset)
    allowlist: frozenset[str] = field(default_factory=frozenset)
    denylist: frozenset[str] = field(default_factory=frozenset)
    context_words: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_config(cls, config: Any) -> RedactionSpec:
        """Build from an already-validated policy value (string or mapping)."""
        if config is None:
            return cls()
        if isinstance(config, str):
            return cls(profile=config)
        return cls(
            profile=config.get("profile", DEFAULT_PROFILE),
            exclude_keys=frozenset(config.get("exclude_keys", ())),
            allowlist=frozenset(config.get("allowlist", ())),
            denylist=frozenset(config.get("denylist", ())),
            context_words=frozenset(config.get("context_words", ())),
        )

    def describe(self) -> dict[str, Any]:
        out: dict[str, Any] = {"profile": self.profile}
        if self.exclude_keys:
            out["exclude_keys"] = sorted(self.exclude_keys)
        if self.allowlist:
            out["allowlist"] = sorted(self.allowlist)
        if self.denylist:
            out["denylist"] = sorted(self.denylist)
        if self.context_words:
            out["context_words"] = sorted(self.context_words)
        return out
