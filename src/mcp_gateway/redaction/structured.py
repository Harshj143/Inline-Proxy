"""Structured (key-aware) redaction.

Detectors scan *values*; this scans *key names*. A field literally named
`password` holding `hunter2` is invisible to every content pattern — nothing
about "hunter2" says secret — but the key name is a dead giveaway. Key
awareness closes that gap, and symmetrically lets a policy protect a field
from redaction (`exclude_keys: [file_path]`) so a path or id is never mangled.

Matching is token-based, not substring: the key is split on separators and
camelCase into lowercase tokens, and a hit requires a whole token to be in the
sensitive set. That catches `aws_secret_access_key` and `apiKey` while sparing
`authorized_users` (contains "auth" but not as a token) and `token_count`
(the LLM field, not a credential) — the substring approach gets both of those
wrong, which is why it isn't used.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Single tokens that reliably indicate a credential-bearing field. Deliberately
# excludes ambiguous ones: bare "token" (token_count), "key" (public_key,
# key_name), "auth" (authorized_users).
DEFAULT_SENSITIVE_TOKENS: frozenset[str] = frozenset({
    "password", "passwd", "pwd", "secret", "apikey", "credential", "credentials",
    "authorization", "passphrase",
})

# Multi-token names checked against the joined (separator-free) key, since they
# never appear as a single token.
DEFAULT_SENSITIVE_JOINED: frozenset[str] = frozenset({
    "apikey", "accesskey", "secretkey", "privatekey", "clientsecret",
    "accesstoken", "refreshtoken", "sessiontoken", "authtoken", "secretaccesskey",
})

_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")


def _tokens(key: str) -> list[str]:
    return [t.lower() for t in _SPLIT.split(key) if t]


@dataclass(frozen=True, slots=True)
class StructuredPolicy:
    exclude_keys: frozenset[str] = field(default_factory=frozenset)
    sensitive_tokens: frozenset[str] = DEFAULT_SENSITIVE_TOKENS
    sensitive_joined: frozenset[str] = DEFAULT_SENSITIVE_JOINED

    def key_is_excluded(self, key: str) -> bool:
        return key.lower() in {k.lower() for k in self.exclude_keys}

    def key_is_sensitive(self, key: str) -> bool:
        tokens = _tokens(key)
        if any(t in self.sensitive_tokens for t in tokens):
            return True
        return "".join(tokens) in self.sensitive_joined
