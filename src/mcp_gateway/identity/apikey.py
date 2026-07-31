"""Static API keys for headless agents that can't do an OIDC flow.

A CI job or an unattended agent has no browser and no interactive login, so the
OIDC path doesn't fit it. It presents a long random API key instead. This is a
weaker credential than a signed, expiring token — it's a bearer secret that
doesn't rotate itself — so it is treated as exactly that: keys are matched in
constant time, only their SHA-256 is ever held in config (never the plaintext),
and a headless identity is expected to map to a low-privilege role like `bot`
whose writes a default-deny pack already blocks.

The store never sees a key's plaintext at rest: `identity.yaml` carries
`key_sha256`, and an operator mints a key + its hash out of band. That way a
leaked config file does not leak usable credentials.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from mcp_gateway.core.context import Principal


@dataclass(frozen=True, slots=True)
class ApiKeyRecord:
    principal_id: str
    key_sha256: str            # lowercase hex of sha256(key)
    roles: tuple[str, ...] = ()


class ApiKeyStore:
    """Resolves a presented API key to a principal, in constant time."""

    def __init__(self, records: list[ApiKeyRecord]):
        # Normalize the stored digests once.
        self._records = [
            ApiKeyRecord(r.principal_id, r.key_sha256.strip().lower(), tuple(r.roles))
            for r in records
        ]

    def resolve(self, presented_key: str) -> Principal | None:
        """The principal for `presented_key`, or None if it matches no record.

        Every record is checked with `compare_digest` and the loop never
        short-circuits on a match, so the time taken does not reveal which (or
        whether a) key matched — a timing side channel on a bearer secret is a
        real leak.
        """
        if not presented_key:
            return None
        digest = hashlib.sha256(presented_key.encode("utf-8")).hexdigest()
        found: Principal | None = None
        for record in self._records:
            if hmac.compare_digest(digest, record.key_sha256):
                found = Principal(id=record.principal_id, roles=record.roles)
        return found

    def __len__(self) -> int:
        return len(self._records)


def hash_key(key: str) -> str:
    """The digest to store in identity.yaml for a given plaintext key."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()
