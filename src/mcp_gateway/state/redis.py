"""Redis-backed session store — shared taint/risk across gateway replicas.

Central mode runs several stateless gateway replicas behind a load balancer.
For a security control that is the whole point: if replica A taints a session
(an untrusted fetch ran) or suspends it (risk crossed the threshold), replica B
handling the next call for that same `Mcp-Session-Id` MUST see it — otherwise an
attacker just retries until they hit a replica with a clean local view. This
store makes the durable session state (taint, risk, suspension, history) live in
Redis instead of one process's memory, so every replica reads the same truth.

What is and isn't shared:
  * **Shared** (persisted on every `save`): taint, risk score/events, suspension,
    history — via `Session.to_dict()`.
  * **Not shared**: `pending` (in-flight tools/call correlation). An in-flight
    call belongs to the replica that forwarded it and completes there; handing a
    half-finished call to another replica would lose its response-path
    disposition. A replica failing mid-call fails that call closed, never
    releases it un-inspected — the safe direction.

Uses the *synchronous* redis client deliberately: the gateway binds its session
in `__init__` (not an async context) and the store's operations are small point
reads/writes to a local Redis. A fully async variant is a later optimisation;
correctness (shared state) comes first. Redis is the `[redis]` extra.

Fail-closed on a serialization miss: an unparseable stored blob is treated as a
fresh session rather than crashing the request — the worst case is a lost taint
mark on one corrupt key, which the next `save` repairs, not an open door.
"""

from __future__ import annotations

import json

from mcp_gateway.core.session import Session
from mcp_gateway.state.base import SessionStore

_DEFAULT_PREFIX = "mcpg:session:"
# Sessions expire so Redis doesn't grow without bound; refreshed on every save.
_DEFAULT_TTL_SECONDS = 24 * 3600


class RedisSessionStore(SessionStore):
    def __init__(
        self,
        client,
        *,
        prefix: str = _DEFAULT_PREFIX,
        ttl_seconds: int | None = _DEFAULT_TTL_SECONDS,
    ):
        # `client` is a redis.Redis (or fakeredis) instance — injected so the
        # caller owns connection config and tests can pass a fake.
        self._client = client
        self._prefix = prefix
        self._ttl = ttl_seconds

    @classmethod
    def from_url(cls, url: str, **kwargs) -> RedisSessionStore:
        try:
            import redis
        except ModuleNotFoundError as exc:  # pragma: no cover
            raise RuntimeError(
                "the redis state backend needs the [redis] extra: "
                "pip install 'mcp-gateway[redis]'"
            ) from exc
        return cls(redis.Redis.from_url(url), **kwargs)

    def _key(self, session_id: str) -> str:
        return f"{self._prefix}{session_id}"

    def get_or_create(self, session_id: str) -> Session:
        existing = self.get(session_id)
        if existing is not None:
            return existing
        session = Session.new(session_id=session_id)
        self.save(session)
        return session

    def get(self, session_id: str) -> Session | None:
        blob = self._client.get(self._key(session_id))
        if blob is None:
            return None
        try:
            data = json.loads(blob)
            return Session.from_dict(data)
        except (ValueError, KeyError, TypeError):
            # Corrupt/legacy blob: treat as absent (the next save repairs it).
            return None

    def save(self, session: Session) -> None:
        payload = json.dumps(session.to_dict(), separators=(",", ":"), default=str)
        key = self._key(session.id)
        if self._ttl:
            self._client.set(key, payload, ex=self._ttl)
        else:
            self._client.set(key, payload)
