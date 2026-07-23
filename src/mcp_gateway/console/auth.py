"""Console authentication: local users, roles, signed session cookies.

Phase 4 ships the simplest thing that is actually safe for a self-hosted
console: a fixed set of local users, passwords stored as PBKDF2 hashes (never
plaintext at rest), and a stateless signed session cookie. OIDC is Phase 9 —
the seam here (a `Principal`-ish `User` returned by a dependency) is what OIDC
slots into later without touching the routes.

Two roles, least-privilege by default:
  * `viewer`   — read-only: sessions, events, policy, the live feed, backtest.
  * `approver` — viewer + the power to resolve a pending approval.

The cookie is a signed token, not a server-side session table: `base64(payload)
"." hmac_sha256(payload)`. Tamper with the payload and the HMAC check fails
closed. It carries an absolute expiry so a stolen cookie is not valid forever.
The signing secret is per-deployment; if none is provided the app mints a random
one at startup (cookies then don't survive a restart — fine for a local tool,
and it means we never ship a hardcoded default secret).

Stdlib only (`hashlib`, `hmac`, `secrets`, `base64`) — no new dependency.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

_PBKDF2_ROUNDS = 200_000
_ALGO = "pbkdf2_sha256"


# ------------------------------------------------------------------ passwords
def hash_password(password: str, *, salt: bytes | None = None) -> str:
    """Return a self-describing `pbkdf2_sha256$rounds$salt$hash` string."""
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ROUNDS)
    return f"{_ALGO}${_PBKDF2_ROUNDS}${_b64(salt)}${_b64(dk)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, rounds_s, salt_s, hash_s = encoded.split("$")
        if algo != _ALGO:
            return False
        salt = _b64d(salt_s)
        expected = _b64d(hash_s)
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, int(rounds_s)
        )
        return hmac.compare_digest(dk, expected)
    except (ValueError, KeyError):
        return False  # malformed hash: fail closed


# --------------------------------------------------------------------- users
@dataclass(frozen=True, slots=True)
class User:
    username: str
    role: str  # "viewer" | "approver"

    @property
    def can_approve(self) -> bool:
        return self.role == "approver"


class LocalUsers:
    """An in-memory user store built from config.

    Each config entry is `{username, role, password_hash}` or, for dev/tests,
    `{username, role, password}` (plaintext, hashed on load — never persist it).
    Unknown roles are rejected at load: a typo must not silently grant or deny.
    """

    ROLES = frozenset({"viewer", "approver"})

    def __init__(self, records: list[dict[str, Any]]):
        self._by_name: dict[str, tuple[User, str]] = {}
        for rec in records:
            username = rec.get("username")
            role = rec.get("role", "viewer")
            if not username:
                raise ValueError("user entry missing 'username'")
            if role not in self.ROLES:
                raise ValueError(
                    f"user {username!r}: unknown role {role!r} "
                    f"(expected one of {sorted(self.ROLES)})"
                )
            if "password_hash" in rec:
                pw_hash = rec["password_hash"]
            elif "password" in rec:
                pw_hash = hash_password(rec["password"])
            else:
                raise ValueError(f"user {username!r}: needs 'password' or 'password_hash'")
            self._by_name[username] = (User(username=username, role=role), pw_hash)

    def authenticate(self, username: str, password: str) -> User | None:
        entry = self._by_name.get(username)
        if entry is None:
            # Hash anyway to keep timing roughly constant against user probing.
            hash_password(password)
            return None
        user, pw_hash = entry
        return user if verify_password(password, pw_hash) else None

    def __len__(self) -> int:
        return len(self._by_name)


# ------------------------------------------------------------- signed cookies
COOKIE_NAME = "mcpg_session"


class CookieSigner:
    def __init__(self, secret: bytes, *, ttl_seconds: int = 12 * 3600):
        self._secret = secret
        self._ttl = ttl_seconds

    def mint(self, user: User, *, now: float | None = None) -> str:
        now = time.time() if now is None else now
        payload = {"u": user.username, "r": user.role, "exp": int(now + self._ttl)}
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        body = _b64(raw)
        return f"{body}.{self._sign(body)}"

    def verify(self, token: str, *, now: float | None = None) -> User | None:
        now = time.time() if now is None else now
        try:
            body, sig = token.split(".", 1)
        except ValueError:
            return None
        if not hmac.compare_digest(sig, self._sign(body)):
            return None
        try:
            payload = json.loads(_b64d(body))
        except (ValueError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict) or payload.get("exp", 0) < now:
            return None
        role = payload.get("r")
        if role not in LocalUsers.ROLES:
            return None
        return User(username=str(payload.get("u", "")), role=role)

    def _sign(self, body: str) -> str:
        return _b64(hmac.new(self._secret, body.encode("utf-8"), hashlib.sha256).digest())


# ------------------------------------------------------------------- helpers
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)
