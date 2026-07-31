"""OIDC token validation — who is calling, proven by a signature we can check.

Until now a principal was pinned at launch (`wrap --principal alice --role
admin`): the operator *asserts* an identity and the gateway trusts the
assertion. That is fine for a laptop sidecar; it is nothing for a shared service
where the caller is a request, not a command line. This module replaces the
assertion with proof — a JWT the caller presents, signed by an identity provider
(Okta, Auth0, any OIDC issuer) whose public keys the gateway fetches and pins.

Two invariants, both non-negotiable on an auth path:

  * **Fail closed.** Every way a token can be wrong — missing, expired, wrong
    issuer or audience, signed by a key we don't recognize, signed with an
    algorithm we didn't ask for, or simply unparseable — ends in `IdentityError`
    and a refused call. There is no "couldn't verify, so allow"; there isn't even
    an anonymous principal to fall back to. `cryptography`/`pyjwt` live behind the
    `[oidc]` extra, and their absence is itself a fail-closed error: a gateway
    that cannot check a signature must not pretend it did.

  * **`alg` is dictated by us, never by the token.** The classic JWT attack is a
    token that says `"alg": "none"`, or that swaps RS256 for HS256 so the public
    key gets used as an HMAC secret. `jwt.decode` is always called with an
    explicit `algorithms` allowlist (asymmetric only), so the header's own claim
    about how it was signed can never widen what we accept.

Key handling is a `JwksProvider`: it caches the issuer's JWKS by `kid` with a
TTL, and on an unrecognized `kid` it refetches **once** before giving up — that
single refetch is what makes ordinary key rotation transparent while a genuinely
unknown key still fails closed. The network fetch is injectable, so the whole
validator is testable offline against a locally generated keypair with no HTTP.
"""

from __future__ import annotations

import json
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from mcp_gateway.core.errors import IdentityError

# Asymmetric only. HS* (shared-secret) is deliberately excluded: with a symmetric
# alg the public verification key doubles as a signing key (the RS→HS attack).
DEFAULT_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")

# JWKS documents rarely change; a few minutes keeps us fresh without hammering
# the IdP. An unknown kid triggers an immediate refetch regardless of this TTL.
DEFAULT_JWKS_TTL_SECONDS = 300


def _require_pyjwt():
    """Import pyjwt (needs the [oidc] extra) or fail closed with an actionable message."""
    try:
        import jwt
        from jwt import PyJWK
    except ImportError:
        raise IdentityError(
            "OIDC token validation needs the [oidc] extra (pyjwt[crypto]): "
            "pip install 'mcp-gateway[oidc]'. Without it, a signature cannot be "
            "verified and the request is refused rather than trusted."
        ) from None
    return jwt, PyJWK


JwksFetcher = Callable[[str], dict[str, Any]]


def _http_fetch(url: str) -> dict[str, Any]:
    """Fetch a JWKS document over HTTPS (stdlib). Replaced in tests."""
    if not url.startswith("https://"):
        # An http JWKS endpoint would let a network attacker swap signing keys.
        raise IdentityError(f"JWKS URL must be https, got {url!r}")
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 (https enforced above)
            return json.loads(resp.read().decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise IdentityError(f"could not fetch JWKS from {url}: {exc}") from None


@dataclass(slots=True)
class JwksProvider:
    """Caches an issuer's JWKS by key id, with a TTL and rotation-aware refetch."""

    jwks_uri: str
    fetcher: JwksFetcher = _http_fetch
    ttl_seconds: float = DEFAULT_JWKS_TTL_SECONDS
    _keys: dict[str, Any] = field(default_factory=dict, init=False)  # kid -> PyJWK
    _fetched_at: float = field(default=0.0, init=False)

    def _refresh(self) -> None:
        _, PyJWK = _require_pyjwt()
        document = self.fetcher(self.jwks_uri)
        keys = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(keys, list) or not keys:
            raise IdentityError(f"JWKS from {self.jwks_uri} has no keys")
        parsed: dict[str, Any] = {}
        for jwk in keys:
            kid = jwk.get("kid") if isinstance(jwk, dict) else None
            if kid is None:
                continue
            try:
                parsed[kid] = PyJWK(jwk)
            except Exception:  # noqa: BLE001 — one malformed key must not poison the set
                continue
        if not parsed:
            raise IdentityError(f"JWKS from {self.jwks_uri} had no usable keys")
        self._keys = parsed
        self._fetched_at = time.monotonic()

    def signing_key(self, kid: str) -> Any:
        """The PyJWK for `kid`, refreshing the cache on a stale TTL or an unknown
        kid (key rotation). A kid still missing after a fresh fetch fails closed."""
        stale = (time.monotonic() - self._fetched_at) > self.ttl_seconds
        if not self._keys or stale:
            self._refresh()
        if kid not in self._keys:
            # Rotation: the IdP may have published a new key since our last fetch.
            self._refresh()
        key = self._keys.get(kid)
        if key is None:
            raise IdentityError(
                f"token signed by unknown key id {kid!r} (not in the issuer's JWKS)"
            )
        return key


@dataclass(slots=True)
class OidcValidator:
    """Validates a JWT against a configured issuer/audience and its JWKS."""

    issuer: str
    audience: str | tuple[str, ...]
    jwks: JwksProvider
    algorithms: tuple[str, ...] = DEFAULT_ALGORITHMS
    leeway_seconds: float = 0.0  # fail-closed by default: no grace on expiry

    def validate(self, token: str) -> dict[str, Any]:
        """Return the verified claims for `token`, or raise `IdentityError`.

        Everything about how the token was signed is checked against *our*
        configuration, never the token's own header beyond the `kid` used to
        select a key from the issuer's published set.
        """
        jwt, _ = _require_pyjwt()
        if not token:
            raise IdentityError("no token presented")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise IdentityError(f"malformed token header: {exc}") from None

        alg = header.get("alg")
        if alg not in self.algorithms:
            # Blocks alg=none and RS→HS confusion before a key is even selected.
            raise IdentityError(
                f"token algorithm {alg!r} is not in the accepted set {self.algorithms}"
            )
        kid = header.get("kid")
        if not kid:
            raise IdentityError("token header has no key id (kid)")

        key = self.jwks.signing_key(kid)
        try:
            claims = jwt.decode(
                token,
                key=key.key,
                algorithms=list(self.algorithms),
                audience=list(self.audience) if isinstance(self.audience, tuple)
                else self.audience,
                issuer=self.issuer,
                leeway=self.leeway_seconds,
                options={
                    "require": ["exp", "iat", "iss", "aud"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )
        except jwt.ExpiredSignatureError:
            raise IdentityError("token has expired") from None
        except jwt.InvalidAudienceError:
            raise IdentityError(
                f"token audience does not match {self.audience!r}"
            ) from None
        except jwt.InvalidIssuerError:
            raise IdentityError(
                f"token issuer does not match {self.issuer!r}"
            ) from None
        except jwt.PyJWTError as exc:
            raise IdentityError(f"token failed validation: {exc}") from None
        return claims
