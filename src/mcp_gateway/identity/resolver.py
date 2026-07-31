"""The single front door: an `Authorization` header in, a `Principal` out.

Everything upstream (the HTTP transport) knows one call: hand the resolver
whatever the client sent in `Authorization`, get back a proven principal or an
`IdentityError`. The resolver decides *how* to prove identity from the auth
scheme the client chose:

    Authorization: Bearer <jwt>      → OIDC: validate the token, map its claims
    Authorization: ApiKey <key>      → look the key up in the API-key store

There is no third path and no default. A missing header, an unknown scheme, an
empty credential, or a configured method that isn't wired all resolve to
`IdentityError` — the gateway never invents an anonymous or "local" principal to
keep a request alive, because on a shared service an unauthenticated call is the
one you most want to refuse.

`require_auth=False` is the one escape hatch, and it is opt-in and loud: it lets
a deployment fall back to a fixed principal (e.g. a laptop sidecar that has no
IdP) instead of demanding a token. It exists so identity can be *configured*
without being *mandatory* everywhere, not as a silent default — the caller must
ask for it, and the gateway audits the fixed principal like any other.
"""

from __future__ import annotations

from dataclasses import dataclass

from mcp_gateway.core.context import Principal
from mcp_gateway.core.errors import IdentityError
from mcp_gateway.identity.apikey import ApiKeyStore
from mcp_gateway.identity.mapping import RoleMapping
from mcp_gateway.identity.oidc import OidcValidator

BEARER = "bearer"
APIKEY = "apikey"


@dataclass(slots=True)
class IdentityResolver:
    """Resolves a request credential to a `Principal`, fail-closed."""

    oidc: OidcValidator | None = None
    mapping: RoleMapping | None = None
    api_keys: ApiKeyStore | None = None
    # When no credential is present AND this is set, use it instead of refusing.
    # Opt-in only; None means "a credential is required" (the secure default).
    anonymous_principal: Principal | None = None

    def resolve(self, authorization: str | None) -> Principal:
        """Return the authenticated principal for an Authorization header value."""
        if not authorization or not authorization.strip():
            if self.anonymous_principal is not None:
                return self.anonymous_principal
            raise IdentityError("no Authorization header (a credential is required)")

        parts = authorization.strip().split(None, 1)
        if len(parts) != 2:
            raise IdentityError(
                "malformed Authorization header (expected '<scheme> <credential>')"
            )
        scheme, credential = parts[0].lower(), parts[1].strip()

        if scheme == BEARER:
            return self._resolve_oidc(credential)
        if scheme == APIKEY:
            return self._resolve_api_key(credential)
        raise IdentityError(
            f"unsupported Authorization scheme {parts[0]!r} "
            f"(use 'Bearer <jwt>' or 'ApiKey <key>')"
        )

    def _resolve_oidc(self, token: str) -> Principal:
        if self.oidc is None or self.mapping is None:
            raise IdentityError("Bearer token presented but OIDC is not configured")
        claims = self.oidc.validate(token)          # raises IdentityError on any fault
        return self.mapping.to_principal(claims)

    def _resolve_api_key(self, key: str) -> Principal:
        if self.api_keys is None:
            raise IdentityError("API key presented but no API keys are configured")
        principal = self.api_keys.resolve(key)
        if principal is None:
            raise IdentityError("unknown API key")
        return principal
