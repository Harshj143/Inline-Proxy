"""Identity: prove who is calling, and turn that into a policy `Principal`.

Phase 9. A principal used to be asserted at launch (`--principal`, `--role`);
here it is resolved per request from a credential the caller presents — an OIDC
JWT (`oidc.py`, validated against the issuer's JWKS) or a static API key
(`apikey.py`, for headless agents). `mapping.py` turns verified claims into a
principal's id + roles per `identity.yaml`; `resolver.py` is the single front
door (`Authorization` header → `Principal`, fail-closed); `config.py` loads the
config into a ready resolver.

Everything here fails closed: a credential that cannot be proven yields
`IdentityError` and a refused call, never an anonymous or default principal
(unless a deployment opts into a fixed one explicitly).
"""

from mcp_gateway.core.errors import IdentityError
from mcp_gateway.identity.apikey import ApiKeyRecord, ApiKeyStore, hash_key
from mcp_gateway.identity.config import load_identity_config
from mcp_gateway.identity.mapping import RoleMapping
from mcp_gateway.identity.oidc import JwksProvider, OidcValidator
from mcp_gateway.identity.resolver import IdentityResolver

__all__ = [
    "ApiKeyRecord",
    "ApiKeyStore",
    "IdentityError",
    "IdentityResolver",
    "JwksProvider",
    "OidcValidator",
    "RoleMapping",
    "hash_key",
    "load_identity_config",
]
