"""`identity.yaml` — the identity config, loaded fail-closed into a resolver.

One document describes how the gateway authenticates callers: the OIDC issuer to
trust, the audience it must have been minted for, how the token's groups become
roles, and any static API keys for headless agents. The loader validates
fail-closed — a config that is ambiguous about who to trust is a hard startup
error, never a service that quietly trusts the wrong thing.

Shape (YAML or JSON):

    schema_version: 1
    oidc:
      issuer: https://dev-12345.okta.com/oauth2/default
      audience: api://mcp-gateway          # str or list
      jwks_uri: https://dev-12345.okta.com/oauth2/default/v1/keys  # optional (derived from issuer)
      leeway_seconds: 0                     # grace on exp/nbf; 0 = fail-closed
    mapping:
      subject_claim: sub                    # → principal id
      groups_claim: groups                  # → roles
      default_role: developer               # when no group matches (optional)
      groups:                               # ORDERED: most-privileged first
        mcp-admins: admin
        mcp-reviewers: reviewer
    api_keys:                               # headless agents (optional)
      - id: ci-bot
        key_sha256: "<hex of sha256(key)>"  # never the plaintext
        roles: [bot]

Either `oidc` or `api_keys` (or both) must be present — an identity config that
authenticates nobody is a mistake, not a valid "deny all" (default-deny is the
policy's job, not identity's). Discovering the JWKS URI from the issuer's
`.well-known/openid-configuration` is deferred; today `jwks_uri` is derived by
convention when omitted, and a non-standard issuer sets it explicitly.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp_gateway.core.errors import IdentityError
from mcp_gateway.identity.apikey import ApiKeyRecord, ApiKeyStore
from mcp_gateway.identity.mapping import RoleMapping
from mcp_gateway.identity.oidc import (
    DEFAULT_ALGORITHMS,
    DEFAULT_JWKS_TTL_SECONDS,
    JwksProvider,
    OidcValidator,
)
from mcp_gateway.identity.resolver import IdentityResolver

_TOP = {"schema_version", "oidc", "mapping", "api_keys"}
_OIDC = {"issuer", "audience", "jwks_uri", "leeway_seconds", "algorithms", "jwks_ttl_seconds"}
_MAPPING = {"subject_claim", "groups_claim", "default_role", "groups"}
_APIKEY = {"id", "key_sha256", "roles"}


def load_identity_config(path: str | Path, *, fetcher=None) -> IdentityResolver:
    """Load `identity.yaml` into a ready `IdentityResolver` (fail-closed).

    `fetcher` overrides the JWKS HTTP fetch (used by tests to serve a local JWKS
    with no network); production uses the built-in https fetcher.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise IdentityError(f"identity config not found: {path}") from None

    document = _parse(text, path)
    if not isinstance(document, dict):
        raise IdentityError(f"{path}: identity config must be a mapping")
    if document.get("schema_version") != 1:
        raise IdentityError(f"{path}: identity config needs schema_version: 1")
    unknown = set(document) - _TOP
    if unknown:
        raise IdentityError(f"{path}: unknown top-level field(s) {sorted(unknown)}")

    oidc_cfg = document.get("oidc")
    api_cfg = document.get("api_keys")
    if oidc_cfg is None and not api_cfg:
        raise IdentityError(
            f"{path}: identity config authenticates nobody — configure `oidc`, "
            f"`api_keys`, or both"
        )

    oidc, mapping = _build_oidc(oidc_cfg, document.get("mapping"), path, fetcher)
    api_keys = _build_api_keys(api_cfg, path)
    return IdentityResolver(oidc=oidc, mapping=mapping, api_keys=api_keys)


def _build_oidc(oidc_cfg, mapping_cfg, path, fetcher):
    if oidc_cfg is None:
        return None, None
    if not isinstance(oidc_cfg, dict):
        raise IdentityError(f"{path}: `oidc` must be a mapping")
    unknown = set(oidc_cfg) - _OIDC
    if unknown:
        raise IdentityError(f"{path}: unknown oidc field(s) {sorted(unknown)}")

    issuer = oidc_cfg.get("issuer")
    if not issuer or not isinstance(issuer, str):
        raise IdentityError(f"{path}: oidc.issuer is required")
    audience = oidc_cfg.get("audience")
    if isinstance(audience, list):
        audience = tuple(audience)
    elif not isinstance(audience, str) or not audience:
        raise IdentityError(f"{path}: oidc.audience is required (string or list)")

    jwks_uri = oidc_cfg.get("jwks_uri") or issuer.rstrip("/") + "/v1/keys"
    algorithms = tuple(oidc_cfg.get("algorithms", DEFAULT_ALGORITHMS))
    provider_kwargs: dict[str, Any] = {
        "jwks_uri": jwks_uri,
        "ttl_seconds": float(oidc_cfg.get("jwks_ttl_seconds", DEFAULT_JWKS_TTL_SECONDS)),
    }
    if fetcher is not None:              # tests inject an offline fetcher; prod uses https
        provider_kwargs["fetcher"] = fetcher
    provider = JwksProvider(**provider_kwargs)
    validator = OidcValidator(
        issuer=issuer,
        audience=audience,
        jwks=provider,
        algorithms=algorithms,
        leeway_seconds=float(oidc_cfg.get("leeway_seconds", 0.0)),
    )

    mapping_cfg = mapping_cfg or {}
    if not isinstance(mapping_cfg, dict):
        raise IdentityError(f"{path}: `mapping` must be a mapping")
    unknown = set(mapping_cfg) - _MAPPING
    if unknown:
        raise IdentityError(f"{path}: unknown mapping field(s) {sorted(unknown)}")
    groups = mapping_cfg.get("groups", {})
    if not isinstance(groups, dict):
        raise IdentityError(f"{path}: mapping.groups must be a mapping of group->role")
    mapping = RoleMapping(
        subject_claim=mapping_cfg.get("subject_claim", "sub"),
        groups_claim=mapping_cfg.get("groups_claim", "groups"),
        groups={str(k): str(v) for k, v in groups.items()},
        default_role=mapping_cfg.get("default_role"),
    )
    return validator, mapping


def _build_api_keys(api_cfg, path):
    if not api_cfg:
        return None
    if not isinstance(api_cfg, list):
        raise IdentityError(f"{path}: `api_keys` must be a list")
    records = []
    for i, entry in enumerate(api_cfg):
        if not isinstance(entry, dict) or set(entry) - _APIKEY:
            raise IdentityError(f"{path}: api_keys[{i}] has unexpected fields")
        pid, digest = entry.get("id"), entry.get("key_sha256")
        if not isinstance(pid, str) or not pid:
            raise IdentityError(f"{path}: api_keys[{i}].id is required")
        if not isinstance(digest, str) or len(digest.strip()) != 64:
            raise IdentityError(
                f"{path}: api_keys[{i}].key_sha256 must be a 64-hex sha256 digest "
                f"(store the hash, never the key)"
            )
        roles = tuple(entry.get("roles", []))
        records.append(ApiKeyRecord(principal_id=pid, key_sha256=digest, roles=roles))
    return ApiKeyStore(records)


def _parse(text: str, path: Path) -> Any:
    if path.suffix == ".json":
        import json
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise IdentityError(f"{path}: not valid JSON ({exc})") from None
    import yaml
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise IdentityError(f"{path}: not valid YAML ({exc})") from None
