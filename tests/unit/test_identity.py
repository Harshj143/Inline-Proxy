"""Identity resolution: every way a credential can be wrong must fail closed.

An auth layer is only worth shipping if it *refuses* the things it should. These
tests sign real JWTs with a locally generated RSA key and serve the JWKS from a
dict (no network), then attack the validator from every angle the spec names —
expired, wrong issuer, wrong audience, unknown key, `alg=none`, an RS→HS
confusion, a revoked key — and assert each is refused, not admitted. Key
rotation gets its own test because the *non*-failure (a refetch that transparently
picks up a new key) is just as load-bearing as the failures.

`pyjwt[crypto]` (the [oidc] extra) is present in the test env, so signing runs;
`test_pyjwt_absent_fails_closed` forces the import to fail to prove the
crypto-absent path refuses rather than trusts.
"""

from __future__ import annotations

import json
import time

import pytest

from mcp_gateway.core.errors import IdentityError
from mcp_gateway.identity import (
    ApiKeyRecord,
    ApiKeyStore,
    IdentityResolver,
    JwksProvider,
    OidcValidator,
    RoleMapping,
    hash_key,
    load_identity_config,
)

pytest.importorskip("jwt", reason="OIDC tests need the [oidc] extra (pyjwt)")
pytest.importorskip("cryptography")

import jwt  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from jwt.algorithms import RSAAlgorithm  # noqa: E402

ISSUER = "https://issuer.example"
AUDIENCE = "api://mcp-gateway"


def _keypair(kid: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid=kid, alg="RS256", use="sig")
    return pem, jwk


@pytest.fixture
def signer():
    """A signing key 'k1', a JWKS serving it, and a token factory."""
    priv, jwk = _keypair("k1")
    state = {"jwks": {"keys": [jwk]}, "fetches": 0}

    def fetch(url):
        state["fetches"] += 1
        return state["jwks"]

    def token(kid="k1", key=priv, **overrides):
        now = int(time.time())
        claims = {
            "iss": ISSUER, "aud": AUDIENCE, "sub": "alice",
            "iat": now, "exp": now + 300, "groups": ["mcp-reviewers"],
        }
        claims.update(overrides)
        return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})

    return {"priv": priv, "jwk": jwk, "state": state, "fetch": fetch, "token": token}


def _validator(signer, **kw):
    provider = JwksProvider(jwks_uri="https://issuer.example/keys", fetcher=signer["fetch"])
    return OidcValidator(issuer=ISSUER, audience=AUDIENCE, jwks=provider, **kw)


# ------------------------------------------------------------------- happy
def test_valid_token_returns_its_claims(signer):
    claims = _validator(signer).validate(signer["token"]())
    assert claims["sub"] == "alice" and claims["groups"] == ["mcp-reviewers"]


def test_jwks_is_cached_not_refetched_per_call(signer):
    v = _validator(signer)
    v.validate(signer["token"]())
    v.validate(signer["token"]())
    assert signer["state"]["fetches"] == 1  # one fetch served both


# --------------------------------------------------------------- rejections
def test_expired_token_is_refused(signer):
    now = int(time.time())
    with pytest.raises(IdentityError, match="expired"):
        _validator(signer).validate(signer["token"](exp=now - 5, iat=now - 10))


def test_wrong_issuer_is_refused(signer):
    with pytest.raises(IdentityError, match="issuer"):
        _validator(signer).validate(signer["token"](iss="https://evil.example"))


def test_wrong_audience_is_refused(signer):
    with pytest.raises(IdentityError, match="audience"):
        _validator(signer).validate(signer["token"](aud="api://someone-else"))


def test_alg_none_is_refused(signer):
    now = int(time.time())
    forged = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "iat": now, "exp": now + 9},
        key=None, algorithm="none",
    )
    with pytest.raises(IdentityError, match="algorithm"):
        _validator(signer).validate(forged)


def test_hs256_token_is_refused(signer):
    """The RS→HS confusion attack presents an HS256 token (the classic trick uses
    the public key as the HMAC secret). Our alg allowlist is asymmetric-only, so
    any HS* token is rejected before a key is even selected — regardless of the
    secret used. Forge with a plain secret to prove the allowlist is the control."""
    now = int(time.time())
    forged = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "iat": now, "exp": now + 9},
        key="x" * 32, algorithm="HS256", headers={"kid": "k1"},
    )
    with pytest.raises(IdentityError, match="algorithm"):
        _validator(signer).validate(forged)


def test_unknown_kid_is_refused_after_a_refetch(signer):
    with pytest.raises(IdentityError, match="unknown key id"):
        _validator(signer).validate(signer["token"](kid="does-not-exist"))
    # It refetched once trying to find the kid (rotation path), then failed.
    assert signer["state"]["fetches"] == 2


def test_token_signed_by_a_foreign_key_is_refused(signer):
    """Right kid label, wrong key: the signature must not verify."""
    other_priv, _ = _keypair("k1")
    with pytest.raises(IdentityError, match="validation|signature"):
        _validator(signer).validate(signer["token"](key=other_priv))


def test_no_token_is_refused(signer):
    with pytest.raises(IdentityError):
        _validator(signer).validate("")


# --------------------------------------------------------------- rotation
def test_key_rotation_is_transparent(signer):
    """A token signed by a newly-published key validates after one refetch — the
    control survives ordinary IdP key rollover without an operator touching it."""
    v = _validator(signer)
    v.validate(signer["token"]())                 # warms the cache with k1
    # IdP rotates: publishes k2, keeps k1. A token arrives signed by k2.
    priv2, jwk2 = _keypair("k2")
    signer["state"]["jwks"] = {"keys": [signer["jwk"], jwk2]}
    claims = v.validate(signer["token"](kid="k2", key=priv2))
    assert claims["sub"] == "alice"


def test_revoked_key_fails_closed(signer):
    """A key removed from the JWKS (revoked) can no longer validate its tokens."""
    v = _validator(signer)
    good = signer["token"]()
    assert v.validate(good)["sub"] == "alice"
    # IdP revokes k1 and publishes only k2.
    _, jwk2 = _keypair("k2")
    signer["state"]["jwks"] = {"keys": [jwk2]}
    # Force cache past TTL so the next call refetches the (now k1-less) JWKS.
    v.jwks.ttl_seconds = -1
    with pytest.raises(IdentityError, match="unknown key id"):
        v.validate(good)


# --------------------------------------------------------------- mapping
def test_mapping_orders_roles_by_config_most_privileged_first():
    m = RoleMapping(groups={"mcp-admins": "admin", "mcp-reviewers": "reviewer"})
    p = m.to_principal({"sub": "alice", "groups": ["mcp-reviewers", "mcp-admins"]})
    assert p.id == "alice"
    assert p.roles == ("admin", "reviewer")  # config order, not token order


def test_mapping_falls_back_to_default_role():
    m = RoleMapping(groups={"mcp-admins": "admin"}, default_role="developer")
    assert m.to_principal({"sub": "bob", "groups": ["nope"]}).roles == ("developer",)


def test_mapping_with_no_match_and_no_default_has_no_role():
    m = RoleMapping(groups={"mcp-admins": "admin"})
    assert m.to_principal({"sub": "bob", "groups": []}).roles == ()


def test_mapping_accepts_a_single_group_string():
    m = RoleMapping(groups={"mcp-admins": "admin"})
    assert m.to_principal({"sub": "bob", "groups": "mcp-admins"}).roles == ("admin",)


def test_mapping_without_a_subject_fails_closed():
    with pytest.raises(IdentityError, match="anonymous"):
        RoleMapping().to_principal({"groups": ["mcp-admins"]})


# --------------------------------------------------------------- api keys
def test_api_key_resolves_to_its_principal():
    store = ApiKeyStore([ApiKeyRecord("ci-bot", hash_key("s3cr3t"), ("bot",))])
    p = store.resolve("s3cr3t")
    assert p is not None and p.id == "ci-bot" and p.roles == ("bot",)


def test_unknown_api_key_resolves_to_none():
    store = ApiKeyStore([ApiKeyRecord("ci-bot", hash_key("s3cr3t"), ("bot",))])
    assert store.resolve("wrong") is None
    assert store.resolve("") is None


# --------------------------------------------------------------- resolver
def test_resolver_dispatches_bearer_to_oidc(signer):
    r = IdentityResolver(
        oidc=_validator(signer), mapping=RoleMapping(groups={"mcp-reviewers": "reviewer"})
    )
    p = r.resolve("Bearer " + signer["token"]())
    assert p.id == "alice" and p.roles == ("reviewer",)


def test_resolver_dispatches_apikey_to_the_store():
    r = IdentityResolver(api_keys=ApiKeyStore([ApiKeyRecord("bot", hash_key("k"), ("bot",))]))
    assert r.resolve("ApiKey k").id == "bot"


@pytest.mark.parametrize("header,match", [
    (None, "no Authorization"),
    ("", "no Authorization"),
    ("Bearer", "malformed"),
    ("Basic abc", "unsupported"),
    ("ApiKey nope", "unknown API key"),
])
def test_resolver_fails_closed(header, match):
    r = IdentityResolver(api_keys=ApiKeyStore([ApiKeyRecord("bot", hash_key("k"), ("bot",))]))
    with pytest.raises(IdentityError, match=match):
        r.resolve(header)


def test_resolver_bearer_without_oidc_configured_is_refused():
    r = IdentityResolver(api_keys=ApiKeyStore([ApiKeyRecord("bot", hash_key("k"), ())]))
    with pytest.raises(IdentityError, match="OIDC is not configured"):
        r.resolve("Bearer whatever")


def test_resolver_anonymous_optin_is_used_only_when_no_credential():
    from mcp_gateway.core.context import Principal

    r = IdentityResolver(
        api_keys=ApiKeyStore([ApiKeyRecord("bot", hash_key("k"), ("bot",))]),
        anonymous_principal=Principal(id="local", roles=("developer",)),
    )
    assert r.resolve(None).id == "local"          # no credential → the opt-in fallback
    assert r.resolve("ApiKey k").id == "bot"        # a credential still wins
    with pytest.raises(IdentityError):
        r.resolve("ApiKey wrong")                   # a WRONG credential still fails closed


# --------------------------------------------------------------- config
def _write(tmp_path, body):
    p = tmp_path / "identity.yaml"
    p.write_text(body)
    return p


def test_config_loads_a_full_resolver(tmp_path, signer):
    cfg = _write(tmp_path, f"""
schema_version: 1
oidc:
  issuer: {ISSUER}
  audience: {AUDIENCE}
  jwks_uri: https://issuer.example/keys
mapping:
  default_role: developer
  groups:
    mcp-reviewers: reviewer
api_keys:
  - id: ci-bot
    key_sha256: "{hash_key('key123')}"
    roles: [bot]
""")
    r = load_identity_config(cfg, fetcher=signer["fetch"])
    assert r.resolve("Bearer " + signer["token"]()).roles == ("reviewer",)
    assert r.resolve("ApiKey key123").id == "ci-bot"


def test_config_that_authenticates_nobody_is_rejected(tmp_path):
    cfg = _write(tmp_path, "schema_version: 1\n")
    with pytest.raises(IdentityError, match="authenticates nobody"):
        load_identity_config(cfg)


def test_config_rejects_a_plaintext_looking_api_key(tmp_path):
    cfg = _write(tmp_path, """
schema_version: 1
api_keys:
  - id: bot
    key_sha256: "not-a-64-hex-digest"
    roles: [bot]
""")
    with pytest.raises(IdentityError, match="64-hex"):
        load_identity_config(cfg)


def test_config_rejects_unknown_fields(tmp_path):
    cfg = _write(tmp_path, "schema_version: 1\nnonsense: true\n")
    with pytest.raises(IdentityError, match="unknown top-level"):
        load_identity_config(cfg)


def test_config_derives_jwks_uri_from_issuer(tmp_path, signer):
    cfg = _write(tmp_path, f"""
schema_version: 1
oidc:
  issuer: {ISSUER}
  audience: {AUDIENCE}
mapping:
  groups: {{mcp-reviewers: reviewer}}
""")
    r = load_identity_config(cfg, fetcher=signer["fetch"])
    # jwks_uri defaulted to <issuer>/v1/keys; the injected fetcher serves it.
    assert r.resolve("Bearer " + signer["token"]()).roles == ("reviewer",)


# --------------------------------------------------------------- fail-closed
def test_pyjwt_absent_fails_closed(signer, monkeypatch):
    """Without pyjwt a signature cannot be checked, so validation must raise
    rather than admit the token."""
    import builtins

    real_import = builtins.__import__

    def no_jwt(name, *args, **kwargs):
        if name == "jwt" or name.startswith("jwt."):
            raise ImportError("simulated: pyjwt not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_jwt)
    with pytest.raises(IdentityError, match=r"\[oidc\] extra"):
        _validator(signer).validate(signer["token"]())
