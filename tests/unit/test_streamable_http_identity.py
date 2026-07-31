"""Phase 9b end to end: identity decides policy, over the real HTTP transport.

This is the exit criterion made executable — two callers in different IdP groups
hit the *same* tool and get different verdicts, and a token that is missing,
expired, or revoked is refused with a 401 before it reaches the upstream. Driven
in-process with httpx.ASGITransport, a fake upstream, and an offline JWKS (a
locally generated RSA key served from a dict) — no subprocess, no network.
"""

from __future__ import annotations

import asyncio
import json
import time

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("jwt")
pytest.importorskip("cryptography")
httpx = pytest.importorskip("httpx")

import jwt  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from jwt.algorithms import RSAAlgorithm  # noqa: E402

from mcp_gateway.identity import (  # noqa: E402
    ApiKeyRecord,
    ApiKeyStore,
    IdentityResolver,
    JwksProvider,
    OidcValidator,
    RoleMapping,
    hash_key,
)
from mcp_gateway.policy.engine import PolicyEngine  # noqa: E402
from mcp_gateway.transports.streamable_http import (  # noqa: E402
    StreamableHttpGateway,
    build_session_parts,
    create_streamable_http_app,
)

ISSUER = "https://issuer.example"
AUDIENCE = "api://mcp"

# admin.tool is blocked by default; only the `admin` role may call it. So the
# same call is allowed for one identity and denied for another — the whole point.
POLICY = {
    "schema_version": 1,
    "default_action": "allow",
    "tools": {
        "admin.tool": {
            "action": "block",
            "reason": "admins only",
            "roles": {"admin": {"action": "allow", "reason": "admin ok"}},
        }
    },
}


class FakeUpstream:
    def __init__(self):
        self.received: list[dict] = []
        self._on_line = None

    async def start(self, on_line, on_exit):
        self._on_line = on_line

    async def send(self, line: str) -> None:
        msg = json.loads(line)
        self.received.append(msg)
        mid, method = msg.get("id"), msg.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2025-03-26", "serverInfo": {"name": "fake"}}
        elif method == "tools/call":
            result = {"content": [{"type": "text", "text": "UPSTREAM-RESULT"}]}
        elif mid is not None:
            result = {}
        else:
            return
        await self._on_line(json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}))

    async def shutdown(self):
        return 0


class MemSink:
    def __init__(self):
        self.events = []

    async def emit(self, event):
        self.events.append(event)


def _signer():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="k1", alg="RS256", use="sig")
    state = {"jwks": {"keys": [jwk]}}

    def token(group, **over):
        now = int(time.time())
        claims = {
            "iss": ISSUER, "aud": AUDIENCE, "sub": f"{group}-user",
            "iat": now, "exp": now + 300, "groups": [group],
        }
        claims.update(over)
        return "Bearer " + jwt.encode(claims, priv, algorithm="RS256", headers={"kid": "k1"})

    return state, token


def _make_app(resolver):
    engine = PolicyEngine.from_documents([(POLICY, "test")])
    upstreams: list[FakeUpstream] = []

    def upstream_factory(_sid):
        up = FakeUpstream()
        upstreams.append(up)
        return up

    parts = build_session_parts(
        engine=engine, spool=MemSink(), upstream_factory=upstream_factory,
        annotate={"transport": "streamable_http"},
    )
    hub = StreamableHttpGateway(parts, response_timeout=5.0, resolver=resolver)
    return create_streamable_http_app(hub), upstreams


def _resolver(state, ttl=300.0):
    provider = JwksProvider(
        jwks_uri="https://issuer.example/keys",
        fetcher=lambda url: state["jwks"],
        ttl_seconds=ttl,
    )
    return IdentityResolver(
        oidc=OidcValidator(issuer=ISSUER, audience=AUDIENCE, jwks=provider),
        mapping=RoleMapping(
            groups={"mcp-admins": "admin", "mcp-devs": "developer"},
            default_role="developer",
        ),
        api_keys=ApiKeyStore([ApiKeyRecord("ci-bot", hash_key("bot-key"), ("developer",))]),
    )


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw")


def _init(group_token):
    return {"headers": {"Authorization": group_token},
            "json": {"jsonrpc": "2.0", "id": 0, "method": "initialize"}}


def _call(sid, token, mid=1):
    return {
        "headers": {"Mcp-Session-Id": sid, "Authorization": token},
        "json": {"jsonrpc": "2.0", "id": mid, "method": "tools/call",
                 "params": {"name": "admin.tool", "arguments": {}}},
    }


# ------------------------------------------------ the exit criterion
def test_two_identities_get_different_verdicts_on_the_same_tool():
    async def scenario():
        state, token = _signer()
        app, upstreams = _make_app(_resolver(state))
        async with _client(app) as c:
            # Admin: session created, admin.tool ALLOWED, reaches the upstream.
            admin = token("mcp-admins")
            sid = (await c.post("/mcp", **_init(admin))).headers["mcp-session-id"]
            r = await c.post("/mcp", **_call(sid, admin))
            assert r.status_code == 200
            assert r.json()["result"]["content"][0]["text"] == "UPSTREAM-RESULT"

            # Developer: same call, BLOCKED at the gateway, never reaches upstream.
            dev = token("mcp-devs")
            sid2 = (await c.post("/mcp", **_init(dev))).headers["mcp-session-id"]
            r2 = await c.post("/mcp", **_call(sid2, dev))
            assert r2.status_code == 200
            assert r2.json()["error"]["code"] == -32001  # policy-denied
        # The upstream saw exactly one tools/call — the admin's.
        all_calls = [m for up in upstreams for m in up.received if m.get("method") == "tools/call"]
        assert len(all_calls) == 1

    asyncio.run(scenario())


# ------------------------------------------------ fail-closed credentials
def test_no_token_is_401():
    async def scenario():
        state, _ = _signer()
        app, _ = _make_app(_resolver(state))
        async with _client(app) as c:
            r = await c.post("/mcp", json={"jsonrpc": "2.0", "id": 0, "method": "initialize"})
            assert r.status_code == 401
            assert "www-authenticate" in {k.lower() for k in r.headers}
    asyncio.run(scenario())


def test_expired_token_is_401():
    async def scenario():
        state, token = _signer()
        app, _ = _make_app(_resolver(state))
        async with _client(app) as c:
            now = int(time.time())
            r = await c.post("/mcp", **_init(token("mcp-admins", exp=now - 5, iat=now - 10)))
            assert r.status_code == 401
    asyncio.run(scenario())


def test_revoked_key_fails_closed_on_the_next_call():
    async def scenario():
        state, token = _signer()
        # ttl=0: refetch the JWKS every call, so a revocation takes effect
        # immediately rather than after the normal cache window.
        app, upstreams = _make_app(_resolver(state, ttl=0.0))
        async with _client(app) as c:
            admin = token("mcp-admins")
            sid = (await c.post("/mcp", **_init(admin))).headers["mcp-session-id"]
            # First call works.
            assert (await c.post("/mcp", **_call(sid, admin))).status_code == 200
            # IdP revokes the signing key: the JWKS no longer contains k1.
            new = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            jwk2 = json.loads(RSAAlgorithm.to_jwk(new.public_key()))
            jwk2.update(kid="k2", alg="RS256", use="sig")
            state["jwks"] = {"keys": [jwk2]}
            # The next call with the now-un-verifiable token is refused.
            r = await c.post("/mcp", **_call(sid, admin, mid=2))
            assert r.status_code == 401
    asyncio.run(scenario())


def test_a_different_identity_cannot_drive_anothers_session():
    async def scenario():
        state, token = _signer()
        app, _ = _make_app(_resolver(state))
        async with _client(app) as c:
            admin = token("mcp-admins")
            sid = (await c.post("/mcp", **_init(admin))).headers["mcp-session-id"]
            # A developer presents a valid token but for someone else's session.
            r = await c.post("/mcp", **_call(sid, token("mcp-devs")))
            assert r.status_code == 403
    asyncio.run(scenario())


def test_api_key_authenticates_a_headless_caller():
    async def scenario():
        state, _ = _signer()
        app, _ = _make_app(_resolver(state))
        async with _client(app) as c:
            r = await c.post("/mcp", headers={"Authorization": "ApiKey bot-key"},
                             json={"jsonrpc": "2.0", "id": 0, "method": "initialize"})
            assert r.status_code == 200  # authenticated as a headless developer
    asyncio.run(scenario())


def test_no_resolver_means_no_auth_required():
    """Backward compatibility: a hub with no resolver authenticates nobody."""
    async def scenario():
        app, _ = _make_app(None)
        async with _client(app) as c:
            r = await c.post("/mcp", json={"jsonrpc": "2.0", "id": 0, "method": "initialize"})
            assert r.status_code == 200
    asyncio.run(scenario())
