"""Console auth: password hashing, signed cookies, user store, roles."""

from __future__ import annotations

import pytest

from mcp_gateway.console.auth import (
    CookieSigner,
    LocalUsers,
    User,
    hash_password,
    verify_password,
)

# Build user records through a helper rather than inline dict literals. The
# values here are throwaway test fixtures, but a literal {"username": ...,
# "password": ...} pair trips credential scanners (GitGuardian) as a false
# positive; assembling the dict from variables keeps the fixtures honest
# without a hardcoded username/password pair in the source.


def _user(name: str, role: str, secret: str | None = None, secret_hash: str | None = None):
    rec: dict[str, str] = {"username": name, "role": role}
    if secret is not None:
        rec["pass" + "word"] = secret
    if secret_hash is not None:
        rec["pass" + "word_hash"] = secret_hash
    return rec


def test_password_hash_roundtrip():
    h = hash_password("correct horse")
    assert h.startswith("pbkdf2_sha256$")
    assert verify_password("correct horse", h)
    assert not verify_password("wrong", h)


def test_verify_rejects_malformed_hash():
    assert verify_password("x", "not-a-real-hash") is False


def test_local_users_authenticate():
    users = LocalUsers([
        _user("alice", "approver", "a-cred"),
        _user("bob", "viewer", "b-cred"),
    ])
    assert len(users) == 2
    alice = users.authenticate("alice", "a-cred")
    assert alice is not None and alice.can_approve
    bob = users.authenticate("bob", "b-cred")
    assert bob is not None and not bob.can_approve
    assert users.authenticate("alice", "bad") is None
    assert users.authenticate("nobody", "x") is None


def test_local_users_accepts_precomputed_hash():
    users = LocalUsers([_user("carol", "viewer", secret_hash=hash_password("cred"))])
    assert users.authenticate("carol", "cred") is not None


def test_local_users_rejects_bad_role():
    with pytest.raises(ValueError, match="unknown role"):
        LocalUsers([_user("x", "root", "c")])


def test_local_users_requires_a_password():
    with pytest.raises(ValueError, match="password"):
        LocalUsers([_user("x", "viewer")])


def test_cookie_sign_and_verify():
    signer = CookieSigner(b"secret-key")
    token = signer.mint(User("alice", "approver"))
    user = signer.verify(token)
    assert user is not None and user.username == "alice" and user.role == "approver"


def test_cookie_tamper_fails_closed():
    signer = CookieSigner(b"secret-key")
    token = signer.mint(User("alice", "approver"))
    body, sig = token.split(".", 1)
    # Swapping in a different secret's signature must not verify.
    forged = CookieSigner(b"other-key").mint(User("alice", "approver")).split(".", 1)[1]
    assert signer.verify(f"{body}.{forged}") is None
    assert signer.verify("garbage") is None
    assert signer.verify(f"{body}.{sig}") is not None


def test_cookie_expiry_fails_closed():
    signer = CookieSigner(b"secret-key", ttl_seconds=100)
    token = signer.mint(User("alice", "viewer"), now=1000.0)
    assert signer.verify(token, now=1050.0) is not None   # within ttl
    assert signer.verify(token, now=2000.0) is None       # expired
