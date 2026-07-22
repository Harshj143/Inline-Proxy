"""Token vaults: determinism, reversibility, and at-rest encryption."""

import base64
import importlib.util
import os

import pytest

from mcp_gateway.redaction.vault import (
    EncryptedSqliteVault,
    InMemoryVault,
    load_kek_from_env,
)

# The encrypted vault needs the [vault] extra (cryptography). Its tests skip
# when it's absent — same graceful-degradation contract as the Presidio tier.
# CI installs the extra so these actually run.
HAVE_CRYPTO = importlib.util.find_spec("cryptography") is not None
requires_crypto = pytest.mark.skipif(
    not HAVE_CRYPTO, reason="the [vault] extra (cryptography) is not installed"
)


# ------------------------------------------------------------- in-memory
def test_in_memory_is_deterministic_and_reversible():
    v = InMemoryVault(key=b"k" * 32)
    t1 = v.tokenize("EMAIL", "alice@example.com")
    t2 = v.tokenize("EMAIL", "alice@example.com")
    assert t1 == t2                                  # same value -> same token
    assert t1 != v.tokenize("EMAIL", "bob@example.com")
    assert v.detokenize(t1) == "alice@example.com"   # reversible
    assert v.detokenize("[EMAIL:tok_unknown]") is None
    assert t1.startswith("[EMAIL:tok_")


# ------------------------------------------------------------- encrypted
@requires_crypto
def test_encrypted_vault_round_trips_and_persists(tmp_path):
    path = str(tmp_path / "vault.db")
    kek = b"K" * 32
    v = EncryptedSqliteVault(path, kek)
    token = v.tokenize("SSN", "123-45-6789")
    assert v.detokenize(token) == "123-45-6789"
    v.close()

    # Reopen with the same KEK: the token space and values survive a restart.
    v2 = EncryptedSqliteVault(path, kek)
    assert v2.tokenize("SSN", "123-45-6789") == token  # deterministic across runs
    assert v2.detokenize(token) == "123-45-6789"
    v2.close()


@requires_crypto
def test_encrypted_vault_value_not_stored_in_plaintext(tmp_path):
    path = tmp_path / "vault.db"
    v = EncryptedSqliteVault(str(path), b"K" * 32)
    v.tokenize("EMAIL", "secret@example.com")
    v.close()
    blob = path.read_bytes()
    assert b"secret@example.com" not in blob  # value is AES-GCM encrypted at rest


@requires_crypto
def test_encrypted_vault_rejects_short_kek(tmp_path):
    with pytest.raises(ValueError, match="at least 32 bytes"):
        EncryptedSqliteVault(str(tmp_path / "v.db"), b"tooshort")


@requires_crypto
def test_wrong_kek_cannot_read(tmp_path):
    path = str(tmp_path / "vault.db")
    v = EncryptedSqliteVault(path, b"A" * 32)
    v.tokenize("EMAIL", "x@example.com")
    v.close()
    # A different KEK cannot unwrap the DEK — the store is useless without it.
    with pytest.raises(Exception):  # noqa: B017 - cryptography raises InvalidTag
        EncryptedSqliteVault(path, b"B" * 32)


# ------------------------------------------------------------------- KEK
def test_load_kek_from_env(monkeypatch):
    monkeypatch.delenv("MCP_GATEWAY_VAULT_KEK", raising=False)
    assert load_kek_from_env() is None

    good = base64.b64encode(os.urandom(32)).decode()
    monkeypatch.setenv("MCP_GATEWAY_VAULT_KEK", good)
    assert len(load_kek_from_env()) == 32

    monkeypatch.setenv("MCP_GATEWAY_VAULT_KEK", base64.b64encode(b"short").decode())
    with pytest.raises(ValueError, match="at least 32 bytes"):
        load_kek_from_env()

    monkeypatch.setenv("MCP_GATEWAY_VAULT_KEK", "!!!not base64!!!")
    with pytest.raises(ValueError, match="not valid base64"):
        load_kek_from_env()
