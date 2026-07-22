"""Token vault — the store behind reversible redaction (tokenize operator).

Tokenization replaces a sensitive value with a stable, meaningless token and
keeps the mapping so an authorized operator can reverse it later (with an
audit record). Two properties matter:

  * Deterministic: the same value always yields the same token, so the model
    can still correlate ("these two records share a customer") without ever
    seeing the value — the same benefit as the hash operator, but reversible.
  * Confidential at rest: the value↔token mapping is the crown jewel; if the
    vault leaks, tokenization bought nothing. The production backend encrypts
    every stored value.

Backends:
  InMemoryVault        stdlib only, non-persistent, RAM-only. Dev/test default.
                       Determinism via keyed BLAKE2; values live only in
                       process memory.
  EncryptedSqliteVault persistent + envelope-encrypted at rest (the [vault]
                       extra: `cryptography`). This is the production path.

Envelope encryption (the KMS pattern): a master Key-Encryption-Key (KEK)
wraps a per-vault Data-Encryption-Key (DEK); values are encrypted under the
DEK. The token itself is a keyed MAC of the value (deterministic lookup key),
and the reversible ciphertext is stored beside it. Rotating the KEK re-wraps
one DEK, not every row.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from abc import ABC, abstractmethod

_TOKEN_LEN = 12  # hex chars of the lookup MAC exposed in the token string
KEK_ENV_VAR = "MCP_GATEWAY_VAULT_KEK"


def load_kek_from_env(var: str = KEK_ENV_VAR) -> bytes | None:
    """Load a base64 KEK (>=32 bytes) from the environment, or None if unset.

    A persistent encrypted vault must never fall back to a random key (the
    store would be unreadable next run), so an absent var returns None and the
    caller decides — the gateway refuses to open an encrypted vault without it.
    """
    raw = os.environ.get(var)
    if not raw:
        return None
    try:
        # binascii.Error (raised on bad input) subclasses ValueError.
        kek = base64.b64decode(raw, validate=True)
    except ValueError:
        raise ValueError(f"{var} is not valid base64") from None
    if len(kek) < 32:
        raise ValueError(f"{var} must decode to at least 32 bytes")
    return kek


class TokenVault(ABC):
    """value <-> token mapping. Deterministic tokens; reversible lookup."""

    @abstractmethod
    def tokenize(self, entity: str, value: str) -> str:
        """Return a stable token for `value`, storing the mapping."""

    @abstractmethod
    def detokenize(self, token: str) -> str | None:
        """Return the original value for a token, or None if unknown."""


def _token_string(entity: str, mac_hex: str) -> str:
    return f"[{entity}:tok_{mac_hex[:_TOKEN_LEN]}]"


class InMemoryVault(TokenVault):
    """Non-persistent, RAM-only vault. Values never touch disk.

    Determinism comes from a keyed BLAKE2 MAC (stdlib), so the same value maps
    to the same token within the process. Suitable for dev, tests, and
    deployments that only need in-session correlation and accept losing the
    mapping on restart. NOT encrypted (it is process memory, not at rest).
    """

    def __init__(self, key: bytes | None = None):
        self._key = key or os.urandom(32)
        self._by_token: dict[str, str] = {}

    def _mac(self, value: str) -> str:
        return hashlib.blake2b(value.encode("utf-8"), key=self._key, digest_size=16).hexdigest()

    def tokenize(self, entity: str, value: str) -> str:
        token = _token_string(entity, self._mac(value))
        self._by_token.setdefault(token, value)
        return token

    def detokenize(self, token: str) -> str | None:
        return self._by_token.get(token)


class EncryptedSqliteVault(TokenVault):
    """Persistent, envelope-encrypted vault (requires the [vault] extra).

    Rows: token (keyed-MAC lookup id) -> AES-GCM ciphertext of the value. The
    DEK is generated once, wrapped by the KEK, and stored in a meta row. The
    MAC subkey (for deterministic token ids) is derived from the KEK, so the
    token space is stable across restarts and unlinkable without the KEK.
    """

    def __init__(self, path: str, kek: bytes):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives.hashes import SHA256
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        except ImportError as exc:  # pragma: no cover - exercised via absence test
            raise RuntimeError(
                "EncryptedSqliteVault needs the [vault] extra: pip install "
                "'mcp-gateway[vault]'"
            ) from exc
        if len(kek) < 32:
            raise ValueError("KEK must be at least 32 bytes")

        import sqlite3

        self._AESGCM = AESGCM
        self._kek = kek
        # Deterministic MAC subkey for token ids (separate from encryption).
        self._mac_key = HKDF(
            algorithm=SHA256(), length=32, salt=None, info=b"mcp-gateway/vault/mac"
        ).derive(kek)

        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS tokens ("
            "token TEXT PRIMARY KEY, nonce BLOB NOT NULL, ct BLOB NOT NULL)"
        )
        self._dek = self._load_or_create_dek()

    def _load_or_create_dek(self) -> bytes:
        row = self._conn.execute(
            "SELECT v FROM meta WHERE k='wrapped_dek'"
        ).fetchone()
        aes = self._AESGCM(self._kek)
        if row is not None:
            blob = row[0]
            nonce, wrapped = blob[:12], blob[12:]
            return aes.decrypt(nonce, wrapped, b"dek")
        dek = os.urandom(32)
        nonce = os.urandom(12)
        wrapped = aes.encrypt(nonce, dek, b"dek")
        self._conn.execute(
            "INSERT INTO meta (k, v) VALUES ('wrapped_dek', ?)", (nonce + wrapped,)
        )
        self._conn.commit()
        return dek

    def _mac(self, value: str) -> str:
        return hmac.new(self._mac_key, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def tokenize(self, entity: str, value: str) -> str:
        token = _token_string(entity, self._mac(value))
        if self._conn.execute(
            "SELECT 1 FROM tokens WHERE token=?", (token,)
        ).fetchone() is None:
            nonce = os.urandom(12)
            ct = self._AESGCM(self._dek).encrypt(nonce, value.encode("utf-8"), b"val")
            self._conn.execute(
                "INSERT INTO tokens (token, nonce, ct) VALUES (?, ?, ?)",
                (token, nonce, ct),
            )
            self._conn.commit()
        return token

    def detokenize(self, token: str) -> str | None:
        row = self._conn.execute(
            "SELECT nonce, ct FROM tokens WHERE token=?", (token,)
        ).fetchone()
        if row is None:
            return None
        nonce, ct = row
        return self._AESGCM(self._dek).decrypt(nonce, ct, b"val").decode("utf-8")

    def close(self) -> None:
        self._conn.close()
