"""Ed25519 keys for policy-bundle signing — and the trust boundary they draw.

A signed policy bundle exists to answer one question at gateway startup: *did
the policy I am about to enforce come from my policy pipeline, unaltered?* The
answer has to hold even against an attacker who can write to the gateway's
bundle directory, so a symmetric MAC is the wrong tool — anything that can
verify a shared-secret MAC can also forge one, which means the key that lets the
gateway *check* policy would also let a compromised gateway *mint* policy.

Ed25519 splits those capabilities. The **private** key lives only where bundles
are produced (a release job, an operator's laptop); it signs. The gateway holds
only the **public** key and can do nothing but verify. Compromising the gateway
does not yield the ability to sign a malicious policy — that is the entire point
of putting a signature here rather than a checksum.

Keys are Ed25519 specifically: small, fast, no parameter choices to get wrong
(no curve/hash/padding knobs the way RSA or ECDSA have), and deterministic
signatures. `cryptography` provides them and lives behind the `[vault]` extra;
this module guards the import and raises a clear, *fail-closed* error when it is
absent, because a gateway that cannot verify a signature must refuse the bundle,
never wave it through (docs golden rule: fail closed on the enforcement path).

A `key_id` is the first 16 hex chars of `sha256(public_key_raw)`. It is not a
secret and not a security control — it just lets a bundle name which key signed
it and lets `keygen` label a key, so an operator rotating keys can tell which
public key a bundle expects without trial verification.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path

from mcp_gateway.core.errors import GatewayError


class SigningError(GatewayError):
    """A key could not be loaded/generated, or crypto support is unavailable.

    A GatewayError so the CLI and gateway treat it like any other fail-closed
    load error: the bundle is not enforced.
    """


def _require_crypto():
    """Import the Ed25519 primitives or fail closed with an actionable message."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError:
        raise SigningError(
            "policy-bundle signing needs the [vault] extra (cryptography): "
            "pip install 'mcp-gateway[vault]'. Without it, signatures cannot be "
            "verified and a signed bundle is refused rather than trusted."
        ) from None
    return ed25519, serialization


def key_id(public_key_raw: bytes) -> str:
    """Short, non-secret identifier for a public key (first 16 hex of its hash)."""
    return hashlib.sha256(public_key_raw).hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class SigningKey:
    """A private Ed25519 key that can sign bundle bytes."""

    _key: object            # cryptography Ed25519PrivateKey (kept opaque here)
    public_raw: bytes

    @property
    def key_id(self) -> str:
        return key_id(self.public_raw)

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)  # type: ignore[attr-defined]

    def verifying_key(self) -> VerifyingKey:
        return VerifyingKey.from_raw(self.public_raw)


@dataclass(frozen=True, slots=True)
class VerifyingKey:
    """A public Ed25519 key that can only verify — all the gateway ever holds."""

    _key: object            # cryptography Ed25519PublicKey
    public_raw: bytes

    @property
    def key_id(self) -> str:
        return key_id(self.public_raw)

    def verify(self, signature: bytes, message: bytes) -> bool:
        """True iff `signature` is this key's signature over `message`.

        `cryptography` signals a bad signature by raising `InvalidSignature`;
        we translate that to a boolean so callers branch on it explicitly and a
        verification failure can never be mistaken for a thrown-and-caught error
        that some outer handler treats as benign.
        """
        from cryptography.exceptions import InvalidSignature

        try:
            self._key.verify(signature, message)  # type: ignore[attr-defined]
            return True
        except InvalidSignature:
            return False

    @classmethod
    def from_raw(cls, public_raw: bytes) -> VerifyingKey:
        ed25519, _ = _require_crypto()
        try:
            key = ed25519.Ed25519PublicKey.from_public_bytes(public_raw)
        except ValueError as exc:
            raise SigningError(f"not a valid Ed25519 public key: {exc}") from None
        return cls(_key=key, public_raw=public_raw)


# ------------------------------------------------------------------ generation
def generate_keypair() -> SigningKey:
    """A fresh Ed25519 signing key. The caller writes it out; we never persist."""
    ed25519, serialization = _require_crypto()
    private = ed25519.Ed25519PrivateKey.generate()
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return SigningKey(_key=private, public_raw=public_raw)


# ------------------------------------------------------------------ (de)serialize
# Keys are stored as PEM: it is the format operators expect, it is unambiguous
# about public-vs-private, and it round-trips through every KMS and secret store.
def private_key_to_pem(key: SigningKey) -> bytes:
    _, serialization = _require_crypto()
    return key._key.private_bytes(  # type: ignore[attr-defined]
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_raw: bytes) -> bytes:
    ed25519, serialization = _require_crypto()
    key = ed25519.Ed25519PublicKey.from_public_bytes(public_raw)
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_b64(public_raw: bytes) -> str:
    """Raw public key as base64 — the compact form a bundle embeds."""
    return base64.b64encode(public_raw).decode("ascii")


def public_raw_from_b64(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise SigningError(f"public key is not valid base64: {exc}") from None


def load_signing_key(path: str | Path) -> SigningKey:
    """Load a private Ed25519 key from a PEM file (fail-closed on anything else)."""
    ed25519, serialization = _require_crypto()
    data = _read_key_file(path)
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        raise SigningError(f"{path}: not a valid PEM private key ({exc})") from None
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise SigningError(
            f"{path}: expected an Ed25519 private key, got {type(key).__name__}"
        )
    public_raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return SigningKey(_key=key, public_raw=public_raw)


def load_verifying_key(path: str | Path) -> VerifyingKey:
    """Load a public Ed25519 key from a PEM file.

    Accepts a public-key PEM; also accepts a *private* key PEM and extracts its
    public half, so an operator who points `--public-key` at the wrong file gets
    a working verify rather than a confusing failure — the private material is
    never used for verification.
    """
    ed25519, serialization = _require_crypto()
    data = _read_key_file(path)
    try:
        key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError):
        # Fall back to a private-key PEM and use its public half.
        try:
            private = serialization.load_pem_private_key(data, password=None)
        except (ValueError, TypeError) as exc:
            raise SigningError(f"{path}: not a valid PEM public key ({exc})") from None
        if not isinstance(private, ed25519.Ed25519PrivateKey):
            raise SigningError(f"{path}: not an Ed25519 key") from None
        key = private.public_key()
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise SigningError(
            f"{path}: expected an Ed25519 public key, got {type(key).__name__}"
        )
    public_raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return VerifyingKey(_key=key, public_raw=public_raw)


def _read_key_file(path: str | Path) -> bytes:
    try:
        return Path(path).read_bytes()
    except FileNotFoundError:
        raise SigningError(f"key file not found: {path}") from None
    except OSError as exc:
        raise SigningError(f"cannot read key file {path}: {exc}") from None
