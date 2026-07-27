"""Versioned, signed policy bundles — the unit a gateway trusts at load time.

A `--policy file.yaml` is fine for a laptop. A fleet of gateways pulling policy
from shared storage needs three things a loose file cannot give: a **version**
so operators can say which policy is live and roll back to a named prior one; an
**integrity** guarantee so a truncated or corrupted download is detected rather
than enforced; and **authenticity** so a policy that did not come from the
release pipeline is refused even if it lands in the right directory. A bundle is
that unit.

Shape — one self-describing JSON object, deliberately `cat`-inspectable:

    {
      "bundle_format": 1,
      "manifest": {
        "name": "github",
        "version": "2026.07.27T18-30-00Z-a1b2c3d4",
        "created": "2026-07-27T18:30:00Z",
        "layers": ["policy.yaml", "roles.yaml"],   # provenance, for humans
        "content_hash": "sha256:…",                 # binds the payload
        "signer_key_id": "6bbd7074b139f6fb"
      },
      "payload": {
        "layers": [{"name": "policy.yaml", "text": "<raw yaml>"}, …]
      },
      "signature": {"algorithm": "ed25519", "value": "<base64>"} | null
    }

**The integrity chain has two links, and both are checked on load.**
`content_hash = sha256(canonical(payload))` binds every byte of policy. The
signature is over `canonical(manifest)` — and the manifest *contains*
`content_hash` — so a valid signature vouches for the hash, and the hash vouches
for the payload. Tamper with one policy character and the hash no longer
matches; regenerate the hash to cover your change and the signature over the
manifest no longer verifies. You cannot fix both without the private key.

Canonicalization is `json.dumps(sort_keys, compact, utf-8)` so the bytes that
get hashed and signed are reproducible regardless of key order or whitespace —
the signer and the verifier must agree on them exactly, or every signature would
appear invalid.

The payload stores each layer's **raw authored text**, not a merged/normalized
policy. Two reasons: the hash then covers exactly what a human wrote and can
diff against, and the gateway re-parses through the same loader it always uses,
so a bundle can never smuggle in a policy shape the normal load path would have
rejected. `build_bundle` parses every layer at build time too — an invalid
policy must never be signed, because a signature is a promise that this policy
is safe to enforce.

Hashing and (de)serialization are stdlib and always available; only *signing*
and *signature verification* need `cryptography` (`[vault]`), and both fail
closed when it is absent. `verify_bundle` reports integrity and authenticity
separately so `bundle show` can confirm a hash without crypto while the gateway
load path still insists on a good signature.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_gateway.core.errors import GatewayError, PolicyError
from mcp_gateway.policy.engine import PolicyEngine
from mcp_gateway.policy.loader import PolicyLayer, parse_document

BUNDLE_FORMAT = 1
_HASH_PREFIX = "sha256:"


class BundleError(GatewayError):
    """A bundle is malformed, fails verification, or cannot be built.

    A GatewayError, so the load path treats a bad bundle the way it treats any
    other fail-closed condition: the policy is not enforced.
    """


# --------------------------------------------------------------------- model
@dataclass(frozen=True, slots=True)
class BundleLayer:
    name: str
    text: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "text": self.text}


@dataclass(frozen=True, slots=True)
class PolicyBundle:
    name: str
    version: str
    created: str
    layers: tuple[BundleLayer, ...]
    content_hash: str
    signer_key_id: str | None = None
    signature: str | None = None          # base64 Ed25519 signature, or None

    @property
    def signed(self) -> bool:
        return self.signature is not None

    # -- canonical byte views the hash and signature are computed over ----------
    def _payload_obj(self) -> dict[str, Any]:
        return {"layers": [layer.to_dict() for layer in self.layers]}

    def payload_bytes(self) -> bytes:
        return _canonical(self._payload_obj())

    def _manifest_obj(self) -> dict[str, Any]:
        # The signed manifest deliberately excludes signer_key_id and the
        # signature: those describe the signature, they are not signed by it.
        # It DOES include content_hash, which is the link to the payload.
        return {
            "name": self.name,
            "version": self.version,
            "created": self.created,
            "layers": [layer.name for layer in self.layers],
            "content_hash": self.content_hash,
        }

    def manifest_bytes(self) -> bytes:
        return _canonical(self._manifest_obj())

    def computed_hash(self) -> str:
        return _HASH_PREFIX + hashlib.sha256(self.payload_bytes()).hexdigest()

    # -- serialization ----------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        manifest = self._manifest_obj()
        manifest["signer_key_id"] = self.signer_key_id
        signature = (
            {"algorithm": "ed25519", "value": self.signature}
            if self.signature is not None else None
        )
        return {
            "bundle_format": BUNDLE_FORMAT,
            "manifest": manifest,
            "payload": self._payload_obj(),
            "signature": signature,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def write(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json() + "\n", encoding="utf-8")

    def with_signature(self, signature: str, signer_key_id: str) -> PolicyBundle:
        from dataclasses import replace

        return replace(self, signature=signature, signer_key_id=signer_key_id)


# --------------------------------------------------------------------- build
def build_bundle(
    layer_paths: list[str | Path],
    *,
    name: str | None = None,
    version: str | None = None,
    created: datetime | None = None,
) -> PolicyBundle:
    """Package policy layers into an unsigned bundle, validating them first.

    Every layer is parsed through the normal loader; an invalid policy raises
    `PolicyError` here rather than being sealed into a signed artifact. The
    version defaults to a sortable, human-legible timestamp plus a short content
    hash, so two bundles built from the same policy at different times are
    distinguishable and any two bundles order by build time.
    """
    if not layer_paths:
        raise BundleError("a bundle needs at least one policy layer")

    layers: list[BundleLayer] = []
    for path in layer_paths:
        p = Path(path)
        try:
            text = p.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise BundleError(f"policy layer not found: {p}") from None
        _parse_layer_text(text, p.name)          # validate; discard the result
        layers.append(BundleLayer(name=p.name, text=text))

    resolved_name = name or _default_name(layers)
    payload_hash = _HASH_PREFIX + hashlib.sha256(
        _canonical({"layers": [layer.to_dict() for layer in layers]})
    ).hexdigest()
    created_dt = created or datetime.now(UTC)
    resolved_version = version or _default_version(created_dt, payload_hash)

    return PolicyBundle(
        name=resolved_name,
        version=resolved_version,
        created=_iso(created_dt),
        layers=tuple(layers),
        content_hash=payload_hash,
    )


def _default_name(layers: list[BundleLayer]) -> str:
    """Best-effort pack name from the first layer's declared `name:`."""
    try:
        import yaml

        doc = yaml.safe_load(layers[0].text)
        if isinstance(doc, dict) and isinstance(doc.get("name"), str) and doc["name"]:
            return doc["name"]
    except Exception:  # noqa: BLE001 — naming is a convenience, never fail the build here
        pass
    return Path(layers[0].name).stem


def _default_version(created: datetime, content_hash: str) -> str:
    stamp = created.astimezone(UTC).strftime("%Y.%m.%dT%H-%M-%SZ")
    short = content_hash.removeprefix(_HASH_PREFIX)[:8]
    return f"{stamp}-{short}"


# --------------------------------------------------------------------- sign
def sign_bundle(bundle: PolicyBundle, signing_key: Any) -> PolicyBundle:
    """Return a copy of `bundle` signed by `signing_key` (a `SigningKey`).

    The signature is over the canonical manifest, which carries content_hash —
    see the module docstring for why that is sufficient to vouch for the payload.
    """
    signature = signing_key.sign(bundle.manifest_bytes())
    return bundle.with_signature(
        signature=base64.b64encode(signature).decode("ascii"),
        signer_key_id=signing_key.key_id,
    )


# --------------------------------------------------------------------- verify
@dataclass(frozen=True, slots=True)
class VerifyResult:
    """The outcome of checking a bundle, integrity and authenticity separately.

    `ok` is the gateway's gate: it requires *both* a matching hash and, when a
    verifying key is supplied, a valid signature. `bundle show` can call
    `verify_bundle` with no key to confirm integrity while leaving `signature`
    unchecked — useful for inspection, never sufficient for enforcement.
    """

    integrity_ok: bool
    signature_state: str          # "valid" | "invalid" | "unsigned" | "unchecked"
    reasons: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.integrity_ok and self.signature_state == "valid"

    @property
    def summary(self) -> str:
        integ = "hash ok" if self.integrity_ok else "hash MISMATCH"
        return f"{integ}, signature {self.signature_state}"


def verify_bundle(bundle: PolicyBundle, verifying_key: Any | None = None) -> VerifyResult:
    """Check a bundle's content hash and (if a key is given) its signature.

    Passing no key checks integrity only and reports the signature as
    `unchecked` — never as valid. The gateway always passes its trusted key, so
    an unsigned or wrongly-signed bundle can never satisfy `ok`.
    """
    reasons: list[str] = []

    integrity_ok = bundle.content_hash == bundle.computed_hash()
    if not integrity_ok:
        reasons.append(
            f"content hash mismatch: manifest says {bundle.content_hash}, "
            f"payload hashes to {bundle.computed_hash()} (bundle was altered "
            f"after it was built)"
        )

    if verifying_key is None:
        signature_state = "unchecked"
    elif bundle.signature is None:
        signature_state = "unsigned"
        reasons.append("bundle carries no signature but a signature is required")
    else:
        try:
            raw = base64.b64decode(bundle.signature, validate=True)
        except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
            signature_state = "invalid"
            reasons.append("signature is not valid base64")
        else:
            if verifying_key.verify(raw, bundle.manifest_bytes()):
                signature_state = "valid"
                if (
                    bundle.signer_key_id is not None
                    and bundle.signer_key_id != verifying_key.key_id
                ):
                    # Signature verified, so the key matches regardless; a stale
                    # key_id label is a warning, not a failure.
                    reasons.append(
                        f"note: signer_key_id {bundle.signer_key_id!r} labels a "
                        f"different key than the one that verified "
                        f"({verifying_key.key_id!r})"
                    )
            else:
                signature_state = "invalid"
                reasons.append(
                    "signature does not verify against the trusted key "
                    "(wrong signer, or the manifest was altered)"
                )

    return VerifyResult(
        integrity_ok=integrity_ok,
        signature_state=signature_state,
        reasons=tuple(reasons),
    )


# --------------------------------------------------------------------- load
def load_bundle(path: str | Path) -> PolicyBundle:
    """Parse a bundle file into a `PolicyBundle` (structure only, no verify)."""
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise BundleError(f"bundle file not found: {p}") from None
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BundleError(f"{p}: not a valid bundle (bad JSON: {exc})") from None
    return parse_bundle(doc, source=str(p))


def parse_bundle(doc: Any, source: str = "<bundle>") -> PolicyBundle:
    if not isinstance(doc, dict):
        raise BundleError(f"{source}: bundle must be a JSON object")
    fmt = doc.get("bundle_format")
    if fmt != BUNDLE_FORMAT:
        raise BundleError(
            f"{source}: unsupported bundle_format {fmt!r}; this build supports "
            f"{BUNDLE_FORMAT}"
        )
    manifest = doc.get("manifest")
    if not isinstance(manifest, dict):
        raise BundleError(f"{source}: bundle 'manifest' must be an object")
    payload = doc.get("payload")
    if not isinstance(payload, dict) or not isinstance(payload.get("layers"), list):
        raise BundleError(f"{source}: bundle 'payload.layers' must be a list")

    layers: list[BundleLayer] = []
    for i, entry in enumerate(payload["layers"]):
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("name"), str)
            or not isinstance(entry.get("text"), str)
        ):
            raise BundleError(f"{source}: payload.layers[{i}] needs string 'name' and 'text'")
        layers.append(BundleLayer(name=entry["name"], text=entry["text"]))
    if not layers:
        raise BundleError(f"{source}: bundle has no policy layers")

    for field_name in ("name", "version", "created", "content_hash"):
        if not isinstance(manifest.get(field_name), str) or not manifest[field_name]:
            raise BundleError(f"{source}: manifest.{field_name} must be a non-empty string")

    signature = None
    sig_obj = doc.get("signature")
    if sig_obj is not None:
        if not isinstance(sig_obj, dict) or sig_obj.get("algorithm") != "ed25519":
            raise BundleError(f"{source}: only 'ed25519' signatures are supported")
        if not isinstance(sig_obj.get("value"), str):
            raise BundleError(f"{source}: signature.value must be a string")
        signature = sig_obj["value"]

    return PolicyBundle(
        name=manifest["name"],
        version=manifest["version"],
        created=manifest["created"],
        layers=tuple(layers),
        content_hash=manifest["content_hash"],
        signer_key_id=manifest.get("signer_key_id"),
        signature=signature,
    )


def engine_from_bundle(bundle: PolicyBundle) -> PolicyEngine:
    """Compile a verified bundle into a `PolicyEngine`.

    Re-parses each layer through the normal loader — the bundle stores raw text,
    never a pre-merged policy, so nothing here can bypass a validation the file
    load path would enforce. Callers must `verify_bundle(...).ok` FIRST; this
    function trusts the payload.
    """
    layers = [_parse_layer_text(layer.text, layer.name) for layer in bundle.layers]
    return PolicyEngine(layers)


# --------------------------------------------------------------------- helpers
def _parse_layer_text(text: str, name: str) -> PolicyLayer:
    """Parse one layer's raw text through the policy loader (YAML or JSON)."""
    if name.endswith(".json"):
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyError(f"{name}: not valid JSON ({exc})") from None
    else:
        try:
            import yaml
        except ImportError:
            raise PolicyError(f"{name}: YAML policies need pyyaml") from None
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise PolicyError(f"{name}: not valid YAML ({exc})") from None
    return parse_document(document, source=name, fallback_name=Path(name).stem)


def _canonical(obj: Any) -> bytes:
    """Deterministic bytes for hashing/signing: sorted keys, no incidental space."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
