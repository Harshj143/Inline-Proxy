"""The signed-bundle core: the integrity chain has to actually hold.

A signature scheme is only worth shipping if it *rejects* the things it claims
to. These tests build real bundles and then attack them — flip a policy byte,
rewrite the payload and recompute its hash, present the wrong signer, strip the
signature — and assert each attack is caught by the specific link meant to catch
it. The showcase is `test_recomputed_hash_still_fails_signature`: the realistic
on-disk attacker rewrites the payload AND fixes up content_hash so integrity
passes, and is still stopped because the signature covers the hash-bearing
manifest.

`cryptography` is present in the test env (the [vault] extra), so signing runs;
`test_crypto_absent_fails_closed` forces the import to fail to prove the
fail-closed path.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json

import pytest

from mcp_gateway.core.errors import PolicyError
from mcp_gateway.policy import bundle as B
from mcp_gateway.policy import signing as S

VALID_POLICY = """\
schema_version: 1
name: demo
default_action: block
tools:
  demo.read: {action: redact, reason: pii}
  demo.write: {action: require_approval, reason: mutating}
"""

ROLES = """\
schema_version: 1
tools:
  demo.write:
    action: require_approval
    roles:
      admin: {action: allow, reason: trusted}
"""


@pytest.fixture
def layers(tmp_path):
    (tmp_path / "policy.yaml").write_text(VALID_POLICY)
    (tmp_path / "roles.yaml").write_text(ROLES)
    return [tmp_path / "policy.yaml", tmp_path / "roles.yaml"]


@pytest.fixture
def key():
    return S.generate_keypair()


@pytest.fixture
def signed(layers, key):
    return B.sign_bundle(B.build_bundle(layers), key)


# --------------------------------------------------------------------- build
def test_build_captures_layers_and_derives_metadata(layers):
    bundle = B.build_bundle(layers)
    assert bundle.name == "demo"                     # from the first layer's name:
    assert [layer.name for layer in bundle.layers] == ["policy.yaml", "roles.yaml"]
    assert bundle.content_hash == bundle.computed_hash()
    assert bundle.content_hash.startswith("sha256:")
    assert not bundle.signed


def test_build_stores_raw_text_not_a_merged_policy(layers):
    """The hash must cover what a human wrote, and load must re-parse it."""
    bundle = B.build_bundle(layers)
    assert bundle.layers[0].text == VALID_POLICY


def test_version_is_sortable_and_unique_per_build(layers):
    from datetime import UTC, datetime

    early = B.build_bundle(layers, created=datetime(2026, 1, 1, tzinfo=UTC))
    late = B.build_bundle(layers, created=datetime(2026, 6, 1, tzinfo=UTC))
    assert early.version < late.version               # timestamp-led, orderable


def test_building_an_invalid_policy_refuses_to_seal_it(tmp_path):
    """A signature is a promise the policy is safe to enforce; never sign a
    policy the loader would reject."""
    bad = tmp_path / "bad.yaml"
    bad.write_text("schema_version: 1\ndefault_action: sideways\n")
    with pytest.raises(PolicyError):
        B.build_bundle([bad])


def test_build_requires_at_least_one_layer():
    with pytest.raises(B.BundleError):
        B.build_bundle([])


def test_build_reports_a_missing_layer(tmp_path):
    with pytest.raises(B.BundleError, match="not found"):
        B.build_bundle([tmp_path / "nope.yaml"])


# ------------------------------------------------------------------- verify
def test_signed_bundle_verifies_against_its_key(signed, key):
    result = B.verify_bundle(signed, key.verifying_key())
    assert result.ok
    assert result.integrity_ok and result.signature_state == "valid"


def test_no_key_checks_integrity_but_never_reports_valid(signed):
    """`bundle show` uses this; it must never let an unchecked signature pass."""
    result = B.verify_bundle(signed)
    assert result.integrity_ok
    assert result.signature_state == "unchecked"
    assert not result.ok


def test_wrong_key_is_rejected(signed):
    other = S.generate_keypair().verifying_key()
    result = B.verify_bundle(signed, other)
    assert not result.ok
    assert result.signature_state == "invalid"


def test_unsigned_bundle_fails_when_a_key_is_required(layers, key):
    unsigned = B.build_bundle(layers)
    result = B.verify_bundle(unsigned, key.verifying_key())
    assert not result.ok
    assert result.signature_state == "unsigned"


def test_flipping_a_policy_byte_breaks_the_hash(signed, key):
    evil = B.BundleLayer("policy.yaml", VALID_POLICY.replace("redact", "allow"))
    tampered = dataclasses.replace(signed, layers=(evil, *signed.layers[1:]))
    result = B.verify_bundle(tampered, key.verifying_key())
    assert not result.integrity_ok and not result.ok


def test_recomputed_hash_still_fails_signature(signed, key):
    """The realistic attack: rewrite the payload AND fix up content_hash so
    integrity passes. The signature over the hash-bearing manifest defeats it."""
    evil = B.BundleLayer("policy.yaml", "schema_version: 1\ndefault_action: allow\n")
    payload = B._canonical({"layers": [evil.to_dict()]})
    new_hash = "sha256:" + hashlib.sha256(payload).hexdigest()
    forged = dataclasses.replace(signed, layers=(evil,), content_hash=new_hash)
    result = B.verify_bundle(forged, key.verifying_key())
    assert result.integrity_ok                          # attacker fixed the hash…
    assert result.signature_state == "invalid"          # …but not the signature
    assert not result.ok


def test_editing_a_manifest_field_breaks_the_signature(signed, key):
    forged = dataclasses.replace(signed, version="9999.evil")
    result = B.verify_bundle(forged, key.verifying_key())
    assert result.integrity_ok                          # payload untouched
    assert result.signature_state == "invalid"          # manifest was signed
    assert not result.ok


def test_corrupt_signature_base64_is_invalid_not_a_crash(signed, key):
    forged = dataclasses.replace(signed, signature="not-base64!!!")
    result = B.verify_bundle(forged, key.verifying_key())
    assert result.signature_state == "invalid" and not result.ok


def test_stale_key_id_label_is_a_warning_not_a_failure(signed, key):
    """If the signature verifies, a mismatched key_id label must not block it —
    it is a hint for humans, not part of the trust decision."""
    mislabeled = dataclasses.replace(signed, signer_key_id="0000deadbeef0000")
    result = B.verify_bundle(mislabeled, key.verifying_key())
    assert result.ok
    assert any("labels a different key" in r for r in result.reasons)


# --------------------------------------------------------------- round-trip
def test_write_load_roundtrip_is_stable(signed, key, tmp_path):
    path = tmp_path / "demo.mcgb.json"
    signed.write(path)
    reloaded = B.load_bundle(path)
    assert reloaded.content_hash == signed.content_hash
    assert reloaded.signature == signed.signature
    assert B.verify_bundle(reloaded, key.verifying_key()).ok


def test_on_disk_bundle_is_plain_inspectable_json(signed, tmp_path):
    path = tmp_path / "demo.mcgb.json"
    signed.write(path)
    doc = json.loads(path.read_text())
    assert doc["bundle_format"] == B.BUNDLE_FORMAT
    assert doc["manifest"]["content_hash"] == signed.content_hash
    assert doc["signature"]["algorithm"] == "ed25519"


@pytest.mark.parametrize("mutate,match", [
    (lambda d: d.update(bundle_format=99), "bundle_format"),
    (lambda d: d.pop("manifest"), "manifest"),
    (lambda d: d.__setitem__("payload", {"layers": []}), "no policy layers"),
    (lambda d: d["manifest"].__setitem__("content_hash", ""), "content_hash"),
    (lambda d: d.__setitem__("signature", {"algorithm": "rsa", "value": "x"}), "ed25519"),
])
def test_malformed_bundle_is_rejected(signed, mutate, match):
    doc = signed.to_dict()
    mutate(doc)
    with pytest.raises(B.BundleError, match=match):
        B.parse_bundle(doc)


# ------------------------------------------------------------------- engine
def test_engine_from_bundle_enforces_the_packed_policy(signed):
    engine = B.engine_from_bundle(signed)
    assert engine.evaluate("demo.read", {}).action == "redact"
    assert engine.evaluate("demo.write", {}).action == "require_approval"
    # The roles layer was packed too, and merges the same way it would from files.
    assert engine.evaluate("demo.write", {}, role="admin").action == "allow"


def test_engine_from_bundle_reparses_through_the_loader(signed):
    """A bundle stores raw text, so a payload the loader would reject cannot be
    smuggled past by pre-merging — engine_from_bundle re-runs validation."""
    evil = B.BundleLayer("policy.yaml", "schema_version: 1\ndefault_action: sideways\n")
    forged = dataclasses.replace(signed, layers=(evil,))
    with pytest.raises(PolicyError):
        B.engine_from_bundle(forged)


# ------------------------------------------------------------- fail-closed
def test_crypto_absent_fails_closed(monkeypatch):
    """Without cryptography a signature cannot be checked, so signing/verifying
    must raise rather than silently trusting the bundle."""
    import builtins

    real_import = builtins.__import__

    def no_crypto(name, *args, **kwargs):
        if name.startswith("cryptography"):
            raise ImportError("simulated: cryptography not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_crypto)
    with pytest.raises(S.SigningError, match=r"\[vault\] extra"):
        S.generate_keypair()
    with pytest.raises(S.SigningError, match=r"\[vault\] extra"):
        S.VerifyingKey.from_raw(b"\x00" * 32)


# ----------------------------------------------------------------- key I/O
def test_key_pem_roundtrip(key, tmp_path):
    priv = tmp_path / "signing.pem"
    pub = tmp_path / "signing.pub.pem"
    priv.write_bytes(S.private_key_to_pem(key))
    pub.write_bytes(S.public_key_to_pem(key.public_raw))

    reloaded_priv = S.load_signing_key(priv)
    reloaded_pub = S.load_verifying_key(pub)
    assert reloaded_priv.key_id == key.key_id == reloaded_pub.key_id
    assert reloaded_pub.verify(reloaded_priv.sign(b"m"), b"m")


def test_load_verifying_key_accepts_a_private_pem(key, tmp_path):
    """Pointing --public-key at the private PEM by mistake still verifies, using
    only the public half; it must never fail confusingly."""
    priv = tmp_path / "signing.pem"
    priv.write_bytes(S.private_key_to_pem(key))
    assert S.load_verifying_key(priv).key_id == key.key_id


def test_loading_a_non_key_file_fails_closed(tmp_path):
    junk = tmp_path / "notakey.pem"
    junk.write_text("hello, not a key\n")
    with pytest.raises(S.SigningError):
        S.load_signing_key(junk)


# ------------------------------------------------------------------- the CLI
from mcp_gateway.cli import main  # noqa: E402


def keypair(tmp_path):
    assert main(["policy", "keygen", "--out", str(tmp_path / "k")]) == 0
    return tmp_path / "k.pem", tmp_path / "k.pub.pem"


def build_signed(tmp_path, layers, priv, out):
    args = ["policy", "bundle", "build", "--out", str(out), "--sign-key", str(priv)]
    for layer in layers:
        args += ["--policy", str(layer)]
    assert main(args) == 0
    return out


def test_cli_keygen_writes_a_locked_down_private_key(tmp_path):
    priv, pub = keypair(tmp_path)
    assert priv.exists() and pub.exists()
    import stat

    assert stat.S_IMODE(priv.stat().st_mode) == 0o600   # signs fleet-wide policy


def test_cli_keygen_refuses_to_clobber_without_force(tmp_path, capsys):
    priv, _ = keypair(tmp_path)
    before = priv.read_bytes()
    assert main(["policy", "keygen", "--out", str(tmp_path / "k")]) == 1
    assert "exists" in capsys.readouterr().err
    assert priv.read_bytes() == before                  # the old key is untouched
    assert main(["policy", "keygen", "--out", str(tmp_path / "k"), "--force"]) == 0
    assert priv.read_bytes() != before                  # --force rotated it


def test_cli_build_verify_roundtrip(tmp_path, layers, capsys):
    priv, pub = keypair(tmp_path)
    out = build_signed(tmp_path, layers, priv, tmp_path / "b.json")
    capsys.readouterr()
    assert main(["policy", "bundle", "verify", str(out), "--public-key", str(pub)]) == 0
    assert "signature valid" in capsys.readouterr().out


def test_cli_verify_rejects_a_tampered_bundle(tmp_path, layers, capsys):
    priv, pub = keypair(tmp_path)
    out = build_signed(tmp_path, layers, priv, tmp_path / "b.json")
    doc = json.loads(out.read_text())
    doc["payload"]["layers"][0]["text"] = "schema_version: 1\ndefault_action: allow\n"
    out.write_text(json.dumps(doc))
    capsys.readouterr()
    assert main(["policy", "bundle", "verify", str(out), "--public-key", str(pub)]) == 1
    assert "MISMATCH" in capsys.readouterr().out


def test_cli_verify_rejects_the_wrong_key(tmp_path, layers):
    priv, _ = keypair(tmp_path)
    other_pub = (tmp_path / "o.pub.pem")
    assert main(["policy", "keygen", "--out", str(tmp_path / "o")]) == 0
    out = build_signed(tmp_path, layers, priv, tmp_path / "b.json")
    assert main(["policy", "bundle", "verify", str(out), "--public-key", str(other_pub)]) == 1


def test_cli_verify_without_a_key_checks_only_integrity(tmp_path, layers, capsys):
    priv, _ = keypair(tmp_path)
    out = build_signed(tmp_path, layers, priv, tmp_path / "b.json")
    capsys.readouterr()
    # An intact bundle passes the integrity-only check…
    assert main(["policy", "bundle", "verify", str(out)]) == 0
    assert "signature unchecked" in capsys.readouterr().out
    # …but a torn one fails even without a key.
    doc = json.loads(out.read_text())
    doc["payload"]["layers"][0]["text"] += "\n# corrupted\n"
    out.write_text(json.dumps(doc))
    assert main(["policy", "bundle", "verify", str(out)]) == 1


def test_cli_build_from_connector(tmp_path, capsys):
    out = tmp_path / "gh.json"
    priv, pub = keypair(tmp_path)
    capsys.readouterr()
    assert main([
        "policy", "bundle", "build", "--connector", "github",
        "--sign-key", str(priv), "--out", str(out),
    ]) == 0
    assert main(["policy", "bundle", "verify", str(out), "--public-key", str(pub)]) == 0


def test_cli_build_unsigned_is_allowed_but_labeled(tmp_path, layers, capsys):
    out = tmp_path / "b.json"
    args = ["policy", "bundle", "build", "--out", str(out)]
    for layer in layers:
        args += ["--policy", str(layer)]
    assert main(args) == 0
    assert "UNSIGNED" in capsys.readouterr().out
    assert not B.load_bundle(out).signed


def test_cli_show_reports_the_manifest(tmp_path, layers, capsys):
    priv, _ = keypair(tmp_path)
    out = build_signed(tmp_path, layers, priv, tmp_path / "b.json")
    capsys.readouterr()
    main(["policy", "bundle", "show", str(out), "--json"])
    info = json.loads(capsys.readouterr().out)
    assert info["name"] == "demo" and info["signed"] is True
    assert info["integrity_ok"] is True


def build_versioned(tmp_path, layers, priv, out, version):
    args = ["policy", "bundle", "build", "--out", str(out),
            "--sign-key", str(priv), "--version", version]
    for layer in layers:
        args += ["--policy", str(layer)]
    assert main(args) == 0
    return out


def test_cli_store_install_current_rollback(tmp_path, layers, capsys):
    priv, pub = keypair(tmp_path)
    store = tmp_path / "store"
    v1 = build_versioned(tmp_path, layers, priv, tmp_path / "v1.json", "v1")
    v2 = build_versioned(tmp_path, layers, priv, tmp_path / "v2.json", "v2")

    common = ["--store", str(store), "--public-key", str(pub)]
    assert main(["policy", "bundle", "install", str(v1), *common]) == 0
    assert main(["policy", "bundle", "install", str(v2), *common]) == 0
    capsys.readouterr()
    assert main(["policy", "bundle", "current", "demo", *common]) == 0
    assert "v2" in capsys.readouterr().out
    # Roll back to the displaced v1.
    assert main(["policy", "bundle", "rollback", "demo", *common]) == 0
    capsys.readouterr()
    main(["policy", "bundle", "current", "demo", *common])
    assert "v1" in capsys.readouterr().out


def test_cli_store_install_rejects_a_forged_bundle(tmp_path, layers, capsys):
    priv, pub = keypair(tmp_path)
    # A bundle signed by a DIFFERENT key than the store trusts.
    assert main(["policy", "keygen", "--out", str(tmp_path / "attacker")]) == 0
    forged = build_signed(tmp_path, layers, tmp_path / "attacker.pem", tmp_path / "f.json")
    capsys.readouterr()
    code = main(["policy", "bundle", "install", str(forged),
                 "--store", str(tmp_path / "store"), "--public-key", str(pub)])
    assert code == 1
    assert "REJECTED" in capsys.readouterr().out
