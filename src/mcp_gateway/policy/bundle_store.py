"""On-disk home for installed policy bundles — verify, swap atomically, never go dark.

The bundle format (`bundle.py`) makes one artifact trustworthy. This module is
what a long-lived gateway points at: a directory that holds the bundles it has
accepted, remembers which one is live, and can be handed a new bundle to adopt.
Three properties, each a direct answer to a way a naive "just overwrite the
policy file" reload gets a security tool killed:

  * **A rejected bundle never becomes live.** `install` verifies *before* it
    swaps. A bundle that fails its hash or signature is refused and the current
    policy keeps enforcing — a bad (or malicious) push cannot take the gateway
    down to no-policy, and cannot replace a strict policy with a forged lax one.
    This is the fail-closed rule applied to reloads.

  * **The swap is atomic.** The live pointer is flipped with `os.replace`, which
    is atomic on POSIX — a concurrent reader sees the old bundle or the new one,
    never a half-written pointer. No window where the gateway reads a truncated
    policy and fails open (or closed) on garbage.

  * **There is always a last-known-good to fall back to.** Each install demotes
    the previously-live bundle to LKG. If the live bundle is later found corrupt
    on disk — bit-rot, a botched manual edit, a partial restore — `current()`
    self-heals to LKG rather than leaving the gateway with no enforceable policy.
    `rollback()` makes that deliberate: undo a policy that verified but behaves
    wrong.

The store **re-verifies on read**, not only on install. Verifying once and
trusting the file forever assumes nothing touches the directory afterward, which
is exactly the assumption an attacker with filesystem access violates. Every
`current()` re-checks the bundle against the store's verifying key, so a file
swapped underneath the gateway is caught at the next read and falls back to LKG.

Layout (per pack name, so one store can hold several packs' bundles):

    <root>/<name>/
      bundles/<version>.json      # immutable, every bundle ever installed
      current.json                # {"version": …, "installed_at": …}  (atomic)
      last_known_good.json        # the pointer the current one displaced

Pure stdlib + the bundle/crypto layer. The store needs a `VerifyingKey` to do
its job; without one it refuses to resolve a bundle (fail closed), because an
unverified bundle store is just a directory of files an attacker can rewrite.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_gateway.policy.bundle import (
    BundleError,
    PolicyBundle,
    load_bundle,
    verify_bundle,
)

CURRENT = "current.json"
LAST_KNOWN_GOOD = "last_known_good.json"
BUNDLES_DIR = "bundles"


@dataclass(frozen=True, slots=True)
class InstallResult:
    """What happened when a bundle was offered to the store."""

    accepted: bool
    name: str
    version: str
    reason: str                       # human-readable outcome
    displaced_version: str | None = None   # the bundle this one demoted to LKG

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted, "name": self.name, "version": self.version,
            "reason": self.reason, "displaced_version": self.displaced_version,
        }


@dataclass(frozen=True, slots=True)
class Resolved:
    """A bundle the store handed back, and which slot it came from."""

    bundle: PolicyBundle
    source: str                       # "current" | "last_known_good"
    fell_back: bool                   # True when current was unusable and LKG served


class BundleStore:
    """A directory of installed bundles with an atomic, verified live pointer."""

    def __init__(self, root: str | Path, verifying_key: Any):
        if verifying_key is None:
            # An unverified store cannot make a trust decision; refusing here is
            # the same fail-closed stance as the load path.
            raise BundleError(
                "BundleStore requires a verifying key — an unverified bundle "
                "store is just a directory of files an attacker can rewrite"
            )
        self.root = Path(root)
        self._key = verifying_key

    # ------------------------------------------------------------- paths
    def _pack_dir(self, name: str) -> Path:
        return self.root / name

    def _pointer_path(self, name: str, which: str) -> Path:
        return self._pack_dir(name) / which

    def _bundle_path(self, name: str, version: str) -> Path:
        return self._pack_dir(name) / BUNDLES_DIR / f"{_safe(version)}.json"

    # ------------------------------------------------------------- install
    def install(self, bundle: PolicyBundle) -> InstallResult:
        """Verify `bundle` and, if good, make it live — demoting the old live
        bundle to last-known-good. A rejected bundle changes nothing.
        """
        result = verify_bundle(bundle, self._key)
        if not result.ok:
            return InstallResult(
                accepted=False, name=bundle.name, version=bundle.version,
                reason=f"rejected: {result.summary}"
                       + (f" — {result.reasons[0]}" if result.reasons else ""),
            )

        pack_dir = self._pack_dir(bundle.name)
        (pack_dir / BUNDLES_DIR).mkdir(parents=True, exist_ok=True)

        # Store the immutable copy (idempotent: re-installing the same version is
        # a no-op on the file, still repoints current).
        bundle_file = self._bundle_path(bundle.name, bundle.version)
        if not bundle_file.exists():
            _atomic_write(bundle_file, bundle.to_json() + "\n")

        displaced = self._read_pointer(bundle.name, CURRENT)
        if displaced is not None and displaced.get("version") != bundle.version:
            # The bundle we are replacing becomes the fallback.
            _atomic_write(
                self._pointer_path(bundle.name, LAST_KNOWN_GOOD),
                json.dumps(displaced),
            )

        pointer = {
            "version": bundle.version,
            "installed_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        # The atomic step: whoever reads current.json sees old or new, never torn.
        _atomic_write(self._pointer_path(bundle.name, CURRENT), json.dumps(pointer))

        return InstallResult(
            accepted=True, name=bundle.name, version=bundle.version,
            reason="installed and made current",
            displaced_version=(
                displaced.get("version")
                if displaced and displaced.get("version") != bundle.version else None
            ),
        )

    # ------------------------------------------------------------- read
    def current(self, name: str) -> Resolved | None:
        """The live, re-verified bundle for `name`, falling back to LKG if the
        current one is missing or no longer verifies. None if neither is usable.
        """
        live = self._load_pointer_bundle(name, CURRENT)
        if live is not None:
            return Resolved(bundle=live, source="current", fell_back=False)

        # Current is gone or fails re-verification — self-heal to LKG.
        lkg = self._load_pointer_bundle(name, LAST_KNOWN_GOOD)
        if lkg is not None:
            return Resolved(bundle=lkg, source="last_known_good", fell_back=True)
        return None

    def current_version(self, name: str) -> str | None:
        pointer = self._read_pointer(name, CURRENT)
        return pointer.get("version") if pointer else None

    def rollback(self, name: str) -> InstallResult:
        """Promote last-known-good back to current (undo a valid-but-wrong policy).

        Swaps the two pointers: the current bundle becomes the new LKG, so a
        rollback is itself reversible. The promoted bundle is re-verified first —
        a rollback must not install something that no longer passes.
        """
        lkg_pointer = self._read_pointer(name, LAST_KNOWN_GOOD)
        if lkg_pointer is None:
            return InstallResult(
                accepted=False, name=name, version="",
                reason="no last-known-good to roll back to",
            )
        lkg_bundle = self._bundle_for(name, lkg_pointer.get("version", ""))
        if lkg_bundle is None or not verify_bundle(lkg_bundle, self._key).ok:
            return InstallResult(
                accepted=False, name=name, version=lkg_pointer.get("version", ""),
                reason="last-known-good is missing or no longer verifies",
            )
        current_pointer = self._read_pointer(name, CURRENT)
        _atomic_write(self._pointer_path(name, CURRENT), json.dumps(lkg_pointer))
        if current_pointer is not None:
            _atomic_write(
                self._pointer_path(name, LAST_KNOWN_GOOD), json.dumps(current_pointer)
            )
        return InstallResult(
            accepted=True, name=name, version=lkg_pointer.get("version", ""),
            reason="rolled back to last-known-good",
            displaced_version=(current_pointer or {}).get("version"),
        )

    def history(self, name: str) -> list[str]:
        """Versions installed for `name`, newest first (by build-sortable name)."""
        bundles_dir = self._pack_dir(name) / BUNDLES_DIR
        if not bundles_dir.is_dir():
            return []
        return sorted((p.stem for p in bundles_dir.glob("*.json")), reverse=True)

    # ------------------------------------------------------------- internals
    def _read_pointer(self, name: str, which: str) -> dict[str, Any] | None:
        path = self._pointer_path(name, which)
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def _bundle_for(self, name: str, version: str) -> PolicyBundle | None:
        if not version:
            return None
        try:
            return load_bundle(self._bundle_path(name, version))
        except BundleError:
            return None

    def _load_pointer_bundle(self, name: str, which: str) -> PolicyBundle | None:
        """Load the bundle a pointer names and re-verify it; None if unusable."""
        pointer = self._read_pointer(name, which)
        if pointer is None:
            return None
        bundle = self._bundle_for(name, pointer.get("version", ""))
        if bundle is None:
            return None
        return bundle if verify_bundle(bundle, self._key).ok else None


def _atomic_write(path: Path, text: str) -> None:
    """Write via a temp file in the same directory + os.replace (atomic on POSIX).

    Same-directory temp guarantees the replace is a rename within one filesystem;
    a cross-device rename is not atomic and would defeat the whole point.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=path.suffix)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _safe(version: str) -> str:
    """A filesystem-safe stem for a version string (versions are author-supplied)."""
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in version)
