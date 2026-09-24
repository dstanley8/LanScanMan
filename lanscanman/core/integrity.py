"""
Tamper detection for LanScanMan's config files.

Files that decide *where the app connects and what it trusts* are signed with
HMAC-SHA256 using one per-install key:

    schedules.json  -> schedules.hmac   (what gets rsynced where, on a timer)
    hosts.json      -> hosts.json.sig   (which IP / username a host means)
    known_hosts     -> known_hosts.sig  (which host keys are trusted)

The key lives in the desktop keyring when one exists (see load_key); only
code that can read the keyring can produce a valid signature. Pure module:
the keyring is reached through a duck-typed `store` (services.secret_store).
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import os
import secrets
from pathlib import Path
from typing import Callable

from lanscanman.log import log

KEYRING_ITEM = "integrity-key"


class IntegrityError(Exception):
    """A signed file cannot be trusted."""


class KeyUnavailable(IntegrityError):
    """The signing key is in the keyring but could not be read (locked,
    prompt dismissed, daemon gone). Nothing is regenerated, so existing
    signatures stay valid for when it is unlocked."""


class TamperedError(IntegrityError):
    """A file's contents do not match its signature (or it has none)."""
    def __init__(self, path: Path):
        self.path = Path(path)
        super().__init__(f"{self.path.name} was modified outside LanScanMan "
                         f"(signature missing or does not match)")


def sign(key: bytes, content: bytes) -> str:
    return _hmac.new(key, content, hashlib.sha256).hexdigest()


def verify(key: bytes, content: bytes, signature: str) -> bool:
    return _hmac.compare_digest(signature.strip(), sign(key, content))


def _write_private(path: Path, data: bytes) -> None:
    """Atomic write with 0600 permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


# ── Signed files ─────────────────────────────────────────────────────────────

class SignedFile:
    """
    A file plus an HMAC signature file next to it.

    read()   -> verified bytes, None if the file does not exist,
                TamperedError / KeyUnavailable otherwise
    write()  -> resolves the key *before* touching the file, so a locked
                keyring never leaves data rewritten but unsigned
    """

    def __init__(self, path: Path, key_provider: Callable[[], bytes],
                 sig_path: Path | None = None):
        self.path = Path(path)
        self.sig_path = Path(sig_path) if sig_path else self.path.with_name(self.path.name + ".sig")
        self._key = key_provider

    def read_unverified(self) -> bytes | None:
        try:
            return self.path.read_bytes()
        except FileNotFoundError:
            return None

    def _signature(self) -> str | None:
        try:
            return self.sig_path.read_text()
        except FileNotFoundError:
            return None

    def read(self) -> bytes | None:
        data = self.read_unverified()
        if data is None:
            return None
        key = self._key()
        sig = self._signature()
        if sig is None or not verify(key, data, sig):
            raise TamperedError(self.path)
        return data

    def write(self, content: bytes) -> None:
        key = self._key()
        _write_private(self.path, content)
        _write_private(self.sig_path, sign(key, content).encode())

    def resign(self) -> None:
        """Explicitly trust the file as it is now (user-approved)."""
        data = self.read_unverified()
        if data is not None:
            self.write(data)

    def is_unsigned(self) -> bool:
        return self.path.exists() and not self.sig_path.exists()


# ── The key ──────────────────────────────────────────────────────────────────

def _read_key_file(key_path: Path) -> bytes | None:
    try:
        data = key_path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as e:
        log.exception(f"failed to read {key_path.name}: {e}")
        return None
    if len(data) < 32:
        log.warning(f"{key_path.name} is too short, ignoring it")
        return None
    return data


def _load_or_create_key_file(key_path: Path) -> bytes:
    """File fallback, used only when no keyring is available: 32 random bytes
    in hmac.key (0600). Anything that can read that file can forge
    signatures — the keyring path exists to avoid this."""
    key = _read_key_file(key_path)
    if key is not None:
        return key
    key = secrets.token_bytes(32)
    try:
        _write_private(key_path, key)
    except OSError as e:
        log.exception(f"failed to write {key_path.name}: {e}")
    return key


def load_key(key_path: Path, store=None) -> tuple[bytes, str]:
    """
    Return (key, where) with where = "keyring" or "file".

    With a keyring (`store.available`) the key lives there. An existing
    hmac.key is migrated into it on first use (so current signatures stay
    valid) and then deleted. Without a keyring, hmac.key is used.

    Raises KeyUnavailable if the keyring exists but refuses access.
    """
    if store is None or not store.available:
        return _load_or_create_key_file(key_path), "file"

    migrating = False
    try:
        stored = store.get(KEYRING_ITEM)
        key = base64.b64decode(stored) if stored else None
        if key is not None and len(key) >= 32:
            file_key = _read_key_file(key_path)
            if file_key is not None and file_key == key:
                key_path.unlink()              # leftover from an interrupted migration
            elif file_key is not None:
                log.warning("hmac.key differs from the keyring key and was left in "
                            "place; the keyring key is being used")
            return key, "keyring"

        key = _read_key_file(key_path)
        migrating = key is not None
        if key is None:
            key = secrets.token_bytes(32)
        store.set(KEYRING_ITEM, base64.b64encode(key).decode())
        if base64.b64decode(store.get(KEYRING_ITEM) or "") != key:
            raise KeyUnavailable("keyring did not return the key that was just stored")
    except KeyUnavailable:
        raise
    except Exception as e:
        raise KeyUnavailable(str(e)) from e

    if migrating:
        try:
            key_path.unlink()
            log.info("moved the HMAC key from hmac.key into the keyring")
        except OSError as e:
            log.warning(f"key copied to keyring but hmac.key could not be removed: {e}")
    return key, "keyring"
