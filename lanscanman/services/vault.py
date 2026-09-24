"""
The Vault hands out the integrity key and remembers it for the session.

- First use asks the keyring (GNOME shows its unlock prompt if needed).
- If you decline, the next *action* that needs the key asks again. Requests
  within a few seconds of a refusal fail straight away, so one click
  ("Refresh All" over ten hosts) produces one prompt, not ten.
- The first time the key is obtained after upgrading, files that existed
  before signing was introduced (hosts.json, known_hosts) are adopted:
  signed as they are. Which files have been adopted is recorded next to the
  key, so deleting a .sig file later does not get the file re-trusted.

Workers call the vault from their own threads, so everything is locked.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Callable

from lanscanman import paths
from lanscanman.core.integrity import KeyUnavailable, SignedFile, load_key
from lanscanman.log import log
from lanscanman.services.secret_store import SecretStore

ADOPTED_ITEM = "integrity-adopted"      # JSON list of adopted file names
DECLINE_COOLDOWN = 5.0                  # seconds


class Vault:
    def __init__(self, store: SecretStore | None = None,
                 key_file: Path | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.store     = store if store is not None else SecretStore(None)
        self.key_file  = key_file or paths.HMAC_KEY
        self.location  = ""                # "keyring" / "file" once unlocked
        self._clock    = clock
        self._key: bytes | None = None
        self._declined_at: float | None = None
        self._lock     = threading.RLock()
        self._files: dict[str, SignedFile] = {}
        self._checks: list[Callable[[], None]] = []

    # ── Key ──────────────────────────────────────────────────────────────────

    @property
    def unlocked(self) -> bool:
        return self._key is not None

    def key(self) -> bytes:
        """The integrity key; prompts via the keyring if needed.
        Raises KeyUnavailable if the keyring refuses."""
        with self._lock:
            if self._key is not None:
                return self._key
            if (self._declined_at is not None
                    and self._clock() - self._declined_at < DECLINE_COOLDOWN):
                raise KeyUnavailable("the keyring unlock was declined")
            try:
                key, where = load_key(self.key_file, self.store)
            except KeyUnavailable:
                self._declined_at = self._clock()
                log.warning("keyring refused the integrity key")
                raise
            self._key, self.location, self._declined_at = key, where, None
            log.info(f"integrity key unlocked (stored in {where})")
            self._adopt_unsigned()
            return key

    def try_unlock(self) -> bool:
        try:
            self.key()
            return True
        except KeyUnavailable:
            return False

    def add_trust_check(self, check: Callable[[], None]) -> None:
        """Register a verifier (raises IntegrityError) run by ensure_trusted()."""
        with self._lock:
            self._checks.append(check)

    def ensure_trusted(self) -> None:
        """Gate for anything that connects: unlock the key, then verify every
        registered file. Raises KeyUnavailable / TamperedError."""
        self.key()
        with self._lock:
            checks = list(self._checks)
        for check in checks:
            check()

    # ── Signed files ─────────────────────────────────────────────────────────

    def signed_file(self, path: Path, sig_path: Path | None = None) -> SignedFile:
        """A SignedFile keyed by this vault, registered for first-run adoption."""
        f = SignedFile(path, self.key, sig_path)
        with self._lock:
            self._files[Path(path).name] = f
            if self._key is not None:
                self._adopt_unsigned()
        return f

    def resign(self, name: str) -> None:
        """User-approved: trust a registered file as it is now."""
        with self._lock:
            f = self._files[name]
        f.resign()
        log.warning(f"{name}: re-signed at the user's request")

    def _adopted(self) -> set[str]:
        raw = None
        if self.location == "keyring":
            raw = self.store.get(ADOPTED_ITEM)
        else:
            marker = self.key_file.with_name("integrity-adopted.json")
            raw = marker.read_text() if marker.exists() else None
        try:
            return set(json.loads(raw)) if raw else set()
        except ValueError:
            return set()

    def _save_adopted(self, names: set[str]) -> None:
        raw = json.dumps(sorted(names))
        if self.location == "keyring":
            self.store.set(ADOPTED_ITEM, raw)
        else:
            self.key_file.with_name("integrity-adopted.json").write_text(raw)

    def _adopt_unsigned(self) -> None:
        """Sign pre-upgrade files once. A file already recorded as adopted is
        never re-trusted automatically, even if its signature disappears."""
        try:
            adopted = self._adopted()
        except Exception as e:
            log.warning(f"could not read adoption record: {e}")
            return
        new = set()
        for name, f in self._files.items():
            if name in adopted:
                continue
            if f.is_unsigned():
                f.resign()
                log.info(f"{name}: existing file signed on first use of integrity checks")
            new.add(name)
        if new:
            try:
                self._save_adopted(adopted | new)
            except Exception as e:
                log.warning(f"could not save adoption record: {e}")


# ── Process-wide instance ────────────────────────────────────────────────────
# The app installs the real one at startup; until then (and in tests) a
# file-backed vault in the config dir is used.

_vault: Vault | None = None


def get_vault() -> Vault:
    global _vault
    if _vault is None:
        _vault = Vault()
    return _vault


def set_vault(vault: Vault | None) -> None:
    global _vault
    _vault = vault
