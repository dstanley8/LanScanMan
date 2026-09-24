"""
Secrets kept in the desktop keyring (GNOME Keyring / KDE Wallet, via the
freedesktop Secret Service) instead of plain files under ~/.config.

What this protects against: the keyring is encrypted on disk with your
login password, so a stolen disk, a leaked backup of ~/.config, or a bug
that lets something read your files no longer exposes the secret.

What it does not protect against: Secret Service has no per-application
access control. Any program already running as you, in an unlocked
session, can ask the keyring for the same item.
"""

from __future__ import annotations

from lanscanman.log import log

SERVICE = "LanScanMan"

# Only real, encrypted backends. The keyring library can also fall back to
# plaintext files (keyrings.alt), which would be no better than what we had.
_SECURE_BACKENDS = (
    ("keyring.backends.SecretService", "Keyring"),   # GNOME Keyring, KeePassXC, …
    ("keyring.backends.kwallet", "DBusKeyring"),     # KDE Wallet
)


class SecretStoreError(Exception):
    """The keyring exists but refused the request (locked, prompt dismissed, …)."""


def _secure_backend():
    """First usable encrypted backend, or None."""
    try:
        import importlib
        for module, cls in _SECURE_BACKENDS:
            try:
                backend_cls = getattr(importlib.import_module(module), cls)
                if backend_cls.priority > 0:     # raises / is <=0 when unavailable
                    return backend_cls()
            except Exception:
                continue
    except Exception:
        pass
    return None


class SecretStore:
    """
    Thin wrapper over one keyring backend. `backend` is anything with
    get_password / set_password / delete_password (tests pass a dict-backed fake).
    """

    def __init__(self, backend=None):
        self._backend = backend

    @classmethod
    def default(cls) -> "SecretStore":
        backend = _secure_backend()
        if backend is None:
            log.warning("no secure keyring available — secrets fall back to files")
        else:
            log.info(f"using keyring backend {type(backend).__module__}")
        return cls(backend)

    @property
    def available(self) -> bool:
        return self._backend is not None

    @property
    def description(self) -> str:
        if self._backend is None:
            return "none"
        return getattr(self._backend, "name", type(self._backend).__name__)

    def get(self, name: str) -> str | None:
        try:
            return self._backend.get_password(SERVICE, name)
        except Exception as e:
            raise SecretStoreError(f"keyring read failed for {name!r}: {e}") from e

    def set(self, name: str, value: str) -> None:
        try:
            self._backend.set_password(SERVICE, name, value)
        except Exception as e:
            raise SecretStoreError(f"keyring write failed for {name!r}: {e}") from e

    def delete(self, name: str) -> None:
        try:
            self._backend.delete_password(SERVICE, name)
        except Exception as e:
            raise SecretStoreError(f"keyring delete failed for {name!r}: {e}") from e
