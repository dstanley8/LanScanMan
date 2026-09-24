"""
Security preferences, kept in a signed file (security.json) rather than the
ordinary Qt settings: something that can write your files must not be able
to quietly switch a protection off.

If the file fails verification, the strict choice is assumed (fail safe).
"""

from __future__ import annotations

import json

from lanscanman import paths
from lanscanman.core.integrity import TamperedError
from lanscanman.log import log
from lanscanman.services.vault import get_vault

DEFAULTS = {"confirm_first_contact": False, "privilege_method": "polkit"}


def _file():
    return get_vault().signed_file(paths.SECURITY_FILE)


def load() -> dict:
    """Current settings. Raises KeyUnavailable if the keyring is locked."""
    try:
        raw = _file().read()
    except TamperedError:
        log.error("security.json failed verification — using the strict settings")
        return {**DEFAULTS, "confirm_first_contact": True, "privilege_method": "polkit"}
    data = json.loads(raw) if raw else {}
    return {**DEFAULTS, **(data if isinstance(data, dict) else {})}


def save(**changes) -> dict:
    current = load()
    current.update(changes)
    _file().write(json.dumps(current, indent=2).encode())
    return current


def confirm_first_contact() -> bool:
    return bool(load()["confirm_first_contact"])


def privilege_method() -> str:
    """'polkit' (asks every scan), 'sudo' (remembered by sudo for a while) or
    'sudo_session' (insecure: LanScanMan keeps the password until it closes)."""
    value = load().get("privilege_method")
    return value if value in ("polkit", "sudo", "sudo_session") else "polkit"
