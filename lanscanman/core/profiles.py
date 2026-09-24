"""
Host profiles (alias, SSH usernames, last IP), persisted to hosts.json.

Profiles are keyed by MAC address so they survive DHCP IP changes; hosts
whose MAC is unknown (e.g. scanned without sudo) are keyed by IP until
rekey_ip_to_mac() upgrades them.

hosts.json is signed (core/integrity.py): it decides which IP and username
a connection goes to, so an edited file could point you — and, for
remote-to-remote transfers, your forwarded SSH agent — at someone else's
machine. If the key is not available at startup the profiles are loaded for
display only (`verified` is False); anything that changes them, or connects
using them, calls require_verified() first.
"""

from __future__ import annotations

import json
from pathlib import Path

from lanscanman import paths
from lanscanman.core.integrity import (
    KeyUnavailable,
    SignedFile,
    TamperedError,
    load_key,
)


class ProfileStore:
    def __init__(self, path: Path | None = None, signed_file: SignedFile | None = None):
        if signed_file is None:
            path = path or paths.HOSTS_FILE
            signed_file = SignedFile(path, lambda: load_key(path.with_name("hmac.key"))[0])
        self._file    = signed_file
        self.path     = signed_file.path
        self.verified = False
        self.problem: Exception | None = None     # why we are unverified, if we are
        self.profiles = self.load()

    # ── Persistence ───────────────────────────────────────────────────────────

    @staticmethod
    def _parse(data: bytes | None) -> dict:
        if not data:
            return {}
        try:
            parsed = json.loads(data)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def load(self) -> dict:
        """Verified load if possible; otherwise a display-only copy with
        `verified` False and `problem` saying why."""
        try:
            data = self._file.read()
            self.verified, self.problem = True, None
        except (KeyUnavailable, TamperedError) as e:
            data = self._file.read_unverified()
            self.verified, self.problem = False, e
        return self._parse(data)

    def require_verified(self) -> None:
        """Re-read hosts.json with its signature checked (prompting for the
        keyring if needed). Raises KeyUnavailable or TamperedError."""
        data = self._file.read()
        self.profiles = self._parse(data)
        self.verified, self.problem = True, None

    def trust_current_file(self) -> None:
        """User-approved: accept hosts.json as it is now and re-sign it."""
        self._file.resign()
        self.require_verified()

    def save(self) -> None:
        self._file.write(json.dumps(self.profiles, indent=4).encode())

    def clear(self) -> None:
        """Delete every profile. Allowed even if the file failed verification:
        it only removes data."""
        self.profiles = {}
        for p in (self._file.path, self._file.sig_path):
            if p.exists():
                p.unlink()
        self.verified, self.problem = True, None

    # ── Lookup ────────────────────────────────────────────────────────────────

    @staticmethod
    def key_for(mac: str, ip: str) -> str:
        return mac if mac else ip

    def get(self, mac: str, ip: str) -> dict:
        return self.profiles.get(self.key_for(mac, ip), {})

    def _existing_key(self, mac: str, ip: str) -> str | None:
        key = mac if (mac and ":" in mac) else ip
        return key if key in self.profiles else None

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def put(self, mac: str, ip: str, hostname: str, alias: str, username: str) -> None:
        """Create or update a profile, preserving any extra users."""
        self.require_verified()
        key = self.key_for(mac, ip)
        extra_users = self.profiles.get(key, {}).get("extra_users", [])
        self.profiles[key] = {
            "alias":       alias,
            "username":    username,
            "last_ip":     ip,
            "hostname":    hostname,
            "extra_users": extra_users,
        }
        self.save()

    def delete(self, mac: str, ip: str) -> bool:
        self.require_verified()
        key = self._existing_key(mac, ip)
        if key is None:
            return False
        del self.profiles[key]
        self.save()
        return True

    # ── Users ─────────────────────────────────────────────────────────────────

    def add_extra_user(self, mac: str, ip: str, username: str) -> bool:
        """Add a secondary username. False if there is no profile or it is already present."""
        self.require_verified()
        key = self._existing_key(mac, ip)
        if key is None:
            return False
        profile = self.profiles[key]
        if username == profile.get("username") or username in profile.get("extra_users", []):
            return False
        profile.setdefault("extra_users", []).append(username)
        self.save()
        return True

    def remove_extra_user(self, mac: str, ip: str, username: str) -> None:
        self.require_verified()
        key = self._existing_key(mac, ip)
        if key is None:
            return
        extras = self.profiles[key].get("extra_users", [])
        if username in extras:
            extras.remove(username)
            self.profiles[key]["extra_users"] = extras
            self.save()

    def set_primary_user(self, mac: str, ip: str, username: str) -> None:
        """Promote a secondary user to primary, demoting the current primary."""
        self.require_verified()
        key = self._existing_key(mac, ip)
        if key is None:
            return
        profile = self.profiles[key]
        current = profile.get("username", "")
        extras  = profile.get("extra_users", [])
        if username not in extras:
            return
        extras.remove(username)
        if current and current not in extras:
            extras.append(current)
        profile["username"]    = username
        profile["extra_users"] = extras
        self.save()

    def all_users(self, mac: str, ip: str) -> list[str]:
        """[primary, *extra_users], or [] if there is no usable primary."""
        profile = self.get(mac, ip)
        primary = profile.get("username", "").strip()
        if not primary or primary == "—":
            return []
        return [primary] + profile.get("extra_users", [])

    def rekey_ip_to_mac(self, ip: str, mac: str) -> bool:
        """Move an IP-keyed profile for `ip` to `mac`. True if anything moved."""
        self.require_verified()
        ip_key = next((k for k, d in self.profiles.items()
                       if d.get("last_ip") == ip and ":" not in k), None)
        if ip_key is None or mac in self.profiles:
            return False
        self.profiles[mac] = self.profiles.pop(ip_key)
        self.save()
        return True
