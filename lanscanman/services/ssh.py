"""
Paramiko plumbing shared by everything that talks SSH.

LanScanMan keeps its own known_hosts (paths.KNOWN_HOSTS), separate from
~/.ssh/known_hosts, and signs it (known_hosts.sig) so a host key cannot be
swapped behind the app's back. Consequences:

- Only this module writes known_hosts. New hosts are trusted on first use
  (TOFU) and the file is re-signed.
- The OpenSSH command line (terminals, rsync) runs with
  StrictHostKeyChecking=yes, so it can only read the file. Before launching
  it, callers run prepare_cli_ssh(), which pins the host's key here first.
- A changed key raises HostKeyMismatchError (with both keys) so the UI can
  show fingerprints and ask before re-trusting.
- First contact is cross-checked against your own ~/.ssh/known_hosts (and
  /etc/ssh/ssh_known_hosts): if you have SSH'd to the host before and the key
  it presents now is different, that's refused as a mismatch instead of
  being silently trusted.
- Every connection first calls vault.ensure_trusted(): keyring unlocked,
  known_hosts and hosts.json verified.
"""

from __future__ import annotations

import base64
import hashlib
import socket
import threading
from pathlib import Path

import paramiko
from paramiko.hostkeys import HostKeyEntry

from lanscanman import paths
from lanscanman.core.integrity import SignedFile
from lanscanman.services import security_settings
from lanscanman.services.vault import get_vault

_lock = threading.RLock()
_file: SignedFile | None = None
_file_vault = None


# Where the user's own OpenSSH trust lives (read-only; tests override this)
SYSTEM_KNOWN_HOSTS = [Path.home() / ".ssh" / "known_hosts", Path("/etc/ssh/ssh_known_hosts")]

LANSCANMAN = "lanscanman"     # mismatch against LanScanMan's own pinned key
SYSTEM = "system"             # first contact contradicts ~/.ssh/known_hosts
NEW = "new"                   # first contact, strict mode: confirm the fingerprint


class HostKeyMismatchError(Exception):
    """A host presented a different key than the trusted one — benign
    (reinstall, IP reused by another device) or malicious (interception)."""
    def __init__(self, hostname, new_key=None, old_key=None, source=LANSCANMAN):
        self.hostname = hostname
        self.new_key = new_key
        self.old_key = old_key
        self.source = source
        super().__init__(f"Host key mismatch for {hostname}")


class SystemKeyMismatch(paramiko.BadHostKeyException):
    """Raised from the paramiko policy on first contact, so every existing
    BadHostKeyException handler treats it as a key change."""


class UnconfirmedHostKey(paramiko.BadHostKeyException):
    """Strict mode: a host seen for the first time, whose key must be
    confirmed before use. A BadHostKeyException so every existing handler
    routes it to the same confirmation dialog."""
    def __init__(self, hostname, key):
        paramiko.SSHException.__init__(self, f"New host {hostname}: key not yet confirmed")
        self.hostname, self.key, self.expected_key = hostname, key, None
        self.args = (hostname, key)

    def __str__(self):
        # paramiko's version formats expected_key, which a new host doesn't have
        return f"New host {self.hostname}: key {fingerprint(self.key)} not yet confirmed"


def fingerprint(key) -> str:
    """OpenSSH-style SHA256 fingerprint, e.g. 'SHA256:nThbg6kX…'."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def mismatch_from(e: paramiko.BadHostKeyException) -> HostKeyMismatchError:
    source = (NEW if isinstance(e, UnconfirmedHostKey) else
              SYSTEM if isinstance(e, SystemKeyMismatch) else LANSCANMAN)
    return HostKeyMismatchError(e.hostname, e.key, e.expected_key, source)


def system_host_keys(label: str) -> dict | None:
    """Keys for this host in the user's own known_hosts files (hashed entries
    included), as {keytype: PKey}, or None if it isn't in any of them."""
    found: dict = {}
    for path in SYSTEM_KNOWN_HOSTS:
        try:
            lines = path.read_text(errors="replace").splitlines() if path.is_file() else []
        except OSError:
            continue
        keys = paramiko.HostKeys()
        for line in lines:
            # Parse line by line: one malformed entry must not hide the rest
            # (or break connecting altogether)
            try:
                entry = HostKeyEntry.from_line(line)
            except Exception:
                continue
            if entry is not None and entry.key is not None:
                for name in entry.hostnames:
                    keys.add(name, entry.key.get_name(), entry.key)
        entry = keys.lookup(label)
        if entry:
            for keytype in entry.keys():
                found.setdefault(keytype, entry[keytype])
    return found or None


def check_first_contact(label: str, key) -> str:
    """'matched' / 'unknown'; raises SystemKeyMismatch if the user's own
    known_hosts has a different key of the same type for this host, and
    (strict mode) UnconfirmedHostKey if there is nothing to compare against."""
    system = system_host_keys(label)
    if not system or key.get_name() not in system:
        if security_settings.confirm_first_contact():
            raise UnconfirmedHostKey(label, key)
        return "unknown"
    if system[key.get_name()].asbytes() != key.asbytes():
        raise SystemKeyMismatch(label, key, system[key.get_name()])
    return "matched"


# ── The signed known_hosts file ──────────────────────────────────────────────

def known_hosts_file() -> SignedFile:
    """The SignedFile for known_hosts, bound to the current vault."""
    global _file, _file_vault
    with _lock:
        vault = get_vault()
        if _file is None or _file_vault is not vault:
            _file = vault.signed_file(paths.KNOWN_HOSTS)
            _file_vault = vault
            vault.add_trust_check(lambda f=_file: f.read())
        return _file


def _entries() -> list[str]:
    data = known_hosts_file().read()          # verified
    return data.decode().splitlines() if data else []


def host_label(ip: str, port: int = 22) -> str:
    """known_hosts spelling of a host: '192.168.50.5' or '[192.168.50.5]:2222'."""
    return ip if port == 22 else f"[{ip}]:{port}"


def add_host_key(hostname: str, key: paramiko.PKey) -> None:
    with _lock:
        lines = _entries()
        lines.append(f"{hostname} {key.get_name()} {key.get_base64()}")
        known_hosts_file().write(("\n".join(lines) + "\n").encode())


def remove_host_from_known_hosts(hostname) -> None:
    with _lock:
        lines = _entries()
        kept = [l for l in lines if not l.startswith(hostname + " ")]
        if kept != lines:
            known_hosts_file().write(("\n".join(kept) + "\n").encode() if kept else b"")


def trusted_host_keys() -> paramiko.HostKeys:
    """Host keys from the verified known_hosts."""
    keys = paramiko.HostKeys()
    for line in _entries():
        entry = HostKeyEntry.from_line(line)
        if entry is not None:
            for name in entry.hostnames:
                keys.add(name, entry.key.get_name(), entry.key)
    return keys


# ── Paramiko ─────────────────────────────────────────────────────────────────

class LanScanManHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Trust-on-first-use, cross-checked against the user's own known_hosts:
    record unknown hosts in the signed known_hosts."""
    def missing_host_key(self, client, hostname, key):
        check_first_contact(hostname, key)
        add_host_key(hostname, key)
        client._host_keys.add(hostname, key.get_name(), key)


def make_ssh_client() -> paramiko.SSHClient:
    get_vault().ensure_trusted()
    known_hosts_file()
    ssh = paramiko.SSHClient()
    host_keys = ssh.get_host_keys()
    for name, keys in trusted_host_keys().items():
        for keytype, key in keys.items():
            host_keys.add(name, keytype, key)
    ssh.set_missing_host_key_policy(LanScanManHostKeyPolicy())
    return ssh


def connect(ip: str, username: str, timeout: float) -> paramiko.SSHClient:
    """Key/agent-authenticated connection with our host key policy."""
    ssh = make_ssh_client()
    ssh.connect(ip, username=username, timeout=timeout,
                look_for_keys=True, allow_agent=True)
    return ssh


def run_remote(ip: str, username: str, command: str,
               connect_timeout: float, exec_timeout: float) -> str:
    """Run one command and return its decoded stdout."""
    ssh = connect(ip, username, connect_timeout)
    try:
        _, stdout, _ = ssh.exec_command(command, timeout=exec_timeout)
        return stdout.read().decode(errors="replace")
    finally:
        ssh.close()


# ── OpenSSH command line ─────────────────────────────────────────────────────

def fetch_host_key(ip: str, port: int = 22, timeout: float = 5.0,
                   key_types: list[str] | None = None) -> paramiko.PKey:
    """The server's host key, from a key exchange only (no login).
    key_types restricts negotiation to types we already have pinned."""
    sock = socket.create_connection((ip, port), timeout=timeout)
    transport = paramiko.Transport(sock)
    try:
        if key_types:
            opts = transport.get_security_options()
            wanted = [k for k in opts.key_types if k in key_types]
            if wanted:
                opts.key_types = wanted
        transport.start_client(timeout=timeout)
        return transport.get_remote_server_key()
    finally:
        transport.close()


def prepare_cli_ssh(ip: str, port: int = 22, fetch=fetch_host_key) -> None:
    """
    Call before launching ssh / rsync / ssh-copy-id: verifies trust, then
    makes sure the host's key is pinned in our known_hosts (TOFU on first
    contact) so the CLI can run with StrictHostKeyChecking=yes.
    Raises HostKeyMismatchError if the host now presents a different key.
    """
    get_vault().ensure_trusted()
    label = host_label(ip, port)
    known = trusted_host_keys().lookup(label)
    if known is None:
        # First contact: ask for a key type the user's own known_hosts has,
        # so it can be compared
        system = system_host_keys(label)
        key = fetch(ip, port, key_types=list(system.keys()) if system else None)
        try:
            check_first_contact(label, key)
        except paramiko.BadHostKeyException as e:
            raise mismatch_from(e) from None
        add_host_key(label, key)
        return
    key = fetch(ip, port, key_types=list(known.keys()))
    stored = known.get(key.get_name())
    if stored is None:
        # Host offered a key type we have not pinned — treat as a change
        raise HostKeyMismatchError(label, key, next(iter(known.values()), None))
    if stored.asbytes() != key.asbytes():
        raise HostKeyMismatchError(label, key, stored)


def accept_new_key(err: HostKeyMismatchError) -> None:
    """The user chose to trust the new key: replace what LanScanMan has
    pinned for this host with it (or just forget the old one if we don't
    have the new key, so the next connection re-pins)."""
    remove_host_from_known_hosts(err.hostname)
    if err.new_key is not None:
        add_host_key(err.hostname, err.new_key)
