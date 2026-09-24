"""
The dialogs for integrity problems, shared by every tab:

- keyring declined/locked  -> explain; the next action will ask again
- file tampered            -> explain, offer to trust the file as it is now
- host key changed         -> ask before re-trusting (possible MITM)

app.py also routes any IntegrityError that escapes a UI handler here, so
a refused keyring never crashes the app.
"""

from __future__ import annotations

import paramiko
from PyQt6.QtWidgets import QMessageBox

from lanscanman import paths
from lanscanman.core.devices import DeviceRegistry, key_change_context
from lanscanman.core.integrity import IntegrityError, KeyUnavailable, TamperedError
from lanscanman.log import log
from lanscanman.services.ssh import (
    LANSCANMAN,
    NEW,
    SYSTEM,
    HostKeyMismatchError,
    accept_new_key,
    fingerprint,
    prepare_cli_ssh,
)
from lanscanman.services.vault import get_vault

_WHAT = {
    "hosts.json":  "your saved host profiles (which IP address and username each host uses)",
    "known_hosts": "LanScanMan's list of trusted SSH host keys",
}


def show_integrity_problem(parent, err: IntegrityError) -> None:
    if isinstance(err, KeyUnavailable):
        QMessageBox.warning(
            parent, "Keyring locked",
            "This action needs LanScanMan's signing key, which is kept in your "
            "keyring, and the keyring was not unlocked.\n\n"
            "Nothing was changed. Try the action again and unlock the keyring "
            "when prompted.")
        return
    if isinstance(err, TamperedError):
        name = err.path.name
        box = QMessageBox(parent)
        box.setIcon(QMessageBox.Icon.Critical)
        box.setWindowTitle("File modified outside LanScanMan")
        box.setText(
            f"{name} — {_WHAT.get(name, 'a LanScanMan settings file')} — was "
            "changed by something other than LanScanMan, or its signature is missing.")
        box.setInformativeText(
            "If you did not edit it yourself, someone may be trying to redirect "
            "your connections. LanScanMan will not connect anywhere until this "
            "is resolved.\n\n"
            "Only choose \"Trust current file\" if you made the change yourself.")
        trust = box.addButton("Trust current file", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton("Keep blocked", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() is trust:
            try:
                get_vault().resign(name)
            except IntegrityError as e:
                show_integrity_problem(parent, e)
        return
    QMessageBox.critical(parent, "Integrity check failed", str(err))


def _device_context(hostname: str) -> tuple[str, str]:
    """What the scanner knows about who owns this IP (see core.devices)."""
    ip = hostname.split("]")[0].lstrip("[")
    try:
        reg = DeviceRegistry(get_vault().signed_file(paths.DEVICES_FILE))
        reg.load()
        return key_change_context(reg.devices, ip)
    except Exception:
        return "unknown", ""


def host_key_file(key) -> str:
    """The server-side public key file matching this key's type."""
    name = key.get_name() if key is not None else "ssh-ed25519"
    kind = "ed25519" if "ed25519" in name else "ecdsa" if "ecdsa" in name else \
        "rsa" if "rsa" in name else "ed25519"
    return f"/etc/ssh/ssh_host_{kind}_key.pub"


def confirm_host_key_change(parent, err) -> bool:
    """
    Ask before trusting a changed (or contradicting) host key. Shows both
    fingerprints and whether the scanner saw a different device take the IP.
    "Keep blocked" is the default. Returns True if the user chose to trust
    the new key, which is then pinned.
    """
    if not isinstance(err, HostKeyMismatchError):
        err = HostKeyMismatchError(str(err))
    host = err.hostname
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Warning)
    if err.source == NEW:
        box.setWindowTitle("Confirm a new host")
        box.setText(f"First connection to <b>{host}</b>.")
        lines = ["Strict mode is on, so LanScanMan shows a new host's key before trusting it. "
                 "Check the fingerprint below against the one the host itself reports."]
        old_label = ""
    elif err.source == SYSTEM:
        box.setWindowTitle("Host key doesn't match your SSH settings")
        box.setText(f"<b>{host}</b> presented a different SSH key from the one in your own "
                    "<code>~/.ssh/known_hosts</code>.")
        lines = ["LanScanMan hasn't connected to this host before, but you have, with "
                 "ordinary ssh — and the key doesn't match what you trusted then."]
        old_label = "In ~/.ssh/known_hosts"
    else:
        box.setWindowTitle("Host key changed")
        box.setText(f"The SSH host key for <b>{host}</b> has changed.")
        lines = []
        old_label = "Previously"
    kind, context = _device_context(host) if err.source == LANSCANMAN else ("unknown", "")
    if context:
        lines.append(context)
    if err.old_key is not None:
        lines.append(f"{old_label}:  {fingerprint(err.old_key)}")
    if err.new_key is not None:
        lines.append(f"Now:  {fingerprint(err.new_key)}")
    lines.append("To compare, run this on that machine (it prints the fingerprint):  "
                 f"ssh-keygen -lf {host_key_file(err.new_key)}")
    if err.source == NEW:
        lines.append("Only continue if the fingerprints match.")
        keep_text, trust_text = "Cancel", "Trust and connect"
    else:
        lines.append("Only trust the new key if you know why it changed.")
        keep_text, trust_text = "Keep blocked", "Trust the new key"
    box.setInformativeText("\n\n".join(lines))
    keep = box.addButton(keep_text, QMessageBox.ButtonRole.RejectRole)
    trust = box.addButton(trust_text, QMessageBox.ButtonRole.DestructiveRole)
    box.setDefaultButton(keep)
    box.setEscapeButton(keep)
    box.exec()
    if box.clickedButton() is not trust:
        return False
    try:
        accept_new_key(err)
    except IntegrityError as e:
        show_integrity_problem(parent, e)
        return False
    log.warning(f"user trusted host key {fingerprint(err.new_key) if err.new_key else '?'} "
                f"for {host} ({err.source})")
    return True


def pin_host_or_warn(parent, ip: str, port: int = 22) -> bool:
    """
    Run before launching ssh / rsync / ssh-copy-id from the UI thread.
    True when the host key is pinned and trusted; False (after telling the
    user why) otherwise.
    """
    for attempt in range(2):
        try:
            prepare_cli_ssh(ip, port)
            return True
        except HostKeyMismatchError as e:
            if attempt or not confirm_host_key_change(parent, e):
                return False
        except IntegrityError as e:
            show_integrity_problem(parent, e)
            return False
        except (OSError, paramiko.SSHException) as e:
            log.warning(f"could not fetch host key for {ip}:{port}: {e}")
            QMessageBox.critical(
                parent, "Could not verify host",
                f"LanScanMan could not reach {ip}:{port} to check its SSH host key:\n\n{e}")
            return False
    return False
