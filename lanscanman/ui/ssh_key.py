"""
SSH key hygiene in the UI: create keys with a passphrase, offer to add one
to an existing unencrypted key, and load the key into the agent.

All of it happens in a terminal running ssh-keygen / ssh-add, so the
passphrase is typed straight into OpenSSH and LanScanMan never sees it.
Once a key has a passphrase, GNOME asks for it the first time the key is
used and can remember it in your login keyring.
"""

from __future__ import annotations

import subprocess

from PyQt6.QtCore import QSettings
from PyQt6.QtWidgets import QCheckBox, QMessageBox

from lanscanman.core import sshkey
from lanscanman.core.connect import PRESS_ENTER, get_terminal_command, terminal_argv
from lanscanman.core.sshkey import (
    add_passphrase_command,
    key_status,
    keygen_command,
    ssh_add_command,
)
from lanscanman.log import log

_SETTINGS_KEY = "security/skipUnencryptedKeyWarning"


def _run_in_terminal(parent, cmd: str, what: str) -> bool:
    term = get_terminal_command()
    if term is None:
        QMessageBox.critical(parent, "No Terminal Found",
            f"No supported terminal emulator found.\n\nRun this yourself:\n  {cmd}")
        return False
    try:
        subprocess.Popen(terminal_argv(term, cmd, PRESS_ENTER))
        return True
    except Exception as e:
        log.exception(f"{what} terminal launch failed")
        QMessageBox.critical(parent, "Terminal Error", str(e))
        return False


def ensure_local_key(parent) -> bool:
    """True if a key exists. Otherwise offers to create one (with a
    passphrase) in a terminal and returns False — the caller stops, and the
    user retries once the key exists."""
    if key_status() != "missing":
        return True
    reply = QMessageBox.question(
        parent, "Create an SSH key",
        "You don't have an SSH key yet (~/.ssh/id_ed25519).\n\n"
        "A terminal will open and run ssh-keygen. Choose a passphrase when it "
        "asks — it protects the key if your files are ever copied. You'll be "
        "asked for it the first time the key is used, and GNOME can remember "
        "it for you.\n\n"
        "When the key has been created, run this action again.",
        QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
    if reply == QMessageBox.StandardButton.Ok:
        _run_in_terminal(parent, keygen_command(), "ssh-keygen")
    return False


def offer_add_passphrase(parent, startup: bool = False) -> None:
    """Warn about an unencrypted key and offer to add a passphrase.
    At startup this can be silenced with "Don't remind me"."""
    if key_status() != "unencrypted":
        if not startup:
            QMessageBox.information(parent, "SSH key", "Your SSH key already has a passphrase.")
        return
    settings = QSettings("LanScanMan", "LanScanMan")
    if startup and settings.value(_SETTINGS_KEY, False, type=bool):
        return
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Warning)
    box.setWindowTitle("SSH key has no passphrase")
    box.setText(f"Your SSH private key ({sshkey.DEFAULT_KEY}) is not protected by a passphrase.")
    box.setInformativeText(
        "Anyone who gets a copy of that file can log in to every machine it's "
        "installed on.\n\n"
        "Adding a passphrase opens a terminal running `ssh-keygen -p`. After that, "
        "GNOME asks for the passphrase the first time the key is used and can "
        "remember it in your login keyring.")
    add = box.addButton("Add passphrase…", QMessageBox.ButtonRole.AcceptRole)
    box.addButton("Later", QMessageBox.ButtonRole.RejectRole)
    dont = None
    if startup:
        dont = QCheckBox("Don't remind me at startup")
        box.setCheckBox(dont)
    box.exec()
    if dont is not None and dont.isChecked():
        settings.setValue(_SETTINGS_KEY, True)
    if box.clickedButton() is add:
        _run_in_terminal(parent, add_passphrase_command(), "ssh-keygen -p")


def load_key_into_agent(parent) -> None:
    """ssh-add in a terminal — for when the agent hasn't picked the key up."""
    if key_status() == "missing":
        ensure_local_key(parent)
        return
    _run_in_terminal(parent, ssh_add_command(), "ssh-add")
