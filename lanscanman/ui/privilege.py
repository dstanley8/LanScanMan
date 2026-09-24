"""
Getting permission for a privileged scan (the UI half of services/privilege).

prepare_privileged_scan() is called before every privileged scan and returns
(go ahead, password-for-this-scan-or-None, mode):

  polkit mode  → the desktop/terminal/askpass prompt happens during the scan
  sudo mode    → nothing to ask if sudo still remembers you (sudo -n);
                 otherwise sudo's askpass program, or LanScanMan's password
                 box — the password goes to sudo once and isn't kept
  sudo_session → INSECURE: asked once in LanScanMan's password box, then kept
                 in memory and re-supplied until the app closes
Nothing is ever installed.
"""

from __future__ import annotations

from PyQt6.QtWidgets import QMessageBox

from lanscanman.core import privilege as P
from lanscanman.core.integrity import IntegrityError
from lanscanman.services import privilege, security_settings


def current_mode() -> str:
    try:
        return security_settings.privilege_method()
    except IntegrityError:
        return P.POLKIT_MODE


def prepare_privileged_scan(parent) -> tuple[bool, str | None, str]:
    caps = privilege.detect()
    mode = current_mode()
    if not caps.nmap:
        QMessageBox.warning(parent, "nmap not installed",
                            "nmap isn't installed. Install it with:  sudo apt install nmap")
        return False, None, mode

    if mode == P.SUDO_SESSION_MODE:
        if not caps.sudo:
            QMessageBox.information(parent, "sudo not available",
                                    "sudo isn't installed. Switch ⚙ → Ask for scan permission "
                                    "with → System prompt.")
            return False, None, mode
        held = privilege.session_password()
        if held is not None:
            # sudo may still remember us; otherwise re-supply the held password
            return True, (None if privilege.sudo_remembers(caps) else held), mode
        from lanscanman.ui.dialogs.host_dialogs import SudoDialog
        dlg = SudoDialog(parent, keep_for_session=True)
        if not dlg.exec() or not dlg.get_password():
            return False, None, mode
        privilege.remember_session_password(dlg.get_password())
        return True, dlg.get_password(), mode

    if mode == P.SUDO_MODE:
        if not caps.sudo:
            QMessageBox.information(parent, "sudo not available",
                                    "sudo isn't installed. Switch ⚙ → Ask for scan permission "
                                    "with → System prompt.")
            return False, None, mode
        if privilege.sudo_remembers(caps) or caps.askpass:
            return True, None, mode
        from lanscanman.ui.dialogs.host_dialogs import SudoDialog
        dlg = SudoDialog(parent)
        if not dlg.exec() or not dlg.get_password():
            return False, None, mode
        return True, dlg.get_password(), mode

    if privilege.methods(caps, mode):
        return True, None, mode
    QMessageBox.information(
        parent, "Privileged scan unavailable",
        "This system has no polkit authentication agent and no sudo askpass program.\n\n"
        "Options:\n"
        "• Use an unprivileged scan (no MAC addresses)\n"
        "• Install a polkit agent (e.g. polkit-gnome) or ssh-askpass\n"
        "• Or switch ⚙ → Ask for scan permission with → sudo")
    return False, None, mode
