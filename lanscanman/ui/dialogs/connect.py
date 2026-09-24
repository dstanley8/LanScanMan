"""
Shared UI components used by multiple tabs.

Currently contains:
  - CustomPortConnectDialog  — connect to any host:port with chosen protocol
  - launch_connection        — actually open the terminal / browser for a connection
"""

import subprocess
import webbrowser

from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QSpinBox,
)

from lanscanman.core.connect import (
    PROTO_PORTS,
    connection_url,
    get_terminal_command,
    guess_protocol,
    ssh_command,
    terminal_argv,
)
from lanscanman.log import log
from lanscanman.ui.trust import pin_host_or_warn

# ─────────────────────────────────────────────────────────────────────────────
# Dialog
# ─────────────────────────────────────────────────────────────────────────────

class CustomPortConnectDialog(QDialog):
    """
    Connect to a host on a specific port with a chosen protocol.

    port and service are used to pre-select the most likely protocol.
    username is pre-filled from the host's profile (SSH only).
    All fields are editable before confirming.
    """

    def __init__(self, ip: str, port: int = 22, service: str = "",
                 username: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Connect — {ip}")
        self.setMinimumWidth(360)
        self._ip = ip

        layout = QFormLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(14, 14, 14, 14)

        # Protocol
        self._proto = QComboBox()
        self._proto.addItems(list(PROTO_PORTS.keys()))
        self._proto.setCurrentText(guess_protocol(service, port))
        self._proto.currentTextChanged.connect(self._on_proto_changed)
        layout.addRow("Protocol:", self._proto)

        # Port
        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(port)
        layout.addRow("Port:", self._port)

        # Username (SSH only)
        self._user = QLineEdit(username)
        self._user.setPlaceholderText("SSH username")
        layout.addRow("Username:", self._user)

        # Hint label
        self._hint = QLabel("")
        self._hint.setStyleSheet("color: #9AA4AF; font-size: 11px;")
        self._hint.setWordWrap(True)
        layout.addRow(self._hint)
        self._update_hint()

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _on_proto_changed(self, proto: str):
        # Auto-update port only if it still matches a known default
        current = self._port.value()
        if current in PROTO_PORTS.values():
            self._port.setValue(PROTO_PORTS[proto])
        self._update_hint()

    def _update_hint(self):
        hints = {
            "SSH":   "Opens a terminal. Username is required.",
            "VNC":   "Opens a VNC URL in your default viewer.",
            "RDP":   "Opens an RDP URL.",
            "HTTP":  "Opens in your default web browser.",
            "HTTPS": "Opens in your default web browser (HTTPS).",
        }
        proto = self._proto.currentText()
        self._hint.setText(hints.get(proto, ""))
        self._user.setEnabled(proto == "SSH")

    def get_data(self) -> tuple[str, int, str]:
        """Returns (protocol, port, username)."""
        return (
            self._proto.currentText(),
            self._port.value(),
            self._user.text().strip(),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Shared connection launcher
# ─────────────────────────────────────────────────────────────────────────────

def launch_connection(ip: str, proto: str, port: int, username: str,
                      parent=None) -> str | None:
    """
    Open a connection to ip:port using the given protocol.

    Returns a human-readable status string on success,
    or None if the launch failed (shows its own error dialog in that case).
    """
    if proto == "SSH":
        if not username:
            QMessageBox.warning(parent, "Username Required",
                "An SSH username is required to open an SSH connection.")
            return None
        if not pin_host_or_warn(parent, ip, port):
            return None
        term = get_terminal_command()
        if term is None:
            QMessageBox.critical(parent, "No Terminal Found",
                "No supported terminal emulator found.\n"
                "Please install one of: gnome-terminal, konsole, "
                "xfce4-terminal, xterm")
            return None
        try:
            subprocess.Popen(terminal_argv(term, ssh_command(username, ip, port)))
            return f"SSH → {username}@{ip}:{port}"
        except Exception as e:
            log.exception("SSH terminal launch failed for %s@%s:%d",
                          username, ip, port)
            QMessageBox.critical(parent, "Terminal Error", str(e))
            return None

    if proto in ("HTTP", "HTTPS", "VNC", "RDP"):
        url = connection_url(proto, ip, port)
        webbrowser.open(url)
        if proto in ("HTTP", "HTTPS"):
            return f"Opened {url}"
        return f"{proto} → {ip}:{port}"

    return None
