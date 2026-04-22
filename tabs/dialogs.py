"""
tabs/dialogs.py
───────────────
Shared UI components used by multiple tabs.

Currently contains:
  - CustomPortConnectDialog  — connect to any host:port with chosen protocol
  - launch_connection        — actually open the terminal / browser for a connection
"""

import subprocess
import webbrowser

from PyQt6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QFormLayout,
    QLabel, QLineEdit, QSpinBox,
)


# ── Default port for each supported protocol ──────────────────────────────────

PROTO_PORTS: dict[str, int] = {
    "SSH":   22,
    "VNC":   5900,
    "RDP":   3389,
    "HTTP":  80,
    "HTTPS": 443,
}

SSH_OPTS = (
    "-o StrictHostKeyChecking=accept-new "
    "-o UserKnownHostsFile=~/.config/LanScanMan/known_hosts"
)


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
        self._proto.setCurrentText(self._guess_protocol(service, port))
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

    @staticmethod
    def _guess_protocol(service: str, port: int) -> str:
        svc = service.lower()
        if "vnc"    in svc:                  return "VNC"
        if "rdp"    in svc or "ms-wbt" in svc: return "RDP"
        if "https"  in svc:                  return "HTTPS"
        if "http"   in svc:                  return "HTTP"
        if "ssh"    in svc:                  return "SSH"
        for proto, default in PROTO_PORTS.items():
            if port == default:
                return proto
        return "SSH"

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

def get_terminal_command() -> list | None:
    """Return the first available terminal emulator command, or None."""
    import shutil
    terminals = [
        ("gnome-terminal", ["--", "bash", "-c"]),
        ("konsole",        ["-e", "bash", "-c"]),
        ("xfce4-terminal", ["-e", "bash -c"]),
        ("mate-terminal",  ["-e", "bash -c"]),
        ("lxterminal",     ["-e", "bash -c"]),
        ("xterm",          ["-e", "bash", "-c"]),
    ]
    for binary, args in terminals:
        if shutil.which(binary):
            return [binary] + args
    return None


def launch_connection(ip: str, proto: str, port: int, username: str,
                      parent=None) -> str | None:
    """
    Open a connection to ip:port using the given protocol.

    Returns a human-readable status string on success,
    or None if the launch failed (shows its own error dialog in that case).
    """
    from PyQt6.QtWidgets import QMessageBox

    if proto == "SSH":
        if not username:
            QMessageBox.warning(parent, "Username Required",
                "An SSH username is required to open an SSH connection.")
            return None
        # Quote user-supplied strings before interpolating into the shell command
        import shlex
        user_q = shlex.quote(username)
        ip_q   = shlex.quote(ip)
        cmd  = f"ssh -p {port} {SSH_OPTS} {user_q}@{ip_q}"
        term = get_terminal_command()
        if term is None:
            QMessageBox.critical(parent, "No Terminal Found",
                "No supported terminal emulator found.\n"
                "Please install one of: gnome-terminal, konsole, "
                "xfce4-terminal, xterm")
            return None
        try:
            subprocess.Popen(term + [f"{cmd}; exec bash"])
            return f"SSH → {username}@{ip}:{port}"
        except Exception as e:
            from log import log
            log.exception("SSH terminal launch failed for %s@%s:%d",
                          username, ip, port)
            QMessageBox.critical(parent, "Terminal Error", str(e))
            return None

    elif proto in ("HTTP", "HTTPS"):
        url = f"{proto.lower()}://{ip}:{port}"
        webbrowser.open(url)
        return f"Opened {url}"

    elif proto == "VNC":
        webbrowser.open(f"vnc://{ip}:{port}")
        return f"VNC → {ip}:{port}"

    elif proto == "RDP":
        webbrowser.open(f"rdp://{ip}:{port}")
        return f"RDP → {ip}:{port}"

    return None