"""Dialogs for the Network Scanner tab: fallback password prompt, tmux session picker, profile and account editing, manual host entry."""


import subprocess

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from lanscanman.core.connect import (
    PRESS_ENTER,
    get_terminal_command,
    ssh_copy_id_command,
    terminal_argv,
)
from lanscanman.log import log
from lanscanman.services.network_manager import NetworkManager
from lanscanman.services.ssh import HostKeyMismatchError
from lanscanman.ui.ssh_key import ensure_local_key
from lanscanman.ui.trust import confirm_host_key_change, pin_host_or_warn


class SudoDialog(QDialog):
    """sudo mode's password box (when no askpass program is installed). The
    password is handed to `sudo -S` once and dropped; sudo itself remembers
    the authentication for a while, not LanScanMan."""
    def __init__(self, parent=None, keep_for_session: bool = False):
        super().__init__(parent)
        self.setWindowTitle("Password for privileged scan")
        layout = QFormLayout(self)
        if keep_for_session:
            note = QLabel("Insecure mode: LanScanMan will keep this in memory until it closes, "
                          "so you won't be asked again. It's never written to disk. "
                          "⚙ → Forget remembered permission drops it.")
        else:
            note = QLabel("This is passed straight to sudo and not kept by LanScanMan. sudo "
                          "remembers it for about 15 minutes; ⚙ → Forget remembered "
                          "permission clears that early.")
        note.setWordWrap(True)
        note.setStyleSheet("color: #f39c12;")
        layout.addRow(note)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow("Your password:", self.password_input)
        buttons = QHBoxLayout()
        self.ok_btn = QPushButton("Scan")
        self.ok_btn.clicked.connect(self.accept)
        buttons.addWidget(self.ok_btn)
        layout.addRow(buttons)

    def get_password(self) -> str:
        return self.password_input.text()


class ConnectionModeDialog(QDialog):
    def __init__(self, sessions, connecting_as: str = "", parent=None):
        super().__init__(parent)
        self.existing_sessions = sessions
        self.setWindowTitle("Connection Options")
        self.setMinimumWidth(360)

        layout = QVBoxLayout(self)

        if connecting_as:
            lbl = QLabel(f"Connecting as  <b>{connecting_as}</b>")
            lbl.setStyleSheet("color: #3498db; margin-bottom: 4px;")
            layout.addWidget(lbl)

        layout.addWidget(QLabel("<b>Choose Connection Mode:</b>"))

        self.mode_selector = QListWidget()
        self.mode_selector.addItem("Standard SSH (No TMUX)")
        self.mode_selector.addItem("New Named TMUX Session")

        if sessions:
            layout.addWidget(QLabel("<b>Attach to Existing Session:</b>"))
            self.mode_selector.addItems(sessions)

        self.mode_selector.setCurrentRow(0)
        layout.addWidget(self.mode_selector)

        self.name_label = QLabel("New Session Name:")
        self.name_input = QLineEdit("LanScanMan")
        layout.addWidget(self.name_label)
        layout.addWidget(self.name_input)

        self.mode_selector.currentRowChanged.connect(self.toggle_input)
        self.toggle_input()

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def toggle_input(self):
        is_new = self.mode_selector.currentItem().text() == "New Named TMUX Session"
        self.name_label.setVisible(is_new)
        self.name_input.setVisible(is_new)

    def get_choice(self):
        text = self.mode_selector.currentItem().text()
        if text == "Standard SSH (No TMUX)":
            return "ssh", None
        if text == "New Named TMUX Session":
            base   = self.name_input.text().strip() or "LanScanMan"
            name   = base
            count  = 1
            while name in self.existing_sessions:
                name  = f"{base}_{count}"
                count += 1
            return "tmux_new", name
        return "tmux_attach", text


class EditProfileDialog(QDialog):
    def __init__(self, ip: str, profile: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Edit Profile — {ip}")
        self.setMinimumWidth(380)

        layout = QFormLayout(self)
        layout.setSpacing(10)

        self._alias = QLineEdit(profile.get("alias", ""))
        self._alias.setPlaceholderText("Human-readable nickname")

        self._user = QLineEdit(profile.get("username", ""))
        self._user.setPlaceholderText("SSH login username")

        # Pre-tick connect if a username already exists so the common
        # "update and reconnect" flow requires no extra clicks.
        self._connect_cb = QCheckBox("Connect via SSH after saving")
        self._connect_cb.setChecked(bool(profile.get("username", "").strip()))

        layout.addRow("Nickname:", self._alias)
        layout.addRow("Username:", self._user)
        layout.addRow(self._connect_cb)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save |
            QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

    def get_data(self) -> tuple[str, str, bool]:
        return (
            self._alias.text().strip(),
            self._user.text().strip(),
            self._connect_cb.isChecked(),
        )


class ManageAccountsDialog(QDialog):
    def __init__(self, ip: str, mac: str, alias: str,
                 net_manager: NetworkManager, parent=None):
        super().__init__(parent)
        self.ip          = ip
        self.mac         = mac
        self.alias       = alias
        self.net_manager = net_manager
        self.setWindowTitle(f"Manage Accounts — {alias or ip}")
        self.setMinimumWidth(420)
        self._setup_ui()
        self._refresh()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(8)

        # Header
        hdr = QLabel(
            f"<b>{self.alias or self.ip}</b>"
            f"  <span style='color:#9AA4AF;'>{self.ip}</span>")
        hdr.setStyleSheet("font-size: 13px;")
        root.addWidget(hdr)

        info = QLabel(
            "★ marks the primary account used for monitoring and disk health.\n"
            "Right-click a scanner row → Connect as… to connect as a specific user.")
        info.setStyleSheet("color: #9AA4AF; font-size: 11px;")
        info.setWordWrap(True)
        root.addWidget(info)

        # User list
        self._list = QListWidget()
        self._list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._list.currentRowChanged.connect(self._on_sel)
        root.addWidget(self._list)

        # Buttons
        btn_row = QHBoxLayout()
        self._add_btn     = QPushButton("Add User")
        self._remove_btn  = QPushButton("Remove")
        self._promote_btn = QPushButton("Set as Primary")
        self._key_btn     = QPushButton("Push SSH Key")

        self._add_btn.clicked.connect(self._add)
        self._remove_btn.clicked.connect(self._remove)
        self._promote_btn.clicked.connect(self._promote)
        self._key_btn.clicked.connect(self._push_key)

        for btn in (self._add_btn, self._remove_btn,
                    self._promote_btn, self._key_btn):
            btn_row.addWidget(btn)
        root.addLayout(btn_row)

        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(self.reject)
        root.addWidget(close)

    def _refresh(self):
        self._list.clear()
        profile = self.net_manager.get_profile(self.mac, self.ip)
        primary = profile.get("username", "—")
        extras  = profile.get("extra_users", [])

        p_item = QListWidgetItem(f"★  {primary}  (primary)")
        p_item.setForeground(QColor("#3498db"))
        p_item.setData(Qt.ItemDataRole.UserRole, ("primary", primary))
        self._list.addItem(p_item)

        for u in extras:
            e_item = QListWidgetItem(f"    {u}")
            e_item.setData(Qt.ItemDataRole.UserRole, ("extra", u))
            self._list.addItem(e_item)

        self._update_buttons()

    def _on_sel(self):
        self._update_buttons()

    def _update_buttons(self):
        item = self._list.currentItem()
        if item is None:
            for btn in (self._remove_btn, self._promote_btn, self._key_btn):
                btn.setEnabled(False)
            return
        kind, _ = item.data(Qt.ItemDataRole.UserRole)
        self._remove_btn.setEnabled(kind == "extra")
        self._promote_btn.setEnabled(kind == "extra")
        self._key_btn.setEnabled(True)

    def _current(self) -> tuple[str, str] | tuple[None, None]:
        item = self._list.currentItem()
        if item is None:
            return None, None
        return item.data(Qt.ItemDataRole.UserRole)

    def _add(self):
        username, ok = QInputDialog.getText(
            self, "Add User", "SSH username to add:")
        if not ok or not username.strip():
            return
        username = username.strip()
        if not self.net_manager.add_extra_user(self.mac, self.ip, username):
            QMessageBox.warning(self, "Already Exists",
                f"'{username}' is already associated with this host.")
            return
        self._refresh()

    def _remove(self):
        kind, user = self._current()
        if kind != "extra" or user is None:
            return
        self.net_manager.remove_extra_user(self.mac, self.ip, user)
        self._refresh()

    def _promote(self):
        kind, user = self._current()
        if kind != "extra" or user is None:
            return
        self.net_manager.set_primary_user(self.mac, self.ip, user)
        self._refresh()

    def _push_key(self):
        kind, user = self._current()
        if user is None:
            return

        if not ensure_local_key(self):
            return
        # Try silent key auth first
        try:
            success, error = self.net_manager.push_ssh_key_silent(user, self.ip)
        except HostKeyMismatchError as e:
            if confirm_host_key_change(self, e):
                try:
                    success, error = self.net_manager.push_ssh_key_silent(
                        user, self.ip)
                except Exception:
                    QMessageBox.critical(self, "Setup Failed",
                        "Failed after retrusting host.")
                    return
            else:
                return

        if success:
            QMessageBox.information(self, "Success",
                f"SSH key installed for {user}@{self.ip}!")
            return

        if error == "auth_failed":
            # Offer ssh-copy-id in terminal — app never sees the password
            ok, _ = self.net_manager.ensure_ssh_key()
            if not ok:
                QMessageBox.critical(self, "Key Generation Failed",
                    "Could not generate a local SSH key pair.")
                return

            reply = QMessageBox.question(
                self, "No Existing Key Auth",
                f"Could not authenticate to {user}@{self.ip} with your SSH key.\n\n"
                f"A terminal will open running:\n"
                f"  ssh-copy-id {user}@{self.ip}\n\n"
                f"You will be prompted for {user}'s password in the terminal.\n"
                f"LanScanMan never sees that password.",
                QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
            if reply != QMessageBox.StandardButton.Ok:
                return

            if not pin_host_or_warn(self, self.ip):
                return
            cmd  = ssh_copy_id_command(user, self.ip)
            term = get_terminal_command()
            if term is None:
                QMessageBox.critical(self, "No Terminal Found",
                    f"No terminal emulator found. Run manually:\n  ssh-copy-id {user}@{self.ip}")
                return
            try:
                subprocess.Popen(terminal_argv(term, cmd, PRESS_ENTER))
            except Exception as e:
                log.exception("ssh-copy-id terminal launch failed for %s@%s",
                              user, self.ip)
                QMessageBox.critical(self, "Terminal Error", str(e))
        else:
            QMessageBox.critical(self, "Setup Failed", error or "Unknown error")


class AddHostDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Host Manually")
        self.setMinimumWidth(360)

        layout = QFormLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(14, 14, 14, 14)

        self._ip    = QLineEdit()
        self._ip.setPlaceholderText("e.g. 192.168.50.50 or 192.168.1.100")

        self._alias = QLineEdit()
        self._alias.setPlaceholderText("Human-readable nickname (optional)")

        self._user  = QLineEdit()
        self._user.setPlaceholderText("SSH login username")

        self._hostname = QLineEdit()
        self._hostname.setPlaceholderText("Hostname (optional)")

        layout.addRow("IP Address:", self._ip)
        layout.addRow("Alias:", self._alias)
        layout.addRow("Username:", self._user)
        layout.addRow("Hostname:", self._hostname)

        note = QLabel(
            "The host will appear in the scanner table immediately.\n"
            "Profile is keyed by IP until a privileged scan or SSH\n"
            "connection can resolve the MAC address.")
        note.setStyleSheet("color: #9AA4AF; font-size: 11px;")
        note.setWordWrap(True)
        layout.addRow(note)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self._validate)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

    def _validate(self):
        if not self._ip.text().strip():
            QMessageBox.warning(self, "IP Required",
                "Please enter an IP address.")
            return
        self.accept()

    def get_data(self) -> dict:
        return {
            "ip":       self._ip.text().strip(),
            "alias":    self._alias.text().strip(),
            "username": self._user.text().strip(),
            "hostname": self._hostname.text().strip(),
        }
