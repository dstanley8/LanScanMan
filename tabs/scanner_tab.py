import csv
import io
import shlex
import socket
import subprocess
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLineEdit, QTableWidget, QTableWidgetItem, QHeaderView, QLabel,
    QMessageBox, QInputDialog, QDialog, QCheckBox, QFormLayout, QMenu,
    QListWidget, QListWidgetItem, QDialogButtonBox, QApplication,
    QFileDialog, QAbstractItemView,
)
from PyQt6.QtCore import Qt, QMetaObject, Q_ARG, pyqtSlot as pyqt6_slot
from PyQt6.QtGui import QColor, QBrush, QCursor, QKeySequence, QShortcut

from concurrent.futures import ThreadPoolExecutor

from scanner import ScannerThread
from manager import NetworkManager, HostKeyMismatchError, remove_host_from_known_hosts
from tabs.dialogs import CustomPortConnectDialog, launch_connection
from log import log

from PyQt6.QtCore import QTimer


# ─────────────────────────────────────────────────────────────────────────────
# SudoDialog
# ─────────────────────────────────────────────────────────────────────────────

class SudoDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Authentication Required")
        layout = QFormLayout(self)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.remember_cb = QCheckBox("Remember for this session")
        layout.addRow("Sudo Password:", self.password_input)
        layout.addRow(self.remember_cb)
        buttons = QHBoxLayout()
        self.ok_btn = QPushButton("Confirm")
        self.ok_btn.clicked.connect(self.accept)
        buttons.addWidget(self.ok_btn)
        layout.addRow(buttons)

    def get_data(self):
        return self.password_input.text(), self.remember_cb.isChecked()


# ─────────────────────────────────────────────────────────────────────────────
# ConnectionModeDialog
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# EditProfileDialog  — replaces two sequential QInputDialog prompts
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# ManageAccountsDialog
# ─────────────────────────────────────────────────────────────────────────────

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

        # Try silent key auth first
        try:
            success, error = self.net_manager.push_ssh_key_silent(user, self.ip)
        except HostKeyMismatchError:
            reply = QMessageBox.question(
                self, "Host Key Changed",
                f"Host key for {self.ip} has changed. Remove and retrust?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                remove_host_from_known_hosts(self.ip)
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

            SSH_OPTS = (
                "-o StrictHostKeyChecking=accept-new "
                "-o UserKnownHostsFile=~/.config/LanScanMan/known_hosts"
            )
            # Quote to defend against malicious profile data
            user_q = shlex.quote(user)
            ip_q   = shlex.quote(self.ip)
            cmd    = f"ssh-copy-id {SSH_OPTS} {user_q}@{ip_q}"

            # Find a terminal — reuse the same logic as ScannerTab
            import shutil
            terminals = [
                ("gnome-terminal", ["--", "bash", "-c"]),
                ("konsole",        ["-e", "bash", "-c"]),
                ("xfce4-terminal", ["-e", "bash -c"]),
                ("mate-terminal",  ["-e", "bash -c"]),
                ("lxterminal",     ["-e", "bash -c"]),
                ("xterm",          ["-e", "bash", "-c"]),
            ]
            term = next(
                ([binary] + args for binary, args in terminals
                 if shutil.which(binary)), None)
            if term is None:
                QMessageBox.critical(self, "No Terminal Found",
                    f"No terminal emulator found. Run manually:\n  ssh-copy-id {user}@{self.ip}")
                return
            try:
                import subprocess
                subprocess.Popen(
                    term + [f"{cmd}; echo; echo 'Done — press Enter to close'; read"])
            except Exception as e:
                log.exception("ssh-copy-id terminal launch failed for %s@%s",
                              user, self.ip)
                QMessageBox.critical(self, "Terminal Error", str(e))
        else:
            QMessageBox.critical(self, "Setup Failed", error or "Unknown error")


# ─────────────────────────────────────────────────────────────────────────────
# AddHostDialog  — manually add a host without scanning
# ─────────────────────────────────────────────────────────────────────────────

class AddHostDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Host Manually")
        self.setMinimumWidth(360)

        layout = QFormLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(14, 14, 14, 14)

        self._ip    = QLineEdit()
        self._ip.setPlaceholderText("e.g. 10.0.0.50 or 192.168.1.100")

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


# ─────────────────────────────────────────────────────────────────────────────
# Main Tab
# ─────────────────────────────────────────────────────────────────────────────

class ScannerTab(QWidget):
    def __init__(self, net_manager, parent=None):
        super().__init__(parent)
        self.net_manager   = net_manager
        self.parent_window = parent
        self.pending_pings = 0
        self.setup_ui()

    # ── Layout ────────────────────────────────────────────────────────────────

    def setup_ui(self):
        layout  = QVBoxLayout(self)
        top_bar = QHBoxLayout()

        # Thorough scan is now a toggled state (default ON) stored as an
        # attribute — the ⚙ menu exposes it without cluttering the toolbar.
        self._thorough = True

        # Opinionated default: only show service shortcuts (VNC, RDP, HTTP)
        # when that port was actually seen open by the scanner. Users can
        # disable this in ⚙ to show shortcuts for all online hosts.
        self._show_unconfirmed_services = False

        self.subnet_input = QLineEdit(self.get_default_subnet())

        self.scan_btn = QPushButton("Scan Network")
        self.scan_btn.setToolTip(
            "Privileged SYN scan via sudo + ARP host discovery.\n"
            "Most accurate — requires your sudo password.")
        self.scan_btn.clicked.connect(self.start_scan)

        self.scan_nosudo_btn = QPushButton("Scan (No Sudo)")
        self.scan_nosudo_btn.setToolTip(
            "Unprivileged TCP connect scan — no sudo needed.\n"
            "Slightly slower; no MAC/vendor data.")
        self.scan_nosudo_btn.setStyleSheet("color: #9AA4AF;")
        self.scan_nosudo_btn.clicked.connect(self.start_scan_nosudo)

        self.cancel_btn = QPushButton("Cancel Scan")
        self.cancel_btn.setStyleSheet("color: #c0392b; font-weight: bold;")
        self.cancel_btn.clicked.connect(self.cancel_scan)
        self.cancel_btn.setVisible(False)

        # ⚙ settings button — holds infrequent / dangerous actions
        self._gear_btn = QPushButton("⚙  Settings")
        self._gear_btn.setFixedWidth(105)
        self._gear_btn.setToolTip("Scan options, export, and danger zone")
        self._gear_btn.clicked.connect(self._show_settings_menu)

        top_bar.addWidget(QLabel("Subnet:"))
        top_bar.addWidget(self.subnet_input)
        top_bar.addWidget(self.scan_btn)
        top_bar.addWidget(self.scan_nosudo_btn)
        top_bar.addWidget(self.cancel_btn)
        top_bar.addStretch()
        top_bar.addWidget(self._gear_btn)

        self.table = QTableWidget(0, 9)
        self.table.verticalHeader().setDefaultSectionSize(50)
        self.table.setHorizontalHeaderLabels([
            "IP", "Alias", "Username", "Hostname",
            "MAC", "Vendor", "SSH", "Ping", "Services",
        ])
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        # Let Alias and Hostname stretch — they contain variable-length text.
        # Everything else has a sensible fixed default the user can still drag.
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)   # Alias
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)   # Hostname
        hdr.resizeSection(0, 110)   # IP
        hdr.resizeSection(2, 100)   # Username
        hdr.resizeSection(4, 145)   # MAC
        hdr.resizeSection(5, 120)   # Vendor
        hdr.resizeSection(6, 65)    # SSH
        hdr.resizeSection(7, 80)    # Ping
        hdr.resizeSection(8, 130)   # Services
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.itemDoubleClicked.connect(self.handle_connect)

        layout.addLayout(top_bar)
        layout.addWidget(self.table)

        # ── Keyboard shortcuts ────────────────────────────────────────────────
        QShortcut(QKeySequence("Ctrl+R"), self).activated.connect(self.start_scan)
        QShortcut(QKeySequence("Ctrl+Shift+R"), self).activated.connect(self.start_scan_nosudo)
        QShortcut(QKeySequence("Escape"), self).activated.connect(self.cancel_scan)

        # Enter/Return connects to the selected row (same as double-click)
        enter_sc = QShortcut(QKeySequence("Return"), self.table)
        enter_sc.activated.connect(self._connect_selected_row)

        # Delete key removes profile for the selected row
        del_sc = QShortcut(QKeySequence("Delete"), self.table)
        del_sc.activated.connect(self._delete_selected_row)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _connect_selected_row(self):
        """Enter key — connect to the currently selected scanner row."""
        item = self.table.currentItem()
        if item:
            self.handle_connect(item)

    def _delete_selected_row(self):
        """Delete key — delete the profile for the currently selected row."""
        row = self.table.currentRow()
        if row >= 0:
            self.delete_profile(row)

    def get_default_subnet(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ".".join(ip.split(".")[:-1]) + ".0/24"
        except Exception:
            return "192.168.1.0/24"

    def _set_scanning_ui(self, scanning: bool):
        self.scan_btn.setVisible(not scanning)
        self.scan_nosudo_btn.setVisible(not scanning)
        self.cancel_btn.setVisible(scanning)
        self.cancel_btn.setEnabled(scanning)

    def _show_settings_menu(self):
        menu = QMenu(self)

        # ── Host management ───────────────────────────────────────────────────
        add_host_act = menu.addAction("Add Host Manually…")
        add_host_act.setToolTip(
            "Add a host that doesn't appear in scan results — useful for\n"
            "hosts behind NAT, on VPN, or that block nmap discovery.")
        add_host_act.triggered.connect(self._add_host_manually)

        menu.addSeparator()

        # ── Scan options ──────────────────────────────────────────────────────
        thorough_act = menu.addAction("Thorough Scan")
        thorough_act.setCheckable(True)
        thorough_act.setChecked(self._thorough)
        thorough_act.setToolTip(
            "Uses -T3 timing with more retries and a longer timeout.\n"
            "Slower but catches hosts that a fast scan misses.")
        thorough_act.toggled.connect(self._set_thorough)

        services_act = menu.addAction("Show service shortcuts for all online hosts")
        services_act.setCheckable(True)
        services_act.setChecked(self._show_unconfirmed_services)
        services_act.setToolTip(
            "When OFF (default): VNC, RDP, HTTP shortcuts only appear when\n"
            "the scanner confirmed that port is open.\n"
            "When ON: shortcuts appear for any online host regardless of\n"
            "whether the port was seen — useful after a no-sudo scan or\n"
            "when ports are filtered.")
        services_act.toggled.connect(self._set_show_unconfirmed_services)

        menu.addSeparator()

        # ── Table tools ───────────────────────────────────────────────────────
        export_act = menu.addAction("Export Table as CSV…")
        export_act.triggered.connect(self._export_csv)

        copy_act = menu.addAction("Copy Table to Clipboard")
        copy_act.triggered.connect(self._copy_table)

        menu.addSeparator()

        # ── Destructive — at the bottom, visually separated ───────────────────
        delete_act = menu.addAction("Delete All Profiles…")
        delete_act.triggered.connect(self.clear_history)

        # Show the menu directly below the gear button
        menu.exec(self._gear_btn.mapToGlobal(
            self._gear_btn.rect().bottomLeft()))

    def _set_thorough(self, checked: bool):
        self._thorough = checked

    def _set_show_unconfirmed_services(self, checked: bool):
        self._show_unconfirmed_services = checked

    def _add_host_manually(self):
        dlg = AddHostDialog(self)
        if not dlg.exec():
            return
        data = dlg.get_data()
        ip       = data["ip"]
        alias    = data["alias"]
        username = data["username"]
        hostname = data["hostname"] or ip

        # Save the profile keyed by IP (no MAC available yet)
        self.net_manager.save_profile(
            mac=None, ip=ip, hostname=hostname,
            alias=alias, username=username)

        # Get the saved profile back so _username_display can work on it
        profile = self.net_manager.get_profile(None, ip)

        # Add a row to the table immediately so it's visible without a rescan
        row = self.table.rowCount()
        self.table.insertRow(row)
        items = [
            QTableWidgetItem(ip),
            QTableWidgetItem(alias or "—"),
            QTableWidgetItem(self._username_display(profile)),
            QTableWidgetItem(hostname),
            QTableWidgetItem("—"),   # MAC — unknown until scan/SSH
            QTableWidgetItem("—"),   # Vendor
            QTableWidgetItem("—"),   # SSH
            QTableWidgetItem("…"),   # Ping — will be filled by background ping
            QTableWidgetItem("—"),   # Services
        ]
        for col, item in enumerate(items):
            if col == 1 and alias:
                item.setForeground(QBrush(QColor("#3498db")))
            self.table.setItem(row, col, item)

        # Run a ping for this row immediately
        self.pending_pings = getattr(self, "pending_pings", 0) + 1
        executor = ThreadPoolExecutor(max_workers=1)
        executor.submit(self.ping_and_update, row, ip)

        self.parent_window.status.setText(
            f"Added {alias or ip} — connect via SSH to resolve MAC address.")

    # ── Scan launch ───────────────────────────────────────────────────────────

    def start_scan(self):
        if not self.parent_window.cached_password:
            dlg = SudoDialog(self)
            if dlg.exec():
                pw, remember = dlg.get_data()
                if not pw:
                    return
                if remember:
                    self.parent_window.cached_password = pw
            else:
                return
        else:
            pw = self.parent_window.cached_password
        self._launch_scan(pw, use_sudo=True)

    def start_scan_nosudo(self):
        self._launch_scan(password=None, use_sudo=False)

    def _launch_scan(self, password, use_sudo: bool):
        self._set_scanning_ui(scanning=True)
        self._start_scan_animation(use_sudo)
        self.thread = ScannerThread(
            self.subnet_input.text(),
            password=password,
            thorough=self._thorough,
            use_sudo=use_sudo,
        )
        self.thread.results_ready.connect(self.on_results)
        self.thread.error_occurred.connect(self.on_error)
        self.thread.start()

    # ── Animation ─────────────────────────────────────────────────────────────

    def _start_scan_animation(self, use_sudo: bool):
        self._anim_step = 0
        thorough_tag    = "(Thorough) " if self._thorough else ""
        mode_tag        = "" if use_sudo else "[No Sudo] "
        self._anim_base = f"{mode_tag}{thorough_tag}"
        self._scan_timer = QTimer(self)
        self._scan_timer.timeout.connect(self._tick_scan_animation)
        self._scan_timer.start(400)

    def _tick_scan_animation(self):
        dots = "." * (self._anim_step % 4)
        self.parent_window.status.setText(f"Scanning {self._anim_base}{dots}")
        self._anim_step += 1

    def _stop_scan_animation(self):
        if hasattr(self, "_scan_timer"):
            self._scan_timer.stop()
            self._scan_timer.deleteLater()

    # ── Scan callbacks ────────────────────────────────────────────────────────

    def cancel_scan(self):
        if hasattr(self, "thread") and self.thread.isRunning():
            self.thread.requestInterruption()
            self.cancel_btn.setEnabled(False)
            self.parent_window.status.setText("Cancelling scan…")

    def on_error(self, err):
        self._stop_scan_animation()
        self._set_scanning_ui(scanning=False)
        if err == "Scan cancelled.":
            self.parent_window.status.setText("Scan cancelled.")
            return
        if "incorrect password" in err.lower() or "sudo" in err.lower():
            self.parent_window.cached_password = None
        self.parent_window.status.setText("Scan failed.")
        QMessageBox.critical(self, "Error", err)

    def on_results(self, scan_results):
        self._stop_scan_animation()
        self._set_scanning_ui(scanning=False)
        self.scan_btn.setEnabled(True)
        self._pending_results = scan_results
        # Stash the sudo mode so _populate_results can read it safely
        # even if self.thread is later replaced or garbage collected.
        self._last_scan_sudo = getattr(self.thread, "use_sudo", True)

        # No-sudo status bar note
        if not self._last_scan_sudo:
            self.parent_window.status.setText(
                "No-sudo scan complete — MAC addresses and vendor info unavailable. "
                "Run a privileged scan for full details.")

        if self.table.rowCount() == 0:
            self._populate_results(scan_results)
            self._animate_rows_in()
        else:
            self._animate_rows_out()

    # ── Fade animations (unchanged) ───────────────────────────────────────────

    def _animate_rows_out(self):
        BG = QColor("#1B1F24")
        self._fadeout_data = []
        for row in range(self.table.rowCount()):
            row_data = []
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item:
                    current = item.foreground().color()
                    if not current.isValid() or current == QColor(0, 0, 0):
                        current = QColor("#D6D6D6")
                    row_data.append((item, current))
                else:
                    row_data.append(None)
            self._fadeout_data.append(row_data)

        self._fadeout_step  = 0
        self._fadeout_steps = 230
        self._fadeout_timer = QTimer(self)
        self._fadeout_timer.timeout.connect(lambda: self._tick_fadeout(BG))
        self._fadeout_timer.start(8)

    def _tick_fadeout(self, BG):
        self._fadeout_step += 1
        t = min((self._fadeout_step / self._fadeout_steps) ** 2, 1.0)
        for row_data in self._fadeout_data:
            for cell in row_data:
                if cell is None:
                    continue
                item, source = cell
                try:
                    r = int(source.red()   + (BG.red()   - source.red())   * t)
                    g = int(source.green() + (BG.green() - source.green()) * t)
                    b = int(source.blue()  + (BG.blue()  - source.blue())  * t)
                    item.setForeground(QBrush(QColor(r, g, b)))
                except RuntimeError:
                    pass
        if self._fadeout_step >= self._fadeout_steps:
            self._fadeout_timer.stop()
            self._fadeout_timer.deleteLater()
            self._populate_results(self._pending_results)
            self._animate_rows_in()

    def _animate_rows_in(self):
        if self.table.rowCount() == 0:
            return
        BG = QColor("#1B1F24")
        self._fade_data = []
        for row in range(self.table.rowCount()):
            row_data = []
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item:
                    target = item.foreground().color()
                    if not target.isValid() or target == QColor(0, 0, 0):
                        target = QColor("#D6D6D6")
                    row_data.append((item, target))
                    item.setForeground(QBrush(BG))
                else:
                    row_data.append(None)
            self._fade_data.append(row_data)

        self._fade_step  = 0
        self._fade_steps = 230
        self._fade_timer = QTimer(self)
        self._fade_timer.timeout.connect(self._tick_fade)
        self._fade_timer.start(8)

    def _tick_fade(self):
        self._fade_step += 1
        t  = min(1.0 - (1.0 - self._fade_step / self._fade_steps) ** 2, 1.0)
        BG = QColor("#1B1F24")
        for row_data in self._fade_data:
            for cell in row_data:
                if cell is None:
                    continue
                item, target = cell
                try:
                    r = int(BG.red()   + (target.red()   - BG.red())   * t)
                    g = int(BG.green() + (target.green() - BG.green()) * t)
                    b = int(BG.blue()  + (target.blue()  - BG.blue())  * t)
                    item.setForeground(QBrush(QColor(r, g, b)))
                except RuntimeError:
                    pass
        if self._fade_step >= self._fade_steps:
            self._fade_timer.stop()
            self._fade_timer.deleteLater()
            self.run_background_pings()

    # ── Table population ──────────────────────────────────────────────────────

    def _username_display(self, profile: dict) -> str:
        """Format username cell: 'dave' or 'dave  +2' if extra_users exist."""
        primary = profile.get("username", "—") or "—"
        extras  = profile.get("extra_users", [])
        if extras:
            return f"{primary}  +{len(extras)}"
        return primary

    def _populate_results(self, scan_results):
        self.table.setRowCount(0)
        history = self.net_manager.load_profiles()

        ip_to_profile_key = {
            data.get("last_ip"): key
            for key, data in history.items()
            if data.get("last_ip")
        }

        master_list = {}
        for key, data in history.items():
            master_list[key] = {
                "ip":       data.get("last_ip", "Unknown"),
                "alias":    data.get("alias", ""),
                "username": self._username_display(data),
                "hostname": data.get("hostname", "—"),
                "mac":      key if ":" in key else "—",
                "vendor":   "—",
                "ssh":      "—",
                "status":   "offline",
            }

        for host in scan_results:
            mac = host["mac"]
            ip  = host["ip"]

            if mac and mac != "—":
                key = mac
            elif ip in ip_to_profile_key:
                key = ip_to_profile_key[ip]
            else:
                key = ip

            profile     = history.get(key, {})
            display_mac = mac if (mac and mac != "—") else (key if ":" in key else "—")

            master_list[key] = {
                "ip":       ip,
                "alias":    profile.get("alias", ""),
                "username": self._username_display(profile),
                "hostname": host["hostname"],
                "mac":      display_mac,
                "vendor":   host["vendor"],
                "ssh":      host["ssh"],
                "services": host.get("services", "None"),
                "status":   "online",
            }

        sorted_keys = sorted(
            master_list.keys(),
            key=lambda k: (
                master_list[k]["status"] == "offline",
                socket.inet_aton(master_list[k]["ip"])
                    if "." in master_list[k]["ip"] else b"",
            ),
        )

        for row, key in enumerate(sorted_keys):
            data = master_list[key]
            self.table.insertRow(row)
            items = [
                QTableWidgetItem(data["ip"]),
                QTableWidgetItem(data["alias"] if data["alias"] else "—"),
                QTableWidgetItem(data["username"]),
                QTableWidgetItem(data["hostname"]),
                QTableWidgetItem(data["mac"]),
                QTableWidgetItem(data["vendor"]),
                QTableWidgetItem(data["ssh"]),
                QTableWidgetItem("..."),
                QTableWidgetItem(data.get("services", "None")),
            ]
            is_online = data["status"] == "online"
            for col, item in enumerate(items):
                if not is_online:
                    item.setForeground(QBrush(QColor("#888888")))
                else:
                    if col == 1 and data["alias"]:
                        item.setForeground(QBrush(QColor("#3498db")))
                    if col == 6 and data["ssh"] == "open":
                        item.setForeground(QBrush(QColor("#27ae60")))
                self.table.setItem(row, col, item)

        if not getattr(self, "_last_scan_sudo", True):
            pass  # status already set in on_results
        else:
            self.parent_window.status.setText(
                f"Scan complete. {len(scan_results)} online. Starting pings…")

    # ── Background pings ──────────────────────────────────────────────────────

    def run_background_pings(self):
        rows = self.table.rowCount()
        self.pending_pings = rows
        executor = ThreadPoolExecutor(max_workers=10)
        for row in range(rows):
            ip_item = self.table.item(row, 0)
            if not ip_item:
                self.pending_pings -= 1
                continue
            executor.submit(self.ping_and_update, row, ip_item.text())

    def ping_and_update(self, row, ip):
        latency = self.net_manager.get_ping_latency(ip)
        QMetaObject.invokeMethod(
            self, "update_ping_cell",
            Qt.ConnectionType.QueuedConnection,
            Q_ARG(int, row),
            Q_ARG(str, latency),
        )

    @pyqt6_slot(int, str)
    def update_ping_cell(self, row, latency):
        item = QTableWidgetItem(latency)
        if "ms" in latency:
            ms_val = float(latency.replace("ms", ""))
            if ms_val < 50:
                item.setForeground(QBrush(QColor("#27ae60")))
            elif ms_val < 150:
                item.setForeground(QBrush(QColor("#f39c12")))
            else:
                item.setForeground(QBrush(QColor("#c0392b")))

            alias_item = self.table.item(row, 1)
            if alias_item and alias_item.foreground().color() == QColor("#888888"):
                alias_text = alias_item.text()
                ssh_item   = self.table.item(row, 6)
                ssh_state  = ssh_item.text() if ssh_item else ""
                for col in range(self.table.columnCount()):
                    cell = self.table.item(row, col)
                    if cell:
                        if col == 1 and alias_text and alias_text != "—":
                            cell.setForeground(QBrush(QColor("#3498db")))
                        elif col == 6 and ssh_state == "open":
                            cell.setForeground(QBrush(QColor("#27ae60")))
                        else:
                            cell.setForeground(QBrush(QColor("#E6E6E6")))
        else:
            item.setForeground(QBrush(QColor("#888888")))

        self.table.setItem(row, 7, item)
        self.pending_pings -= 1
        if self.pending_pings <= 0:
            self.parent_window.status.setText("Scan complete. All pings verified.")

    # ── Context menu ──────────────────────────────────────────────────────────

    def show_context_menu(self, pos):
        item = self.table.itemAt(pos)
        if not item:
            return
        row           = item.row()
        ip            = self.table.item(row, 0).text()
        mac           = self.table.item(row, 4).text()
        ping_text     = self.table.item(row, 7).text()
        services_text = self.table.item(row, 8).text().upper()
        is_online     = "ms" in ping_text.lower()

        profile     = self.net_manager.get_profile(mac, ip)
        extra_users = profile.get("extra_users", [])

        style     = self.style()
        edit_icon = style.standardIcon(style.StandardPixmap.SP_FileIcon)
        key_icon  = style.standardIcon(style.StandardPixmap.SP_ComputerIcon)

        menu = QMenu(self.table)

        # ── Profile management ────────────────────────────────────────────────
        edit_action      = menu.addAction(edit_icon, "Edit Profile")
        manage_action    = menu.addAction("Manage Accounts")
        setup_key_action = menu.addAction(key_icon, "Setup SSH Key (primary)")
        delete_action    = menu.addAction("Delete Profile")

        # ── Connect as secondary user (only shown when extras exist + online) ─
        connect_actions = {}
        if is_online and extra_users:
            menu.addSeparator()
            connect_menu = QMenu("Connect as…", menu)
            for u in extra_users:
                act = connect_menu.addAction(u)
                connect_actions[act] = u
            menu.addMenu(connect_menu)

        # ── Custom port connect (always shown when online) ────────────────────
        custom_port_action = None
        if is_online:
            custom_port_action = menu.addAction("Connect on custom port…")
            custom_port_action.setToolTip(
                "Connect to this host on a specific port — useful when SSH,\n"
                "VNC, or RDP is running on a non-standard port.")

        # ── WoL ───────────────────────────────────────────────────────────────
        wake_action = None
        if not is_online and mac and ":" in mac:
            menu.addSeparator()
            wake_action = menu.addAction(f"⚡ Wake Device (WoL) — {mac}")

        # ── Services ──────────────────────────────────────────────────────────
        SERVICE_ACTIONS = {
            "HTTP":  {"cmd": "http://{ip}",  "icon": "🌐", "label": "Open Web Dashboard"},
            "HTTPS": {"cmd": "https://{ip}", "icon": "🔒", "label": "Open Secure Web"},
            "VNC":   {"cmd": "vnc://{ip}",   "icon": "🖥️", "label": "Launch VNC Viewer"},
            "RDP":   {"cmd": "rdp://{ip}",   "icon": "🪟", "label": "Launch RDP Session"},
        }
        service_actions_mapped = {}
        if is_online:
            # Opinionated default: only show a service shortcut when the scanner
            # confirmed that port is open. If the user has enabled
            # "Show service shortcuts for all online hosts" in ⚙, show all
            # shortcuts for any reachable host regardless of port knowledge.
            services_to_show = (
                SERVICE_ACTIONS.keys()
                if self._show_unconfirmed_services
                else [k for k in SERVICE_ACTIONS if k in services_text]
            )
            if services_to_show:
                menu.addSeparator()
                for srv_key in services_to_show:
                    srv_data = SERVICE_ACTIONS[srv_key]
                    # When showing unconfirmed services, dim the label slightly
                    # to signal these ports haven't been verified
                    label = srv_data["label"]
                    if self._show_unconfirmed_services and srv_key not in services_text:
                        label += "  (port unverified)"
                    act = menu.addAction(f"{srv_data['icon']} {label}")
                    service_actions_mapped[act] = srv_data["cmd"].format(ip=ip)

        action = menu.exec(QCursor.pos())
        if action is None:
            return

        if action == edit_action:
            self.edit_profile(row)
        elif action == manage_action:
            self.manage_accounts(row)
        elif action == setup_key_action:
            self.run_ssh_key_setup(row)
        elif action == delete_action:
            self.delete_profile(row)
        elif action == wake_action:
            success, err = self.net_manager.wake_device(mac)
            if success:
                self.parent_window.status.setText(f"WoL packet sent to {mac}")
            else:
                QMessageBox.critical(self, "WoL Error", f"Failed: {err}")
        elif action in connect_actions:
            # Connect as a specific secondary user — full tmux probe, same as double-click
            self._do_connect(row, ip, mac, connect_actions[action])
        elif action == custom_port_action:
            self._open_custom_port_dialog(row, ip, mac)
        elif action in service_actions_mapped:
            import webbrowser
            webbrowser.open(service_actions_mapped[action])

    # ── Profile actions ───────────────────────────────────────────────────────

    def delete_profile(self, row):
        ip    = self.table.item(row, 0).text()
        mac   = self.table.item(row, 4).text()
        alias = self.table.item(row, 1).text()

        reply = QMessageBox.question(
            self, "Delete Profile",
            f"Delete saved profile for {alias if alias and alias != '—' else ip}?\n\n"
            "This will remove the alias, username, and all secondary accounts.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            key = mac if mac and ":" in mac else ip
            if key in self.net_manager.profiles:
                del self.net_manager.profiles[key]
                import json
                with open(self.net_manager.config_file, "w") as f:
                    json.dump(self.net_manager.profiles, f, indent=4)
            self.table.setItem(row, 1, QTableWidgetItem("—"))
            self.table.item(row, 1).setForeground(QBrush(QColor("#888888")))
            self.table.setItem(row, 2, QTableWidgetItem("—"))
            self.parent_window.status.setText(f"Profile deleted for {ip}")
            if "ms" not in self.table.item(row, 7).text():
                self.table.removeRow(row)

    def edit_profile(self, row):
        ip       = self.table.item(row, 0).text()
        mac      = self.table.item(row, 4).text()
        hostname = self.table.item(row, 3).text()
        profile  = self.net_manager.get_profile(mac, ip)

        dlg = EditProfileDialog(ip, profile, self)
        if not dlg.exec():
            return

        alias, user, connect_after = dlg.get_data()
        self.net_manager.save_profile(mac, ip, hostname, alias, user)

        # Refresh the row display
        self._refresh_profile_row(row)

        if connect_after and user:
            self._do_connect(row, ip, mac, user)

    def manage_accounts(self, row):
        ip    = self.table.item(row, 0).text()
        mac   = self.table.item(row, 4).text()
        alias = self.table.item(row, 1).text()
        if alias == "—":
            alias = ""

        dlg = ManageAccountsDialog(ip, mac, alias, self.net_manager, self)
        dlg.exec()
        # Refresh username column after dialog closes (user may have promoted/added)
        self._refresh_profile_row(row)

    def _refresh_profile_row(self, row: int):
        """Refresh alias and username columns for a row from the current profile."""
        ip      = self.table.item(row, 0).text()
        mac     = self.table.item(row, 4).text()
        profile = self.net_manager.get_profile(mac, ip)
        alias   = profile.get("alias", "") or "—"

        alias_item = QTableWidgetItem(alias)
        alias_item.setForeground(
            QBrush(QColor("#3498db")) if alias != "—" else QBrush(QColor("#888888")))
        self.table.setItem(row, 1, alias_item)
        self.table.setItem(row, 2, QTableWidgetItem(self._username_display(profile)))

    def _open_custom_port_dialog(self, row: int, ip: str, mac: str):
        """Right-click → Connect on custom port… — opens dialog pre-filled from profile."""
        profile  = self.net_manager.get_profile(mac, ip)
        username = profile.get("username", "").strip()

        dlg = CustomPortConnectDialog(
            ip=ip, port=22, service="ssh",
            username=username, parent=self)
        if not dlg.exec():
            return

        proto, port, user = dlg.get_data()
        status = launch_connection(ip, proto, port, user, parent=self)
        if status:
            self.parent_window.status.setText(status)

    # ── SSH connect ───────────────────────────────────────────────────────────

    def handle_connect(self, item):
        """Double-click handler — always connects as primary user."""
        row     = item.row()
        ip      = self.table.item(row, 0).text()
        mac     = self.table.item(row, 4).text()
        profile = self.net_manager.get_profile(mac, ip)
        user    = profile.get("username", "").strip()

        if not user or user == "—":
            QMessageBox.warning(self, "Username Required",
                f"No SSH username is set for {ip}.\n\nPlease edit the profile first.")
            self.edit_profile(row)
            return

        self._do_connect(row, ip, mac, user)

    def _do_connect(self, row: int, ip: str, mac: str, user: str):
        """
        Core SSH connect flow — identical for primary (double-click) and
        secondary users (right-click submenu).  Probes for tmux, handles
        key auth, shows ConnectionModeDialog, launches terminal.
        """
        self.parent_window.status.setText(f"Probing {ip} as {user}…")
        QApplication.processEvents()

        try:
            success, sessions = self.net_manager.get_remote_tmux_sessions(user, ip)
        except HostKeyMismatchError:
            reply = QMessageBox.question(
                self, "Host Key Changed",
                f"The host key for {ip} has changed.\n\n"
                "This is normal if the OS was recently reinstalled.\n"
                "It could also indicate a security issue.\n\n"
                "Remove the old key and trust the new one?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                remove_host_from_known_hosts(ip)
                try:
                    success, sessions = self.net_manager.get_remote_tmux_sessions(user, ip)
                except Exception:
                    QMessageBox.critical(self, "Connection Failed",
                        f"Could not connect to {ip} after retrusting.")
                    return
            else:
                self.parent_window.status.setText("Connection cancelled.")
                return

        if not success:
            msg = QMessageBox.question(
                self, "SSH Key Required",
                f"Could not authenticate with {user}@{ip} using your SSH key.\n\n"
                "Would you like to push your SSH key for this user now?\n"
                "(Choosing 'No' will attempt a standard password login)",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                | QMessageBox.StandardButton.Cancel,
            )
            if msg == QMessageBox.StandardButton.Yes:
                self._push_key_for_user(ip, mac, user)
                return
            elif msg == QMessageBox.StandardButton.Cancel:
                self.parent_window.status.setText("Connection cancelled.")
                return
            choice_type, val = "ssh", None
        elif sessions is None:
            choice_type, val = "ssh", None
        else:
            dlg = ConnectionModeDialog(sessions, connecting_as=user, parent=self)
            if not dlg.exec():
                self.parent_window.status.setText("Connection cancelled.")
                return
            choice_type, val = dlg.get_choice()

        # MAC enrichment (silent — upgrades IP-keyed profiles to MAC-keyed)
        if success:
            current_mac = self.table.item(row, 4).text()
            if not current_mac or ":" not in current_mac:
                enriched = self.net_manager.enrich_profile_with_mac(user, ip)
                if enriched:
                    self.table.setItem(row, 4, QTableWidgetItem(enriched))

        SSH_OPTS = ("-o StrictHostKeyChecking=accept-new "
                    "-o UserKnownHostsFile=~/.config/LanScanMan/known_hosts")
        # Quote ip and user to defend against malicious profile data —
        # these values originate from scan results or user input and should
        # never be interpolated raw into a shell command string.
        user_q = shlex.quote(user)
        ip_q   = shlex.quote(ip)
        ssh_base = f"ssh -t {SSH_OPTS} {user_q}@{ip_q}"

        if choice_type == "tmux_new":
            session_name = shlex.quote(val or "LanScanMan")
            final_cmd = f"{ssh_base} 'tmux new -s {session_name} || tmux a'"
        elif choice_type == "tmux_attach":
            session_q = shlex.quote(val or "")
            final_cmd = f"{ssh_base} 'tmux a -t {session_q}'"
        else:
            final_cmd = f"ssh {SSH_OPTS} {user_q}@{ip_q}"

        term = self.get_terminal_command()
        if term is None:
            QMessageBox.critical(self, "Terminal Error",
                "No supported terminal emulator found.\n"
                "Please install one of: gnome-terminal, konsole, xfce4-terminal, xterm")
            return

        try:
            self.parent_window.status.setText(f"Connecting to {ip} as {user}…")
            subprocess.Popen(term + [f"{final_cmd}; exec bash"])
        except Exception as e:
            log.exception("Terminal launch failed for %s@%s", user, ip)
            QMessageBox.critical(self, "Terminal Error",
                f"Could not launch terminal: {str(e)}")

    def get_terminal_command(self):
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

    # ── SSH key setup ─────────────────────────────────────────────────────────

    def run_ssh_key_setup(self, row):
        """Push SSH key for the profile's primary user."""
        ip      = self.table.item(row, 0).text()
        mac     = self.table.item(row, 4).text()
        profile = self.net_manager.get_profile(mac, ip)
        user    = profile.get("username")
        if not user or user == "—":
            QMessageBox.warning(self, "Missing Info",
                "Set a Username in 'Edit Profile' first.")
            return
        self._push_key_for_user(ip, mac, user)

    def _push_key_for_user(self, ip: str, mac: str, user: str):
        """
        Install SSH key for a user — no password ever handled by the app.

        Tries silent key auth first (works if another key is already trusted).
        If that fails, offers to launch ssh-copy-id in a terminal so the user
        authenticates in their own session.
        """
        self.parent_window.status.setText(f"Installing SSH key for {user}@{ip}…")
        QApplication.processEvents()

        try:
            success, error = self.net_manager.push_ssh_key_silent(user, ip)
        except HostKeyMismatchError:
            reply = QMessageBox.question(
                self, "Host Key Changed",
                f"The host key for {ip} has changed.\n\n"
                "Remove the old key and trust the new one?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                remove_host_from_known_hosts(ip)
                try:
                    success, error = self.net_manager.push_ssh_key_silent(user, ip)
                except Exception:
                    QMessageBox.critical(self, "Setup Failed",
                        "Failed after retrusting host.")
                    return
            else:
                self.parent_window.status.setText("Key setup cancelled.")
                return

        if success:
            QMessageBox.information(self, "Success",
                f"SSH key installed for {user}@{ip}!")
            self.parent_window.status.setText(f"Key installed for {user}.")
            return

        if error == "auth_failed":
            # Key auth not set up yet — offer ssh-copy-id in terminal
            # First make sure a local key pair exists
            ok, result = self.net_manager.ensure_ssh_key()
            if not ok:
                QMessageBox.critical(self, "Key Generation Failed", result)
                return

            reply = QMessageBox.question(
                self, "No Existing Key Auth",
                f"Could not authenticate to {user}@{ip} with your SSH key.\n\n"
                f"A terminal will open and run:\n"
                f"  ssh-copy-id {user}@{ip}\n\n"
                f"You will be prompted for {user}'s password in the terminal.\n"
                f"LanScanMan never sees that password.",
                QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel,
            )
            if reply != QMessageBox.StandardButton.Ok:
                self.parent_window.status.setText("Key setup cancelled.")
                return

            SSH_OPTS = (
                "-o StrictHostKeyChecking=accept-new "
                "-o UserKnownHostsFile=~/.config/LanScanMan/known_hosts"
            )
            user_q = shlex.quote(user)
            ip_q   = shlex.quote(ip)
            cmd = f"ssh-copy-id {SSH_OPTS} {user_q}@{ip_q}"
            term = self.get_terminal_command()
            if term is None:
                QMessageBox.critical(self, "No Terminal Found",
                    "No supported terminal emulator found.\n\n"
                    f"Run this manually:\n  ssh-copy-id {user}@{ip}")
                return
            try:
                subprocess.Popen(
                    term + [f"{cmd}; echo; echo 'Done — press Enter to close'; read"])
                self.parent_window.status.setText(
                    f"ssh-copy-id launched for {user}@{ip} — authenticate in the terminal.")
            except Exception as e:
                log.exception("ssh-copy-id launch failed for %s@%s", user, ip)
                QMessageBox.critical(self, "Terminal Error", str(e))
        else:
            QMessageBox.critical(self, "Setup Failed", error)

    # ── Export ────────────────────────────────────────────────────────────────

    def _export_csv(self):
        if self.table.rowCount() == 0:
            self.parent_window.status.setText("Nothing to export — run a scan first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Scanner Table",
            "lanscanman_hosts.csv", "CSV Files (*.csv)")
        if not path:
            return
        headers = [
            self.table.horizontalHeaderItem(c).text()
            for c in range(self.table.columnCount())
        ]
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for row in range(self.table.rowCount()):
                writer.writerow([
                    self.table.item(row, col).text()
                    if self.table.item(row, col) else ""
                    for col in range(self.table.columnCount())
                ])
        self.parent_window.status.setText(
            f"Exported {self.table.rowCount()} rows to {path}")

    def _copy_table(self):
        if self.table.rowCount() == 0:
            self.parent_window.status.setText("Nothing to copy — run a scan first.")
            return
        headers = "\t".join(
            self.table.horizontalHeaderItem(c).text()
            for c in range(self.table.columnCount()))
        rows = [headers]
        for row in range(self.table.rowCount()):
            rows.append("\t".join(
                self.table.item(row, col).text()
                if self.table.item(row, col) else ""
                for col in range(self.table.columnCount())
            ))
        QApplication.clipboard().setText("\n".join(rows))
        self.parent_window.status.setText(
            f"Copied {self.table.rowCount()} rows to clipboard.")

    # ── Clear history ─────────────────────────────────────────────────────────

    def clear_history(self):
        count = len(self.net_manager.profiles)
        if count == 0:
            self.parent_window.status.setText("No profiles to delete.")
            return

        noun  = "profile" if count == 1 else "profiles"
        reply = QMessageBox.question(
            self, "Delete All Profiles",
            f"Permanently delete all {count} saved {noun}?\n\n"
            "This will remove every alias, username, and secondary account.\n"
            "This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            if self.net_manager.config_file.exists():
                self.net_manager.config_file.unlink()
            self.net_manager.profiles = {}
            self.table.setRowCount(0)
            self.parent_window.status.setText(
                f"Deleted {count} {noun}.")