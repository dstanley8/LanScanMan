


from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QBrush, QColor, QCursor, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from lanscanman.core.privilege import validate_scan_args
from lanscanman.services.network_manager import NetworkManager
from lanscanman.ui.dialogs.connect import CustomPortConnectDialog, launch_connection
from lanscanman.ui.privilege import prepare_privileged_scan
from lanscanman.workers.scanner import HostScanThread

# ─────────────────────────────────────────────────────────────────────────────
# Host Inspector Tab
# ─────────────────────────────────────────────────────────────────────────────

# Column indices
_C_PORT    = 0
_C_PROTO   = 1
_C_STATE   = 2
_C_SERVICE = 3
_C_VERSION = 4


class HostInspectorTab(QWidget):
    """
    Deep port scanner for a single host.
    Discovers open ports, detects service versions, and lets you
    connect to any port with your chosen protocol.
    """

    def __init__(self, net_manager: NetworkManager, parent=None):
        super().__init__(parent)
        self.net_manager   = net_manager
        self.parent_window = parent
        self._thread: HostScanThread | None = None
        self._all_results: list[dict] = []
        self._setup_ui()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(8)

        # ── Controls ─────────────────────────────────────────────────────────
        ctrl = QHBoxLayout()

        # Host selector
        self._host_combo = QComboBox()
        self._host_combo.setMinimumWidth(200)
        self._host_combo.setEditable(True)
        self._host_combo.lineEdit().setPlaceholderText("Select host or enter IP…")
        self._host_combo.setToolTip(
            "Select a profiled host or type any IP address")

        # Scan mode radios
        mode_group = QGroupBox("Scan Mode")
        mode_group.setStyleSheet(
            "QGroupBox { border: 1px solid #2A313B; border-radius: 6px; "
            "margin-top: 6px; padding: 6px 10px; }"
            "QGroupBox::title { color: #9AA4AF; font-size: 11px; "
            "subcontrol-origin: margin; left: 10px; }")
        mode_lay = QHBoxLayout(mode_group)
        mode_lay.setSpacing(12)

        self._mode_grp = QButtonGroup(self)
        self._rb_quick  = QRadioButton("Quick  (top 1000)")
        self._rb_full   = QRadioButton("Full  (all 65535)")
        self._rb_custom = QRadioButton("Custom:")
        self._rb_quick.setChecked(True)
        self._custom_input = QLineEdit()
        self._custom_input.setPlaceholderText("e.g. 22,80,443 or 1-1024")
        self._custom_input.setFixedWidth(160)
        self._custom_input.setEnabled(False)

        for i, rb in enumerate([self._rb_quick, self._rb_full, self._rb_custom]):
            self._mode_grp.addButton(rb, i)
            mode_lay.addWidget(rb)
        mode_lay.addWidget(self._custom_input)
        self._rb_custom.toggled.connect(self._custom_input.setEnabled)

        # Sudo checkbox
        from PyQt6.QtWidgets import QCheckBox
        self._sudo_cb = QCheckBox("Privileged scan")
        self._sudo_cb.setChecked(True)
        self._sudo_cb.setToolTip(
            "Enables SYN scanning and more accurate version detection.\n"
            "Your desktop asks for your password; LanScanMan never sees it.\n"
            "Uncheck to run without root (slower, less accurate).")

        # Scan / cancel buttons
        self._scan_btn   = QPushButton("Scan Host")
        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setStyleSheet("color: #c0392b; font-weight: bold;")
        self._cancel_btn.setVisible(False)
        self._scan_btn.clicked.connect(self._start_scan)
        self._cancel_btn.clicked.connect(self._cancel_scan)

        ctrl.addWidget(QLabel("Host:"))
        ctrl.addWidget(self._host_combo, 1)
        ctrl.addWidget(mode_group)
        ctrl.addWidget(self._sudo_cb)
        ctrl.addWidget(self._scan_btn)
        ctrl.addWidget(self._cancel_btn)
        root.addLayout(ctrl)

        # ── Filter bar ────────────────────────────────────────────────────────
        filter_bar = QHBoxLayout()
        filter_bar.addWidget(QLabel("Filter:"))
        self._filter = QLineEdit()
        self._filter.setPlaceholderText(
            "Port number, service name, or version string…")
        self._filter.setClearButtonEnabled(True)
        self._filter.textChanged.connect(self._apply_filter)
        self._count_lbl = QLabel("")
        self._count_lbl.setStyleSheet("color: #9AA4AF; font-size: 11px;")
        filter_bar.addWidget(self._filter)
        filter_bar.addWidget(self._count_lbl)
        root.addLayout(filter_bar)

        # ── Results table ─────────────────────────────────────────────────────
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels([
            "Port", "Protocol", "State", "Service", "Version",
        ])
        self._table.verticalHeader().setDefaultSectionSize(36)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(
            self._show_context_menu)
        self._table.itemDoubleClicked.connect(self._on_double_click)

        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hdr.setSectionResizeMode(_C_VERSION, QHeaderView.ResizeMode.Stretch)
        hdr.resizeSection(_C_PORT,    70)
        hdr.resizeSection(_C_PROTO,   75)
        hdr.resizeSection(_C_STATE,   75)
        hdr.resizeSection(_C_SERVICE, 130)

        root.addWidget(self._table)

        # ── Info bar ──────────────────────────────────────────────────────────
        info = QLabel(
            "Select a host and scan mode, then click Scan Host.  "
            "Double-click any row or right-click to connect on that port.")
        info.setStyleSheet("color: #9AA4AF; font-size: 11px;")
        root.addWidget(info)

        # ── Keyboard shortcuts ────────────────────────────────────────────────
        QShortcut(QKeySequence("F5"), self).activated.connect(self._start_scan)
        QShortcut(QKeySequence("Escape"), self).activated.connect(
            self._cancel_scan)
        enter_sc = QShortcut(QKeySequence("Return"), self._table)
        enter_sc.activated.connect(self._connect_selected_row)

    # ── Host list ─────────────────────────────────────────────────────────────

    def showEvent(self, event):
        super().showEvent(event)
        self._refresh_host_list()

    def _refresh_host_list(self):
        """Rebuild the host dropdown from current profiles."""
        current = self._host_combo.currentText()
        self._host_combo.blockSignals(True)
        self._host_combo.clear()

        for key, profile in self.net_manager.profiles.items():
            ip    = profile.get("last_ip", key)
            alias = profile.get("alias", "").strip()
            label = f"{alias}  ({ip})" if alias else ip
            self._host_combo.addItem(label, userData=ip)

        # Restore previous selection or typed IP
        idx = self._host_combo.findText(current)
        if idx >= 0:
            self._host_combo.setCurrentIndex(idx)
        elif current:
            self._host_combo.setCurrentText(current)

        self._host_combo.blockSignals(False)

    def _resolved_ip(self) -> str:
        """Get IP from combo — either from profile userData or raw typed text."""
        idx = self._host_combo.currentIndex()
        if idx >= 0:
            data = self._host_combo.itemData(idx)
            if data:
                return data
        return self._host_combo.currentText().strip()

    def _profile_for_current_host(self) -> dict:
        idx = self._host_combo.currentIndex()
        if idx >= 0:
            ip = self._host_combo.itemData(idx) or ""
            for profile in self.net_manager.profiles.values():
                if profile.get("last_ip") == ip:
                    return profile
        return {}

    # ── Scan ──────────────────────────────────────────────────────────────────

    def _start_scan(self):
        ip = self._resolved_ip()
        if not ip:
            QMessageBox.warning(self, "No Host",
                "Please select a host or enter an IP address.")
            return

        if self._thread and self._thread.isRunning():
            return

        # Determine mode
        mode = "quick"
        if self._rb_full.isChecked():
            mode = "full"
        elif self._rb_custom.isChecked():
            mode = "custom"

        use_sudo = self._sudo_cb.isChecked()
        password = None
        if mode == "custom":
            reason = validate_scan_args(
                ["-sS", "-p", self._custom_input.text().strip().replace(" ", ""),
                 "-oX", "-", ip])
            if reason:
                QMessageBox.warning(self, "Custom ports",
                                    "Use port numbers and ranges only, e.g. 22,80,8000-8100.")
                return
        privilege_mode = "polkit"
        if use_sudo:
            ok, password, privilege_mode = prepare_privileged_scan(self)
            if not ok:
                return

        # Clear previous results
        self._all_results = []
        self._table.setRowCount(0)
        self._count_lbl.setText("")
        self._filter.clear()

        label = self._host_combo.currentText()
        mode_label = {"quick": "Quick", "full": "Full", "custom": "Custom"}[mode]
        self._set_status(f"Scanning {label} — {mode_label} mode…")

        self._thread = HostScanThread(
            ip=ip, mode=mode,
            custom_ports=self._custom_input.text(),
            privileged=use_sudo,
            password=password,
            privilege_mode=privilege_mode,
        )
        self._thread.results_ready.connect(self._on_results)
        self._thread.error_occurred.connect(self._on_error)
        self._thread.start()

        self._scan_btn.setVisible(False)
        self._cancel_btn.setVisible(True)

        # Animate status while scanning
        self._anim_step = 0
        self._anim_timer = QTimer(self)
        self._anim_timer.timeout.connect(self._tick_anim)
        self._anim_timer.start(400)

    def _cancel_scan(self):
        if self._thread and self._thread.isRunning():
            self._thread.requestInterruption()
            self._cancel_btn.setEnabled(False)
            self._set_status("Cancelling…")

    def _stop_anim(self):
        if hasattr(self, "_anim_timer"):
            self._anim_timer.stop()
            self._anim_timer.deleteLater()

    def _tick_anim(self):
        dots = "." * (self._anim_step % 4)
        host = self._host_combo.currentText()
        self._set_status(f"Scanning {host}{dots}")
        self._anim_step += 1

    def _on_results(self, results: list):
        self._stop_anim()
        self._scan_btn.setVisible(True)
        self._cancel_btn.setVisible(True)
        self._cancel_btn.setEnabled(True)
        self._scan_btn.setVisible(True)
        self._cancel_btn.setVisible(False)

        self._all_results = results
        self._apply_filter()

        open_count = sum(1 for r in results if r["state"] == "open")
        host       = self._host_combo.currentText()
        self._set_status(
            f"{host} — {open_count} open port(s) found "
            f"({len(results)} total). "
            "Double-click or right-click any row to connect.")

    def _on_error(self, err: str):
        self._stop_anim()
        self._scan_btn.setVisible(True)
        self._cancel_btn.setVisible(False)
        self._cancel_btn.setEnabled(True)

        if err == "Scan cancelled.":
            self._set_status("Scan cancelled.")
            return
        if err.startswith("Scan cancelled"):
            self._set_status(err)
            return
        self._set_status("Scan failed.")
        QMessageBox.critical(self, "Scan Error", err)

    # ── Table population + filter ─────────────────────────────────────────────

    def _apply_filter(self):
        query = self._filter.text().strip().lower()
        self._table.setRowCount(0)

        shown = 0
        for r in self._all_results:
            if query:
                haystack = (
                    str(r["port"]) + " " +
                    r["protocol"] + " " +
                    r["state"]    + " " +
                    r["service"]  + " " +
                    r["version"]
                ).lower()
                if query not in haystack:
                    continue

            row = self._table.rowCount()
            self._table.insertRow(row)

            port_item    = QTableWidgetItem(str(r["port"]))
            proto_item   = QTableWidgetItem(r["protocol"].upper())
            state_item   = QTableWidgetItem(r["state"])
            service_item = QTableWidgetItem(r["service"])
            version_item = QTableWidgetItem(r["version"])

            # Colour by state
            if r["state"] == "open":
                state_item.setForeground(QBrush(QColor("#27ae60")))
                port_item.setForeground(QBrush(QColor("#3498db")))
            elif r["state"] == "filtered":
                state_item.setForeground(QBrush(QColor("#f39c12")))
            else:
                for item in (port_item, proto_item, state_item,
                             service_item, version_item):
                    item.setForeground(QBrush(QColor("#9AA4AF")))

            version_item.setForeground(QBrush(QColor("#9AA4AF")))

            for col, item in enumerate([
                port_item, proto_item, state_item, service_item, version_item
            ]):
                self._table.setItem(row, col, item)

            shown += 1

        total = len(self._all_results)
        if total:
            self._count_lbl.setText(
                f"{shown} of {total}" if query else f"{total} port(s)")
        else:
            self._count_lbl.setText("")

    # ── Connect actions ───────────────────────────────────────────────────────

    def _row_data(self, row: int) -> dict | None:
        if row < 0 or row >= self._table.rowCount():
            return None
        return {
            "port":    int(self._table.item(row, _C_PORT).text()),
            "proto":   self._table.item(row, _C_PROTO).text(),
            "state":   self._table.item(row, _C_STATE).text(),
            "service": self._table.item(row, _C_SERVICE).text(),
            "version": self._table.item(row, _C_VERSION).text(),
        }

    def _connect_selected_row(self):
        row = self._table.currentRow()
        if row >= 0:
            self._open_connect_dialog(row)

    def _on_double_click(self, item):
        self._open_connect_dialog(item.row())

    def _open_connect_dialog(self, row: int):
        data = self._row_data(row)
        if not data:
            return
        ip       = self._resolved_ip()
        profile  = self._profile_for_current_host()
        username = profile.get("username", "").strip()

        dlg = CustomPortConnectDialog(
            ip=ip,
            port=data["port"],
            service=data["service"],
            username=username,
            parent=self,
        )
        if not dlg.exec():
            return

        proto, port, user = dlg.get_data()
        self._launch_connection(ip, proto, port, user)

    def _launch_connection(self, ip: str, proto: str, port: int, user: str):
        status = launch_connection(ip, proto, port, user, parent=self)
        if status:
            self._set_status(status)

    # ── Context menu ──────────────────────────────────────────────────────────

    def _show_context_menu(self, pos):
        item = self._table.itemAt(pos)
        if not item:
            return
        row  = item.row()
        data = self._row_data(row)
        if not data:
            return

        menu = QMenu(self)

        connect_act = menu.addAction(
            f"Connect on port {data['port']}…")
        connect_act.triggered.connect(
            lambda: self._open_connect_dialog(row))

        # Quick-launch shortcuts for known services
        svc   = data["service"].lower()
        port  = data["port"]
        ip    = self._resolved_ip()
        profile  = self._profile_for_current_host()
        username = profile.get("username", "").strip()

        if "ssh" in svc or port == 22:
            menu.addSeparator()
            ssh_act = menu.addAction(f"SSH — {ip}:{port}")
            ssh_act.triggered.connect(
                lambda: self._launch_connection(ip, "SSH", port, username))

        if "http" in svc and "https" not in svc:
            http_act = menu.addAction(f"Open HTTP — {ip}:{port}")
            http_act.triggered.connect(
                lambda: self._launch_connection(ip, "HTTP", port, username))

        if "https" in svc or port == 443:
            https_act = menu.addAction(f"Open HTTPS — {ip}:{port}")
            https_act.triggered.connect(
                lambda: self._launch_connection(ip, "HTTPS", port, username))

        if "vnc" in svc or port in (5900, 5901, 5902):
            vnc_act = menu.addAction(f"VNC — {ip}:{port}")
            vnc_act.triggered.connect(
                lambda: self._launch_connection(ip, "VNC", port, username))

        if "rdp" in svc or "ms-wbt" in svc or port == 3389:
            rdp_act = menu.addAction(f"RDP — {ip}:{port}")
            rdp_act.triggered.connect(
                lambda: self._launch_connection(ip, "RDP", port, username))

        menu.addSeparator()
        copy_act = menu.addAction(f"Copy port number  ({data['port']})")
        copy_act.triggered.connect(
            lambda: QApplication.clipboard().setText(str(data["port"])))

        menu.exec(QCursor.pos())

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _set_status(self, msg: str):
        if self.parent_window:
            self.parent_window.status.setText(msg)
