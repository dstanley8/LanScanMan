"""Per-host disk list with SMART details, opened from the Disk Health tab."""

from datetime import datetime

from PyQt6.QtCore import Qt, QTimer, pyqtSlot
from PyQt6.QtGui import QBrush, QColor
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from lanscanman.core.drive_report import (
    HostData,
    disk_request,
    disks_for_host,
    host_request,
)
from lanscanman.core.formatting import (
    bad_sector_color,
    disk_temp_color,
    fmt_bytes,
    fmt_hours,
    wear_color,
)
from lanscanman.core.smart import smart_color, smart_text
from lanscanman.core.smart_history import SmartLogger, smart_log_key
from lanscanman.ui.dialogs.smart_history import SmartHistoryDialog
from lanscanman.ui.trust import confirm_host_key_change
from lanscanman.workers.probes import SmartProbeWorker

_D_DEV      = 0


_D_MODEL    = 1


_D_CAP      = 2


_D_USED     = 3


_D_SMART    = 4


_D_TEMP     = 5


_D_HOURS    = 6


_D_TBW      = 7


_D_BAD      = 8


_D_WEAR     = 9


class SmartDiskDialog(QDialog):
    def __init__(self, ip: str, username: str, alias: str = "",
                 disks: list | None = None, profile_key: str = "",
                 parent=None, ask_ai=None, read_at=None):
        super().__init__(parent)
        self.ask_ai = ask_ai                 # (title, report) -> opens a drive-health chat
        self._read_at = read_at
        self._current_disks: list[dict] = []
        self.ip          = ip
        self.username    = username
        self.alias       = alias or ip
        self.profile_key = profile_key or ip
        self.setWindowTitle(f"Disk Health — {self.alias}")
        self.setMinimumSize(1100, 400)
        self.resize(1260, 440)
        self._worker: SmartProbeWorker | None = None

        self._build_ui()
        if disks is not None:
            self._apply_disks(disks)
        else:
            self._set_status("⏳  Probing disks…", "#f39c12")

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(30_000)
        if disks is None:
            self._refresh()

    # ── Layout ───────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(8)

        # Header
        hdr = QHBoxLayout()
        title = QLabel(
            f"<b>{self.alias}</b>"
            f"  <span style='color:#9AA4AF;font-size:12px;'>{self.ip}</span>"
        )
        title.setStyleSheet("font-size: 14px;")
        self._lbl_status = QLabel("Initialising…")
        self._lbl_status.setStyleSheet("color: #9AA4AF; font-size: 11px;")
        hdr.addWidget(title)
        hdr.addStretch()
        hdr.addWidget(self._lbl_status)
        root.addLayout(hdr)

        # SMART notes banner (hidden by default, shown when no sudo)
        self._lbl_note = QLabel(
            "ℹ  Some disks show no SMART data. "
            "Grant passwordless sudo for smartctl on the remote host to enable full access: "
            "echo 'username ALL=(root) NOPASSWD: /usr/bin/smartctl' | sudo tee /etc/sudoers.d/smartctl"
        )
        self._lbl_note.setWordWrap(True)
        self._lbl_note.setStyleSheet(
            "color: #f39c12; background: #1e1a0a; border: 1px solid #5a4a00; "
            "border-radius: 4px; padding: 5px; font-size: 11px;"
        )
        self._lbl_note.setVisible(False)
        root.addWidget(self._lbl_note)

        # Disk table
        self._table = QTableWidget(0, 10)
        self._table.setHorizontalHeaderLabels([
            "Device", "Model", "Capacity", "Used (fs)",
            "SMART", "Temp", "Power On", "TBW", "Bad Sectors", "Wear",
        ])
        self._table.verticalHeader().setDefaultSectionSize(38)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        hdr_view = self._table.horizontalHeader()
        hdr_view.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hdr_view.setSectionResizeMode(_D_MODEL, QHeaderView.ResizeMode.Stretch)
        for col, w in [(_D_DEV, 130), (_D_CAP, 90), (_D_USED, 135), (_D_SMART, 100),
                       (_D_TEMP, 65), (_D_HOURS, 95), (_D_TBW, 90),
                       (_D_BAD, 105), (_D_WEAR, 75)]:
            hdr_view.resizeSection(col, w)

        # Tooltip hints for abbreviated column headers
        tips = {
            _D_TBW:  "Total Terabytes Written — total data written to the drive lifetime",
            _D_BAD:  "Bad Sectors — sum of Reallocated + Pending + Uncorrectable sectors",
            _D_WEAR: "Wear — for SSDs: percentage of rated write endurance consumed",
            _D_HOURS:"Power-on time (days / hours)",
        }
        for col, tip in tips.items():
            self._table.horizontalHeaderItem(col).setToolTip(tip)

        root.addWidget(self._table)

        # Right-click for history; double-click also opens history
        from PyQt6.QtCore import Qt as _Qt
        self._table.setContextMenuPolicy(_Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_disk_menu)
        self._table.itemDoubleClicked.connect(
            lambda item: self._open_history(item.row()))

        # Footer
        footer = QHBoxLayout()
        self._auto_cb   = QCheckBox("Auto-refresh")
        self._auto_cb.setChecked(True)
        self._spin      = QSpinBox()
        self._spin.setRange(15, 300)
        self._spin.setValue(30)
        self._spin.setSuffix(" s")
        self._spin.setFixedWidth(72)
        self._auto_cb.toggled.connect(self._toggle_auto)
        self._spin.valueChanged.connect(self._update_interval)

        refresh_btn = QPushButton("Refresh Now")
        refresh_btn.clicked.connect(self._refresh)
        close_btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close_btn.rejected.connect(self.reject)

        footer.addWidget(self._auto_cb)
        footer.addWidget(self._spin)
        footer.addStretch()
        if self.ask_ai is not None:
            ai_btn = QPushButton("Ask AI about these disks…")
            ai_btn.setToolTip("Send this host's disk readings and SMART history to a local AI.\n"
                              "You'll see the full report before anything is sent.")
            ai_btn.clicked.connect(lambda: self._ask_ai(None))
            footer.addWidget(ai_btn)
        footer.addWidget(refresh_btn)
        footer.addWidget(close_btn)
        root.addLayout(footer)

    # ── Data ─────────────────────────────────────────────────────────────────

    def _apply_disks(self, disks: list):
        self._current_disks = list(disks)
        self._set_status("● Live", "#27ae60")
        self._table.setRowCount(0)
        self._disk_devs: list[str] = []   # kernel device names per row (display only)
        self._disk_keys: list[str] = []   # stable log keys per row (serial or dev fallback)

        any_unavailable = False
        any_udisks      = False
        for disk in disks:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._disk_devs.append(disk.get("dev", ""))
            self._disk_keys.append(smart_log_key(disk.get("dev", ""), disk.get("serial")))

            if not disk.get("smart_available"):
                any_unavailable = True
            if disk.get("smart_method") == "udisks":
                any_udisks = True

            # SMART cell text — annotate udisks results so user knows it's limited
            smart_method = disk.get("smart_method")
            if smart_method == "udisks":
                smart_display = smart_text(disk.get("smart_ok"), True) + " ¹"
            else:
                smart_display = smart_text(disk.get("smart_ok"), disk.get("smart_available"))

            # Bad sectors: sum of whichever counters are present
            bad_parts = [disk.get("reallocated"), disk.get("pending"), disk.get("uncorrectable")]
            known     = [v for v in bad_parts if v is not None]
            bad_total = sum(known) if known else None

            # Used space from df
            used_b  = disk.get("fs_used_bytes")
            total_b = disk.get("fs_total_bytes")
            if used_b is not None and total_b:
                used_str = f"{fmt_bytes(used_b)} / {fmt_bytes(total_b)}"
            elif used_b is not None:
                used_str = fmt_bytes(used_b)
            else:
                used_str = "?"

            wear = disk.get("wear_pct_used")
            wear_str = f"{wear}%" if wear is not None else "?"

            cells = [
                (f"/dev/{disk['dev']}",                "#E6E6E6"),
                (disk.get("model") or "Unknown",        "#E6E6E6"),
                (fmt_bytes(disk.get("capacity_bytes")), "#9AA4AF"),
                (used_str,                              "#9AA4AF"),
                (smart_display,                         smart_color(disk.get("smart_ok"))),
                (f"{disk['temperature_c']}°C" if disk.get("temperature_c") is not None else "?",
                 disk_temp_color(disk.get("temperature_c"))),
                (fmt_hours(disk.get("power_on_hours")),  "#9AA4AF"),
                (f"{disk['tbw_tb']:.1f} TB" if disk.get("tbw_tb") is not None else "?",
                 "#9AA4AF"),
                (str(bad_total) if bad_total is not None else "?",
                 bad_sector_color(bad_total)),
                (wear_str, wear_color(wear)),
            ]

            for col, (text, color) in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setForeground(QBrush(QColor(color)))
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self._table.setItem(row, col, item)

            # Left-align device name and model
            for col in (_D_DEV, _D_MODEL):
                self._table.item(row, col).setTextAlignment(
                    Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

            # Bold the SMART cell
            smart_item = self._table.item(row, _D_SMART)
            font = smart_item.font()
            font.setBold(True)
            smart_item.setFont(font)

            # Tooltip for bad sectors breakdown
            if any(v is not None for v in bad_parts):
                r_str = str(disk.get("reallocated")) if disk.get("reallocated") is not None else "?"
                p_str = str(disk.get("pending"))     if disk.get("pending")     is not None else "?"
                u_str = str(disk.get("uncorrectable"))if disk.get("uncorrectable")is not None else "?"
                self._table.item(row, _D_BAD).setToolTip(
                    f"Reallocated: {r_str}\nPending: {p_str}\nUncorrectable: {u_str}"
                )

        self._lbl_note.setVisible(any_unavailable or any_udisks)
        if any_udisks and not any_unavailable:
            self._lbl_note.setText(
                "¹  Some disks are showing basic health via UDisks (kernel-cached SMART) "
                "because smartctl requires root access. Deep metrics (TBW, wear, full bad-sector counts) "
                "are unavailable for those drives. To enable full SMART access:\n"
                "echo 'username ALL=(root) NOPASSWD: /usr/bin/smartctl' "
                "| sudo tee /etc/sudoers.d/smartctl"
            )
        else:
            self._lbl_note.setText(
                "ℹ  Some disks show no SMART data at all. "
                "Grant passwordless sudo for smartctl to enable full access:\n"
                "echo 'username ALL=(root) NOPASSWD: /usr/bin/smartctl' "
                "| sudo tee /etc/sudoers.d/smartctl"
            )

    def _show_disk_menu(self, pos):
        from PyQt6.QtGui import QCursor
        from PyQt6.QtWidgets import QMenu
        item = self._table.itemAt(pos)
        if not item:
            return
        row = item.row()
        menu = QMenu(self)
        hist_act = menu.addAction("View SMART History…")
        hist_act.triggered.connect(lambda: self._open_history(row))
        if self.ask_ai is not None:
            ai_act = menu.addAction("Ask AI about this disk…")
            ai_act.triggered.connect(lambda: self._ask_ai(row))
        menu.exec(QCursor.pos())

    def host_data(self) -> HostData:
        logged = SmartLogger(self.profile_key, self.alias).all_disks()
        disks = disks_for_host(self._current_disks, logged,
                               lambda d: smart_log_key(d.get("dev", ""), d.get("serial")))
        return HostData(self.alias, self.ip, disks, self._read_at or datetime.now())

    def _ask_ai(self, row: int | None):
        """row=None: the whole host; otherwise one disk."""
        host = self.host_data()
        if not host.disks:
            QMessageBox.information(self, "Ask AI", "No disk data for this host yet — click Refresh Now.")
            return
        if row is None:
            self.ask_ai(f"Disk health — {self.alias}", host_request(host))
            return
        key = self._disk_keys[row] if 0 <= row < len(getattr(self, "_disk_keys", [])) else None
        disk = next((d for d in host.disks if d.key == key), None)
        if disk is not None:
            name = disk.reading.get("model") if disk.reading else disk.key
            self.ask_ai(f"Disk health — {self.alias} / {name}", disk_request(host, disk))

    def _open_history(self, row: int):
        if row < 0 or row >= len(getattr(self, "_disk_devs", [])):
            return
        dev = self._disk_devs[row]
        key = self._disk_keys[row] if row < len(getattr(self, "_disk_keys", [])) else dev
        if not dev:
            return
        logger = SmartLogger(self.profile_key, self.alias)
        if not logger.has_history(key):
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.information(self, "No History",
                f"No SMART history has been recorded for /dev/{dev} yet.\n\n"
                "History is logged automatically each time a probe completes. "
                "Try refreshing and checking back.")
            return
        dlg = SmartHistoryDialog(dev, logger, key=key, parent=self)
        dlg.exec()

    def _set_status(self, text: str, color: str):
        self._lbl_status.setText(text)
        self._lbl_status.setStyleSheet(f"color: {color}; font-size: 11px;")

    # ── Refresh ───────────────────────────────────────────────────────────────

    def _refresh(self):
        if self._worker and self._worker.isRunning():
            return
        self._set_status("⏳  Probing…", "#f39c12")
        self._worker = SmartProbeWorker(self.ip, self.username)
        self._worker.result_ready.connect(self._on_result)
        self._worker.probe_error.connect(self._on_error)
        self._worker.host_key_changed.connect(self._on_key_change)
        self._worker.start()

    @pyqtSlot(str, list)
    def _on_result(self, _ip, disks):
        self._apply_disks(disks)

    @pyqtSlot(str, str)
    def _on_error(self, _ip, msg):
        self._set_status(f"✖  {msg[:70]}", "#c0392b")

    @pyqtSlot(str)
    def _on_key_change(self, ip, err=None):
        self._timer.stop()
        if confirm_host_key_change(self, err or ip):
            self._refresh()
        if self._auto_cb.isChecked():
            self._timer.start()

    def _toggle_auto(self, checked: bool):
        if checked:
            self._timer.start(self._spin.value() * 1000)
        else:
            self._timer.stop()

    def _update_interval(self, value: int):
        if self._auto_cb.isChecked():
            self._timer.start(value * 1000)

    def closeEvent(self, event):
        self._timer.stop()
        if self._worker:
            try:
                self._worker.result_ready.disconnect(self._on_result)
                self._worker.probe_error.disconnect(self._on_error)
                self._worker.host_key_changed.disconnect(self._on_key_change)
            except Exception:
                pass
            if self._worker.isRunning():
                self._worker.wait(8000)
        super().closeEvent(event)
