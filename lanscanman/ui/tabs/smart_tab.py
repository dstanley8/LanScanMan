from datetime import datetime
from typing import Callable

from PyQt6.QtCore import Qt, QTimer, pyqtSlot
from PyQt6.QtGui import QBrush, QColor, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from lanscanman.core.drive_report import HostData, disks_for_host, fleet_request
from lanscanman.core.formatting import fmt_bytes
from lanscanman.core.smart import overall_health
from lanscanman.core.smart_history import SmartLogger, smart_log_key
from lanscanman.ui.dialogs.smart_disk import SmartDiskDialog
from lanscanman.ui.trust import confirm_host_key_change
from lanscanman.workers.probes import SmartProbeWorker

# ─────────────────────────────────────────────────────────────────────────────
# Remote probe command
#
# Discovers physical disks via lsblk, grabs partition usage via df, then
# runs smartctl (trying passwordless sudo first, then without) for each disk.
# Every section is bounded by ###TAG### sentinels so the output can be split
# reliably even when individual commands emit nothing.
# ─────────────────────────────────────────────────────────────────────────────


# ─────────────────────────────────────────────────────────────────────────────
# Disk detail dialog
# ─────────────────────────────────────────────────────────────────────────────

# Column indices for the disk table inside the dialog


# ─────────────────────────────────────────────────────────────────────────────
# SmartTab — main tab, one row per configured host
# ─────────────────────────────────────────────────────────────────────────────

_T_STATUS  = 0
_T_ALIAS   = 1
_T_IP      = 2
_T_DISKS   = 3
_T_HEALTH  = 4
_T_UPDATED = 5


class SmartTab(QWidget):
    def __init__(self, net_manager, parent=None):
        super().__init__(parent)
        self.net_manager   = net_manager
        self.parent_window = parent
        self._workers: dict[str, SmartProbeWorker] = {}
        self._cache:   dict[str, list]              = {}   # ip -> last disk list
        self._read_at: dict[str, datetime]          = {}   # ip -> when it was read
        # Set by the app: ask_ai(title, report) opens a drive-health chat
        self.ask_ai: Callable[[str, str], bool] | None = None
        self._setup_ui()
        self._auto_timer = QTimer(self)
        self._auto_timer.timeout.connect(self._refresh_all)

    # ── Layout ────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        root = QVBoxLayout(self)

        bar = QHBoxLayout()
        self._refresh_btn = QPushButton("Refresh All")
        self._refresh_btn.clicked.connect(self._refresh_all)

        self._auto_cb = QCheckBox("Auto-refresh")
        self._auto_cb.toggled.connect(self._toggle_auto)
        self._spin = QSpinBox()
        self._spin.setRange(30, 600)
        self._spin.setValue(120)
        self._spin.setSuffix(" s")
        self._spin.setFixedWidth(78)
        self._spin.setToolTip("Auto-refresh interval")
        self._spin.valueChanged.connect(self._update_interval)

        self._lbl_info = QLabel(
            "Double-click a row to view per-disk SMART details.  "
            "Requires smartctl on the remote host (sudo NOPASSWD recommended)."
        )
        self._lbl_info.setStyleSheet("color: #9AA4AF; font-size: 11px;")

        self._ask_ai_btn = QPushButton("Ask AI (fleet report)…")
        self._ask_ai_btn.setToolTip(
            "Send every host's disk readings and SMART history to a local AI\n"
            "for a ranked review. You'll see the full report before anything is sent.")
        self._ask_ai_btn.clicked.connect(self._ask_ai_fleet)

        bar.addWidget(self._refresh_btn)
        bar.addWidget(self._ask_ai_btn)
        bar.addSpacing(8)
        bar.addWidget(self._auto_cb)
        bar.addWidget(self._spin)
        bar.addStretch()
        bar.addWidget(self._lbl_info)
        root.addLayout(bar)

        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels([
            "Status", "Alias", "IP", "Disks", "Overall Health", "Last Updated",
        ])
        self._table.verticalHeader().setDefaultSectionSize(40)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hdr.setSectionResizeMode(_T_ALIAS,   QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(_T_HEALTH,  QHeaderView.ResizeMode.Stretch)
        for col, w in [(_T_STATUS, 80), (_T_IP, 130),
                       (_T_DISKS, 140), (_T_UPDATED, 110)]:
            hdr.resizeSection(col, w)

        self._table.itemDoubleClicked.connect(self._on_double_click)
        root.addWidget(self._table)

        QShortcut(QKeySequence("F5"), self).activated.connect(self._refresh_all)

    def showEvent(self, event):
        super().showEvent(event)
        self._populate()

    def _populate(self):
        """Sync rows with net_manager.profiles without wiping existing data."""
        # Build the set of IPs that should be present
        wanted: dict[str, tuple] = {}   # ip -> (alias, username)
        for key, profile in self.net_manager.profiles.items():
            username = profile.get("username", "").strip()
            if not username or username == "—":
                continue
            alias = profile.get("alias", "").strip() or key
            ip    = profile.get("last_ip", key)
            wanted[ip] = (alias, username)

        # Remove rows whose host is no longer in profiles
        for row in range(self._table.rowCount() - 1, -1, -1):
            s  = self._table.item(row, _T_STATUS)
            ip = s.data(Qt.ItemDataRole.UserRole) if s else None
            if ip not in wanted:
                self._table.removeRow(row)

        # Collect IPs already rendered
        existing: set[str] = set()
        for row in range(self._table.rowCount()):
            s  = self._table.item(row, _T_STATUS)
            ip = s.data(Qt.ItemDataRole.UserRole) if s else None
            if ip:
                existing.add(ip)

        # Add rows for newly configured hosts, re-applying any cached result
        for ip, (alias, username) in wanted.items():
            if ip not in existing:
                self._add_row(alias, ip, username)
                if ip in self._cache:
                    self._on_result(ip, self._cache[ip])

        if self._table.rowCount() == 0:
            self._set_statusbar(
                "No configured hosts. Set an alias and username in the Scanner tab.")
        else:
            self._set_statusbar(
                f"{self._table.rowCount()} host(s) — click Refresh All to probe SMART data.")

    def _add_row(self, alias: str, ip: str, username: str):
        row = self._table.rowCount()
        self._table.insertRow(row)

        status_item = QTableWidgetItem("—")
        status_item.setData(Qt.ItemDataRole.UserRole,     ip)
        status_item.setData(Qt.ItemDataRole.UserRole + 1, username)
        status_item.setData(Qt.ItemDataRole.UserRole + 2, alias)
        status_item.setForeground(QBrush(QColor("#9AA4AF")))

        self._table.setItem(row, _T_STATUS,  status_item)
        self._table.setItem(row, _T_ALIAS,   QTableWidgetItem(alias))
        self._table.setItem(row, _T_IP,      QTableWidgetItem(ip))
        self._table.setItem(row, _T_DISKS,   QTableWidgetItem("—"))
        self._table.setItem(row, _T_HEALTH,  QTableWidgetItem("—"))
        self._table.setItem(row, _T_UPDATED, QTableWidgetItem("—"))

        self._table.item(row, _T_ALIAS).setForeground(QBrush(QColor("#3498db")))

    # ── Probing ───────────────────────────────────────────────────────────────

    def _refresh_all(self):
        for row in range(self._table.rowCount()):
            self._probe_row(row)

    def _probe_row(self, row: int):
        s        = self._table.item(row, _T_STATUS)
        ip       = s.data(Qt.ItemDataRole.UserRole)
        username = s.data(Qt.ItemDataRole.UserRole + 1)
        if not ip or not username:
            return
        if ip in self._workers and self._workers[ip].isRunning():
            return

        s.setText("Probing…")
        s.setForeground(QBrush(QColor("#f39c12")))

        worker = SmartProbeWorker(ip, username)
        worker.result_ready.connect(self._on_result)
        worker.probe_error.connect(self._on_error)
        worker.host_key_changed.connect(self._on_key_change)
        worker.finished.connect(lambda _ip=ip: self._workers.pop(_ip, None))
        self._workers[ip] = worker
        worker.start()

    # ── Worker callbacks ──────────────────────────────────────────────────────

    @pyqtSlot(str, list)
    def _on_result(self, ip: str, disks: list):
        self._cache[ip] = disks
        self._read_at[ip] = datetime.now()
        row = self._find_row(ip)
        if row == -1:
            return

        # ── Log SMART history ─────────────────────────────────────────────────
        # Resolve profile key (prefer MAC so log file survives IP changes)
        alias   = self._table.item(row, _T_ALIAS).text() if row != -1 else ip
        SmartLogger(self._profile_key(ip), alias).record(disks)

        health_text, health_color = overall_health(disks)

        # Sum raw capacity bytes across all disks for the overview column
        total_bytes = sum(d.get("capacity_bytes") or 0 for d in disks)
        if total_bytes:
            disks_txt = f"{len(disks)}  ·  {fmt_bytes(total_bytes)}"
        else:
            disks_txt = str(len(disks))

        self._set_cell(row, _T_STATUS,  "Online",     "#27ae60")
        self._set_cell(row, _T_DISKS,   disks_txt,    "#9AA4AF")
        self._set_cell(row, _T_HEALTH,  health_text,  health_color)
        self._set_cell(row, _T_UPDATED, datetime.now().strftime("%H:%M:%S"), "#9AA4AF")

        font = self._table.item(row, _T_HEALTH).font()
        font.setBold(True)
        self._table.item(row, _T_HEALTH).setFont(font)

        self._set_statusbar(f"SMART probe complete for {ip}.")

    @pyqtSlot(str, str)
    def _on_error(self, ip: str, msg: str):
        row = self._find_row(ip)
        if row == -1:
            return
        s = self._table.item(row, _T_STATUS)
        s.setText("Error")
        s.setForeground(QBrush(QColor("#c0392b")))
        s.setToolTip(msg)
        self._set_statusbar(f"Could not reach {ip}: {msg[:80]}")

    @pyqtSlot(str)
    def _on_key_change(self, ip: str, err=None):
        row = self._find_row(ip)
        if row != -1:
            self._set_cell(row, _T_STATUS, "Key Changed", "#c0392b")

        if confirm_host_key_change(self, err or ip):
            if row != -1:
                self._probe_row(row)

    # ── Double-click ──────────────────────────────────────────────────────────

    def _on_double_click(self, item):
        row      = item.row()
        s        = self._table.item(row, _T_STATUS)
        ip       = s.data(Qt.ItemDataRole.UserRole)
        username = s.data(Qt.ItemDataRole.UserRole + 1)
        alias    = s.data(Qt.ItemDataRole.UserRole + 2)

        dlg = SmartDiskDialog(
            ip=ip, username=username, alias=alias,
            disks=self._cache.get(ip),
            profile_key=self._profile_key(ip),
            parent=self,
            ask_ai=self.ask_ai,
            read_at=self._read_at.get(ip),
        )
        dlg.exec()

    def _profile_key(self, ip: str) -> str:
        """The SMART log is keyed by profile (MAC where known) so it survives IP changes."""
        for key, profile in self.net_manager.profiles.items():
            if profile.get("last_ip") == ip:
                return key
        return ip

    # ── Ask AI: fleet report ──────────────────────────────────────────────────

    def fleet_data(self) -> list[HostData]:
        """Every host in the table: this session's readings plus everything in
        its SMART history log."""
        hosts = []
        for row in range(self._table.rowCount()):
            s = self._table.item(row, _T_STATUS)
            ip, alias = s.data(Qt.ItemDataRole.UserRole), s.data(Qt.ItemDataRole.UserRole + 2)
            logged = SmartLogger(self._profile_key(ip), alias or ip).all_disks()
            disks = disks_for_host(self._cache.get(ip), logged,
                                   lambda d: smart_log_key(d.get("dev", ""), d.get("serial")))
            if disks:
                hosts.append(HostData(alias or ip, ip, disks, self._read_at.get(ip)))
        return hosts

    def _ask_ai_fleet(self):
        if self.ask_ai is None:
            return
        hosts = self.fleet_data()
        if not hosts:
            QMessageBox.information(self, "Ask AI",
                                    "No disk data yet — click Refresh All to read your hosts' disks first.")
            return
        self.ask_ai(f"Disk health — fleet ({sum(len(h.disks) for h in hosts)} disks)",
                    fleet_request(hosts))

    # ── Auto-refresh ──────────────────────────────────────────────────────────

    def _toggle_auto(self, checked: bool):
        if checked:
            self._auto_timer.start(self._spin.value() * 1000)
        else:
            self._auto_timer.stop()

    def _update_interval(self, value: int):
        if self._auto_cb.isChecked():
            self._auto_timer.start(value * 1000)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _find_row(self, ip: str) -> int:
        for row in range(self._table.rowCount()):
            item = self._table.item(row, _T_STATUS)
            if item and item.data(Qt.ItemDataRole.UserRole) == ip:
                return row
        return -1

    def _set_cell(self, row: int, col: int, text: str, color: str):
        item = self._table.item(row, col)
        if item is None:
            item = QTableWidgetItem()
            self._table.setItem(row, col, item)
        item.setText(text)
        item.setForeground(QBrush(QColor(color)))

    def _set_statusbar(self, msg: str):
        if self.parent_window:
            self.parent_window.status.setText(msg)
