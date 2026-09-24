


from PyQt6.QtCore import Qt, QTimer, pyqtSlot
from PyQt6.QtGui import QBrush, QColor, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from lanscanman.core.formatting import (
    BAD,
    GOOD,
    MUTED,
    WARN,
    fmt_uptime,
    hw_temp_color,
    usage_color,
)
from lanscanman.core.probe import health_summary
from lanscanman.ui.dialogs.host_stats import HostStatsDialog
from lanscanman.ui.trust import confirm_host_key_change
from lanscanman.workers.probes import ProbeWorker

# ─────────────────────────────────────────────────────────────────────────────
# MonitorTab — table listing all hosts that have a saved profile + username
# ─────────────────────────────────────────────────────────────────────────────

# Table column indices
_COL_STATUS  = 0
_COL_ALIAS   = 1
_COL_IP      = 2
_COL_DISTRO  = 3
_COL_CPU     = 4
_COL_RAM     = 5
_COL_GPU     = 6
_COL_UPTIME  = 7
_COL_UPDATED = 8
_COL_HEALTH  = 9

_HEALTH_COLOR = {"good": GOOD, "warn": WARN, "bad": BAD, "unknown": MUTED}


class MonitorTab(QWidget):
    def __init__(self, net_manager, parent=None):
        super().__init__(parent)
        self.net_manager   = net_manager
        self.parent_window = parent
        self._workers: dict[str, ProbeWorker] = {}   # ip -> active worker
        self._cache:   dict[str, dict]         = {}   # ip -> last parsed data
        self._setup_ui()
        self._auto_timer = QTimer(self)
        self._auto_timer.timeout.connect(self._refresh_all)

    # ── UI ───────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        root = QVBoxLayout(self)

        # ── Controls bar ────────────────────────────────────────────────────
        bar = QHBoxLayout()

        self._refresh_btn = QPushButton("Refresh All")
        self._refresh_btn.clicked.connect(self._refresh_all)

        self._auto_cb = QCheckBox("Auto-refresh")
        self._auto_cb.toggled.connect(self._toggle_auto)

        self._spin = QSpinBox()
        self._spin.setRange(10, 300)
        self._spin.setValue(30)
        self._spin.setSuffix(" s")
        self._spin.setFixedWidth(75)
        self._spin.setToolTip("Auto-refresh interval")
        self._spin.valueChanged.connect(self._update_interval)

        self._lbl_info = QLabel("Double-click a row to open the live stats panel.")
        self._lbl_info.setStyleSheet("color: #9AA4AF; font-size: 11px;")

        bar.addWidget(self._refresh_btn)
        bar.addSpacing(8)
        bar.addWidget(self._auto_cb)
        bar.addWidget(self._spin)
        bar.addStretch()
        bar.addWidget(self._lbl_info)
        root.addLayout(bar)

        # ── Table ────────────────────────────────────────────────────────────
        self._table = QTableWidget(0, 10)
        self._table.setHorizontalHeaderLabels([
            "Status", "Alias", "IP", "OS / Distro",
            "CPU % · °C", "RAM %", "GPU % · °C", "Uptime", "Last Updated", "Health",
        ])
        self._table.verticalHeader().setDefaultSectionSize(42)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hdr.setSectionResizeMode(_COL_ALIAS,   QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(_COL_DISTRO,  QHeaderView.ResizeMode.Stretch)
        hdr.resizeSection(_COL_STATUS,  80)
        hdr.resizeSection(_COL_IP,     120)
        hdr.resizeSection(_COL_CPU,    105)
        hdr.resizeSection(_COL_RAM,     70)
        hdr.resizeSection(_COL_GPU,    105)
        hdr.resizeSection(_COL_UPTIME, 100)
        hdr.resizeSection(_COL_UPDATED,120)
        hdr.resizeSection(_COL_HEALTH, 220)

        self._table.itemDoubleClicked.connect(self._on_double_click)
        root.addWidget(self._table)

        QShortcut(QKeySequence("F5"), self).activated.connect(self._refresh_all)

    # ── Population ───────────────────────────────────────────────────────────

    def showEvent(self, event):
        """Sync rows with profiles whenever the tab becomes visible."""
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
            s  = self._table.item(row, _COL_STATUS)
            ip = s.data(Qt.ItemDataRole.UserRole) if s else None
            if ip not in wanted:
                self._table.removeRow(row)

        # Collect IPs already rendered
        existing: set[str] = set()
        for row in range(self._table.rowCount()):
            s  = self._table.item(row, _COL_STATUS)
            ip = s.data(Qt.ItemDataRole.UserRole) if s else None
            if ip:
                existing.add(ip)

        # Add rows for newly configured hosts, re-applying cached data immediately
        for ip, (alias, username) in wanted.items():
            if ip not in existing:
                self._add_row(alias, ip, username)
                if ip in self._cache:
                    self._on_result(ip, self._cache[ip])

        if self._table.rowCount() == 0:
            self._set_status_bar(
                "No configured hosts found. Add an alias and username in the Scanner tab.")
        else:
            self._set_status_bar(
                f"{self._table.rowCount()} host(s) — click Refresh All to probe.")

    def _add_row(self, alias: str, ip: str, username: str):
        row = self._table.rowCount()
        self._table.insertRow(row)

        status_item = QTableWidgetItem("—")
        status_item.setData(Qt.ItemDataRole.UserRole,     ip)        # ip
        status_item.setData(Qt.ItemDataRole.UserRole + 1, username)  # username
        status_item.setData(Qt.ItemDataRole.UserRole + 2, alias)     # alias
        status_item.setForeground(QBrush(QColor("#9AA4AF")))

        self._table.setItem(row, _COL_STATUS,  status_item)
        self._table.setItem(row, _COL_ALIAS,   QTableWidgetItem(alias))
        self._table.setItem(row, _COL_IP,      QTableWidgetItem(ip))
        self._table.setItem(row, _COL_DISTRO,  QTableWidgetItem("—"))
        self._table.setItem(row, _COL_CPU,     QTableWidgetItem("—"))
        self._table.setItem(row, _COL_RAM,     QTableWidgetItem("—"))
        self._table.setItem(row, _COL_GPU,     QTableWidgetItem("—"))
        self._table.setItem(row, _COL_UPTIME,  QTableWidgetItem("—"))
        self._table.setItem(row, _COL_UPDATED, QTableWidgetItem("—"))
        self._table.setItem(row, _COL_HEALTH,  QTableWidgetItem("—"))

        self._table.item(row, _COL_ALIAS).setForeground(QBrush(QColor("#3498db")))

    # ── Refresh orchestration ─────────────────────────────────────────────────

    def _refresh_all(self):
        for row in range(self._table.rowCount()):
            self._probe_row(row)

    def _probe_row(self, row: int):
        status_item = self._table.item(row, _COL_STATUS)
        if status_item is None:
            return
        ip       = status_item.data(Qt.ItemDataRole.UserRole)
        username = status_item.data(Qt.ItemDataRole.UserRole + 1)

        if ip in self._workers and self._workers[ip].isRunning():
            return                              # Already probing this host

        status_item.setText("Probing…")
        status_item.setForeground(QBrush(QColor("#f39c12")))

        worker = ProbeWorker(ip, username)
        worker.result_ready.connect(self._on_result)
        worker.probe_error.connect(self._on_error)
        worker.host_key_changed.connect(self._on_key_change)
        # Remove from dict only after run() has fully returned — not in the
        # result/error slots, where the thread may still be in its cleanup phase.
        worker.finished.connect(lambda _ip=ip: self._workers.pop(_ip, None))
        self._workers[ip] = worker
        worker.start()

    # ── Worker callbacks ──────────────────────────────────────────────────────

    @pyqtSlot(str, dict)
    def _on_result(self, ip: str, data: dict):
        # Don't pop self._workers here — the finished signal handles that
        # once run() has truly returned, avoiding a destroy-while-running crash.
        self._cache[ip] = data
        row = self._find_row(ip)
        if row == -1:
            return

        # Status cell
        s = self._table.item(row, _COL_STATUS)
        s.setText("Online")
        s.setForeground(QBrush(QColor("#27ae60")))

        # Distro
        self._set_cell(row, _COL_DISTRO, data.get("distro") or "—", "#9AA4AF")

        # CPU — show usage and temperature together in one cell
        cpu_pct  = data.get("cpu_usage")
        cpu_temp = data.get("cpu_temp_c")
        if cpu_pct is not None and cpu_temp is not None:
            cpu_txt   = f"{cpu_pct:.1f}%  ·  {cpu_temp}°C"
            cpu_color = hw_temp_color(cpu_temp)
        elif cpu_pct is not None:
            cpu_txt   = f"{cpu_pct:.1f}%"
            cpu_color = usage_color(cpu_pct)
        else:
            cpu_txt, cpu_color = "—", "#9AA4AF"
        self._set_cell(row, _COL_CPU, cpu_txt, cpu_color)

        # RAM
        total_kb = data.get("mem_total_kb")
        avail_kb = data.get("mem_avail_kb")
        if total_kb and avail_kb is not None:
            used_kb = total_kb - avail_kb
            ram_pct = round(100.0 * used_kb / total_kb, 1)
            self._set_cell(row, _COL_RAM, f"{ram_pct:.1f}%", usage_color(ram_pct))
        else:
            self._set_cell(row, _COL_RAM, "—", "#9AA4AF")

        # GPU — show usage and temperature together in one cell
        gpu_pct  = data.get("gpu_usage")
        gpu_temp = data.get("gpu_temp_c")
        if gpu_pct is not None and gpu_temp is not None:
            gpu_txt   = f"{gpu_pct}%  ·  {gpu_temp}°C"
            gpu_color = hw_temp_color(gpu_temp)
        elif gpu_pct is not None:
            gpu_txt   = f"{gpu_pct}%"
            gpu_color = usage_color(gpu_pct)
        else:
            gpu_txt, gpu_color = "—", "#9AA4AF"
        self._set_cell(row, _COL_GPU, gpu_txt, gpu_color)

        # Uptime
        up = data.get("uptime_seconds")
        self._set_cell(row, _COL_UPTIME, fmt_uptime(up) if up else "—", "#9AA4AF")

        # Timestamp
        from datetime import datetime
        self._set_cell(row, _COL_UPDATED,
                       datetime.now().strftime("%H:%M:%S"), "#9AA4AF")

        # Health: failed services, containers down, updates, reboot required
        text, severity, findings = health_summary(data)
        self._set_cell(row, _COL_HEALTH, text, _HEALTH_COLOR[severity])
        self._table.item(row, _COL_HEALTH).setToolTip(
            "\n".join(findings) if findings else
            "No failed services, stopped containers, pending updates or reboot."
            if severity == "good" else "Health checks unavailable on this host.")

        self._set_status_bar(f"Probe complete for {ip}.")

    @pyqtSlot(str, str)
    def _on_error(self, ip: str, msg: str):
        # Don't pop self._workers here — the finished signal handles that.
        row = self._find_row(ip)
        if row == -1:
            return
        s = self._table.item(row, _COL_STATUS)
        s.setText("Error")
        s.setForeground(QBrush(QColor("#c0392b")))
        s.setToolTip(msg)
        for col in [_COL_DISTRO, _COL_CPU, _COL_RAM, _COL_GPU, _COL_UPTIME]:
            self._set_cell(row, col, "—", "#9AA4AF")
        self._set_status_bar(f"Could not reach {ip}: {msg[:80]}")

    @pyqtSlot(str)
    def _on_key_change(self, ip: str, err=None):
        # Don't pop self._workers here — the finished signal handles that.
        row = self._find_row(ip)
        if row != -1:
            s = self._table.item(row, _COL_STATUS)
            s.setText("Key Changed")
            s.setForeground(QBrush(QColor("#c0392b")))

        if confirm_host_key_change(self, err or ip):
            if row != -1:
                self._probe_row(row)

    # ── Double-click ─────────────────────────────────────────────────────────

    def _on_double_click(self, item):
        row = item.row()
        s        = self._table.item(row, _COL_STATUS)
        ip       = s.data(Qt.ItemDataRole.UserRole)
        username = s.data(Qt.ItemDataRole.UserRole + 1)
        alias    = s.data(Qt.ItemDataRole.UserRole + 2)

        dlg = HostStatsDialog(
            ip       = ip,
            username = username,
            alias    = alias,
            data     = self._cache.get(ip),   # Pass cached data so dialog isn't blank
            parent   = self,
        )
        dlg.exec()

    # ── Auto-refresh ──────────────────────────────────────────────────────────

    def _toggle_auto(self, checked: bool):
        if checked:
            self._auto_timer.start(self._spin.value() * 1000)
        else:
            self._auto_timer.stop()

    def _update_interval(self, value: int):
        if self._auto_cb.isChecked():
            self._auto_timer.start(value * 1000)

    # ── Utilities ────────────────────────────────────────────────────────────

    def _find_row(self, ip: str) -> int:
        for row in range(self._table.rowCount()):
            item = self._table.item(row, _COL_STATUS)
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

    def _set_status_bar(self, msg: str):
        if self.parent_window:
            self.parent_window.status.setText(msg)
