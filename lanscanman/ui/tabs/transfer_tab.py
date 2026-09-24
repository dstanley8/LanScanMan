


import json

from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QBrush, QColor, QCursor, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from lanscanman import paths
from lanscanman.core.formatting import fmt_bytes, fmt_speed_eta
from lanscanman.core.notify import notify
from lanscanman.core.schedules import ScheduleManager
from lanscanman.log import log
from lanscanman.ui.dialogs.transfer_dialogs import AddTransferDialog
from lanscanman.ui.tabs.schedules_widget import SchedulesWidget, build_add_to_list_menu
from lanscanman.workers.rsync import RsyncWorker

# ── Table column indices ──────────────────────────────────────────────────────
_C_STATUS   = 0   # status text
_C_NAME     = 1   # file / folder name
_C_ROUTE    = 2   # "sender → receiver"
_C_PROGRESS = 3   # QProgressBar via setCellWidget
_C_SIZE     = 4   # "4.2 GB / 10.9 GB"
_C_SPEED    = 5   # "45.2 MB/s  ·  2m 14s"


# ─────────────────────────────────────────────────────────────────────────────
# Transfer Tab
# ─────────────────────────────────────────────────────────────────────────────

class TransferTab(QWidget):
    def __init__(self, net_manager, parent=None,
                 schedule_manager: "ScheduleManager | None" = None,
                 schedule_integrity_failed: bool = False):
        super().__init__(parent)
        self.net_manager    = net_manager
        self.parent_window  = parent
        self.schedule_manager = schedule_manager
        self._schedule_integrity_failed = schedule_integrity_failed
        self.active_workers: dict[int, "RsyncWorker"] = {}
        self._progress_bars: dict[int, QProgressBar]  = {}
        self._output_bufs:   dict[int, list[str]]     = {}  # tid → rsync stdout lines
        self._next_id       = 0
        self._session_completed = 0
        self._session_bytes     = 0
        self.history_file = paths.TRANSFER_HISTORY
        self._setup_ui()
        self._load_history()

    def _new_id(self) -> int:
        self._next_id += 1
        return self._next_id

    # ── Layout ────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setSpacing(6)
        outer.setContentsMargins(0, 0, 0, 0)

        # ── Toggle bar: Queue / Schedules ─────────────────────────────────────
        toggle_bar = QHBoxLayout()
        toggle_bar.setContentsMargins(6, 4, 6, 0)
        toggle_bar.setSpacing(0)

        self._toggle_queue = QPushButton("Queue")
        self._toggle_queue.setCheckable(True)
        self._toggle_queue.setChecked(True)
        self._toggle_schedules = QPushButton("Schedules")
        self._toggle_schedules.setCheckable(True)

        self._toggle_group = QButtonGroup(self)
        self._toggle_group.setExclusive(True)
        self._toggle_group.addButton(self._toggle_queue, 0)
        self._toggle_group.addButton(self._toggle_schedules, 1)
        self._toggle_group.idClicked.connect(self._on_toggle_clicked)

        for b in (self._toggle_queue, self._toggle_schedules):
            b.setStyleSheet("""
                QPushButton {
                    background: #20262E; color: #9AA4AF; border: 1px solid #2A313B;
                    padding: 6px 16px; font-size: 12px;
                }
                QPushButton:checked {
                    background: #2A313B; color: #E6E6E6;
                    border-bottom: 2px solid #3498db;
                }
                QPushButton:hover:!checked { color: #E6E6E6; }
            """)

        toggle_bar.addWidget(self._toggle_queue)
        toggle_bar.addWidget(self._toggle_schedules)
        toggle_bar.addStretch()
        outer.addLayout(toggle_bar)

        # ── Stacked widget: Queue section | Schedules section ────────────────
        self._stack = QStackedWidget()
        self._queue_widget = self._build_queue_widget()
        self._stack.addWidget(self._queue_widget)

        if self.schedule_manager is not None:
            self._schedules_widget = SchedulesWidget(
                self.schedule_manager,
                integrity_failed=self._schedule_integrity_failed,
                parent=self,
            )
            self._schedules_widget.changed.connect(self._on_schedules_changed)
            self._stack.addWidget(self._schedules_widget)
        else:
            self._schedules_widget = None
            # Placeholder so the toggle still works
            placeholder = QLabel(
                "Schedules are unavailable — schedule manager failed to initialise.")
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            placeholder.setStyleSheet("color: #9AA4AF; padding: 40px;")
            self._stack.addWidget(placeholder)

        outer.addWidget(self._stack)

        QShortcut(QKeySequence("Ctrl+N"), self).activated.connect(self._open_dialog)

    def _build_queue_widget(self) -> QWidget:
        """Build the existing Queue UI inside a container widget."""
        qw = QWidget()
        root = QVBoxLayout(qw)
        root.setSpacing(6)

        # Controls bar
        bar = QHBoxLayout()
        self._add_btn = QPushButton("Add Transfer")
        self._add_btn.clicked.connect(self._open_dialog)
        self._clear_btn = QPushButton("Clear Finished")
        self._clear_btn.clicked.connect(self._clear_finished)
        self._summary_lbl = QLabel("")
        self._summary_lbl.setStyleSheet("color: #9AA4AF; font-size: 11px;")
        bar.addWidget(self._add_btn)
        bar.addWidget(self._clear_btn)
        bar.addStretch()
        bar.addWidget(self._summary_lbl)
        root.addLayout(bar)

        # Table
        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels([
            "Status", "Name", "Route", "Progress", "Size", "Speed / ETA",
        ])
        self._table.verticalHeader().setDefaultSectionSize(46)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        self._table.currentItemChanged.connect(self._on_selection_changed)

        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hdr.setSectionResizeMode(_C_NAME,     QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(_C_PROGRESS, QHeaderView.ResizeMode.Fixed)
        hdr.resizeSection(_C_STATUS,   150)
        hdr.resizeSection(_C_ROUTE,    220)
        hdr.resizeSection(_C_PROGRESS, 200)
        hdr.resizeSection(_C_SIZE,     180)
        hdr.resizeSection(_C_SPEED,    200)

        root.addWidget(self._table)

        # ── Detail panel — tabbed output + error view ─────────────────────────
        self._detail = QFrame()
        self._detail.setFixedHeight(130)
        self._detail.setStyleSheet(
            "QFrame { background: #1B1F24; border-top: 1px solid #2A313B; }")
        dl = QVBoxLayout(self._detail)
        dl.setContentsMargins(10, 6, 10, 6)
        dl.setSpacing(3)

        # Src / Dst labels
        self._det_src = QLabel("—")
        self._det_dst = QLabel("—")
        for lbl in (self._det_src, self._det_dst):
            lbl.setStyleSheet("color: #9AA4AF; font-size: 11px;")
            lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        dl.addWidget(self._det_src)
        dl.addWidget(self._det_dst)

        # Tabbed area: Output (rsync file list) | Errors (stderr)
        _tab_style = """
            QTabWidget::pane {
                border: none;
                background: transparent;
            }
            QTabBar::tab {
                background: #20262E;
                color: #9AA4AF;
                padding: 2px 10px;
                font-size: 10px;
                border: none;
                border-top-left-radius: 3px;
                border-top-right-radius: 3px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #2A313B;
                color: #E6E6E6;
            }
        """
        _pte_style = lambda border_color: f"""
            QPlainTextEdit {{
                color: #E6E6E6;
                font-size: 11px;
                font-family: monospace;
                background: transparent;
                border: none;
                border-left: 2px solid {border_color};
                padding-left: 6px;
            }}
            QScrollBar:vertical {{
                background: #1B1F24; width: 6px; border-radius: 3px;
            }}
            QScrollBar::handle:vertical {{
                background: #3A4452; border-radius: 3px; min-height: 16px;
            }}
            QScrollBar::handle:vertical:hover {{ background: #3498db; }}
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {{ height: 0px; }}
        """

        self._det_tabs = QTabWidget()
        self._det_tabs.setStyleSheet(_tab_style)

        self._det_out = QPlainTextEdit()
        self._det_out.setReadOnly(True)
        self._det_out.setStyleSheet(_pte_style("#3498db"))
        self._det_out.setPlaceholderText("rsync output will appear here during transfer…")

        self._det_err = QPlainTextEdit()
        self._det_err.setReadOnly(True)
        self._det_err.setStyleSheet(_pte_style("#c0392b"))
        self._det_err.setPlaceholderText("Errors will appear here if the transfer fails…")

        self._det_tabs.addTab(self._det_out, "Output")
        self._det_tabs.addTab(self._det_err, "Errors")
        dl.addWidget(self._det_tabs)
        root.addWidget(self._detail)

        return qw

    # ── Toggle / schedules helpers ───────────────────────────────────────────

    def _on_toggle_clicked(self, idx: int):
        self._stack.setCurrentIndex(idx)

    def _on_schedules_changed(self):
        """Persist schedule changes immediately."""
        if self.schedule_manager is not None:
            try:
                self.schedule_manager.save()
            except Exception as e:
                log.exception(f"failed to save schedules: {e}")

    def refresh_schedules_view(self):
        """Called externally (e.g. after a timer-driven run updates state)."""
        if self._schedules_widget is not None:
            self._schedules_widget.refresh()

    def run_schedule_by_id(self, schedule_id: str, skip_confirm_dialog: bool = False):
        """Called by the main window timer when a schedule is due."""
        if self._schedules_widget is None or self.schedule_manager is None:
            return
        sched = self.schedule_manager.find(schedule_id)
        if sched is None:
            return
        self._schedules_widget.run_schedule(
            sched,
            skip_confirm_dialog=skip_confirm_dialog,
            triggered_by_timer=True,
        )

    # ── Detail panel ─────────────────────────────────────────────────────────

    def _on_selection_changed(self, current, _prev):
        if current is None:
            self._det_src.setText("—")
            self._det_dst.setText("—")
            self._det_out.setPlainText("")
            self._det_err.setPlainText("")
            return
        row  = current.row()
        s_item = self._table.item(row, _C_STATUS)
        data   = s_item.data(Qt.ItemDataRole.UserRole)
        err    = s_item.data(Qt.ItemDataRole.UserRole + 1)
        tid    = s_item.data(Qt.ItemDataRole.UserRole + 2)

        if data:
            self._det_src.setText(f"Src:  {data.get('full_source', '—')}")
            self._det_dst.setText(f"Dst:  {data.get('full_dest',   '—')}")
        else:
            self._det_src.setText("—")
            self._det_dst.setText("—")

        # Output tab — show buffered rsync stdout for this transfer
        lines = self._output_bufs.get(tid, [])
        self._det_out.setPlainText("\n".join(lines))
        if lines:
            # Scroll to bottom to show most recent output
            self._det_out.moveCursor(
                self._det_out.textCursor().MoveOperation.End)

        # Errors tab
        self._det_err.setPlainText(err or "")
        if err:
            self._det_err.moveCursor(
                self._det_err.textCursor().MoveOperation.Start)
            # Switch to Errors tab automatically when there's an error
            self._det_tabs.setCurrentIndex(1)

    # ── History ───────────────────────────────────────────────────────────────

    def _save_history(self):
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        rows = []
        for r in range(self._table.rowCount()):
            s = self._table.item(r, _C_STATUS)
            if s is None: continue
            rows.append({
                "status":   s.text(),
                "name":     self._table.item(r, _C_NAME).text()  if self._table.item(r, _C_NAME)  else "",
                "route":    self._table.item(r, _C_ROUTE).text() if self._table.item(r, _C_ROUTE) else "",
                "size":     self._table.item(r, _C_SIZE).text()  if self._table.item(r, _C_SIZE)  else "",
                "raw_data": s.data(Qt.ItemDataRole.UserRole),
            })
        with open(self.history_file, "w") as f:
            json.dump(rows, f, indent=4)

    def _load_history(self):
        if not self.history_file.exists(): return
        try:
            with open(self.history_file) as f:
                history = json.load(f)
            for entry in history:
                status = entry.get("status", "Unknown")
                if status not in ("Completed", "Failed", "Cancelled"):
                    status = "Interrupted"
                data = entry.get("raw_data") or {}
                tid  = self._new_id()
                self._add_row(
                    status=status,
                    name=entry.get("name", "—"),
                    route=entry.get("route", "—"),
                    size=entry.get("size", "—"),
                    raw_data=data,
                    transfer_id=tid,
                )
                row = self._table.rowCount() - 1
                self._apply_status_colour(row, status)
        except Exception as e:
            print(f"History load error: {e}")

    # ── Row management ────────────────────────────────────────────────────────

    def _find_row(self, tid: int) -> int:
        for r in range(self._table.rowCount()):
            item = self._table.item(r, _C_STATUS)
            if item and item.data(Qt.ItemDataRole.UserRole + 2) == tid:
                return r
        return -1

    def _get_alias(self, ip: str) -> str:
        for profile in self.net_manager.profiles.values():
            if profile.get("last_ip") == ip:
                alias = profile.get("alias", "").strip()
                if alias: return alias
        return ip

    def _make_route(self, data: dict) -> str:
        sip = data.get("sender_ip", "127.0.0.1")
        rip = data.get("receiver_ip", "127.0.0.1")
        s   = "Local" if sip == "127.0.0.1" else self._get_alias(sip)
        r   = "Local" if rip == "127.0.0.1" else self._get_alias(rip)
        return f"{s}  →  {r}"

    def _make_progress_bar(self, pct: int = 0, is_dry: bool = False) -> QProgressBar:
        bar   = QProgressBar()
        color = "#3498db" if not is_dry else "#f39c12"
        bar.setRange(0, 100)
        bar.setValue(pct)
        bar.setFormat("Queued" if pct == 0 else f"{pct}%")
        bar.setTextVisible(True)
        bar.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid #2A313B; border-radius: 4px;
                background: #0d1117; color: #E6E6E6; text-align: center;
            }}
            QProgressBar::chunk {{ background: {color}; border-radius: 3px; }}
        """)
        return bar

    def _add_row(self, status: str, name: str, route: str, size: str,
                 raw_data: dict | None = None, transfer_id: int | None = None,
                 speed: str = "—"):
        row = self._table.rowCount()
        self._table.insertRow(row)

        s_item = QTableWidgetItem(status)
        if raw_data:
            s_item.setData(Qt.ItemDataRole.UserRole, raw_data)
        if transfer_id is not None:
            s_item.setData(Qt.ItemDataRole.UserRole + 2, transfer_id)

        is_dry = "--dry-run" in (raw_data or {}).get("args", [])
        pct    = 100 if status == "Completed" else 0

        bar = self._make_progress_bar(pct, is_dry)
        if transfer_id is not None:
            self._progress_bars[transfer_id] = bar

        self._table.setItem(row, _C_STATUS,   s_item)
        self._table.setItem(row, _C_NAME,     QTableWidgetItem(name))
        self._table.setItem(row, _C_ROUTE,    QTableWidgetItem(route))
        self._table.setItem(row, _C_PROGRESS, QTableWidgetItem(""))
        self._table.setCellWidget(row, _C_PROGRESS, bar)
        self._table.setItem(row, _C_SIZE,     QTableWidgetItem(size))
        self._table.setItem(row, _C_SPEED,    QTableWidgetItem(speed))

        # Colour the route column
        route_item = self._table.item(row, _C_ROUTE)
        route_item.setForeground(QBrush(QColor("#9AA4AF")))

    def _apply_status_colour(self, row: int, status: str):
        item = self._table.item(row, _C_STATUS)
        if status == "Completed":
            item.setForeground(QBrush(QColor("#27ae60")))
        elif status.startswith("Failed") or status == "Interrupted":
            item.setForeground(QBrush(QColor("#c0392b")))
        elif status in ("Cancelled",):
            item.setForeground(QBrush(QColor("#9AA4AF")))
        else:
            item.setForeground(QBrush(QColor("#E6E6E6")))

    def _update_session_summary(self):
        if self._session_completed == 0:
            self._summary_lbl.setText("")
            return
        size_str = fmt_bytes(str(self._session_bytes))
        self._summary_lbl.setText(
            f"Session:  {self._session_completed} completed  ·  {size_str} transferred")

    # ── Dialog + launch ───────────────────────────────────────────────────────

    def _open_dialog(self):
        scanner_tab = self.parent_window.scanner_page
        devices = []
        for r in range(scanner_tab.table.rowCount()):
            ip_item    = scanner_tab.table.item(r, 0)
            alias_item = scanner_tab.table.item(r, 1)
            mac_item   = scanner_tab.table.item(r, 4)
            if not ip_item: continue
            ip    = ip_item.text()
            mac   = mac_item.text() if mac_item else ""
            alias = alias_item.text().strip() if alias_item else ""
            # Strip any "+N" suffix that _username_display adds to the table cell
            alias = alias.split("  +")[0].strip() if alias else ""
            if not alias or alias == "—":
                continue

            profile     = self.net_manager.get_profile(mac, ip)
            primary     = profile.get("username", "").strip()
            extra_users = profile.get("extra_users", [])

            # Primary user — label is plain alias when no extras, qualified when there are
            if primary:
                label = f"{alias} — {primary}" if extra_users else alias
                devices.append((label, ip, primary))

            # Secondary users — always qualified with the username
            for user in extra_users:
                devices.append((f"{alias} — {user}", ip, user))

        dlg = AddTransferDialog(devices, self)
        if dlg.exec():
            self._process_new(dlg.get_transfer_data())

    def _process_new(self, data: dict):
        tid   = self._new_id()
        route = self._make_route(data)
        is_dry = "--dry-run" in data.get("args", [])
        status = "Dry Run — Queued" if is_dry else "Queued"

        self._add_row(
            status=status,
            name=data["name"],
            route=route,
            size="Calculating…",
            raw_data=data,
            transfer_id=tid,
        )

        worker = RsyncWorker(tid, data)
        worker.progress_update.connect(self._on_progress)
        worker.output_line.connect(self._on_output_line)
        worker.finished.connect(self._on_finished)
        self._output_bufs[tid] = []
        self.active_workers[tid] = worker
        worker.start()
        self._save_history()

    # ── Worker callbacks ──────────────────────────────────────────────────────

    @pyqtSlot(int, str)
    def _on_output_line(self, tid: int, line: str):
        """Buffer a stdout line from rsync and append to output panel if selected."""
        buf = self._output_bufs.get(tid)
        if buf is not None:
            buf.append(line)
        # Live-append to panel if this transfer is the currently selected row
        row = self._find_row(tid)
        if row != -1 and row == self._table.currentRow():
            self._det_out.appendPlainText(line)

    @pyqtSlot(int, str, str, str, str, str)
    def _on_progress(self, tid, status, percent, size, speed, eta):
        row = self._find_row(tid)
        if row == -1: return

        self._table.item(row, _C_STATUS).setText(status)
        self._table.item(row, _C_SIZE).setText(size)
        self._table.item(row, _C_SPEED).setText(fmt_speed_eta(speed, eta))

        bar = self._progress_bars.get(tid)
        if bar:
            try:
                pv = int(percent.replace("%", ""))
                bar.setValue(pv)
                bar.setFormat(f"{pv}%")
            except ValueError:
                pass

    @pyqtSlot(int, str, str, int)
    def _on_finished(self, tid: int, final_status: str, error: str, total_bytes: int):
        row = self._find_row(tid)
        if row != -1:
            s_item = self._table.item(row, _C_STATUS)
            if error:
                short = error.splitlines()[0][:70]
                s_item.setText(f"Failed: {short}")
                s_item.setData(Qt.ItemDataRole.UserRole + 1, error)
                s_item.setForeground(QBrush(QColor("#c0392b")))
                notify("Transfer Failed", self._table.item(row, _C_NAME).text())
                # Update detail panel if this row is selected
                self._det_err.setPlainText(error)
                # Scroll to the top so the first line (the most useful one)
                # is visible rather than the end of a long stderr dump
                self._det_err.moveCursor(self._det_err.textCursor().MoveOperation.Start)
            else:
                data   = s_item.data(Qt.ItemDataRole.UserRole) or {}
                is_dry = "--dry-run" in data.get("args", [])
                s_item.setText("Dry Run — Done" if is_dry else final_status)
                self._apply_status_colour(row, final_status)
                bar = self._progress_bars.get(tid)
                if bar:
                    bar.setValue(100)
                    bar.setFormat("Done (dry)" if is_dry else "100%")
                if final_status == "Completed":
                    # Clean up size display "x / x" → just total
                    size_txt = self._table.item(row, _C_SIZE).text()
                    if "/" in size_txt:
                        self._table.item(row, _C_SIZE).setText(size_txt.split("/")[-1].strip())
                    self._table.item(row, _C_SPEED).setText("—")
                    if not is_dry:
                        notify("Transfer Complete",
                                self._table.item(row, _C_NAME).text())

            # Session stats
            if final_status == "Completed":
                self._session_completed += 1
                self._session_bytes     += total_bytes
                self._update_session_summary()

        worker = self.active_workers.pop(tid, None)
        if worker:
            worker.wait()
        self._save_history()

    # ── Context menu ──────────────────────────────────────────────────────────

    def _show_context_menu(self, pos):
        item = self._table.itemAt(pos)
        if not item: return
        row    = item.row()
        status = self._table.item(row, _C_STATUS).text()
        active = "Transferring" in status or "Queued" in status or "Checking" in status

        menu = QMenu(self)
        act_cancel  = menu.addAction("Cancel Transfer")
        act_cancel.setEnabled(active)
        act_cancel.triggered.connect(lambda: self._cancel(row))

        act_restart = menu.addAction("Restart Transfer")
        act_restart.setEnabled(not active)
        act_restart.triggered.connect(lambda: self._restart(row))

        # Add to schedule list submenu — only if schedule manager is present
        if self.schedule_manager is not None:
            menu.addSeparator()
            data = self._table.item(row, _C_STATUS).data(Qt.ItemDataRole.UserRole)
            if isinstance(data, dict):
                submenu = build_add_to_list_menu(
                    parent=self,
                    manager=self.schedule_manager,
                    transfer_data=data,
                    on_changed=self._on_schedules_changed_from_queue,
                )
                menu.addMenu(submenu)

        menu.addSeparator()
        act_delete = menu.addAction("Delete Row")
        act_delete.setEnabled(not active)
        act_delete.triggered.connect(lambda: self._delete_row(row))

        menu.exec(QCursor.pos())

    def _on_schedules_changed_from_queue(self):
        """Called when a transfer is added to a schedule via the queue context menu."""
        self._on_schedules_changed()
        if self._schedules_widget is not None:
            self._schedules_widget.refresh()

    def _cancel(self, row: int):
        tid = self._table.item(row, _C_STATUS).data(Qt.ItemDataRole.UserRole + 2)
        worker = self.active_workers.get(tid)
        if worker:
            worker.stop()
            self._table.item(row, _C_STATUS).setText("Cancelling…")

    def _restart(self, row: int):
        s_item = self._table.item(row, _C_STATUS)
        data   = s_item.data(Qt.ItemDataRole.UserRole)
        tid    = s_item.data(Qt.ItemDataRole.UserRole + 2)
        if not data or not tid: return
        s_item.setText("Queued")
        s_item.setForeground(QBrush(QColor("#E6E6E6")))
        s_item.setData(Qt.ItemDataRole.UserRole + 1, None)
        self._det_err.setPlainText("")
        self._det_out.setPlainText("")
        self._output_bufs[tid] = []   # clear previous run's output
        bar = self._progress_bars.get(tid)
        if bar:
            bar.setValue(0)
            bar.setFormat("Queued")
        worker = RsyncWorker(tid, data)
        worker.progress_update.connect(self._on_progress)
        worker.output_line.connect(self._on_output_line)
        worker.finished.connect(self._on_finished)
        self.active_workers[tid] = worker
        worker.start()

    def _delete_row(self, row: int):
        tid = self._table.item(row, _C_STATUS).data(Qt.ItemDataRole.UserRole + 2)
        if tid in self.active_workers: return
        self._progress_bars.pop(tid, None)
        self._output_bufs.pop(tid, None)
        self._table.removeRow(row)
        self._save_history()

    def _clear_finished(self):
        for r in range(self._table.rowCount() - 1, -1, -1):
            s = self._table.item(r, _C_STATUS)
            if s is None: continue
            txt = s.text()
            if txt in ("Completed", "Cancelled", "Interrupted") or \
               txt.startswith("Failed") or txt.startswith("Dry Run"):
                tid = s.data(Qt.ItemDataRole.UserRole + 2)
                self._progress_bars.pop(tid, None)
                self._output_bufs.pop(tid, None)
                self._table.removeRow(r)
        self._save_history()
