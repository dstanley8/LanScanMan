"""
The Schedules section of the File Transfers tab.

- SchedulesWidget: table of schedule lists with run / edit / pause controls
- build_add_to_list_menu: the "Add to schedule list…" submenu for the Queue

Dialogs live in ui/dialogs/schedule_dialogs.py; execution is
workers/scheduled_runner.py on top of core/schedule_runner.py.
"""

from __future__ import annotations

from datetime import datetime
from typing import Callable

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QCursor
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from lanscanman.core.notify import notify
from lanscanman.core.schedules import (
    DAY_LABELS,
    RunLogEntry,
    Schedule,
    ScheduleManager,
    Transfer,
)
from lanscanman.ui.dialogs.schedule_dialogs import (
    NewScheduleDialog,
    RunConfirmDialog,
    ScheduleRunDetailDialog,
)
from lanscanman.workers.scheduled_runner import ScheduledRunner

# ─────────────────────────────────────────────────────────────────────────────
# Schedules table widget
# ─────────────────────────────────────────────────────────────────────────────

# Column indices
_SC_NAME    = 0
_SC_TRIGGER = 1
_SC_LAST    = 2
_SC_NEXT    = 3
_SC_STATUS  = 4
_SC_ENABLED = 5


class SchedulesWidget(QWidget):
    """The Schedules section of the Transfer tab."""

    # Emitted whenever we've mutated the manager so the host can re-save.
    changed = pyqtSignal()

    def __init__(self, schedule_manager: ScheduleManager,
                 integrity_failed: bool = False, parent=None):
        super().__init__(parent)
        self._manager = schedule_manager
        self._integrity_failed = integrity_failed
        self._active_runners: dict[str, ScheduledRunner] = {}
        self._run_status: dict[str, list[dict]] = {}  # sid → per-transfer status
        self._paused = False
        self._setup_ui()
        self.refresh()

    # ── UI ──────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(6)

        # Integrity banner
        self._banner = QLabel(
            "⚠ The schedules file failed integrity verification and was not loaded. "
            "Scheduled transfers will not run until this is resolved. "
            "Delete ~/.config/LanScanMan/schedules.json and schedules.hmac "
            "to reset, or restore a trusted backup."
        )
        self._banner.setWordWrap(True)
        self._banner.setStyleSheet(
            "color: #E6E6E6; background: #402020; border: 1px solid #c0392b; "
            "border-radius: 4px; padding: 8px;")
        self._banner.setVisible(self._integrity_failed)
        root.addWidget(self._banner)

        # Controls
        bar = QHBoxLayout()
        self._new_btn = QPushButton("New Schedule List")
        self._new_btn.clicked.connect(self._open_new_dialog)
        bar.addWidget(self._new_btn)

        self._run_now_btn = QPushButton("Run Now")
        self._run_now_btn.clicked.connect(self._run_selected)
        self._run_now_btn.setEnabled(False)
        bar.addWidget(self._run_now_btn)

        self._edit_btn = QPushButton("Edit…")
        self._edit_btn.clicked.connect(self._edit_selected)
        self._edit_btn.setEnabled(False)
        bar.addWidget(self._edit_btn)

        self._delete_btn = QPushButton("Delete")
        self._delete_btn.clicked.connect(self._delete_selected)
        self._delete_btn.setEnabled(False)
        bar.addWidget(self._delete_btn)

        bar.addStretch()

        self._pause_btn = QPushButton("⏸  Pause All")
        self._pause_btn.setCheckable(True)
        self._pause_btn.setToolTip(
            "Pause all automatic schedule triggers.\n"
            "Schedules already running will finish; no new ones will start."
        )
        self._pause_btn.toggled.connect(self._on_pause_toggled)
        self._pause_btn.setEnabled(not self._integrity_failed)
        bar.addWidget(self._pause_btn)

        root.addLayout(bar)

        # Table
        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels(
            ["Name", "Trigger", "Last Run", "Next Run", "Status", "Enabled"])
        self._table.verticalHeader().setDefaultSectionSize(32)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.currentItemChanged.connect(self._on_selection_changed)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        self._table.doubleClicked.connect(self._on_double_click)

        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(_SC_NAME, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(_SC_TRIGGER, QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(_SC_LAST, QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(_SC_NEXT, QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(_SC_STATUS, QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(_SC_ENABLED, QHeaderView.ResizeMode.Fixed)
        hdr.resizeSection(_SC_TRIGGER, 200)
        hdr.resizeSection(_SC_LAST, 150)
        hdr.resizeSection(_SC_NEXT, 150)
        hdr.resizeSection(_SC_STATUS, 110)
        hdr.resizeSection(_SC_ENABLED, 80)
        root.addWidget(self._table)

        # Detail panel — list of transfers in the selected schedule
        self._detail = QFrame()
        self._detail.setFixedHeight(150)
        self._detail.setStyleSheet(
            "QFrame { background: #1B1F24; border-top: 1px solid #2A313B; }")
        dl = QVBoxLayout(self._detail)
        dl.setContentsMargins(10, 6, 10, 6)
        self._detail_title = QLabel("Select a schedule to see its transfers")
        self._detail_title.setStyleSheet("color: #9AA4AF; font-size: 11px;")
        dl.addWidget(self._detail_title)
        self._detail_text = QPlainTextEdit()
        self._detail_text.setReadOnly(True)
        self._detail_text.setStyleSheet(
            "QPlainTextEdit { color: #E6E6E6; font-size: 11px; "
            "font-family: monospace; background: transparent; border: none; "
            "border-left: 2px solid #3498db; padding-left: 6px; }")
        dl.addWidget(self._detail_text)
        root.addWidget(self._detail)

    # ── Refresh & display ───────────────────────────────────────────────────

    def refresh(self):
        self._table.setRowCount(0)
        now = datetime.now()
        for s in self._manager.schedules:
            self._add_row(s, now)
        self._on_selection_changed(None, None)

    def _add_row(self, s: Schedule, now: datetime):
        r = self._table.rowCount()
        self._table.insertRow(r)

        name_item = QTableWidgetItem(s.name)
        name_item.setData(Qt.ItemDataRole.UserRole, s.id)
        self._table.setItem(r, _SC_NAME, name_item)

        self._table.setItem(r, _SC_TRIGGER, QTableWidgetItem(self._trigger_summary(s)))

        last = s.last_run or "—"
        if last and last != "—":
            last = self._fmt_iso(last)
        self._table.setItem(r, _SC_LAST, QTableWidgetItem(last))

        nxt_dt = s.next_due(now)
        nxt_text = "—"
        if s.trigger.type == "manual":
            nxt_text = "Manual only"
        elif nxt_dt:
            nxt_text = nxt_dt.strftime("%a %d %b %H:%M")
        self._table.setItem(r, _SC_NEXT, QTableWidgetItem(nxt_text))

        status_item = QTableWidgetItem(s.last_status or "—")
        if s.last_status == "completed":
            status_item.setForeground(QBrush(QColor("#2ecc71")))
        elif s.last_status in ("partial", "aborted"):
            status_item.setForeground(QBrush(QColor("#f39c12")))
        elif s.last_status == "failed":
            status_item.setForeground(QBrush(QColor("#c0392b")))
        self._table.setItem(r, _SC_STATUS, status_item)

        cb = QCheckBox()
        cb.setChecked(s.enabled)
        cb.stateChanged.connect(lambda state, sid=s.id: self._on_enabled_toggled(sid, state))
        wrap = QWidget()
        hl = QHBoxLayout(wrap)
        hl.setContentsMargins(0, 0, 0, 0)
        hl.addWidget(cb)
        hl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._table.setCellWidget(r, _SC_ENABLED, wrap)

    @staticmethod
    def _trigger_summary(s: Schedule) -> str:
        t = s.trigger
        if t.type == "manual":
            return "Manual"
        if t.type == "interval":
            v = t.interval_value
            u = t.interval_unit
            return f"Every {v} {u}"
        if t.type == "scheduled":
            day_labels = {k: lbl for k, lbl in DAY_LABELS}
            days = ", ".join(day_labels.get(d, d) for d in t.days)
            return f"{days} at {t.time}"
        return t.type

    @staticmethod
    def _fmt_iso(iso: str) -> str:
        try:
            dt = datetime.fromisoformat(iso)
            return dt.strftime("%a %d %b %H:%M")
        except Exception:
            return iso

    def _current_schedule(self) -> Schedule | None:
        row = self._table.currentRow()
        if row < 0:
            return None
        name_item = self._table.item(row, _SC_NAME)
        if not name_item:
            return None
        sid = name_item.data(Qt.ItemDataRole.UserRole)
        return self._manager.find(sid) if sid else None

    def _on_selection_changed(self, _cur, _prev):
        s = self._current_schedule()
        has_sel = s is not None
        self._run_now_btn.setEnabled(has_sel and not self._integrity_failed)
        self._edit_btn.setEnabled(has_sel)
        self._delete_btn.setEnabled(has_sel)
        if not s:
            self._detail_title.setText("Select a schedule to see its transfers")
            self._detail_text.setPlainText("")
            return
        self._detail_title.setText(
            f"{s.name} — {len(s.transfers)} transfer(s)")
        lines = []
        for i, t in enumerate(s.transfers, 1):
            lines.append(f"{i}. {t.full_source}")
            lines.append(f"   → {t.full_dest}")
        self._detail_text.setPlainText("\n".join(lines) or "(empty list)")

    # ── Actions ─────────────────────────────────────────────────────────────

    def _on_pause_toggled(self, paused: bool):
        self._paused = paused
        self._pause_btn.setText("▶  Resume All" if paused else "⏸  Pause All")
        self._pause_btn.setStyleSheet(
            "QPushButton { color: #f39c12; border-color: #f39c12; }" if paused else ""
        )

    def is_paused(self) -> bool:
        return self._paused

    def _open_new_dialog(self):
        dlg = NewScheduleDialog(parent=self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        s = dlg.get_schedule()
        self._manager.schedules.append(s)
        self.changed.emit()
        self.refresh()

    def _edit_selected(self):
        s = self._current_schedule()
        if not s:
            return
        dlg = NewScheduleDialog(schedule=s, parent=self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        updated = dlg.get_schedule()
        # Replace in place preserving id
        updated.id = s.id
        updated.last_run = s.last_run
        updated.last_status = s.last_status
        updated.run_log = s.run_log
        for i, existing in enumerate(self._manager.schedules):
            if existing.id == s.id:
                self._manager.schedules[i] = updated
                break
        self.changed.emit()
        self.refresh()

    def _delete_selected(self):
        s = self._current_schedule()
        if not s:
            return
        resp = QMessageBox.question(
            self, "Delete schedule",
            f"Delete the schedule list '{s.name}'? This cannot be undone.",
        )
        if resp != QMessageBox.StandardButton.Yes:
            return
        self._manager.schedules = [x for x in self._manager.schedules if x.id != s.id]
        self.changed.emit()
        self.refresh()

    def _on_enabled_toggled(self, sid: str, state: int):
        s = self._manager.find(sid)
        if not s:
            return
        s.enabled = bool(state)
        self.changed.emit()

    def _run_selected(self):
        s = self._current_schedule()
        if not s:
            return
        self.run_schedule(s, skip_confirm_dialog=False)

    # ── External API (called from host / timer) ────────────────────────────

    def run_schedule(self, s: Schedule, skip_confirm_dialog: bool = False,
                     triggered_by_timer: bool = False):
        """Start a ScheduledRunner for this schedule, asking first if configured.

        triggered_by_timer: if True, the call came from the automatic timer or
        missed-run handler — it will be silently blocked when paused.  Manual
        'Run Now' clicks pass False and always proceed.
        """
        if self._integrity_failed:
            return
        if triggered_by_timer and self._paused:
            return
        if s.id in self._active_runners:
            return
        if not s.transfers:
            QMessageBox.information(
                self, "Empty list",
                f"'{s.name}' has no transfers. Add some before running.")
            return
        if s.confirm_before_run and not skip_confirm_dialog:
            dlg = RunConfirmDialog(s, self)
            if dlg.exec() != QDialog.DialogCode.Accepted:
                # User skipped — advance last_run so timer doesn't re-ask
                # immediately on the next minute tick
                s.skip()
                self.changed.emit()
                self.refresh()
                return

        runner = ScheduledRunner(s)
        runner.transfer_started.connect(self._on_transfer_started)
        runner.transfer_finished.connect(self._on_transfer_finished)
        runner.list_finished.connect(self._on_list_finished)
        self._active_runners[s.id] = runner
        # Initialise per-transfer status tracking for this run
        self._run_status[s.id] = [
            {"source": t.full_source, "dest": t.full_dest,
             "status": "Not started", "bytes": 0}
            for t in s.transfers
        ]
        self._set_status_text(s.id, "Running…", color="#3498db")
        runner.start()

    def _set_status_text(self, sid: str, text: str, color: str | None = None):
        for r in range(self._table.rowCount()):
            item = self._table.item(r, _SC_NAME)
            if item and item.data(Qt.ItemDataRole.UserRole) == sid:
                st = self._table.item(r, _SC_STATUS)
                if st:
                    st.setText(text)
                    if color:
                        st.setForeground(QBrush(QColor(color)))
                return

    def _on_list_finished(self, sid: str, overall: str, entry_dict: dict):
        s = self._manager.find(sid)
        runner = self._active_runners.pop(sid, None)
        if runner:
            runner.wait(2000)
        if not s:
            return
        entry = RunLogEntry(
            started=entry_dict.get("started", ""),
            finished=entry_dict.get("finished", ""),
            status=entry_dict.get("status", overall),
            transfers=list(entry_dict.get("transfers") or []),
        )
        s.add_run(entry)
        # Update _run_status from the completed run log so detail dialog
        # reflects final states
        if sid in self._run_status:
            for i, t_result in enumerate(entry_dict.get("transfers") or []):
                if i < len(self._run_status[sid]):
                    self._run_status[sid][i]["status"] = t_result.get("status", "—")
                    self._run_status[sid][i]["bytes"] = t_result.get("bytes", 0)
        self.changed.emit()
        self.refresh()
        notify(f"Schedule finished: {s.name}", f"Status: {overall}")

    def _on_transfer_started(self, sid: str, idx: int, source: str, dest: str):
        """Update per-transfer status to Running when a transfer begins."""
        statuses = self._run_status.get(sid)
        if statuses and 0 <= idx < len(statuses):
            statuses[idx]["status"] = "Running…"

    def _on_transfer_finished(self, sid: str, idx: int, status: str, total_bytes: int):
        """Update per-transfer status when a transfer completes."""
        statuses = self._run_status.get(sid)
        if statuses and 0 <= idx < len(statuses):
            statuses[idx]["status"] = status
            statuses[idx]["bytes"] = total_bytes

    def _on_double_click(self, _index):
        """Open the run detail dialog for the double-clicked schedule."""
        s = self._current_schedule()
        if not s:
            return
        statuses = self._run_status.get(s.id)
        def _after_change():
            self._on_schedules_changed_local()
        dlg = ScheduleRunDetailDialog(s, statuses, on_changed=_after_change, parent=self)
        dlg.exec()

    def _on_schedules_changed_local(self):
        """Called when the detail dialog mutates the schedule (e.g. removes a transfer)."""
        self.changed.emit()
        self.refresh()

    # ── Context menu ────────────────────────────────────────────────────────

    def _show_context_menu(self, pos):
        s = self._current_schedule()
        if not s:
            return
        menu = QMenu(self)
        run_act = menu.addAction("Run Now")
        run_act.setEnabled(not self._integrity_failed and s.id not in self._active_runners)
        run_act.triggered.connect(lambda: self.run_schedule(s))
        menu.addSeparator()
        edit_act = menu.addAction("Edit…")
        edit_act.triggered.connect(self._edit_selected)
        del_act = menu.addAction("Delete")
        del_act.triggered.connect(self._delete_selected)
        menu.exec(QCursor.pos())


# ─────────────────────────────────────────────────────────────────────────────
# Add-to-list menu builder (called from transfer_tab.py right-click handler)
# ─────────────────────────────────────────────────────────────────────────────

def build_add_to_list_menu(
    parent: QWidget,
    manager: ScheduleManager,
    transfer_data: dict,
    on_changed: Callable[[], None],
) -> QMenu:
    """
    Build the 'Add to schedule list…' submenu used by the Queue's right-click
    context menu. Lists existing schedules plus a 'Create new list…' entry.

    transfer_data is the dict shape returned by AddTransferDialog.get_transfer_data.
    on_changed is called after a successful add/create so the host can re-save
    the manager.
    """
    menu = QMenu("Add to schedule list…", parent)

    def _transfer_from_data() -> Transfer:
        return Transfer(
            full_source=transfer_data.get("full_source", ""),
            full_dest=transfer_data.get("full_dest", ""),
            args=list(transfer_data.get("args") or []),
            sender_ip=transfer_data.get("sender_ip", ""),
            sender_user=transfer_data.get("sender_user", ""),
            receiver_ip=transfer_data.get("receiver_ip", ""),
            src_path=transfer_data.get("src_path", ""),
            dst_path=transfer_data.get("dst_path", ""),
        )

    def _validate_transfer(t: Transfer) -> bool:
        ok, reason = t.validate()
        if not ok:
            QMessageBox.warning(
                parent, "Cannot add to schedule",
                f"This transfer cannot be scheduled: {reason}",
            )
            return False
        return True

    # Create new list
    new_act = menu.addAction("Create new list…")
    def _do_new():
        t = _transfer_from_data()
        if not _validate_transfer(t):
            return
        dlg = NewScheduleDialog(initial_transfer=t, parent=parent)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            manager.schedules.append(dlg.get_schedule())
            on_changed()
    new_act.triggered.connect(_do_new)

    if manager.schedules:
        menu.addSeparator()
        for s in manager.schedules:
            act = menu.addAction(s.name)
            def _do_add(checked=False, sid=s.id):
                sched = manager.find(sid)
                if not sched:
                    return
                t = _transfer_from_data()
                if not _validate_transfer(t):
                    return
                sched.transfers.append(t)
                on_changed()
                QMessageBox.information(
                    parent, "Added",
                    f"Transfer added to '{sched.name}'.",
                )
            act.triggered.connect(_do_add)

    return menu


# ─────────────────────────────────────────────────────────────────────────────
# Schedule run detail dialog — double-click on a schedule list to open
# ─────────────────────────────────────────────────────────────────────────────


# Detail table column indices
