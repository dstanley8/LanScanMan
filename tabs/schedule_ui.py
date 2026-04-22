"""
tabs/schedule_ui.py — UI and execution for scheduled rsync lists.

Provides:
- NewScheduleDialog: create or edit a schedule list
- SchedulesWidget: the Schedules section of the Transfer tab
- ScheduledRunner: QThread that executes a schedule's transfers sequentially
- AddToListMenu helper: builds the right-click submenu for the Queue table

Kept separate from transfer_tab.py to keep that file focused on ad-hoc
transfers and the existing queue.
"""

from __future__ import annotations

import copy
import subprocess
from datetime import datetime
from typing import Callable

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QCursor
from PyQt6.QtWidgets import (
    QButtonGroup, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFrame,
    QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMenu,
    QMessageBox, QPlainTextEdit, QPushButton, QRadioButton, QSpinBox,
    QTableWidget, QTableWidgetItem, QTimeEdit, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)
from PyQt6.QtCore import QTime

from log import log
from schedule_manager import (
    Schedule, Transfer, Trigger, ScheduleManager, RunLogEntry,
    validate_path, validate_args,
)


_DAYS = [
    ("monday", "Mon"),
    ("tuesday", "Tue"),
    ("wednesday", "Wed"),
    ("thursday", "Thu"),
    ("friday", "Fri"),
    ("saturday", "Sat"),
    ("sunday", "Sun"),
]


def _notify(title: str, body: str):
    try:
        subprocess.Popen(
            ["notify-send", "-a", "LanScanMan", title, body],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# New / edit schedule dialog
# ─────────────────────────────────────────────────────────────────────────────

class NewScheduleDialog(QDialog):
    """Create or edit a scheduled rsync list."""

    def __init__(self, schedule: Schedule | None = None,
                 initial_transfer: Transfer | None = None,
                 parent=None):
        super().__init__(parent)
        self.setWindowTitle("Schedule List" if schedule else "New Schedule List")
        self.resize(640, 560)
        # Work on a copy; only commit when OK pressed
        self._schedule = copy.deepcopy(schedule) if schedule else Schedule()
        if initial_transfer and not schedule:
            self._schedule.transfers.append(initial_transfer)
        self._setup_ui()
        self._populate_from_schedule()

    # ── UI ──────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(8)

        # Name
        name_row = QHBoxLayout()
        name_row.addWidget(QLabel("Name:"))
        self._name = QLineEdit()
        self._name.setPlaceholderText("e.g. Weekly media backup")
        name_row.addWidget(self._name)
        root.addLayout(name_row)

        # Trigger group
        trig_grp = QGroupBox("When to run")
        tg = QVBoxLayout(trig_grp)

        self._rb_manual = QRadioButton("Manual only — I'll press a button")
        self._rb_interval = QRadioButton("Repeat every:")
        self._rb_scheduled = QRadioButton("On specific days at a set time")
        self._rb_group = QButtonGroup(self)
        for i, rb in enumerate((self._rb_manual, self._rb_interval, self._rb_scheduled)):
            self._rb_group.addButton(rb, i)
            tg.addWidget(rb)

        # Interval value + unit
        int_row = QHBoxLayout()
        int_row.addSpacing(20)
        int_row.addWidget(QLabel("Every"))
        self._interval_value = QSpinBox()
        self._interval_value.setRange(1, 9999)
        self._interval_value.setValue(24)
        int_row.addWidget(self._interval_value)
        self._interval_unit = QComboBox()
        for key, label in [("minutes", "minutes"), ("hours", "hours"),
                            ("days", "days"), ("months", "months")]:
            self._interval_unit.addItem(label, key)
        self._interval_unit.setCurrentIndex(1)  # default hours
        int_row.addWidget(self._interval_unit)
        int_row.addStretch()
        tg.addLayout(int_row)

        # Scheduled days + time
        sch_row = QHBoxLayout()
        sch_row.addSpacing(20)
        self._day_checks: dict[str, QCheckBox] = {}
        for key, label in _DAYS:
            cb = QCheckBox(label)
            self._day_checks[key] = cb
            sch_row.addWidget(cb)
        tg.addLayout(sch_row)

        time_row = QHBoxLayout()
        time_row.addSpacing(20)
        time_row.addWidget(QLabel("at"))
        self._time_edit = QTimeEdit()
        self._time_edit.setDisplayFormat("HH:mm")
        self._time_edit.setTime(QTime(2, 0))
        time_row.addWidget(self._time_edit)
        time_row.addStretch()
        tg.addLayout(time_row)

        root.addWidget(trig_grp)

        # Behaviour group
        beh_grp = QGroupBox("Behaviour")
        bg = QVBoxLayout(beh_grp)

        self._cb_confirm = QCheckBox(
            "Ask before running — pop up a dialog showing what will run")
        bg.addWidget(self._cb_confirm)

        missed_row = QHBoxLayout()
        missed_row.addWidget(QLabel("If the scheduled time was missed:"))
        self._missed = QComboBox()
        self._missed.addItem("Warn me before running", "warn")
        self._missed.addItem("Run without asking", "run")
        self._missed.addItem("Skip to next scheduled time", "skip")
        missed_row.addWidget(self._missed)
        missed_row.addStretch()
        bg.addLayout(missed_row)

        fail_row = QHBoxLayout()
        fail_row.addWidget(QLabel("If a transfer in the list fails:"))
        self._fail = QComboBox()
        self._fail.addItem("Continue with the next transfer", "continue")
        self._fail.addItem("Abort the whole list", "abort")
        fail_row.addWidget(self._fail)
        fail_row.addStretch()
        bg.addLayout(fail_row)

        root.addWidget(beh_grp)

        # Transfers
        tr_grp = QGroupBox("Transfers in this list")
        trl = QVBoxLayout(tr_grp)
        self._transfers_tree = QTreeWidget()
        self._transfers_tree.setHeaderLabels(["Source", "Destination"])
        self._transfers_tree.setRootIsDecorated(False)
        self._transfers_tree.setAlternatingRowColors(True)
        trl.addWidget(self._transfers_tree)

        btn_row = QHBoxLayout()
        self._remove_btn = QPushButton("Remove selected")
        self._remove_btn.clicked.connect(self._remove_selected)
        btn_row.addWidget(self._remove_btn)
        btn_row.addStretch()
        self._hint = QLabel(
            "Tip: add transfers by right-clicking a transfer in the Queue.")
        self._hint.setStyleSheet("color: #9AA4AF; font-size: 11px;")
        btn_row.addWidget(self._hint)
        trl.addLayout(btn_row)
        root.addWidget(tr_grp)

        # OK / Cancel — route OK through _validate
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self._validate_and_accept)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)

        # Initial enable state
        self._rb_group.buttonClicked.connect(lambda _: self._update_enablement())

    def _populate_from_schedule(self):
        s = self._schedule
        self._name.setText(s.name if s.name != "Untitled" else "")

        # Trigger
        t = s.trigger
        if t.type == "interval":
            self._rb_interval.setChecked(True)
            self._interval_value.setValue(t.interval_value)
            idx = self._interval_unit.findData(t.interval_unit)
            if idx >= 0:
                self._interval_unit.setCurrentIndex(idx)
        elif t.type == "scheduled":
            self._rb_scheduled.setChecked(True)
            for d in t.days:
                cb = self._day_checks.get(d)
                if cb:
                    cb.setChecked(True)
            try:
                hh, mm = map(int, t.time.split(":"))
                self._time_edit.setTime(QTime(hh, mm))
            except Exception:
                pass
        else:
            self._rb_manual.setChecked(True)

        self._cb_confirm.setChecked(s.confirm_before_run)

        idx = self._missed.findData(s.missed_run)
        if idx >= 0:
            self._missed.setCurrentIndex(idx)
        idx = self._fail.findData(s.on_transfer_failure)
        if idx >= 0:
            self._fail.setCurrentIndex(idx)

        self._refresh_transfers()
        self._update_enablement()

    def _refresh_transfers(self):
        self._transfers_tree.clear()
        for t in self._schedule.transfers:
            item = QTreeWidgetItem([t.full_source or "—", t.full_dest or "—"])
            self._transfers_tree.addTopLevelItem(item)

    def _update_enablement(self):
        is_interval = self._rb_interval.isChecked()
        is_scheduled = self._rb_scheduled.isChecked()
        self._interval_value.setEnabled(is_interval)
        self._interval_unit.setEnabled(is_interval)
        for cb in self._day_checks.values():
            cb.setEnabled(is_scheduled)
        self._time_edit.setEnabled(is_scheduled)

    # ── Actions ─────────────────────────────────────────────────────────────

    def _remove_selected(self):
        idxs = sorted(
            (self._transfers_tree.indexOfTopLevelItem(i)
             for i in self._transfers_tree.selectedItems()),
            reverse=True,
        )
        for i in idxs:
            if 0 <= i < len(self._schedule.transfers):
                del self._schedule.transfers[i]
        self._refresh_transfers()

    def _validate_and_accept(self):
        # Pull values into self._schedule, validate, accept on success
        name = self._name.text().strip()
        if not name:
            QMessageBox.warning(self, "Missing name", "Please give this schedule a name.")
            return
        self._schedule.name = name

        if self._rb_manual.isChecked():
            self._schedule.trigger = Trigger(type="manual")
        elif self._rb_interval.isChecked():
            self._schedule.trigger = Trigger(
                type="interval",
                interval_value=int(self._interval_value.value()),
                interval_unit=self._interval_unit.currentData() or "hours",
            )
        else:
            days = [k for k, cb in self._day_checks.items() if cb.isChecked()]
            if not days:
                QMessageBox.warning(
                    self, "No days selected",
                    "Please select at least one day for the schedule.")
                return
            t = self._time_edit.time()
            self._schedule.trigger = Trigger(
                type="scheduled", days=days,
                time=f"{t.hour():02d}:{t.minute():02d}",
            )

        self._schedule.confirm_before_run = self._cb_confirm.isChecked()
        self._schedule.missed_run = self._missed.currentData() or "warn"
        self._schedule.on_transfer_failure = self._fail.currentData() or "continue"

        ok, reason = self._schedule.validate()
        if not ok:
            QMessageBox.warning(self, "Invalid schedule", reason)
            return

        self.accept()

    def get_schedule(self) -> Schedule:
        return self._schedule


# ─────────────────────────────────────────────────────────────────────────────
# Run confirmation dialog
# ─────────────────────────────────────────────────────────────────────────────

class RunConfirmDialog(QDialog):
    """Shown before a schedule runs when confirm_before_run is True."""

    def __init__(self, schedule: Schedule, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Run '{schedule.name}'?")
        self.resize(520, 380)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(f"<b>{schedule.name}</b> is about to run."))
        lay.addWidget(QLabel(f"{len(schedule.transfers)} transfer(s) will be performed:"))

        lst = QPlainTextEdit()
        lst.setReadOnly(True)
        lst.setStyleSheet("font-family: monospace; font-size: 11px;")
        lines = []
        for i, t in enumerate(schedule.transfers, 1):
            lines.append(f"{i}. {t.full_source}")
            lines.append(f"   → {t.full_dest}")
            lines.append("")
        lst.setPlainText("\n".join(lines))
        lay.addWidget(lst)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.button(QDialogButtonBox.StandardButton.Ok).setText("Run Now")
        btns.button(QDialogButtonBox.StandardButton.Cancel).setText("Skip")
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)


# ─────────────────────────────────────────────────────────────────────────────
# Scheduled runner — executes transfers sequentially in a thread
# ─────────────────────────────────────────────────────────────────────────────

class ScheduledRunner(QThread):
    """
    Runs a Schedule's transfers sequentially using rsync.

    Signals:
        transfer_started(schedule_id, transfer_index, source, dest)
        transfer_finished(schedule_id, transfer_index, status, bytes)
        list_finished(schedule_id, overall_status, run_log_entry_dict)
    """
    transfer_started  = pyqtSignal(str, int, str, str)
    transfer_finished = pyqtSignal(str, int, str, int)
    list_finished     = pyqtSignal(str, str, dict)

    # Reuse the existing RsyncWorker logic. To avoid a circular import we
    # import at run() time.
    def __init__(self, schedule: Schedule, parent=None):
        super().__init__(parent)
        self._schedule = copy.deepcopy(schedule)
        self._stop_requested = False

    def stop(self):
        self._stop_requested = True

    def run(self):
        # Late import to break circular dependency
        from tabs.transfer_tab import RsyncWorker

        sched = self._schedule
        started = datetime.now().isoformat(timespec="seconds")
        transfer_results: list[dict] = []
        overall = "completed"

        for idx, t in enumerate(sched.transfers):
            if self._stop_requested:
                overall = "aborted"
                break

            # Revalidate path on each transfer as a last-line defence
            ok, reason = t.validate()
            if not ok:
                log.error(
                    f"schedule {sched.name!r} transfer {idx} rejected: {reason}")
                transfer_results.append({
                    "source": t.full_source,
                    "dest": t.full_dest,
                    "status": "rejected",
                    "bytes": 0,
                    "reason": reason,
                })
                if sched.on_transfer_failure == "abort":
                    overall = "aborted"
                    break
                overall = "partial"
                continue

            self.transfer_started.emit(
                sched.id, idx, t.full_source, t.full_dest)

            # Build the data dict that RsyncWorker expects. Transfer dataclass
            # already mirrors that shape.
            data = {
                "full_source": t.full_source,
                "full_dest": t.full_dest,
                "args": list(t.args),
                "sender_ip": t.sender_ip,
                "sender_user": t.sender_user,
                "receiver_ip": t.receiver_ip,
                "src_path": t.src_path,
                "dst_path": t.dst_path,
            }

            # Run synchronously in this thread
            worker = RsyncWorker(tid=0, data=data)
            status_holder = {"status": "running", "bytes": 0, "error": ""}

            def _on_finished(_tid, final_status, error, total_bytes):
                status_holder["status"] = final_status
                status_holder["bytes"] = total_bytes
                status_holder["error"] = error

            worker.finished.connect(_on_finished)
            # We run the worker's run() directly (not .start()) since we're
            # already in a thread and want synchronous execution.
            try:
                worker.run()
            except Exception as e:
                log.exception(f"scheduled rsync failed: {e}")
                status_holder["status"] = "Failed"
                status_holder["error"] = str(e)

            final_status = status_holder["status"]
            total_bytes = status_holder["bytes"]

            transfer_results.append({
                "source": t.full_source,
                "dest": t.full_dest,
                "status": final_status,
                "bytes": total_bytes,
            })
            self.transfer_finished.emit(
                sched.id, idx, final_status, total_bytes)

            failed = (final_status.startswith("Failed")
                      or final_status in ("Cancelled", "Interrupted"))
            if failed:
                if sched.on_transfer_failure == "abort":
                    overall = "aborted"
                    break
                overall = "partial"

            if self._stop_requested:
                overall = "aborted"
                break

        finished = datetime.now().isoformat(timespec="seconds")
        entry = RunLogEntry(
            started=started,
            finished=finished,
            status=overall,
            transfers=transfer_results,
        )
        # Emit as dict so the receiver (main thread) can append it to the
        # persisted schedule without touching dataclasses cross-thread.
        self.list_finished.emit(sched.id, overall, {
            "started": entry.started,
            "finished": entry.finished,
            "status": entry.status,
            "transfers": entry.transfers,
        })


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
            day_labels = {k: lbl for k, lbl in _DAYS}
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
        _notify(f"Schedule finished: {s.name}", f"Status: {overall}")

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

def _fmt_bytes(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


# Detail table column indices
_DC_NUM    = 0
_DC_SOURCE = 1
_DC_DEST   = 2
_DC_STATUS = 3
_DC_BYTES  = 4


class ScheduleRunDetailDialog(QDialog):
    """
    Shows all transfers in a schedule list with their current run status.
    Mirrors the Queue table style. Right-click a row to remove the transfer
    from the schedule list. Detail panel shows full paths on row selection.
    """

    _STATUS_COLOURS = {
        "Not started": "#9AA4AF",
        "Running…":    "#3498db",
        "Completed":   "#2ecc71",
        "completed":   "#2ecc71",
        "partial":     "#f39c12",
        "aborted":     "#f39c12",
        "rejected":    "#f39c12",
    }

    def __init__(self, schedule: Schedule,
                 run_status: list[dict] | None,
                 on_changed: Callable | None = None,
                 parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Run detail — {schedule.name}")
        self.resize(820, 500)
        self._schedule = schedule
        self._run_status = run_status or []
        self._on_changed = on_changed
        self._setup_ui()
        self._populate()

    def _setup_ui(self):
        lay = QVBoxLayout(self)
        lay.setSpacing(6)

        s = self._schedule
        self._header = QLabel()
        self._header.setStyleSheet("color: #9AA4AF; font-size: 11px; padding: 4px 0;")
        lay.addWidget(self._header)
        self._refresh_header()

        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(
            ["#", "Source", "Destination", "Status", "Transferred"])
        self._table.verticalHeader().setDefaultSectionSize(36)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.currentItemChanged.connect(self._on_row_changed)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)

        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(_DC_NUM,    QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(_DC_SOURCE, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(_DC_DEST,   QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(_DC_STATUS, QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(_DC_BYTES,  QHeaderView.ResizeMode.Fixed)
        hdr.resizeSection(_DC_NUM,    40)
        hdr.resizeSection(_DC_STATUS, 120)
        hdr.resizeSection(_DC_BYTES,  110)
        lay.addWidget(self._table)

        detail = QFrame()
        detail.setFixedHeight(80)
        detail.setStyleSheet(
            "QFrame { background: #1B1F24; border-top: 1px solid #2A313B; }")
        dl = QVBoxLayout(detail)
        dl.setContentsMargins(10, 6, 10, 6)
        self._det_src = QLabel("—")
        self._det_dst = QLabel("—")
        for lbl in (self._det_src, self._det_dst):
            lbl.setStyleSheet("color: #9AA4AF; font-size: 11px;")
            lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        dl.addWidget(self._det_src)
        dl.addWidget(self._det_dst)
        lay.addWidget(detail)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    def _refresh_header(self):
        s = self._schedule
        self._header.setText(
            f"<b>{s.name}</b> &nbsp;·&nbsp; "
            f"{len(s.transfers)} transfer(s) &nbsp;·&nbsp; "
            f"Trigger: {self._trigger_text(s)}"
        )

    def _populate(self):
        self._table.setRowCount(0)
        for i, t in enumerate(self._schedule.transfers):
            status_info = self._run_status[i] if i < len(self._run_status) else None
            status = status_info["status"] if status_info else "Not started"
            total_bytes = status_info.get("bytes", 0) if status_info else 0

            r = self._table.rowCount()
            self._table.insertRow(r)

            num_item = QTableWidgetItem(str(i + 1))
            num_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            # Store original transfer index so removal works after table changes
            num_item.setData(Qt.ItemDataRole.UserRole, i)
            self._table.setItem(r, _DC_NUM, num_item)

            src_item = QTableWidgetItem(t.full_source or t.src_path or "—")
            src_item.setData(Qt.ItemDataRole.UserRole, (t.full_source, t.full_dest))
            self._table.setItem(r, _DC_SOURCE, src_item)

            self._table.setItem(r, _DC_DEST, QTableWidgetItem(
                t.full_dest or t.dst_path or "—"))

            status_item = QTableWidgetItem(status)
            colour = self._STATUS_COLOURS.get(status)
            if not colour:
                if (status.startswith("Failed")
                        or status in ("Cancelled", "Interrupted", "rejected")):
                    colour = "#c0392b"
                else:
                    colour = "#E6E6E6"
            status_item.setForeground(QBrush(QColor(colour)))
            self._table.setItem(r, _DC_STATUS, status_item)

            bytes_text = _fmt_bytes(total_bytes) if total_bytes else "—"
            bytes_item = QTableWidgetItem(bytes_text)
            bytes_item.setTextAlignment(
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self._table.setItem(r, _DC_BYTES, bytes_item)

    def _show_context_menu(self, pos):
        item = self._table.itemAt(pos)
        if not item:
            return
        row = item.row()
        num_item = self._table.item(row, _DC_NUM)
        if not num_item:
            return
        transfer_idx = num_item.data(Qt.ItemDataRole.UserRole)

        menu = QMenu(self)
        remove_act = menu.addAction("Remove from list")
        remove_act.triggered.connect(lambda: self._remove_transfer(row, transfer_idx))
        menu.exec(QCursor.pos())

    def _remove_transfer(self, row: int, transfer_idx: int):
        t = self._schedule.transfers
        if not (0 <= transfer_idx < len(t)):
            return
        src = t[transfer_idx].full_source or t[transfer_idx].src_path or "?"
        resp = QMessageBox.question(
            self, "Remove transfer",
            f"Remove this transfer from the schedule list?\n\n{src}",
        )
        if resp != QMessageBox.StandardButton.Yes:
            return
        del t[transfer_idx]
        # Trim _run_status to match — if the run hasn't started yet for
        # this index it doesn't matter, but keep them aligned
        if transfer_idx < len(self._run_status):
            del self._run_status[transfer_idx]
        self._refresh_header()
        self._populate()
        self._det_src.setText("—")
        self._det_dst.setText("—")
        if self._on_changed:
            self._on_changed()

    def _on_row_changed(self, current, _prev):
        if current is None:
            self._det_src.setText("—")
            self._det_dst.setText("—")
            return
        src_item = self._table.item(current.row(), _DC_SOURCE)
        if src_item:
            pair = src_item.data(Qt.ItemDataRole.UserRole)
            if pair:
                self._det_src.setText(f"Source:      {pair[0]}")
                self._det_dst.setText(f"Destination: {pair[1]}")

    @staticmethod
    def _trigger_text(s: Schedule) -> str:
        t = s.trigger
        if t.type == "manual":
            return "Manual"
        if t.type == "interval":
            return f"Every {t.interval_value} {t.interval_unit}"
        if t.type == "scheduled":
            day_labels = {k: lbl for k, lbl in _DAYS}
            days = ", ".join(day_labels.get(d, d) for d in t.days)
            return f"{days} at {t.time}"
        return t.type