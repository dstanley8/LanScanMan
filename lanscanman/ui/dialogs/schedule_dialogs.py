"""Dialogs for scheduled transfer lists: create/edit, confirm-before-run, run history."""

import copy
from typing import Callable

from PyQt6.QtCore import Qt, QTime
from PyQt6.QtGui import QBrush, QColor, QCursor
from PyQt6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTimeEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from lanscanman.core.formatting import fmt_bytes
from lanscanman.core.schedules import DAY_LABELS, Schedule, Transfer, Trigger


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
        for key, label in DAY_LABELS:
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

            bytes_text = fmt_bytes(total_bytes) if total_bytes else "—"
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
            day_labels = {k: lbl for k, lbl in DAY_LABELS}
            days = ", ".join(day_labels.get(d, d) for d in t.days)
            return f"{days} at {t.time}"
        return t.type
