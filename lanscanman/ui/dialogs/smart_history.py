"""
tabs/smart_log.py
─────────────────
SMART attribute logging and history visualisation.

Storage: ~/.config/LanScanMan/smart_log/<profile_key>.json
One file per host. One entry per disk per "state change" using a
first-seen / last-seen deduplication strategy:

  - Only the attributes that indicate permanent degradation are tracked:
    reallocated, pending, uncorrectable, wear_pct_used, tbw_tb.
    power_on_hours is recorded for context but does NOT trigger new entries.
  - Temperature is intentionally excluded — it is session-only UI data.
  - When a new probe result matches the last committed attribute set,
    the "last_seen" timestamp of the current entry is updated in-place.
  - When attributes change, the current entry is finalised and a new one
    starts. This means any stable period is represented by exactly two
    timestamps: first_seen and last_seen.

Alert: if degradation attributes worsen (increase), a notify-send
desktop notification is fired immediately.
"""

from __future__ import annotations

from datetime import datetime

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from lanscanman.core.smart_history import SmartLogger

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────


# Attributes that trigger a new log entry when they change

# Attributes stored in each entry (context only — do not trigger new entries)


# ─────────────────────────────────────────────────────────────────────────────
# History chart widget  (custom QPainter — no matplotlib dependency)
# ─────────────────────────────────────────────────────────────────────────────

class _ChartWidget(QWidget):
    """
    A dark-themed line chart drawn with QPainter.

    Data points are (datetime, float). The X axis is time, Y axis is value.
    Each distinct state period is shown as a horizontal segment with dots
    at first_seen and last_seen.
    """

    MARGIN_L = 58
    MARGIN_R = 20
    MARGIN_T = 20
    MARGIN_B = 40

    def __init__(self, parent=None):
        super().__init__(parent)
        self._points: list[tuple[datetime, datetime, float | None]] = []
        self._label  = ""
        self._unit   = ""
        self.setMinimumHeight(200)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setStyleSheet("background: #0d1117; border-radius: 6px;")

    def set_data(self, points: list[tuple[datetime, datetime, float | None]],
                 label: str, unit: str = ""):
        """points = list of (first_seen_dt, last_seen_dt, value)"""
        self._points = points
        self._label  = label
        self._unit   = unit
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        ml, mr, mt, mb = self.MARGIN_L, self.MARGIN_R, self.MARGIN_T, self.MARGIN_B
        plot_w = w - ml - mr
        plot_h = h - mt - mb

        bg = QColor("#0d1117")
        p.fillRect(0, 0, w, h, bg)

        if not self._points:
            p.setPen(QColor("#9AA4AF"))
            p.drawText(0, 0, w, h, Qt.AlignmentFlag.AlignCenter, "No history recorded yet")
            return

        # ── Data ranges ───────────────────────────────────────────────────────
        all_vals  = [v for _, _, v in self._points if v is not None]
        all_times = [t for fs, ls, _ in self._points for t in (fs, ls)]

        if not all_vals or not all_times:
            p.setPen(QColor("#9AA4AF"))
            p.drawText(0, 0, w, h, Qt.AlignmentFlag.AlignCenter, "No data to display")
            return

        t_min  = min(all_times)
        t_max  = max(all_times)
        v_min  = min(all_vals)
        v_max  = max(all_vals)
        t_span = max((t_max - t_min).total_seconds(), 1)
        v_span = max(v_max - v_min, 1)

        # When all recorded values are identical (a perfectly stable attribute),
        # the Y axis would show the same number five times which looks broken.
        # Expand the axis slightly around the constant value so the label
        # variation is visible and the flat line sits in the middle.
        flat_line = (v_max == v_min)
        if flat_line:
            centre = v_min
            v_min  = centre - 1
            v_max  = centre + 1
            v_span = 2

        def tx(dt: datetime) -> float:
            return ml + (dt - t_min).total_seconds() / t_span * plot_w

        def ty(val: float) -> float:
            return mt + plot_h - (val - v_min) / v_span * plot_h

        # ── Grid lines ────────────────────────────────────────────────────────
        grid_pen = QPen(QColor("#1A2030"))
        grid_pen.setWidth(1)
        p.setPen(grid_pen)
        for i in range(5):
            y = mt + i * plot_h // 4
            p.drawLine(ml, y, ml + plot_w, y)

        # ── Axes ──────────────────────────────────────────────────────────────
        axis_pen = QPen(QColor("#2A313B"))
        axis_pen.setWidth(1)
        p.setPen(axis_pen)
        p.drawLine(ml, mt, ml, mt + plot_h)
        p.drawLine(ml, mt + plot_h, ml + plot_w, mt + plot_h)

        # ── Y axis labels ─────────────────────────────────────────────────────
        lbl_font = QFont()
        lbl_font.setPointSize(8)
        p.setFont(lbl_font)
        p.setPen(QColor("#9AA4AF"))
        for i in range(5):
            val = v_min + (v_max - v_min) * (4 - i) / 4
            y   = mt + i * plot_h // 4
            txt = f"{val:.1f}" if isinstance(val, float) else str(int(val))
            p.drawText(0, y - 8, ml - 4, 16,
                       Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                       txt)

        # ── X axis labels (dates) ─────────────────────────────────────────────
        n_labels = min(5, len(all_times))
        for i in range(n_labels):
            dt  = t_min + (t_max - t_min) * i / max(n_labels - 1, 1)
            x   = tx(dt)
            txt = dt.strftime("%d %b" if t_span > 86400 else "%H:%M")
            p.drawText(int(x) - 25, mt + plot_h + 4, 50, 20,
                       Qt.AlignmentFlag.AlignCenter, txt)

        # ── Data segments ─────────────────────────────────────────────────────
        line_pen = QPen(QColor("#3498db"))
        line_pen.setWidth(2)
        p.setPen(line_pen)

        dot_color    = QColor("#3498db")
        change_color = QColor("#e07070")

        prev_x2 = prev_y = None

        for idx, (fs, ls, val) in enumerate(self._points):
            if val is None:
                continue
            x1 = tx(fs)
            x2 = tx(ls)
            y  = ty(val)

            # Vertical connector from previous segment if value changed
            if prev_x2 is not None and prev_y != y:
                change_pen = QPen(change_color)
                change_pen.setWidth(1)
                change_pen.setStyle(Qt.PenStyle.DashLine)
                p.setPen(change_pen)
                p.drawLine(int(prev_x2), int(prev_y), int(prev_x2), int(y))
                p.setPen(line_pen)

            # Connect to previous segment if same value
            if prev_x2 is not None and prev_y == y:
                p.setPen(line_pen)
                p.drawLine(int(prev_x2), int(prev_y), int(x1), int(y))

            # Horizontal segment (first_seen → last_seen)
            p.setPen(line_pen)
            p.drawLine(int(x1), int(y), int(x2), int(y))

            # Dots at segment endpoints
            p.setBrush(dot_color)
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(int(x1) - 3, int(y) - 3, 6, 6)
            if abs(x2 - x1) > 8:
                p.drawEllipse(int(x2) - 3, int(y) - 3, 6, 6)
            p.setBrush(Qt.BrushStyle.NoBrush)

            prev_x2, prev_y = x2, y

        # ── Title ─────────────────────────────────────────────────────────────
        title_font = QFont()
        title_font.setPointSize(9)
        title_font.setBold(True)
        p.setFont(title_font)
        p.setPen(QColor("#E6E6E6"))
        title = f"{self._label}" + (f"  ({self._unit})" if self._unit else "")
        p.drawText(ml, 2, plot_w, mt - 2, Qt.AlignmentFlag.AlignCenter, title)

        p.end()


# ─────────────────────────────────────────────────────────────────────────────
# History dialog
# ─────────────────────────────────────────────────────────────────────────────

_ATTR_LABELS = {
    "reallocated":   ("Reallocated Sectors",  "sectors"),
    "pending":       ("Pending Sectors",       "sectors"),
    "uncorrectable": ("Uncorrectable Errors",  "errors"),
    "wear_pct_used": ("Wear",                  "%"),
    "tbw_tb":        ("Total Bytes Written",   "TB"),
    "power_on_hours":("Power-On Hours",        "hours"),
}


class SmartHistoryDialog(QDialog):
    """
    Shows the logged SMART history for a single disk as a line chart.
    Opened from SmartDiskDialog when the user clicks "History" on a disk row.
    """

    def __init__(self, dev: str, logger: SmartLogger, key: str | None = None, parent=None):
        super().__init__(parent)
        self._dev    = dev
        self._logger = logger
        _key = key if key is not None else dev
        meta, self._history = logger.get_history(_key)
        model  = meta.get("model", "")
        title  = f"SMART History — /dev/{dev}"
        if model:
            title += f"  ({model})"
        self.setWindowTitle(title)
        self.setMinimumSize(720, 420)
        self._setup_ui()
        self._refresh_chart()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(8)

        # ── Attribute selector ────────────────────────────────────────────────
        top = QHBoxLayout()
        top.addWidget(QLabel("Attribute:"))
        self._attr_combo = QComboBox()

        # Only add attributes that have at least one non-None value
        for key, (label, unit) in _ATTR_LABELS.items():
            has_data = any(
                e.get(key) is not None for e in self._history)
            if has_data:
                self._attr_combo.addItem(label, userData=(key, unit))

        if self._attr_combo.count() == 0:
            self._attr_combo.addItem("No data available", userData=None)

        self._attr_combo.currentIndexChanged.connect(self._refresh_chart)
        top.addWidget(self._attr_combo)
        top.addStretch()

        # Entry count
        self._count_lbl = QLabel("")
        self._count_lbl.setStyleSheet("color: #9AA4AF; font-size: 11px;")
        top.addWidget(self._count_lbl)
        root.addLayout(top)

        # ── Chart ─────────────────────────────────────────────────────────────
        self._chart = _ChartWidget()
        root.addWidget(self._chart, 1)

        # ── Legend ────────────────────────────────────────────────────────────
        legend = QLabel(
            "<span style='color:#3498db;'>●</span> Value over time  "
            "<span style='color:#e07070;'>╌</span> Value changed")
        legend.setStyleSheet("font-size: 10px; color: #9AA4AF;")
        root.addWidget(legend)

        # ── Close button ──────────────────────────────────────────────────────
        from PyQt6.QtWidgets import QDialogButtonBox
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(self.reject)
        root.addWidget(close)

    def _refresh_chart(self):
        data = self._attr_combo.currentData()
        if data is None:
            self._chart.set_data([], "No data")
            self._count_lbl.setText("")
            return

        key, unit = data

        points: list[tuple[datetime, datetime, float | None]] = []
        for entry in self._history:
            val = entry.get(key)
            try:
                fs = datetime.fromisoformat(entry["first_seen"])
                ls = datetime.fromisoformat(entry["last_seen"])
                points.append((fs, ls, float(val) if val is not None else None))
            except (KeyError, ValueError):
                continue

        label = _ATTR_LABELS.get(key, (key, ""))[0]
        self._chart.set_data(points, label, unit)

        n = len(self._history)
        self._count_lbl.setText(
            f"{n} recorded state{'s' if n != 1 else ''}")
