import re
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QLabel, QHBoxLayout, QWidget


# ─────────────────────────────────────────────────────────────────────────────
# WiFi signal reading — all from /proc and /sys, no tools needed
# ─────────────────────────────────────────────────────────────────────────────

def _read_wifi() -> tuple[str | None, int | None]:
    """
    Return (interface_name, signal_dbm) for the connected WiFi interface,
    or (None, None) if not on WiFi or unable to read.

    Sources tried in order:
      1. /proc/net/wireless  — always present if kernel wireless drivers loaded
      2. /sys/class/net/<iface>/wireless/  — existence check only (no signal there)

    /proc/net/wireless format (kernel >= 2.4):
      Inter-| sta-|   Quality        |   Discarded ...
       face | tus | link level noise | ...
      wlan0: 0000   55.  -55.  -256 ...
                         ^^^^^ this is signal level in dBm (with a trailing dot)
    """
    proc_wireless = Path("/proc/net/wireless")
    if not proc_wireless.exists():
        return None, None

    try:
        lines = proc_wireless.read_text().splitlines()
    except OSError:
        return None, None

    for line in lines:
        # Skip header lines (they don't start with a word followed by colon)
        m = re.match(r"^\s*(\w+):\s+\S+\s+\S+\s+([-\d]+)", line)
        if m:
            iface  = m.group(1)
            # The level field is the third numeric column.
            # When the "updated" flag is set the kernel appends a dot; strip it.
            level_str = m.group(2).replace(".", "").strip()
            try:
                dbm = int(level_str)
                # Sanity check: valid WiFi RSSI is usually -100 to -20 dBm.
                # Some kernels report 0 when disconnected.
                if dbm == 0 or dbm > 0:
                    return iface, None   # connected but level not meaningful
                return iface, dbm
            except ValueError:
                return iface, None

    return None, None


def _dbm_to_label(dbm: int | None) -> tuple[str, str]:
    """
    Convert a dBm value to a human-readable label and hex colour.
    Returns ("label", "#colour").
    """
    if dbm is None:
        return "WiFi: ?", "#9AA4AF"
    if dbm >= -50:
        return f"WiFi: {dbm} dBm  ▂▄▆█", "#27ae60"
    if dbm >= -65:
        return f"WiFi: {dbm} dBm  ▂▄▆_", "#27ae60"
    if dbm >= -75:
        return f"WiFi: {dbm} dBm  ▂▄__", "#f39c12"
    if dbm >= -85:
        return f"WiFi: {dbm} dBm  ▂___", "#f39c12"
    return f"WiFi: {dbm} dBm  ____", "#c0392b"


# ─────────────────────────────────────────────────────────────────────────────
# Widget
# ─────────────────────────────────────────────────────────────────────────────

class WifiStrengthWidget(QWidget):
    """
    A compact label that shows the local machine's WiFi signal strength.
    Designed to sit in the main window's status bar alongside the status label.

    Poll interval: 10 seconds (configurable via POLL_MS).
    Hides itself entirely when not on WiFi so it doesn't clutter the bar
    on wired-only machines.
    """

    POLL_MS = 10_000

    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 0, 4, 0)
        layout.setSpacing(0)

        self._lbl = QLabel("")
        self._lbl.setStyleSheet("font-size: 11px;")
        self._lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self._lbl)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._update)
        self._timer.start(self.POLL_MS)

        # Read immediately on startup
        self._update()

    def _update(self):
        iface, dbm = _read_wifi()

        if iface is None:
            # Not on WiFi — hide the whole widget
            self.setVisible(False)
            return

        self.setVisible(True)
        label, color = _dbm_to_label(dbm)
        self._lbl.setText(label)
        self._lbl.setStyleSheet(f"color: {color}; font-size: 11px;")
        self._lbl.setToolTip(
            f"Interface: {iface}\n"
            f"Signal: {dbm} dBm\n"
            + (
                "Excellent" if dbm is not None and dbm >= -50 else
                "Good"      if dbm is not None and dbm >= -65 else
                "Fair"      if dbm is not None and dbm >= -75 else
                "Weak"      if dbm is not None and dbm >= -85 else
                "Very weak" if dbm is not None else
                "Unknown"
            )
        )