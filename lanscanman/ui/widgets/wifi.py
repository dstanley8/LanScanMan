
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QWidget

from lanscanman.core.wifi import dbm_to_label, read_wifi, signal_quality

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
        iface, dbm = read_wifi()

        if iface is None:
            # Not on WiFi — hide the whole widget
            self.setVisible(False)
            return

        self.setVisible(True)
        label, color = dbm_to_label(dbm)
        self._lbl.setText(label)
        self._lbl.setStyleSheet(f"color: {color}; font-size: 11px;")
        self._lbl.setToolTip(
            f"Interface: {iface}\n"
            f"Signal: {dbm} dBm\n"
            f"{signal_quality(dbm)}"
        )
