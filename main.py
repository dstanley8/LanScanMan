import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QTabWidget, QLabel, QMessageBox
from PyQt6.QtCore import QSettings, QTimer
from PyQt6.QtGui import QIcon, QKeySequence, QShortcut
from datetime import datetime
from tabs.scanner_tab import ScannerTab
from tabs.transfer_tab import TransferTab
from manager import NetworkManager
from tabs.monitor_tab import MonitorTab
from tabs.smart_tab import SmartTab
from tabs.about_tab import AboutTab
from tabs.host_inspector_tab import HostInspectorTab
from wifi_widget import WifiStrengthWidget
from schedule_manager import ScheduleManager, ScheduleIntegrityError
from log import log

# =========================
# LanScanMan Theme Config
# =========================

THEME = {
    "bg": "#121417",
    "panel": "#1B1F24",
    "panel_alt": "#20262E",
    "text": "#E6E6E6",
    "muted": "#9AA4AF",
    "accent": "#3498db",
    "good": "#27ae60",
    "warn": "#f39c12",
    "bad": "#c0392b",
    "radius": 8,
    "border": "1px solid #2A313B",
}


def apply_theme(app):
    app.setStyleSheet(f"""
/* ========================= CORE BACKGROUND ========================= */
QMainWindow {{
    background-color: {THEME['bg']};
    color: {THEME['text']};
}}

/* ========================= LABELS ========================= */
QLabel {{ color: {THEME['text']}; }}
QLabel[role="muted"] {{ color: {THEME['muted']}; }}

/* ========================= INPUT FIELDS ========================= */
QLineEdit {{
    background-color: {THEME['panel_alt']};
    border: {THEME['border']};
    padding: 6px;
    border-radius: {THEME['radius']}px;
    color: {THEME['text']};
}}
QLineEdit:focus {{ border: 1px solid {THEME['accent']}; }}

/* ========================= CHECKBOXES ========================= */
QCheckBox {{ color: {THEME['text']}; spacing: 8px; }}
QCheckBox::indicator {{
    width: 15px; height: 15px;
    border-radius: 3px;
    border: 1px solid #3A4452;
    background-color: {THEME['panel_alt']};
}}
QCheckBox::indicator:checked {{
    background-color: #2ecc71;
    border: 1px solid #27ae60;
}}
QCheckBox::indicator:hover {{ border: 1px solid {THEME['accent']}; }}

/* ========================= BUTTONS ========================= */
QPushButton {{
    background-color: {THEME['panel_alt']};
    border: {THEME['border']};
    padding: 6px 10px;
    border-radius: {THEME['radius']}px;
    color: {THEME['text']};
}}
QPushButton:hover {{ border: 1px solid {THEME['accent']}; }}
QPushButton:pressed {{ background-color: #151A20; }}

/* ========================= TABLES ========================= */
QTableWidget {{
    background-color: {THEME['panel']};
    border: {THEME['border']};
    gridline-color: transparent;
    color: #D6D6D6;
    alternate-background-color: #171B21;
}}
QTableWidget::item {{
    border-bottom: 1px solid #1A1F26;
    padding: 6px;
}}
QHeaderView::section {{
    background-color: {THEME['panel_alt']};
    color: {THEME['text']};
    padding: 6px;
    border: none;
    border-bottom: 1px solid {THEME['accent']};
}}

/* ========================= COMBOBOXES ========================= */
QComboBox {{
    background-color: {THEME['panel_alt']};
    border: {THEME['border']};
    padding: 6px;
    border-radius: {THEME['radius']}px;
    color: {THEME['text']};
}}
QComboBox:hover {{ border: 1px solid {THEME['accent']}; }}
QComboBox QAbstractItemView {{
    background-color: {THEME['panel']};
    selection-background-color: {THEME['accent']};
    color: {THEME['text']};
    border: {THEME['border']};
}}

/* ========================= TABS ========================= */
QTabWidget::pane {{
    border: {THEME['border']};
    border-radius: {THEME['radius']}px;
    background-color: {THEME['panel']};
}}
QTabBar::tab {{
    background-color: {THEME['panel_alt']};
    color: {THEME['text']};
    padding: 8px 14px;
    margin-right: 4px;
    border-top-left-radius: {THEME['radius']}px;
    border-top-right-radius: {THEME['radius']}px;
    border: {THEME['border']};
}}
QTabBar::tab:selected {{
    background-color: {THEME['panel']};
    border-bottom: 2px solid {THEME['accent']};
}}
QTabBar::tab:hover {{ border: 1px solid {THEME['accent']}; }}

/* ========================= GROUP BOXES ========================= */
QGroupBox {{
    border: {THEME['border']};
    margin-top: 10px;
    padding: 10px;
    border-radius: {THEME['radius']}px;
}}

/* ========================= DIALOGS / POPUPS ========================= */
QDialog {{ background-color: {THEME['bg']}; color: {THEME['text']}; }}
QMessageBox {{ background-color: {THEME['bg']}; color: {THEME['text']}; }}
QMessageBox QLabel {{ color: {THEME['text']}; }}
QDialogButtonBox QPushButton {{ min-width: 80px; }}

/* ========================= TOOLTIPS ========================= */
QToolTip {{
    background-color: {THEME['panel']};
    color: {THEME['text']};
    border: {THEME['border']};
    padding: 4px;
    border-radius: 6px;
}}
""")


class LanScanManApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LanScanMan")
        self.resize(1100, 650)

        self.net_manager     = NetworkManager()
        self.cached_password = None

        # Schedule manager — load schedules with HMAC integrity check
        self.schedule_manager = ScheduleManager()
        schedule_integrity_failed = False
        try:
            self.schedule_manager.load()
        except ScheduleIntegrityError as e:
            log.error(f"schedule integrity check failed: {e}")
            schedule_integrity_failed = True
        except Exception as e:
            log.exception(f"unexpected error loading schedules: {e}")

        # Tabs
        self.tabs            = QTabWidget()
        self.scanner_page    = ScannerTab(self.net_manager, self)
        self.transfer_page   = TransferTab(
            self.net_manager, self,
            schedule_manager=self.schedule_manager,
            schedule_integrity_failed=schedule_integrity_failed,
        )
        self.monitor_page    = MonitorTab(self.net_manager, self)
        self.smart_page      = SmartTab(self.net_manager, self)
        self.inspector_page  = HostInspectorTab(self.net_manager, self)
        self.about_page      = AboutTab(self)

        self.tabs.addTab(self.scanner_page,   "Network Scanner")
        self.tabs.addTab(self.inspector_page, "Host Inspector")
        self.tabs.addTab(self.monitor_page,   "Host Monitor")
        self.tabs.addTab(self.smart_page,     "Disk Health")
        self.tabs.addTab(self.transfer_page,  "File Transfers")
        self.tabs.addTab(self.about_page,     "About")

        self.setCentralWidget(self.tabs)

        # Status bar
        self.status = QLabel("Ready")
        self.wifi   = WifiStrengthWidget(self)
        self.statusBar().addPermanentWidget(self.wifi)
        self.statusBar().addPermanentWidget(self.status)

        apply_theme(app)

        # Restore previous window geometry (size + position)
        settings = QSettings("LanScanMan", "LanScanMan")
        geometry = settings.value("windowGeometry")
        if geometry:
            self.restoreGeometry(geometry)

        # Ctrl+Tab — cycle tabs forward
        sc_next = QShortcut(QKeySequence("Ctrl+Tab"), self)
        sc_next.activated.connect(self._next_tab)

        # Ctrl+Shift+Tab — cycle tabs backward
        sc_prev = QShortcut(QKeySequence("Ctrl+Shift+Tab"), self)
        sc_prev.activated.connect(self._prev_tab)

        # Show integrity warning dialog if schedules failed to load
        if schedule_integrity_failed:
            QTimer.singleShot(500, self._show_integrity_warning)

        # Start the schedule timer — ticks every minute, checks due schedules
        self._schedule_timer = QTimer(self)
        self._schedule_timer.setInterval(60_000)  # 60s
        self._schedule_timer.timeout.connect(self._check_due_schedules)
        if not schedule_integrity_failed:
            self._schedule_timer.start()
            # Also handle missed runs on startup (delay slightly so the UI
            # is fully painted before we pop dialogs)
            QTimer.singleShot(1500, self._handle_missed_schedules_on_startup)

    def _next_tab(self):
        count = self.tabs.count()
        self.tabs.setCurrentIndex((self.tabs.currentIndex() + 1) % count)

    def _prev_tab(self):
        count = self.tabs.count()
        self.tabs.setCurrentIndex((self.tabs.currentIndex() - 1) % count)

    def _show_integrity_warning(self):
        QMessageBox.warning(
            self,
            "Schedule integrity check failed",
            "LanScanMan's scheduled transfers file failed its integrity check. "
            "This means schedules.json has been modified outside LanScanMan, "
            "or the HMAC key is missing.\n\n"
            "Scheduled transfers will NOT run until this is resolved.\n\n"
            "To reset: delete ~/.config/LanScanMan/schedules.json and "
            "schedules.hmac, then restart LanScanMan.\n\n"
            "If you believe this is a false alarm (e.g. you restored from "
            "backup), restore the matching schedules.hmac file as well.",
        )

    def _check_due_schedules(self):
        """Called by QTimer every minute. Fire schedules whose time has come."""
        if self.schedule_manager is None:
            return
        try:
            due = self.schedule_manager.due_now()
        except Exception as e:
            log.exception(f"error checking due schedules: {e}")
            return
        for sched in due:
            try:
                self.transfer_page.run_schedule_by_id(
                    sched.id, skip_confirm_dialog=False)
            except Exception as e:
                log.exception(f"failed to fire schedule {sched.name!r}: {e}")

    def _handle_missed_schedules_on_startup(self):
        """
        On startup, look for schedules whose time has passed and honour their
        missed_run setting (skip / run / warn).
        """
        if self.schedule_manager is None:
            return
        try:
            missed = self.schedule_manager.missed_since_last_open()
        except Exception as e:
            log.exception(f"error checking missed schedules: {e}")
            return
        for sched in missed:
            if sched.missed_run == "skip":
                # Advance last_run so the QTimer doesn't fire it 60s later
                sched.skip()
                try:
                    self.schedule_manager.save()
                except Exception as e:
                    log.exception(f"failed to save after skipping {sched.name!r}: {e}")
                continue
            if sched.missed_run == "run":
                self.transfer_page.run_schedule_by_id(
                    sched.id, skip_confirm_dialog=True)
                continue
            # "warn"
            resp = QMessageBox.question(
                self,
                f"Missed schedule: {sched.name}",
                f"The scheduled run for '{sched.name}' was missed "
                f"(LanScanMan was not running at the scheduled time).\n\n"
                f"Would you like to run it now?",
            )
            if resp == QMessageBox.StandardButton.Yes:
                self.transfer_page.run_schedule_by_id(
                    sched.id, skip_confirm_dialog=True)
            else:
                # User declined — advance last_run so the QTimer doesn't
                # re-ask on its next 60-second tick.
                sched.skip()
                try:
                    self.schedule_manager.save()
                except Exception as e:
                    log.exception(f"failed to save after skipping {sched.name!r}: {e}")

    def closeEvent(self, event):
        # Persist window geometry across sessions
        settings = QSettings("LanScanMan", "LanScanMan")
        settings.setValue("windowGeometry", self.saveGeometry())
        super().closeEvent(event)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LanScanManApp()
    window.show()
    sys.exit(app.exec())