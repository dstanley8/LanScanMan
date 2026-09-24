"""
Main window: builds the tabs, the status bar, and the once-a-minute timer
that fires scheduled transfers. Start the app with `python3 main.py`.
"""

import sys

from PyQt6.QtCore import QSettings, QThread, QTimer
from PyQt6.QtGui import QKeySequence, QShortcut
from PyQt6.QtWidgets import QApplication, QLabel, QMainWindow, QMessageBox, QTabWidget

from lanscanman.core.integrity import IntegrityError
from lanscanman.core.schedules import (
    ScheduleIntegrityError,
    ScheduleKeyUnavailable,
    ScheduleManager,
)
from lanscanman.log import log
from lanscanman.services import privilege
from lanscanman.services.network_manager import NetworkManager
from lanscanman.services.secret_store import SecretStore
from lanscanman.services.ssh import known_hosts_file
from lanscanman.services.vault import Vault, get_vault, set_vault
from lanscanman.ui.ssh_key import offer_add_passphrase
from lanscanman.ui.tabs.about_tab import AboutTab
from lanscanman.ui.tabs.ai_tab import AITab
from lanscanman.ui.tabs.host_inspector_tab import HostInspectorTab
from lanscanman.ui.tabs.monitor_tab import MonitorTab
from lanscanman.ui.tabs.scanner_tab import ScannerTab
from lanscanman.ui.tabs.smart_tab import SmartTab
from lanscanman.ui.tabs.transfer_tab import TransferTab
from lanscanman.ui.theme import apply_theme
from lanscanman.ui.trust import show_integrity_problem
from lanscanman.ui.widgets.wifi import WifiStrengthWidget
from lanscanman.workers.ai import wait_for_all


class LanScanManApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LanScanMan")
        self.resize(1100, 650)

        # Signing key for hosts.json / known_hosts / schedules.json. The first
        # use below asks the keyring (GNOME shows its unlock prompt). If that
        # is declined the app still opens: profiles are shown read-only and
        # every action that connects or edits asks again.
        self.vault = get_vault()
        self.net_manager     = NetworkManager()
        known_hosts_file()                    # register for signing / checks

        self.schedule_manager = ScheduleManager(key_provider=self.vault.key)
        schedule_integrity_failed = False
        self._schedule_error: Exception | None = None
        try:
            self.schedule_manager.load()
        except ScheduleIntegrityError as e:
            log.error(f"schedule integrity check failed: {e}")
            schedule_integrity_failed = True
            self._schedule_error = e
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
        self.ai_page         = AITab(self.scanner_page.current_hosts, self)
        self.scanner_page.hosts_changed.connect(self.ai_page.mark_stale)
        self.smart_page.ask_ai = self.ai_page.open_drive_chat
        self.about_page      = AboutTab(self)

        self.tabs.addTab(self.scanner_page,   "Network Scanner")
        self.tabs.addTab(self.inspector_page, "Host Inspector")
        self.tabs.addTab(self.monitor_page,   "Host Monitor")
        self.tabs.addTab(self.smart_page,     "Disk Health")
        self.tabs.addTab(self.transfer_page,  "File Transfers")
        self.tabs.addTab(self.ai_page,        "AI")
        self.tabs.addTab(self.about_page,     "About")

        self.setCentralWidget(self.tabs)

        # Status bar
        self.status = QLabel("Ready")
        self.wifi   = WifiStrengthWidget(self)
        self.statusBar().addPermanentWidget(self.wifi)
        self.statusBar().addPermanentWidget(self.status)

        apply_theme(QApplication.instance())

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

        # hosts.json / known_hosts problems found at startup
        QTimer.singleShot(300, self._report_startup_trust)

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

    def _report_startup_trust(self):
        offer_add_passphrase(self, startup=True)
        if not self.vault.unlocked:
            self.status.setText("Keyring locked — actions that connect will ask to unlock it.")
            return
        problems = []
        if self.net_manager.store.problem is not None:
            problems.append(self.net_manager.store.problem)
        try:
            known_hosts_file().read()
        except IntegrityError as e:
            problems.append(e)
        for err in problems:
            show_integrity_problem(self, err)

    def _show_integrity_warning(self):
        if isinstance(self._schedule_error, ScheduleKeyUnavailable):
            QMessageBox.warning(
                self,
                "Keyring unavailable",
                "LanScanMan keeps the key that signs your scheduled transfers in "
                "your desktop keyring, and the keyring could not be read "
                "(it may be locked, or the unlock prompt was dismissed).\n\n"
                "Scheduled transfers will NOT run this session. Nothing has been "
                "changed — unlock the keyring and restart LanScanMan.\n\n"
                f"Details: {self._schedule_error}",
            )
            return
        QMessageBox.warning(
            self,
            "Schedule integrity check failed",
            "LanScanMan's scheduled transfers file failed its integrity check. "
            "This means schedules.json has been modified outside LanScanMan, "
            "or its signing key (in your keyring) is missing.\n\n"
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


def _excepthook(exc_type, exc, tb):
    """Integrity problems escaping a UI handler become a dialog, not a crash.
    (Replacing sys.excepthook also stops PyQt aborting on other errors;
    those are logged.)"""
    app = QApplication.instance()
    on_gui_thread = app is not None and QThread.currentThread() is app.thread()
    if isinstance(exc, IntegrityError) and on_gui_thread:
        show_integrity_problem(app.activeWindow(), exc)
        return
    log.error("unhandled exception", exc_info=(exc_type, exc, tb))


def main() -> int:
    app = QApplication(sys.argv)
    set_vault(Vault(SecretStore.default()))
    sys.excepthook = _excepthook
    window = LanScanManApp()
    window.show()
    code = app.exec()
    wait_for_all()          # don't destroy in-flight AI requests mid-run
    privilege.forget_if_used()   # don't leave sudo's remembered password behind
    return code
