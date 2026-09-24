import copy
from dataclasses import asdict

from PyQt6.QtCore import QThread, pyqtSignal

from lanscanman.core.schedule_runner import run_schedule
from lanscanman.core.schedules import Schedule, Transfer
from lanscanman.workers.rsync import RsyncWorker


class ScheduledRunner(QThread):
    """Runs a Schedule's transfers one after another on this thread."""
    transfer_started  = pyqtSignal(str, int, str, str)   # schedule_id, idx, source, dest
    transfer_finished = pyqtSignal(str, int, str, int)   # schedule_id, idx, status, bytes
    list_finished     = pyqtSignal(str, str, dict)       # schedule_id, overall, run_log_entry

    def __init__(self, schedule: Schedule, parent=None):
        super().__init__(parent)
        self._schedule = copy.deepcopy(schedule)
        self._stop_requested = False

    def stop(self):
        self._stop_requested = True

    @staticmethod
    def _run_transfer(t: Transfer) -> tuple[str, int]:
        # Call run() directly rather than start(): we are already off the
        # UI thread and want the transfers strictly sequential.
        worker = RsyncWorker(tid=0, data=asdict(t))
        result = {"status": "Failed", "bytes": 0}

        def _on_finished(_tid, status, _error, total_bytes):
            result["status"], result["bytes"] = status, total_bytes

        worker.finished.connect(_on_finished)
        worker.run()
        return result["status"], result["bytes"]

    def run(self):
        sched = self._schedule
        entry = run_schedule(
            sched, self._run_transfer,
            should_stop=lambda: self._stop_requested,
            on_started=lambda i, t: self.transfer_started.emit(
                sched.id, i, t.full_source, t.full_dest),
            on_finished=lambda i, s, b: self.transfer_finished.emit(sched.id, i, s, b),
        )
        # A plain dict, so the UI thread can persist it without sharing dataclasses
        self.list_finished.emit(sched.id, entry.status, asdict(entry))
