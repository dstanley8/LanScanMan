import paramiko
from PyQt6.QtCore import QThread, pyqtSignal

from lanscanman.core.probe import PROBE_CMD, parse_probe_output
from lanscanman.core.smart import SMART_PROBE_CMD, parse_smart_probe
from lanscanman.services.ssh import mismatch_from, run_remote


class _RemoteProbe(QThread):
    """SSH in, run a read-only probe script, emit the parsed result."""
    probe_error      = pyqtSignal(str, str)   # (ip, message)
    host_key_changed = pyqtSignal(str, object)   # (ip, HostKeyMismatchError)

    command = ""
    connect_timeout = 8
    exec_timeout = 15

    def __init__(self, ip: str, username: str, parent=None):
        super().__init__(parent)
        self.ip       = ip
        self.username = username

    def parse(self, raw: str):
        raise NotImplementedError

    def run(self):
        try:
            raw = run_remote(self.ip, self.username, self.command,
                             self.connect_timeout, self.exec_timeout)
            self.result_ready.emit(self.ip, self.parse(raw))
        except paramiko.BadHostKeyException as e:
            self.host_key_changed.emit(self.ip, mismatch_from(e))
        except Exception as e:
            self.probe_error.emit(self.ip, str(e))


class ProbeWorker(_RemoteProbe):
    """CPU / RAM / GPU stats for the Host Monitor tab."""
    result_ready = pyqtSignal(str, dict)      # (ip, stats)
    command = PROBE_CMD

    def parse(self, raw):
        return parse_probe_output(raw)


class SmartProbeWorker(_RemoteProbe):
    """Per-disk SMART data for the Disk Health tab."""
    result_ready = pyqtSignal(str, list)      # (ip, [disk])
    command = SMART_PROBE_CMD
    connect_timeout = 10
    exec_timeout = 30

    def parse(self, raw):
        return parse_smart_probe(raw)
