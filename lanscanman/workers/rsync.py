import os
import signal
import subprocess
import threading

from PyQt6.QtCore import QThread, pyqtSignal

from lanscanman.core import rsync
from lanscanman.core.integrity import IntegrityError
from lanscanman.core.rsync import LOCALHOST
from lanscanman.services.ssh import HostKeyMismatchError, connect, prepare_cli_ssh


class RsyncWorker(QThread):
    """
    Runs one transfer. `data` is the dict produced by AddTransferDialog
    (or a schedules.Transfer): full_source, full_dest, src_path, args,
    sender_ip, sender_user, receiver_ip.
    """
    progress_update = pyqtSignal(int, str, str, str, str, str)  # tid, status, pct, size, speed, eta
    output_line     = pyqtSignal(int, str)                      # tid, rsync stdout line
    finished        = pyqtSignal(int, str, str, int)            # tid, status, error, total_bytes

    def __init__(self, tid: int, data: dict, parent=None):
        super().__init__()
        self.tid     = tid
        self.data    = data
        self.process = None

    def _preflight(self) -> str | None:
        """Check the source path exists (skipped for globs). Returns an error or None."""
        src  = self.data.get("src_path", "")
        sip  = self.data.get("sender_ip", LOCALHOST)
        if "*" in src or "?" in src:
            return None
        if sip == LOCALHOST:
            return None if os.path.exists(src) else f"Source path does not exist: {src}"
        # Deliberately no sender→receiver connectivity test for remote→remote:
        # the real transfer authenticates via agent forwarding (-A), which a
        # preflight from here would not exercise.
        try:
            ssh = connect(sip, self.data.get("sender_user", ""), timeout=8)
            sftp = ssh.open_sftp()
            sftp.stat(src.rstrip("/") or "/")
            sftp.close()
            ssh.close()
        except FileNotFoundError:
            return f"Source path does not exist on {sip}: {src}"
        except Exception as e:
            return f"Could not verify source path: {e}"
        return None

    def _pin_remote_host(self) -> str | None:
        """Pin the host key of whichever end ssh will connect to, so the CLI
        can run with StrictHostKeyChecking=yes. Returns an error or None."""
        sip = self.data.get("sender_ip", LOCALHOST)
        rip = self.data.get("receiver_ip", LOCALHOST)
        target = sip if sip != LOCALHOST else rip
        if target == LOCALHOST:
            return None
        try:
            prepare_cli_ssh(target)
        except HostKeyMismatchError as e:
            return (f"The SSH host key for {e.hostname} has changed. Connect to it "
                    f"from the Network Scanner to review and re-trust it.")
        except IntegrityError as e:
            return str(e)
        except Exception as e:
            return f"Could not verify the host key of {target}: {e}"
        return None

    def run(self):
        error = self._pin_remote_host() or self._preflight()
        if error:
            self.finished.emit(self.tid, "Failed", error, 0)
            return

        is_dry = "--dry-run" in self.data.get("args", [])
        status_label = "Dry Run…" if is_dry else "Transferring…"
        total_bytes = 0
        try:
            cmd = rsync.build_command(self.data)
            self.progress_update.emit(self.tid, status_label, "0%", "—", "—", "—")
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, preexec_fn=os.setsid,
            )
            # Echo the exact command so the user can see what ran
            self.output_line.emit(self.tid, "$ " + " ".join(cmd))
            self.output_line.emit(self.tid, "")

            # Drain stderr concurrently: if its ~64 KB pipe buffer fills,
            # rsync blocks and the stdout loop below hangs forever.
            stderr_lines: list[str] = []
            def _drain_stderr():
                for line in self.process.stderr:
                    stderr_lines.append(line)
            stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
            stderr_thread.start()

            # Read in chunks — progress2 rewrites its line with \r, so
            # line-buffered reads would give no live updates.
            buf = ""
            while True:
                chunk = self.process.stdout.read(256)
                if not chunk:
                    break
                lines, buf = rsync.split_output(buf + chunk)
                for line in lines:
                    p = rsync.parse_progress(line)
                    if p:
                        total_bytes = p.total_estimate
                        self.progress_update.emit(self.tid, status_label, f"{p.percent}%",
                                                  p.size_display, p.speed, p.eta)
                    elif line.strip():
                        # file names, summaries, dry-run previews
                        self.output_line.emit(self.tid, line.rstrip())

            p = rsync.parse_progress(buf) if buf else None
            if p and p.percent > 0:
                total_bytes = p.total_estimate

            stderr_thread.join()
            self.process.wait()
            err = "".join(stderr_lines).strip()

            if self.process.returncode == 0:
                self.finished.emit(self.tid, "Completed", "", total_bytes)
            elif self.process.returncode == rsync.EXIT_CANCELLED:
                self.finished.emit(self.tid, "Cancelled", "", 0)
            else:
                self.finished.emit(self.tid, "Failed", err, 0)
        except Exception as e:
            self.finished.emit(self.tid, "Failed", str(e), 0)

    def stop(self):
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            except Exception:
                try:
                    self.process.terminate()
                except Exception:
                    pass
