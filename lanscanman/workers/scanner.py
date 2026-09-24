import os
import subprocess

import nmap
from PyQt6.QtCore import QThread, pyqtSignal

from lanscanman.core import privilege as P
from lanscanman.core.nmap_scan import (
    host_scan_args,
    nmap_error_message,
    parse_host_scan,
    parse_subnet_scan,
    subnet_scan_args,
)
from lanscanman.core.privilege import validate_scan_args
from lanscanman.services import privilege
from lanscanman.services.privilege import detect, methods


class _NmapThread(QThread):
    """
    Runs nmap and returns python-nmap's `scan` dict.

    Privileged scans go through the first working method from
    services.privilege (pkexec → pkexec with a terminal agent → sudo -A);
    `password` is only set when the user opted into the password-box
    fallback, and is used for this one run.
    """
    results_ready  = pyqtSignal(list)
    error_occurred = pyqtSignal(str)
    method_used    = pyqtSignal(str)

    privileged = False
    password: str | None = None
    mode: str = P.POLKIT_MODE

    def _exec(self, argv: list[str], env_extra: dict, stdin_text: str | None):
        """(returncode, stdout, stderr), or None if cancelled. Output is read
        continuously so a large scan can't fill the pipe and stall."""
        env = {**os.environ, **env_extra}
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin_text is not None else None,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=env)
        pending_input = stdin_text
        while True:
            try:
                out, err = proc.communicate(input=pending_input, timeout=0.25)
                return proc.returncode, out, err
            except subprocess.TimeoutExpired:
                pending_input = None           # already written
                if self.isInterruptionRequested():
                    try:
                        proc.kill()
                    except PermissionError:
                        # A root process (pkexec / sudo) can't be signalled by us;
                        # it finishes on its own and its output is discarded.
                        pass
                    return None

    def _run_nmap(self, nmap_args: list[str]) -> dict | None:
        """Return python-nmap's `scan` dict, or None after emitting an error."""
        if not self.privileged:
            result = self._exec(["nmap", *nmap_args], {}, None)
            return self._finish(result, "unprivileged")

        reason = validate_scan_args(nmap_args)
        if reason:
            self.error_occurred.emit(f"Scan options not allowed: {reason}")
            return None
        caps = detect()
        if self.password is not None:
            order = [P.PASSWORD]
        else:
            order = methods(caps, self.mode)
        if not order:
            self.error_occurred.emit(
                "No way to run a privileged scan was found (no polkit agent, no sudo "
                "askpass). Use an unprivileged scan, or switch ⚙ → Ask for scan "
                "permission with → sudo.")
            return None
        last = P.NO_AGENT
        for method in order:
            argv, env = privilege.command(method, caps, nmap_args)
            if method == P.PKEXEC_TTY:
                privilege.start_tty_agent(caps)
                self.msleep(1500)              # let the agent register
            self.method_used.emit(method)
            result = self._exec(argv, env, (self.password + "\n") if method == P.PASSWORD else None)
            if method == P.PASSWORD:
                self.password = None           # used once, then dropped
            if result is None:
                self.error_occurred.emit("Scan cancelled.")
                return None
            code, out, err = result
            outcome = P.classify(method, code, err)
            if outcome in (P.NO_AGENT, P.NEEDS_PASSWORD):
                last = outcome
                continue                       # try the next method
            if outcome != P.OK:
                if method == P.PASSWORD and outcome == P.DENIED:
                    privilege.drop_session_password()   # a held password that no longer works
                self.error_occurred.emit(P.outcome_message(outcome, method, err))
                return None
            if method in (P.SUDO_CACHED, P.ASKPASS, P.PASSWORD):
                privilege.note_sudo_used()     # so it can be forgotten on exit
            return self._parse(out)
        self.error_occurred.emit(P.outcome_message(last, order[-1]))
        return None

    def _finish(self, result, method):
        if result is None:
            self.error_occurred.emit("Scan cancelled.")
            return None
        code, out, err = result
        if code != 0:
            self.error_occurred.emit(nmap_error_message(err))
            return None
        return self._parse(out)

    @staticmethod
    def _parse(xml: str) -> dict:
        return nmap.PortScanner().analyse_nmap_xml_scan(xml).get("scan", {})


class ScannerThread(_NmapThread):
    """Subnet discovery for the Network Scanner tab."""

    def __init__(self, target, privileged=True, thorough=False, password=None,
                 mode=P.POLKIT_MODE):
        super().__init__()
        self.target     = target
        self.privileged = privileged
        self.thorough   = thorough
        self.password   = password
        self.mode       = mode

    @property
    def use_sudo(self) -> bool:            # older name, still read by the tab
        return self.privileged

    def run(self):
        try:
            scan = self._run_nmap(subnet_scan_args(self.target, self.privileged, self.thorough))
            if scan is not None:
                self.results_ready.emit(parse_subnet_scan(scan))
        except Exception as e:
            self.error_occurred.emit(str(e))


class HostScanThread(_NmapThread):
    """Single-host port + version scan for the Host Inspector tab.
    Emits a list of {port, protocol, state, service, version}."""
    progress_msg = pyqtSignal(str)

    def __init__(self, ip: str, mode: str = "quick", custom_ports: str = "",
                 privileged: bool = True, password: str | None = None, parent=None,
                 privilege_mode: str = P.POLKIT_MODE):
        super().__init__(parent)
        self.ip           = ip
        self.scan_mode    = mode
        self.mode         = privilege_mode
        self.custom_ports = custom_ports.strip()
        self.privileged   = privileged
        self.password     = password

    def run(self):
        try:
            args = host_scan_args(self.ip, self.scan_mode, self.privileged, self.custom_ports)
        except ValueError as e:
            self.error_occurred.emit(str(e))
            return
        try:
            scan = self._run_nmap(args)
            if scan is not None:
                self.results_ready.emit(parse_host_scan(scan, self.ip))
        except Exception as e:
            self.error_occurred.emit(str(e))
