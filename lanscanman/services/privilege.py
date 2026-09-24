"""
Detecting and using the system's own ways of running a privileged scan
(see core/privilege.py for the order and why). LanScanMan never sees your
password except in the opt-in `password` method, and installs nothing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

from lanscanman.core import privilege as P
from lanscanman.core.connect import get_terminal_command, terminal_argv

# Graphical password prompts sudo can use (sudo -A)
ASKPASS_CANDIDATES = (
    "/usr/bin/ssh-askpass", "/usr/lib/ssh/ssh-askpass", "/usr/lib/openssh/gnome-ssh-askpass",
    "/usr/libexec/openssh/gnome-ssh-askpass", "/usr/libexec/openssh/ssh-askpass",
    "/usr/bin/ksshaskpass", "/usr/bin/lxqt-openssh-askpass", "/usr/bin/x11-ssh-askpass",
)
TTY_AGENT_SECONDS = 300          # the terminal agent closes itself after this


@dataclass
class Capabilities:
    pkexec: str | None = None
    pkttyagent: str | None = None
    terminal: list[str] | None = None
    sudo: str | None = None
    askpass: str | None = None
    nmap: str | None = None


def detect(which=shutil.which, exists=os.path.exists,
           terminal=get_terminal_command) -> Capabilities:
    caps = Capabilities(pkexec=which("pkexec"), pkttyagent=which("pkttyagent"),
                        sudo=which("sudo"), nmap=which("nmap"))
    caps.terminal = terminal()
    env_askpass = os.environ.get("SUDO_ASKPASS")
    for candidate in ([env_askpass] if env_askpass else []) + list(ASKPASS_CANDIDATES):
        if candidate and exists(candidate):
            caps.askpass = candidate
            break
    return caps


def methods(caps: Capabilities, mode: str = P.POLKIT_MODE) -> list[str]:
    """Methods that don't need LanScanMan's password box, in the order to try
    them. In sudo mode the first is 'use what sudo remembers'."""
    if not caps.nmap:
        return []
    out = []
    if mode in (P.SUDO_MODE, P.SUDO_SESSION_MODE):
        if caps.sudo:
            out.append(P.SUDO_CACHED)
            if caps.askpass and mode == P.SUDO_MODE:
                out.append(P.ASKPASS)          # session mode uses its own password box
        return out
    if caps.pkexec:
        out.append(P.PKEXEC)
        if caps.pkttyagent and caps.terminal:
            out.append(P.PKEXEC_TTY)
    if caps.sudo and caps.askpass:
        out.append(P.ASKPASS)
    return out


def command(method: str, caps: Capabilities, nmap_args: list[str]) -> tuple[list[str], dict]:
    """(argv, extra environment) for one privileged nmap run."""
    target = caps.nmap
    if method in (P.PKEXEC, P.PKEXEC_TTY):
        return [caps.pkexec, target, *nmap_args], {}
    if method == P.SUDO_CACHED:
        return [caps.sudo, "-n", target, *nmap_args], {}
    if method == P.ASKPASS:
        return [caps.sudo, "-A", target, *nmap_args], {"SUDO_ASKPASS": caps.askpass}
    if method == P.PASSWORD:
        return [caps.sudo, "-S", "-p", "", target, *nmap_args], {}
    raise ValueError(method)


def start_tty_agent(caps: Capabilities, pid: int | None = None, popen=subprocess.Popen):
    """Open a terminal running polkit's text agent for this process, so pkexec
    can ask for the password there. Closes itself after a few minutes."""
    pid = pid or os.getpid()
    script = (f"echo 'LanScanMan is asking for permission to run a network scan.'; "
              f"echo 'Type your password below — it goes to polkit, not to LanScanMan.'; echo; "
              f"timeout {TTY_AGENT_SECONDS} {caps.pkttyagent} --process {pid} --fallback")
    return popen(terminal_argv(caps.terminal, script, then=""),
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ── sudo's own credential cache ──────────────────────────────────────────────

_sudo_used = False

# INSECURE session mode only: the password, held until the app closes.
# Never written anywhere; see forget().
_session_password: str | None = None


def remember_session_password(password: str) -> None:
    global _session_password
    _session_password = password


def session_password() -> str | None:
    return _session_password


def drop_session_password() -> None:
    global _session_password
    _session_password = None


def note_sudo_used() -> None:
    global _sudo_used
    _sudo_used = True


def sudo_remembers(caps: Capabilities, run=subprocess.run) -> bool:
    """True while sudo still remembers this process's authentication."""
    if not caps.sudo:
        return False
    try:
        return run([caps.sudo, "-n", "true"], capture_output=True, timeout=5).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def forget(caps: Capabilities | None = None, run=subprocess.run) -> bool:
    """`sudo -k`: make sudo forget the remembered authentication now, and drop
    any password held for the insecure session mode."""
    global _sudo_used
    drop_session_password()
    caps = caps or detect()
    if not caps.sudo:
        return False
    try:
        ok = run([caps.sudo, "-k"], capture_output=True, timeout=5).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
    _sudo_used = False
    return ok


def forget_if_used(run=subprocess.run) -> None:
    """At exit: don't leave sudo's cache (or a held password) behind."""
    drop_session_password()
    if _sudo_used:
        forget(run=run)
