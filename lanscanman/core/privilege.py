"""
Running privileged scans without LanScanMan handling your password, using
only what the system already has — nothing is installed.

Two modes, chosen in ⚙ (a signed security setting):

  polkit (default) — asks every scan, LanScanMan never sees the password:
    pkexec        your desktop's authentication agent
    pkexec_tty    polkit's text agent (pkttyagent) in a terminal, for desktops
                  with no agent running
    askpass       `sudo -A` with a graphical askpass, for systems without polkit

  sudo — remembered by sudo itself for ~15 minutes:
    sudo_cached   `sudo -n` — succeeds while sudo still remembers you
    askpass       `sudo -A` with a graphical askpass program, if installed
    password      otherwise LanScanMan's own password box → `sudo -S`, once;
                  the password is not kept — sudo's cache does the remembering

  sudo_session — INSECURE, opt-in: like sudo, but LanScanMan's password box
    keeps the password in memory until the app closes and re-supplies it
    whenever sudo's own memory has expired. Never written to disk or logged;
    dropped on Forget, mode change, rejection and exit.

Without a terminal, sudo keys its credential cache to the parent process
(timestamp_type=tty falls back to ppid), i.e. to LanScanMan itself, so the
cache isn't shared with anything else you run. `sudo -k` clears it; the app
does that on exit.

Before asking for permission, the nmap arguments are checked against the
shapes LanScanMan itself generates (validate_scan_args), so nothing typed
into the app — e.g. a custom port list — can smuggle in --script, output
files or extra targets.
"""

from __future__ import annotations

import ipaddress
import re

PKEXEC, PKEXEC_TTY, ASKPASS, PASSWORD = "pkexec", "pkexec_tty", "askpass", "password"
SUDO_CACHED = "sudo_cached"
POLKIT_MODE, SUDO_MODE, SUDO_SESSION_MODE = "polkit", "sudo", "sudo_session"
MODES = (POLKIT_MODE, SUDO_MODE, SUDO_SESSION_MODE)


# ── Argument check ───────────────────────────────────────────────────────────

_FLAGS = {"-sS", "-sT", "-sV", "-PR", "-p-", "-T3", "-T4"}
_PORTSPEC = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")


def _int_in(value, low, high):
    return value.isdigit() and low <= int(value) <= high


def _ports_ok(spec):
    if not _PORTSPEC.match(spec):
        return False
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        lo, hi = int(lo), int(hi or lo)
        if not (1 <= lo <= hi <= 65535):
            return False
    return True


def _target_ok(target):
    if target.startswith("-"):
        return False
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False


def validate(args):
    """None if acceptable, otherwise the reason it was refused."""
    args = list(args)
    if not args:
        return "no arguments"
    target = args.pop()
    if not _target_ok(target):
        return f"target must be one IP address or network, got {target!r}"
    scan_types = 0
    output = False
    i = 0
    while i < len(args):
        a = args[i]
        value = args[i + 1] if i + 1 < len(args) else None
        if a in _FLAGS:
            scan_types += a in ("-sS", "-sT")
            i += 1
            continue
        if a == "-p" and value is not None and _ports_ok(value):
            pass
        elif a == "--top-ports" and value is not None and _int_in(value, 1, 65535):
            pass
        elif a == "--version-intensity" and value is not None and _int_in(value, 0, 9):
            pass
        elif a == "--max-retries" and value is not None and _int_in(value, 0, 10):
            pass
        elif a == "--host-timeout" and value is not None and value.endswith("s") \
                and _int_in(value[:-1], 1, 3600):
            pass
        elif a == "-oX" and value == "-":
            output = True
        else:
            return f"option not allowed: {a!r}"
        i += 2
    if scan_types != 1:
        return "exactly one of -sS / -sT is required"
    if not output:
        return "-oX - is required"
    return None


def validate_scan_args(args: list[str]) -> str | None:
    """None if these are nmap arguments LanScanMan would generate, else why not."""
    return validate(args)


# ── Outcomes ─────────────────────────────────────────────────────────────────

OK, CANCELLED, NO_AGENT, DENIED, FAILED = "ok", "cancelled", "no_agent", "denied", "failed"
NEEDS_PASSWORD = "needs_password"          # sudo -n: nothing remembered right now


def classify(method: str, returncode: int, stderr: str) -> str:
    """Turn a privileged run's exit into an outcome."""
    err = stderr.lower()
    if returncode == 0:
        return OK
    if method in (PKEXEC, PKEXEC_TTY):
        if "no authentication agent" in err:
            return NO_AGENT
        if returncode == 126:
            return CANCELLED                     # dialog dismissed
        if returncode == 127:
            return DENIED                        # not authorised
        return FAILED
    # sudo
    if method == SUDO_CACHED:
        if "password is required" in err or "a terminal is required" in err:
            return NEEDS_PASSWORD
        return FAILED
    if "no password was provided" in err or "askpass" in err and "cancel" in err:
        return CANCELLED
    if ("incorrect password" in err or "a password is required" in err
            or "sorry, try again" in err or "not in the sudoers" in err):
        return DENIED
    return FAILED


def outcome_message(outcome: str, method: str, stderr: str = "") -> str:
    if outcome == CANCELLED:
        return "Scan cancelled — permission was not granted."
    if outcome == DENIED:
        return ("Permission denied — the password was wrong, or this account isn't "
                "allowed to run privileged scans.")
    if outcome == NO_AGENT:
        return "No authentication agent is running to ask for your password."
    if outcome == NEEDS_PASSWORD:
        return "sudo no longer remembers your password — scan again to be asked for it."
    return f"Nmap error: {stderr.strip()}"
