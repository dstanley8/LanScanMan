"""Local WiFi signal strength, read from /proc/net/wireless (no tools needed)."""

from __future__ import annotations

import re
from pathlib import Path

from lanscanman.core.formatting import BAD, GOOD, MUTED, WARN

PROC_WIRELESS = Path("/proc/net/wireless")

_LINE_RE = re.compile(r"^\s*(\w+):\s+\S+\s+\S+\s+([-\d]+)")


def parse_proc_wireless(text: str) -> tuple[str | None, int | None]:
    """
    Return (interface, signal_dbm) for the first wireless interface, or
    (None, None) if there is none. dBm is None when the level is not meaningful.

    Format (kernel >= 2.4):
      Inter-| sta-|   Quality        |   Discarded ...
       face | tus | link level noise | ...
      wlan0: 0000   55.  -55.  -256 ...
                         ^^^^ signal level in dBm; trailing dot = "updated"
    """
    for line in text.splitlines():
        m = _LINE_RE.match(line)
        if not m:
            continue
        iface = m.group(1)
        try:
            dbm = int(m.group(2).replace(".", ""))
        except ValueError:
            return iface, None
        # Some kernels report 0 when disconnected; real RSSI is negative
        return iface, (dbm if dbm < 0 else None)
    return None, None


def read_wifi(path: Path = PROC_WIRELESS) -> tuple[str | None, int | None]:
    try:
        return parse_proc_wireless(path.read_text())
    except OSError:
        return None, None


def signal_quality(dbm: int | None) -> str:
    if dbm is None:
        return "Unknown"
    if dbm >= -50:
        return "Excellent"
    if dbm >= -65:
        return "Good"
    if dbm >= -75:
        return "Fair"
    if dbm >= -85:
        return "Weak"
    return "Very weak"


def dbm_to_label(dbm: int | None) -> tuple[str, str]:
    """(status-bar text, hex colour) for a signal level."""
    if dbm is None:
        return "WiFi: ?", MUTED
    if dbm >= -50:
        return f"WiFi: {dbm} dBm  ▂▄▆█", GOOD
    if dbm >= -65:
        return f"WiFi: {dbm} dBm  ▂▄▆_", GOOD
    if dbm >= -75:
        return f"WiFi: {dbm} dBm  ▂▄__", WARN
    if dbm >= -85:
        return f"WiFi: {dbm} dBm  ▂___", WARN
    return f"WiFi: {dbm} dBm  ____", BAD
