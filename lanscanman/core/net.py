"""Small network helpers: Wake-on-LAN packets, ping output, MAC addresses."""

from __future__ import annotations

import re

_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$")


def is_mac(value: str | None) -> bool:
    return bool(value) and bool(_MAC_RE.match(value))


def magic_packet(mac: str) -> bytes:
    """Wake-on-LAN payload: 6 x 0xFF then the MAC repeated 16 times."""
    clean = mac.replace(":", "").replace("-", "")
    return bytes.fromhex("FF" * 6 + clean * 16)


def parse_ping_latency(stdout: str) -> str | None:
    """'…time=0.412 ms' -> '0.4ms'; None if no reply line is present."""
    for line in stdout.splitlines():
        if "time=" in line:
            return f"{float(line.split('time=')[1].split(' ')[0]):.1f}ms"
    return None
