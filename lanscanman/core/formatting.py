"""
Human-readable formatting and the traffic-light colour thresholds shared by
every tab. Pure functions — no Qt.
"""

from datetime import timedelta

# Palette (matches THEME in ui/theme.py)
GOOD  = "#27ae60"
WARN  = "#f39c12"
BAD   = "#c0392b"
MUTED = "#9AA4AF"


# ── Sizes and durations ──────────────────────────────────────────────────────

def fmt_bytes(n) -> str:
    """1536 -> '1.5 KB'. None -> '?'. Accepts ints or rsync-style '1,234'."""
    if n is None:
        return "?"
    if isinstance(n, str):
        try:
            n = int(n.replace(",", ""))
        except ValueError:
            return n
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def fmt_mb(mb) -> str:
    if mb is None:
        return "?"
    if mb >= 1024:
        return f"{mb / 1024:.1f} GB"
    return f"{mb} MB"


def fmt_uptime(seconds: float) -> str:
    """90061 -> '1d 1h 1m'. Minutes are always shown."""
    td = timedelta(seconds=int(seconds))
    hours   = td.seconds // 3600
    minutes = (td.seconds % 3600) // 60
    parts = []
    if td.days:
        parts.append(f"{td.days}d")
    if hours:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def fmt_hours(h) -> str:
    """Power-on hours -> '2y 10d', '3d 4h' or '5h'."""
    if h is None:
        return "?"
    h = int(h)
    days, hours = divmod(h, 24)
    if days >= 365:
        years, rem = divmod(days, 365)
        return f"{years}y {rem}d"
    if days:
        return f"{days}d {hours}h"
    return f"{hours}h"


def fmt_eta(raw: str) -> str:
    """rsync 'H:MM:SS' or 'MM:SS' -> '1h 2m' / '2m 5s' / '5s'. Unparseable input is returned as-is."""
    try:
        parts = [int(p) for p in raw.split(":")]
    except ValueError:
        return raw
    if len(parts) == 3:
        h, m, s = parts
        if h:
            return f"{h}h {m}m"
    elif len(parts) == 2:
        m, s = parts
    else:
        return raw
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def fmt_speed_eta(speed: str, eta: str) -> str:
    parts = []
    if speed:
        parts.append(speed)
    if eta:
        parts.append(fmt_eta(eta))
    return "  ·  ".join(parts) if parts else "—"


# ── Colour thresholds ────────────────────────────────────────────────────────

def usage_color(pct) -> str:
    """CPU / RAM / GPU utilisation."""
    if pct is None:
        return MUTED
    if pct < 60:
        return GOOD
    if pct < 85:
        return WARN
    return BAD


def disk_temp_color(c) -> str:
    if c is None:
        return MUTED
    if c < 40:
        return GOOD
    if c < 55:
        return WARN
    return BAD


def hw_temp_color(c) -> str:
    """CPU / GPU die temperature — these run hotter than disks."""
    if c is None:
        return MUTED
    if c < 65:
        return GOOD
    if c < 85:
        return WARN
    return BAD


def wear_color(pct_used) -> str:
    """pct_used = 0 (new) … 100 (fully worn)."""
    if pct_used is None:
        return MUTED
    if pct_used < 50:
        return GOOD
    if pct_used < 80:
        return WARN
    return BAD


def bad_sector_color(n) -> str:
    if n is None:
        return MUTED
    return BAD if n > 0 else GOOD
