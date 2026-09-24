"""
Drive-health reports for a local AI to interpret.

LanScanMan does the arithmetic (trends, rates, projections, its own
rule-based view) and states it as plain facts; the AI's job is to interpret,
not to calculate — small local models are unreliable at maths. The report is
shown to the user, editable, before anything is sent.

Pure: disk dicts come from core.smart, history from core.smart_history.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from lanscanman.core.formatting import fmt_bytes

SYSTEM_PROMPT = """\
You are a storage-reliability assistant helping someone look after the disks \
on their home network. You will be given drive reports produced by \
LanScanMan: current SMART readings, trends it has already calculated from its \
own history log, and its simple rule-based view.

For each disk:
1. Give a verdict: OK / Keep an eye on it / Plan a replacement / Replace now.
2. Explain it using the specific numbers in the report.
3. Suggest practical next steps — for example backing up, running a long \
SMART self-test, checking cooling or cabling. Show any command as a command \
for the user to run; LanScanMan will not run anything itself.

Rules:
- Use only the data given. If something needed isn't there, say it's unknown.
- Trust the trends and rates as given; don't recalculate them.
- Attribute meanings vary between manufacturers (especially wear and \
temperature attributes) — say so when it matters.
- Be direct and concise. When there are several disks, start with the ones \
that need attention."""

_CHANGE_LABELS = {
    "reallocated":   "Reallocated sectors",
    "pending":       "Pending sectors",
    "uncorrectable": "Uncorrectable errors",
}


@dataclass
class DiskData:
    """One disk: its latest reading (may be None if only history exists)
    and its history entries from the SMART log."""
    key: str                                  # serial, or device name
    dev: str = ""
    reading: dict | None = None
    meta: dict = field(default_factory=dict)  # {"model", "serial"} from the log
    history: list[dict] = field(default_factory=list)


@dataclass
class HostData:
    label: str                                # alias or hostname
    ip: str
    disks: list[DiskData] = field(default_factory=list)
    read_at: datetime | None = None           # when the current readings were taken


# ── Small helpers ────────────────────────────────────────────────────────────

def _date(iso: str | None) -> str:
    return (iso or "?")[:10]


def _parse(iso: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(iso) if iso else None
    except ValueError:
        return None


def disk_kind(disk: dict) -> str:
    dev, model = disk.get("dev", ""), (disk.get("model") or "").upper()
    if dev.startswith("nvme") or disk.get("available_spare_pct") is not None:
        return "NVMe SSD"
    if disk.get("wear_pct_used") is not None or "SSD" in model:
        return "SATA SSD"
    return "hard drive (or SSD without wear data)"


def age_text(hours) -> str:
    if hours is None:
        return "unknown"
    years = hours / 8766
    return f"{hours:,} h (about {years:.1f} years powered on)" if years >= 0.1 else f"{hours:,} h"


# ── Trends: calculated here, stated as facts ─────────────────────────────────

def trends(history: list[dict], now: datetime | None = None) -> list[str]:
    """Plain-language trend statements from a disk's history entries."""
    if not history:
        return ["No history recorded yet — only the current reading is available."]
    now = now or datetime.now()
    out: list[str] = []
    start, end = history[0].get("first_seen"), history[-1].get("last_seen")
    span_days = None
    if _parse(start) and _parse(end):
        span_days = (_parse(end) - _parse(start)).days
        out.append(f"History covers {_date(start)} to {_date(end)} ({span_days} days, "
                   f"{len(history)} recorded state(s)).")

    for key, label in _CHANGE_LABELS.items():
        values = [(h.get("first_seen"), h.get(key)) for h in history if h.get(key) is not None]
        if not values:
            continue
        first, last = values[0][1], values[-1][1]
        if last == 0 and first == 0:
            out.append(f"{label}: 0 throughout.")
            continue
        first_nonzero = next((d for d, v in values if v), None)
        rises = [(d, v) for (d, v), (_, prev) in zip(values[1:], values) if v > prev]
        text = f"{label}: {first} → {last}"
        if first_nonzero:
            text += f" (first non-zero on {_date(first_nonzero)})"
        if rises:
            last_rise = _parse(rises[-1][0])
            days_since = (now - last_rise).days if last_rise else None
            text += f"; increased {len(rises)} time(s), most recently {_date(rises[-1][0])}"
            if days_since is not None:
                text += (" — still rising recently" if days_since <= 30
                         else f" — stable for {days_since} days since")
        elif last:
            text += "; not increasing during the recorded history"
        out.append(text + ".")

    for key, label, unit in (("wear_pct_used", "Wear used", "%"), ("tbw_tb", "Data written", " TB")):
        points = [(_parse(h.get("first_seen")), h.get(key)) for h in history
                  if h.get(key) is not None and _parse(h.get("first_seen"))]
        if len(points) < 2:
            continue
        (t0, v0), (t1, v1) = points[0], points[-1]
        months = (t1 - t0).days / 30.44
        if months < 0.5 or v1 == v0:
            out.append(f"{label}: {v0}{unit} → {v1}{unit} (too little change to estimate a rate).")
            continue
        per_month = (v1 - v0) / months
        text = (f"{label}: {v0}{unit} → {v1}{unit} over {months:.1f} months "
                f"(about {per_month:.2f}{unit} per month")
        if key == "tbw_tb":
            text += f", {per_month * 12:.1f} TB per year"
        text += ")"
        if key == "wear_pct_used" and per_month > 0 and v1 < 100:
            years_left = (100 - v1) / per_month / 12
            text += f"; at this rate it would reach 100% in about {years_left:.1f} years"
        out.append(text + ".")
    return out


def rule_view(disk: dict | None, history: list[dict]) -> str:
    """LanScanMan's own simple assessment, using the same thresholds as its
    colour coding — given to the AI as a starting point, not a conclusion."""
    if not disk:
        return "No current reading — only history is available."
    if not disk.get("smart_available", True):
        return "SMART data not available for this disk."
    notes = []
    if disk.get("smart_ok") is False:
        notes.append("SMART self-assessment FAILED")
    bad = {k: disk.get(k) for k in _CHANGE_LABELS if disk.get(k)}
    if bad:
        rising = any("still rising" in t for t in trends(history)) if history else False
        notes.append(("bad sectors, still increasing" if rising else "bad sectors (not increasing)")
                     + " — " + ", ".join(f"{_CHANGE_LABELS[k].lower()} {v}" for k, v in bad.items()))
    wear = disk.get("wear_pct_used")
    if wear is not None and wear >= 80:
        notes.append(f"heavily worn ({wear}% used)")
    elif wear is not None and wear >= 50:
        notes.append(f"wearing ({wear}% used)")
    spare = disk.get("available_spare_pct")
    if spare is not None and spare < 20:
        notes.append(f"low spare capacity ({spare}%)")
    temp = disk.get("temperature_c")
    if temp is not None and temp >= 55:
        notes.append(f"running hot ({temp} °C)")
    elif temp is not None and temp >= 40:
        notes.append(f"warm ({temp} °C)")
    return "; ".join(notes) if notes else "no problems found by LanScanMan's thresholds."


# ── Report sections ──────────────────────────────────────────────────────────

_HISTORY_ROWS = 12


def _reading_lines(d: dict) -> list[str]:
    def show(v, suffix=""):
        return "unknown" if v is None else f"{v}{suffix}"
    ok = d.get("smart_ok")
    lines = [
        f"- SMART self-assessment: {'PASSED' if ok else 'FAILED' if ok is False else 'unknown'}"
        f" (read via {d.get('smart_method') or 'nothing — SMART unavailable'})",
        f"- Temperature: {show(d.get('temperature_c'), ' °C')}",
        f"- Power-on time: {age_text(d.get('power_on_hours'))}",
        f"- Reallocated sectors: {show(d.get('reallocated'))}",
        f"- Pending sectors: {show(d.get('pending'))}",
        f"- Uncorrectable errors: {show(d.get('uncorrectable'))}",
        f"- Wear used: {show(d.get('wear_pct_used'), '%')}",
    ]
    if d.get("available_spare_pct") is not None:
        lines.append(f"- Available spare: {d['available_spare_pct']}%")
    lines.append(f"- Data written: {show(d.get('tbw_tb'), ' TB')}")
    if d.get("fs_total_bytes"):
        pct = 100 * (d.get("fs_used_bytes") or 0) / d["fs_total_bytes"]
        lines.append(f"- Filesystems on it: {fmt_bytes(d.get('fs_used_bytes'))} used of "
                     f"{fmt_bytes(d['fs_total_bytes'])} ({pct:.0f}%)")
    return lines


def _history_table(history: list[dict]) -> list[str]:
    rows = history[-_HISTORY_ROWS:]
    out = ["History (each row is a period with unchanged readings):",
           "first seen | last seen | realloc | pending | uncorr | wear % | TB written | power-on h"]
    if len(history) > len(rows):
        out.append(f"(… {len(history) - len(rows)} earlier row(s) omitted; the trends above cover them)")
    for h in rows:
        cells = [_date(h.get("first_seen")), _date(h.get("last_seen"))] + [
            "-" if h.get(k) is None else str(h.get(k))
            for k in ("reallocated", "pending", "uncorrectable", "wear_pct_used",
                      "tbw_tb", "power_on_hours")]
        out.append(" | ".join(cells))
    return out


def disk_section(host: HostData, disk: DiskData, now: datetime | None = None) -> str:
    d = disk.reading or {}
    model = d.get("model") or disk.meta.get("model") or "unknown model"
    serial = d.get("serial") or disk.meta.get("serial") or "unknown"
    size = fmt_bytes(d["capacity_bytes"]) if d.get("capacity_bytes") else "unknown size"
    kind = disk_kind(d) if d else "unknown type"
    dev = disk.dev or d.get("dev") or disk.key
    lines = [f"### {model} — /dev/{dev} on {host.label} ({host.ip})",
             f"Type: {kind}, {size}. Serial: {serial}."]
    if disk.reading:
        when = host.read_at.strftime("%Y-%m-%d %H:%M") if host.read_at else "this session"
        lines.append(f"Current reading ({when}):")
        lines += _reading_lines(d)
    else:
        lines.append("No current reading this session — history only.")
    lines.append("Trends (calculated by LanScanMan from its history log):")
    lines += [f"- {t}" for t in trends(disk.history, now)]
    lines.append(f"LanScanMan's rule-based view: {rule_view(disk.reading, disk.history)}")
    if disk.history:
        lines += _history_table(disk.history)
    return "\n".join(lines)


# ── The three scopes ─────────────────────────────────────────────────────────

def disk_request(host: HostData, disk: DiskData, now: datetime | None = None) -> str:
    return ("Please assess the health of this disk and tell me what, if anything, I "
            "should do about it.\n\n" + disk_section(host, disk, now))


def host_request(host: HostData, now: datetime | None = None) -> str:
    body = "\n\n".join(disk_section(host, d, now) for d in host.disks) or "(no disks)"
    return (f"Please assess the health of the {len(host.disks)} disk(s) in {host.label} "
            f"({host.ip}). Start with any that need attention, then summarise the rest.\n\n"
            f"## {host.label} ({host.ip})\n\n" + body)


def fleet_request(hosts: list[HostData], now: datetime | None = None) -> str:
    total = sum(len(h.disks) for h in hosts)
    parts = [f"## {h.label} ({h.ip})\n\n" + "\n\n".join(disk_section(h, d, now) for d in h.disks)
             for h in hosts if h.disks]
    return (f"Please review the health of all {total} disk(s) across {len(parts)} host(s) on my "
            "network. Rank them by how much attention they need, give each a verdict, and "
            "finish with the most important actions overall.\n\n" + "\n\n".join(parts))


def disks_for_host(readings: list[dict] | None, logged: dict[str, tuple[dict, list[dict]]],
                   key_for) -> list[DiskData]:
    """Merge the current readings with every disk in the SMART log (so disks
    only seen in history are included). key_for(disk) -> log key."""
    out: list[DiskData] = []
    seen = set()
    for r in readings or []:
        key = key_for(r)
        meta, history = logged.get(key, ({}, []))
        out.append(DiskData(key=key, dev=r.get("dev", ""), reading=r, meta=meta, history=history))
        seen.add(key)
    for key, (meta, history) in logged.items():
        if key not in seen and history:
            out.append(DiskData(key=key, dev="", reading=None, meta=meta, history=history))
    return out
