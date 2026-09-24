"""
SMART attribute history: storage, de-duplication and worsening alerts.
The chart that draws it lives in ui/dialogs/smart_history.py.

Storage: ~/.config/LanScanMan/smart_log/<profile_key>.json
One file per host. One entry per disk per "state change" using a
first-seen / last-seen deduplication strategy:

  - Only the attributes that indicate permanent degradation are tracked:
    reallocated, pending, uncorrectable, wear_pct_used, tbw_tb.
    power_on_hours is recorded for context but does NOT trigger new entries.
  - Temperature is intentionally excluded — it is session-only UI data.
  - When a new probe result matches the last committed attribute set,
    the "last_seen" timestamp of the current entry is updated in-place.
  - When attributes change, the current entry is finalised and a new one
    starts. This means any stable period is represented by exactly two
    timestamps: first_seen and last_seen.

Alert: if degradation attributes worsen (increase), a notify-send
desktop notification is fired immediately.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from lanscanman import paths
from lanscanman.core.notify import notify
from lanscanman.log import log

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

LOG_DIR = paths.SMART_LOG_DIR

# Attributes that trigger a new log entry when they change
_CHANGE_KEYS = ("reallocated", "pending", "uncorrectable", "wear_pct_used", "tbw_tb")

# Increases in these are damage worth a notification. TBW is not: it grows
# with normal use, so it's recorded (and charted) but never alerts.
_ALERT_KEYS = tuple(k for k in _CHANGE_KEYS if k != "tbw_tb")

# Attributes stored in each entry (context only — do not trigger new entries)
_CONTEXT_KEYS = ("power_on_hours",)


def smart_log_key(dev: str, serial: str | None) -> str:
    """
    Return the stable key used to index a disk in the SMART log.

    Prefer serial number: it is tied to the physical drive and survives moves
    between bays, ports, or controllers.  Fall back to the kernel device node
    (sda, nvme0n1, …) only when no serial is available.
    """
    s = (serial or "").strip()
    return s if s else dev


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _extract_attrs(disk: dict) -> dict:
    """Pull the loggable attributes from a parsed disk dict."""
    return {k: disk.get(k) for k in _CHANGE_KEYS + _CONTEXT_KEYS}


def _change_keys_equal(a: dict, b: dict) -> bool:
    """True if the degradation-triggering keys are identical between two attr dicts."""
    return all(a.get(k) == b.get(k) for k in _CHANGE_KEYS)


def _attrs_worsened(old: dict, new: dict) -> list[str]:
    """
    Return a list of human-readable descriptions of any attributes that
    increased (worsened) between two attr dicts.
    Only considers _CHANGE_KEYS that are numeric and increased.
    """
    worsened = []
    labels = {
        "reallocated":    "Reallocated sectors",
        "pending":        "Pending sectors",
        "uncorrectable":  "Uncorrectable errors",
        "wear_pct_used":  "Wear",
        "tbw_tb":         "TBW",
    }
    for k in _ALERT_KEYS:
        old_v = old.get(k)
        new_v = new.get(k)
        if old_v is None or new_v is None:
            continue
        try:
            if float(new_v) > float(old_v):
                worsened.append(
                    f"{labels.get(k, k)}: {old_v} → {new_v}")
        except (TypeError, ValueError):
            pass
    return worsened


# ─────────────────────────────────────────────────────────────────────────────
# Logger
# ─────────────────────────────────────────────────────────────────────────────

class SmartLogger:
    """
    Reads and writes SMART history for a single host.

    profile_key: the key used in hosts.json (MAC or IP)
    alias:       human-readable host name for notifications
    """

    def __init__(self, profile_key: str, alias: str = "",
                 log_dir: Path | None = None, notifier=notify):
        self.profile_key = profile_key.replace(":", "-")   # safe filename
        self.alias       = alias or profile_key
        self._dir        = log_dir or LOG_DIR
        self._path       = self._dir / f"{self.profile_key}.json"
        self._notify     = notifier
        self._data       = self._load()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self) -> dict:
        if not self._path.exists():
            return {}
        try:
            return json.loads(self._path.read_text())
        except Exception:
            # Corrupted log file — log it so the user can see why their
            # history has vanished rather than silently resetting.
            log.exception("SMART log file is corrupt or unreadable: %s",
                          self._path)
            return {}

    def _save(self):
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._data, indent=2))

    # ── Public API ────────────────────────────────────────────────────────────

    def record(self, disks: list[dict]):
        """
        Record a probe result for all disks on this host.
        Applies first-seen / last-seen deduplication.
        Fires a desktop notification if any disk has worsened.
        """
        changed = False
        for disk in disks:
            dev    = disk.get("dev", "unknown")
            key    = smart_log_key(dev, disk.get("serial"))
            attrs  = _extract_attrs(disk)
            changed |= self._record_disk(key, dev, disk, attrs)

        if changed:
            self._save()

    def _record_disk(self, key: str, dev: str, disk: dict, attrs: dict) -> bool:
        """
        Update history for one disk. Returns True if the log was modified.
        key  — stable log key (serial number, or dev name if no serial)
        dev  — kernel device node name (for notification messages)
        """
        disk_data = self._data.setdefault(key, {
            "model":   disk.get("model", ""),
            "serial":  disk.get("serial", ""),
            "history": [],
        })

        # Keep model/serial current in case we get better data later
        if disk.get("model"):
            disk_data["model"]  = disk["model"]
        if disk.get("serial"):
            disk_data["serial"] = disk["serial"]

        history = disk_data["history"]
        now     = _now()

        if not history:
            # First ever entry
            history.append({
                "first_seen": now,
                "last_seen":  now,
                **attrs,
            })
            return True

        last = history[-1]

        if _change_keys_equal(last, attrs):
            # Same state — just update last_seen timestamp in-place
            if last["last_seen"] != now:
                last["last_seen"] = now
                return True
            return False

        # State has changed — check for worsening and notify
        worsened = _attrs_worsened(last, attrs)
        if worsened:
            body = f"/dev/{dev} on {self.alias}:\n" + "\n".join(worsened)
            self._notify("⚠ Disk health change detected", body, critical=True)

        # Commit a new entry
        history.append({
            "first_seen": now,
            "last_seen":  now,
            **attrs,
        })
        return True

    def get_history(self, dev: str) -> tuple[dict, list[dict]]:
        """
        Return (disk_meta, history_list) for a device, or ({}, []) if none.
        history_list entries have: first_seen, last_seen, + all attrs.
        """
        disk_data = self._data.get(dev, {})
        return (
            {"model": disk_data.get("model", ""), "serial": disk_data.get("serial", "")},
            disk_data.get("history", []),
        )

    def all_disks(self) -> dict[str, tuple[dict, list[dict]]]:
        """{log key: (meta, history)} for every disk ever recorded on this host."""
        return {key: self.get_history(key) for key in self._data}

    def has_history(self, dev: str) -> bool:
        return dev in self._data and len(self._data[dev].get("history", [])) > 0
