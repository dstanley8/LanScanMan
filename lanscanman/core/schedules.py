"""
Scheduled rsync lists for LanScanMan.

Provides:
- ScheduleManager: load/save schedules with HMAC integrity verification
- Schedule: a named collection of rsync transfers with a trigger
- Path validation to reject shell metacharacters
- HMAC-SHA256 of schedules.json (see core/integrity.py for the key)

File layout under ~/.config/LanScanMan/:
    schedules.json   # the data (600)
    schedules.hmac   # hex HMAC of schedules.json content (600)
"""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from lanscanman import paths
from lanscanman.core.integrity import (
    IntegrityError,
    KeyUnavailable,
    SignedFile,
    TamperedError,
    load_key,
)
from lanscanman.log import log

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

CONFIG_DIR = paths.CONFIG_DIR
SCHEDULES_PATH = paths.SCHEDULES_FILE
HMAC_PATH = paths.SCHEDULES_HMAC
KEY_PATH = paths.HMAC_KEY

MAX_RUN_LOG = 10
# (key, short label) in display order
DAY_LABELS = [("monday", "Mon"), ("tuesday", "Tue"), ("wednesday", "Wed"),
              ("thursday", "Thu"), ("friday", "Fri"), ("saturday", "Sat"),
              ("sunday", "Sun")]
_WEEKDAY = {"monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3,
            "friday": 4, "saturday": 5, "sunday": 6}
SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------

# Characters that must never appear in a user-supplied path.
# Even with subprocess lists (shell=False) these would indicate tampering
# or confusion, and are never legitimate in a local or remote rsync path.
_FORBIDDEN_PATH_CHARS = set(';&|><$`()\\{}[]!#~%\'"\n\r\t')


def validate_path(path: str) -> tuple[bool, str]:
    """Return (ok, reason). Reject paths containing shell metacharacters."""
    if not path:
        return False, "path is empty"
    bad = [c for c in path if c in _FORBIDDEN_PATH_CHARS]
    if bad:
        unique = sorted(set(bad))
        return False, f"path contains forbidden characters: {''.join(unique)}"
    return True, ""


def validate_args(args: list[str]) -> tuple[bool, str]:
    """
    Return (ok, reason). Each arg must start with '-' and contain no shell
    metacharacters or whitespace. Rejects anything that could inject commands
    into the rsync shell string used for remote-to-remote transfers.
    """
    for i, arg in enumerate(args):
        if not arg:
            return False, f"arg {i} is empty"
        if not arg.startswith("-"):
            return False, f"arg {i} must start with '-': {arg!r}"
        if any(c in arg for c in _FORBIDDEN_PATH_CHARS):
            return False, f"arg {i} contains forbidden characters: {arg!r}"
        if any(c in arg for c in (" ", "\t", "\n", "\r")):
            return False, f"arg {i} contains whitespace: {arg!r}"
    return True, ""


# ---------------------------------------------------------------------------
# Integrity errors
# ---------------------------------------------------------------------------

def _ensure_config_dir(config_dir: Path = CONFIG_DIR) -> None:
    config_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(config_dir, 0o700)
    except OSError:
        pass


class ScheduleIntegrityError(IntegrityError):
    """schedules.json failed verification (tampered, or key unavailable)."""


# A locked/declined keyring surfaces as this; it is also a ScheduleIntegrityError
# so callers that only catch that still disable schedules safely.
class ScheduleKeyUnavailable(ScheduleIntegrityError, KeyUnavailable):
    pass


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Transfer:
    """A single rsync operation within a schedule list."""
    full_source: str = ""
    full_dest: str = ""
    args: list[str] = field(default_factory=list)
    sender_ip: str = ""
    sender_user: str = ""
    receiver_ip: str = ""
    src_path: str = ""
    dst_path: str = ""

    def validate(self) -> tuple[bool, str]:
        # Validate src_path / dst_path (bare paths used for preflight checks)
        ok, reason = validate_path(self.src_path)
        if not ok:
            return False, f"source path {reason}"
        ok, reason = validate_path(self.dst_path)
        if not ok:
            return False, f"destination path {reason}"
        # Validate full_source / full_dest (what actually gets passed to rsync).
        # validate_path accepts user@host:/path format — @ and : are not forbidden.
        ok, reason = validate_path(self.full_source)
        if not ok:
            return False, f"full source {reason}"
        ok, reason = validate_path(self.full_dest)
        if not ok:
            return False, f"full destination {reason}"
        # Validate rsync args — must all start with '-' and contain no
        # metacharacters. Critical for the remote-to-remote bash string path.
        ok, reason = validate_args(self.args)
        if not ok:
            return False, f"rsync args: {reason}"
        return True, ""


@dataclass
class Trigger:
    """How a schedule list decides when to run."""
    type: str = "manual"   # manual | interval | scheduled
    # interval fields
    interval_value: int = 24
    interval_unit: str = "hours"   # minutes | hours | days | months
    # scheduled fields
    days: list[str] = field(default_factory=list)
    time: str = "02:00"   # 24-hour HH:MM

    VALID_DAYS = {"monday", "tuesday", "wednesday", "thursday",
                  "friday", "saturday", "sunday"}
    VALID_UNITS = {"minutes", "hours", "days", "months"}

    def to_timedelta(self) -> timedelta:
        """Convert interval settings to a timedelta (months approximated as 30 days)."""
        v = max(1, self.interval_value)
        if self.interval_unit == "minutes":
            return timedelta(minutes=v)
        if self.interval_unit == "hours":
            return timedelta(hours=v)
        if self.interval_unit == "days":
            return timedelta(days=v)
        if self.interval_unit == "months":
            return timedelta(days=v * 30)
        return timedelta(hours=v)  # safe fallback

    def validate(self) -> tuple[bool, str]:
        if self.type not in ("manual", "interval", "scheduled"):
            return False, f"unknown trigger type: {self.type}"
        if self.type == "interval":
            if self.interval_value < 1:
                return False, "interval value must be >= 1"
            if self.interval_unit not in self.VALID_UNITS:
                return False, f"unknown interval unit: {self.interval_unit}"
        elif self.type == "scheduled":
            if not self.days:
                return False, "scheduled trigger needs at least one day"
            bad = [d for d in self.days if d not in self.VALID_DAYS]
            if bad:
                return False, f"unknown day(s): {', '.join(bad)}"
            if not re.fullmatch(r"\d{2}:\d{2}", self.time):
                return False, f"time must be HH:MM, got {self.time!r}"
            hh, mm = map(int, self.time.split(":"))
            if not (0 <= hh <= 23 and 0 <= mm <= 59):
                return False, f"time out of range: {self.time}"
        return True, ""


@dataclass
class RunLogEntry:
    started: str = ""
    finished: str = ""
    status: str = ""  # completed | failed | aborted | partial
    transfers: list[dict] = field(default_factory=list)


@dataclass
class Schedule:
    """A named collection of transfers with a trigger and run history."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "Untitled"
    enabled: bool = True
    confirm_before_run: bool = False
    missed_run: str = "warn"          # skip | run | warn
    on_transfer_failure: str = "continue"  # continue | abort
    trigger: Trigger = field(default_factory=Trigger)
    last_run: str = ""                # ISO 8601
    last_status: str = ""
    run_log: list[RunLogEntry] = field(default_factory=list)
    transfers: list[Transfer] = field(default_factory=list)

    def validate(self) -> tuple[bool, str]:
        if not self.name.strip():
            return False, "name is empty"
        if self.missed_run not in ("skip", "run", "warn"):
            return False, f"invalid missed_run: {self.missed_run}"
        if self.on_transfer_failure not in ("continue", "abort"):
            return False, f"invalid on_transfer_failure: {self.on_transfer_failure}"
        ok, reason = self.trigger.validate()
        if not ok:
            return False, f"trigger: {reason}"
        for i, t in enumerate(self.transfers):
            ok, reason = t.validate()
            if not ok:
                return False, f"transfer {i}: {reason}"
        return True, ""

    def add_run(self, entry: RunLogEntry) -> None:
        self.run_log.insert(0, entry)
        if len(self.run_log) > MAX_RUN_LOG:
            self.run_log = self.run_log[:MAX_RUN_LOG]
        self.last_run = entry.started
        self.last_status = entry.status

    def skip(self, now: datetime | None = None) -> None:
        """
        Mark this schedule as skipped right now.
        Advances last_run to now so is_due() won't fire again until the next
        proper interval — preventing the QTimer from re-asking every minute.
        Does NOT write a run_log entry (a skip is not a run).
        """
        self.last_run = (now or datetime.now()).isoformat(timespec="seconds")

    def next_due(self, now: datetime) -> datetime | None:
        """Compute the next datetime this schedule should fire, or None for manual."""
        t = self.trigger
        if t.type == "manual":
            return None
        if t.type == "interval":
            if not self.last_run:
                return now
            try:
                last = datetime.fromisoformat(self.last_run)
            except ValueError:
                return now
            return last + t.to_timedelta()
        if t.type == "scheduled":
            try:
                hh, mm = map(int, t.time.split(":"))
            except ValueError:
                return None
            target_weekdays = {_WEEKDAY[d] for d in t.days if d in _WEEKDAY}
            if not target_weekdays:
                return None
            for offset in range(0, 8):
                candidate = (now + timedelta(days=offset)).replace(
                    hour=hh, minute=mm, second=0, microsecond=0)
                if candidate.weekday() in target_weekdays and candidate > now:
                    return candidate
            return None
        return None

    def is_due(self, now: datetime) -> bool:
        """Return True if this schedule should fire now."""
        if not self.enabled:
            return False
        if self.trigger.type == "manual":
            return False
        if self.trigger.type == "interval":
            if not self.last_run:
                return True
            try:
                last = datetime.fromisoformat(self.last_run)
            except ValueError:
                return True
            return now >= last + self.trigger.to_timedelta()
        if self.trigger.type == "scheduled":
            try:
                hh, mm = map(int, self.trigger.time.split(":"))
            except ValueError:
                return False
            target_weekdays = {_WEEKDAY[d] for d in self.trigger.days if d in _WEEKDAY}
            if now.weekday() not in target_weekdays:
                return False
            target_today = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
            if now < target_today:
                return False
            if self.last_run:
                try:
                    last = datetime.fromisoformat(self.last_run)
                    if last.date() == now.date() and last >= target_today:
                        return False
                except ValueError:
                    pass
            return True
        return False


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class ScheduleManager:
    """Loads, validates, and saves scheduled rsync lists with HMAC integrity."""

    def __init__(self, config_dir: Path | None = None,
                 key_provider: Callable[[], bytes] | None = None):
        """key_provider returns the signing key (services.vault.Vault.key);
        without one, hmac.key in config_dir is used."""
        self.config_dir     = config_dir or paths.CONFIG_DIR
        self.schedules_path = self.config_dir / SCHEDULES_PATH.name
        self.hmac_path      = self.config_dir / HMAC_PATH.name
        self.schedules: list[Schedule] = []
        self._key_provider  = key_provider or (
            lambda: load_key(self.config_dir / KEY_PATH.name)[0])
        self._file = SignedFile(self.schedules_path, self._key, self.hmac_path)
        self._loaded = False

    def _key(self) -> bytes:
        try:
            return self._key_provider()
        except KeyUnavailable as e:
            raise ScheduleKeyUnavailable(str(e)) from e

    # ---- Load / save ----

    def load(self) -> None:
        """Load schedules from disk. Raises ScheduleIntegrityError on HMAC
        mismatch and ScheduleKeyUnavailable if the keyring refuses."""
        self._loaded = True
        try:
            content = self._file.read()
        except TamperedError:
            log.error("schedules.json HMAC verification failed — file may have been "
                      "tampered with. Refusing to load.")
            raise ScheduleIntegrityError(
                "schedules.json integrity check failed. "
                "The file has been modified outside LanScanMan, "
                "or its signing key is missing. Scheduled transfers will not run "
                "until this is resolved.")
        except OSError as e:
            log.exception(f"failed to read schedules.json: {e}")
            content = None
        if content is None:
            self.schedules = []
            return
        try:
            data = json.loads(content.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            log.exception(f"failed to parse schedules.json: {e}")
            self.schedules = []
            return
        self.schedules = self._parse(data)

    def save(self) -> None:
        """Write schedules to disk and re-sign. The key is resolved before
        anything is written (a locked keyring raises, file untouched)."""
        _ensure_config_dir(self.config_dir)
        data = {
            "version": SCHEMA_VERSION,
            "lists": [self._schedule_to_dict(s) for s in self.schedules],
        }
        content = json.dumps(data, indent=2).encode("utf-8")
        try:
            self._file.write(content)
        except OSError as e:
            log.exception(f"failed to write schedules.json: {e}")

    # ---- Serialisation ----

    @staticmethod
    def _schedule_to_dict(s: Schedule) -> dict:
        d = asdict(s)
        # Dataclass asdict converts nested dataclasses too, so trigger/transfers/run_log
        # are already plain dicts. Nothing else to do.
        return d

    def _parse(self, data: Any) -> list[Schedule]:
        if not isinstance(data, dict):
            log.warning("schedules.json root is not a dict")
            return []
        lists = data.get("lists") or []
        if not isinstance(lists, list):
            log.warning("schedules.json 'lists' is not a list")
            return []
        out: list[Schedule] = []
        for i, raw in enumerate(lists):
            if not isinstance(raw, dict):
                continue
            try:
                sched = self._dict_to_schedule(raw)
            except Exception as e:
                log.exception(f"failed to parse schedule {i}: {e}")
                continue
            ok, reason = sched.validate()
            if not ok:
                log.warning(f"schedule {i} ({sched.name!r}) invalid: {reason}")
                continue
            out.append(sched)
        return out

    @staticmethod
    def _dict_to_schedule(d: dict) -> Schedule:
        trig_raw = d.get("trigger") or {}
        # Backward compat: old files used "hours" key, new uses interval_value+unit
        old_hours = trig_raw.get("hours")
        interval_value = int(trig_raw.get("interval_value", old_hours or 24))
        interval_unit = trig_raw.get("interval_unit", "hours" if old_hours else "hours")
        trigger = Trigger(
            type=trig_raw.get("type", "manual"),
            interval_value=interval_value,
            interval_unit=interval_unit,
            days=list(trig_raw.get("days") or []),
            time=trig_raw.get("time", "02:00"),
        )
        transfers = []
        for t_raw in d.get("transfers") or []:
            if not isinstance(t_raw, dict):
                continue
            transfers.append(Transfer(
                full_source=t_raw.get("full_source", ""),
                full_dest=t_raw.get("full_dest", ""),
                args=list(t_raw.get("args") or []),
                sender_ip=t_raw.get("sender_ip", ""),
                sender_user=t_raw.get("sender_user", ""),
                receiver_ip=t_raw.get("receiver_ip", ""),
                src_path=t_raw.get("src_path", ""),
                dst_path=t_raw.get("dst_path", ""),
            ))
        run_log = []
        for r_raw in d.get("run_log") or []:
            if not isinstance(r_raw, dict):
                continue
            run_log.append(RunLogEntry(
                started=r_raw.get("started", ""),
                finished=r_raw.get("finished", ""),
                status=r_raw.get("status", ""),
                transfers=list(r_raw.get("transfers") or []),
            ))
        return Schedule(
            id=d.get("id") or str(uuid.uuid4()),
            name=d.get("name", "Untitled"),
            enabled=bool(d.get("enabled", True)),
            confirm_before_run=bool(d.get("confirm_before_run", False)),
            missed_run=d.get("missed_run", "warn"),
            on_transfer_failure=d.get("on_transfer_failure", "continue"),
            trigger=trigger,
            last_run=d.get("last_run", ""),
            last_status=d.get("last_status", ""),
            run_log=run_log,
            transfers=transfers,
        )

    # ---- Convenience ----

    def find(self, schedule_id: str) -> Schedule | None:
        for s in self.schedules:
            if s.id == schedule_id:
                return s
        return None

    def due_now(self, now: datetime | None = None) -> list[Schedule]:
        """Return schedules whose time has arrived."""
        now = now or datetime.now()
        return [s for s in self.schedules if s.is_due(now)]

    def missed_since_last_open(self, now: datetime | None = None) -> list[Schedule]:
        """
        Return schedules whose next_due was in the past before we opened.
        Used on startup to honour the missed_run setting.
        """
        now = now or datetime.now()
        missed = []
        for s in self.schedules:
            if not s.enabled or s.trigger.type == "manual":
                continue
            nd = s.next_due(now)
            if nd is None:
                continue
            # If next_due is in the future by its own calculation, nothing missed.
            # If schedule is_due right now, treat as missed so caller can decide.
            if s.is_due(now):
                missed.append(s)
        return missed