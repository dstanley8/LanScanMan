import json
from datetime import datetime, timedelta

import pytest

from lanscanman.core.schedules import (
    MAX_RUN_LOG,
    RunLogEntry,
    Schedule,
    ScheduleIntegrityError,
    ScheduleManager,
    Transfer,
    Trigger,
    validate_args,
    validate_path,
)

# 2026-09-21 is a Monday
MON_9AM = datetime(2026, 9, 21, 9, 0)


def _transfer(**kw):
    base = dict(full_source="/home/carol/docs/", full_dest="carol@192.168.50.5:/backup/docs",
                src_path="/home/carol/docs/", dst_path="/backup/docs",
                args=["-a", "--delete"], receiver_ip="192.168.50.5")
    base.update(kw)
    return Transfer(**base)


# ── validation ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", ["/home/carol/My Files", "carol@host:/srv/data", "rel/path-1_2.txt"])
def test_validate_path_accepts(path):
    assert validate_path(path) == (True, "")


@pytest.mark.parametrize("path", ["", "/tmp/a;rm -rf ~", "$(whoami)", "`id`", "a|b", "~/x", "a\nb"])
def test_validate_path_rejects(path):
    ok, reason = validate_path(path)
    assert not ok and reason


def test_validate_args():
    assert validate_args(["-a", "--delete", "--exclude=*.tmp"]) == (True, "")
    assert not validate_args(["-a", ""])[0]
    assert not validate_args(["delete"])[0]                  # must start with '-'
    assert not validate_args(["--rsh=ssh;id"])[0]            # metacharacter
    assert not validate_args(["--exclude= x"])[0]            # whitespace


def test_transfer_validate_reports_which_field():
    assert _transfer().validate() == (True, "")
    ok, reason = _transfer(full_dest="host:/x;y").validate()
    assert not ok and reason.startswith("full destination")
    ok, reason = _transfer(args=["-a", "x"]).validate()
    assert not ok and reason.startswith("rsync args")


def test_trigger_validate():
    assert Trigger(type="manual").validate()[0]
    assert not Trigger(type="cron").validate()[0]
    assert not Trigger(type="interval", interval_value=0).validate()[0]
    assert not Trigger(type="interval", interval_unit="weeks").validate()[0]
    assert not Trigger(type="scheduled", days=[]).validate()[0]
    assert not Trigger(type="scheduled", days=["funday"]).validate()[0]
    assert not Trigger(type="scheduled", days=["monday"], time="25:00").validate()[0]
    assert not Trigger(type="scheduled", days=["monday"], time="9:00").validate()[0]
    assert Trigger(type="scheduled", days=["monday"], time="09:00").validate()[0]


@pytest.mark.parametrize("unit, delta", [
    ("minutes", timedelta(minutes=3)), ("hours", timedelta(hours=3)),
    ("days", timedelta(days=3)), ("months", timedelta(days=90)),
])
def test_interval_to_timedelta(unit, delta):
    assert Trigger(type="interval", interval_value=3, interval_unit=unit).to_timedelta() == delta


# ── due-time logic ───────────────────────────────────────────────────────────

def test_manual_and_disabled_never_due():
    assert not Schedule(trigger=Trigger(type="manual")).is_due(MON_9AM)
    s = Schedule(enabled=False, trigger=Trigger(type="interval"))
    assert not s.is_due(MON_9AM)


def test_interval_due():
    s = Schedule(trigger=Trigger(type="interval", interval_value=2, interval_unit="hours"))
    assert s.is_due(MON_9AM)                                   # never run
    s.last_run = (MON_9AM - timedelta(hours=1)).isoformat()
    assert not s.is_due(MON_9AM)
    assert s.next_due(MON_9AM) == MON_9AM + timedelta(hours=1)
    s.last_run = (MON_9AM - timedelta(hours=2)).isoformat()
    assert s.is_due(MON_9AM)
    s.last_run = "not a date"
    assert s.is_due(MON_9AM)


def test_scheduled_due_once_per_day():
    s = Schedule(trigger=Trigger(type="scheduled", days=["monday"], time="08:30"))
    assert not s.is_due(MON_9AM.replace(hour=8))               # too early
    assert s.is_due(MON_9AM)                                   # after 08:30, not yet run
    s.last_run = MON_9AM.replace(minute=5).isoformat()
    assert not s.is_due(MON_9AM.replace(minute=30))            # already ran today
    assert not s.is_due(MON_9AM + timedelta(days=1))           # Tuesday


def test_scheduled_next_due():
    s = Schedule(trigger=Trigger(type="scheduled", days=["wednesday", "monday"], time="08:30"))
    assert s.next_due(MON_9AM) == datetime(2026, 9, 23, 8, 30)            # Wed
    assert s.next_due(MON_9AM.replace(hour=7)) == datetime(2026, 9, 21, 8, 30)
    s.trigger.days = ["monday"]
    assert s.next_due(MON_9AM) == datetime(2026, 9, 28, 8, 30)            # next week


def test_skip_suppresses_until_next_interval():
    s = Schedule(trigger=Trigger(type="interval", interval_value=1, interval_unit="days"))
    s.skip(MON_9AM)
    assert not s.is_due(MON_9AM + timedelta(hours=23))
    assert s.is_due(MON_9AM + timedelta(days=1))
    assert s.run_log == []


def test_add_run_caps_log_and_updates_last():
    s = Schedule()
    for i in range(MAX_RUN_LOG + 3):
        s.add_run(RunLogEntry(started=f"2026-01-{i + 1:02d}", status="completed"))
    assert len(s.run_log) == MAX_RUN_LOG
    assert s.run_log[0].started == f"2026-01-{MAX_RUN_LOG + 3:02d}"      # newest first
    assert s.last_run == s.run_log[0].started


# ── persistence + HMAC ───────────────────────────────────────────────────────

def _saved_manager(config_dir):
    m = ScheduleManager(config_dir)
    m.schedules = [Schedule(name="Nightly", transfers=[_transfer()],
                            trigger=Trigger(type="scheduled", days=["friday"], time="02:00"))]
    m.save()
    return m


def test_roundtrip(config_dir):
    original = _saved_manager(config_dir)
    loaded = ScheduleManager(config_dir)
    loaded.load()
    assert loaded.schedules == original.schedules
    assert loaded.find(original.schedules[0].id).name == "Nightly"
    assert loaded.find("missing") is None


def test_files_are_private(config_dir):
    _saved_manager(config_dir)
    for name in ("schedules.json", "schedules.hmac", "hmac.key"):
        assert (config_dir / name).stat().st_mode & 0o777 == 0o600


def test_tampered_file_is_refused(config_dir):
    _saved_manager(config_dir)
    path = config_dir / "schedules.json"
    data = json.loads(path.read_text())
    data["lists"][0]["transfers"][0]["full_dest"] = "evil@attacker:/loot"
    path.write_text(json.dumps(data))
    with pytest.raises(ScheduleIntegrityError):
        ScheduleManager(config_dir).load()


def test_missing_hmac_is_refused(config_dir):
    _saved_manager(config_dir)
    (config_dir / "schedules.hmac").unlink()
    with pytest.raises(ScheduleIntegrityError):
        ScheduleManager(config_dir).load()


def test_no_file_means_no_schedules(config_dir):
    m = ScheduleManager(config_dir)
    m.load()
    assert m.schedules == []


def _write_signed(config_dir, payload: dict):
    """Write schedules.json with a valid HMAC, as if saved by the app."""
    ScheduleManager(config_dir)._file.write(json.dumps(payload).encode())


def test_invalid_entries_are_dropped_on_load(config_dir):
    _write_signed(config_dir, {"version": 1, "lists": [
        {"name": "good", "trigger": {"type": "manual"}},
        {"name": "bad path", "transfers": [{"src_path": "/a;b", "dst_path": "/x",
                                            "full_source": "/a", "full_dest": "/x"}]},
        {"name": "", "trigger": {"type": "manual"}},
        "not a dict",
    ]})
    m = ScheduleManager(config_dir)
    m.load()
    assert [s.name for s in m.schedules] == ["good"]


def test_legacy_hours_trigger_is_migrated(config_dir):
    _write_signed(config_dir, {"lists": [{"name": "old", "trigger": {"type": "interval", "hours": 6}}]})
    m = ScheduleManager(config_dir)
    m.load()
    t = m.schedules[0].trigger
    assert (t.interval_value, t.interval_unit) == (6, "hours")


def test_due_now_and_missed(config_dir):
    m = ScheduleManager(config_dir)
    due = Schedule(name="due", trigger=Trigger(type="interval", interval_value=1, interval_unit="hours"))
    manual = Schedule(name="manual")
    later = Schedule(name="later", trigger=Trigger(type="interval", interval_value=1, interval_unit="days"),
                     last_run=MON_9AM.isoformat())
    m.schedules = [due, manual, later]
    assert m.due_now(MON_9AM) == [due]
    assert m.missed_since_last_open(MON_9AM) == [due]
