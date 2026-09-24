import json

from lanscanman.core import smart_history
from lanscanman.core.smart_history import SmartLogger, smart_log_key


class Notifier:
    def __init__(self):
        self.calls = []

    def __call__(self, title, body, critical=False):
        self.calls.append((title, body, critical))


def _disk(**attrs):
    base = {"dev": "sda", "serial": "SER1", "model": "Disk",
            "reallocated": 0, "pending": 0, "uncorrectable": 0,
            "wear_pct_used": 5, "tbw_tb": 1.0, "power_on_hours": 100}
    base.update(attrs)
    return base


def _clock(monkeypatch, *stamps):
    it = iter(stamps)
    monkeypatch.setattr(smart_history, "_now", lambda: next(it))


def test_smart_log_key_prefers_serial():
    assert smart_log_key("sda", "ABC123") == "ABC123"
    assert smart_log_key("sda", "  ") == "sda"
    assert smart_log_key("sda", None) == "sda"


def test_first_record_writes_file(tmp_path, monkeypatch):
    _clock(monkeypatch, "2026-01-01T00:00:00")
    log = SmartLogger("aa:bb:cc:dd:ee:ff", log_dir=tmp_path, notifier=Notifier())
    log.record([_disk()])
    path = tmp_path / "aa-bb-cc-dd-ee-ff.json"          # colons made filename-safe
    data = json.loads(path.read_text())
    assert data["SER1"]["history"][0]["first_seen"] == "2026-01-01T00:00:00"


def test_unchanged_attributes_only_extend_last_seen(tmp_path, monkeypatch):
    _clock(monkeypatch, "T1", "T2", "T3")
    log = SmartLogger("host", log_dir=tmp_path, notifier=Notifier())
    log.record([_disk()])
    log.record([_disk(power_on_hours=200)])      # context-only change
    log.record([_disk(power_on_hours=300)])
    _, history = log.get_history("SER1")
    assert len(history) == 1
    assert (history[0]["first_seen"], history[0]["last_seen"]) == ("T1", "T3")


def test_worsening_starts_new_entry_and_notifies(tmp_path, monkeypatch):
    _clock(monkeypatch, "T1", "T2")
    notes = Notifier()
    log = SmartLogger("host", alias="nas", log_dir=tmp_path, notifier=notes)
    log.record([_disk()])
    log.record([_disk(reallocated=8)])
    _, history = log.get_history("SER1")
    assert [h["reallocated"] for h in history] == [0, 8]
    assert len(notes.calls) == 1
    title, body, critical = notes.calls[0]
    assert critical and "/dev/sda on nas" in body and "Reallocated sectors: 0 → 8" in body


def test_improvement_logs_without_notifying(tmp_path, monkeypatch):
    _clock(monkeypatch, "T1", "T2")
    notes = Notifier()
    log = SmartLogger("host", log_dir=tmp_path, notifier=notes)
    log.record([_disk(pending=4)])
    log.record([_disk(pending=0)])       # pending sectors remapped
    assert len(log.get_history("SER1")[1]) == 2
    assert notes.calls == []


def test_history_persists_across_instances(tmp_path, monkeypatch):
    _clock(monkeypatch, "T1")
    SmartLogger("host", log_dir=tmp_path, notifier=Notifier()).record([_disk()])
    again = SmartLogger("host", log_dir=tmp_path, notifier=Notifier())
    assert again.has_history("SER1")
    assert again.get_history("SER1")[0] == {"model": "Disk", "serial": "SER1"}
    assert not again.has_history("nope")


def test_corrupt_file_starts_fresh(tmp_path):
    (tmp_path / "host.json").write_text("{not json")
    log = SmartLogger("host", log_dir=tmp_path, notifier=Notifier())
    assert not log.has_history("SER1")


def test_tbw_growth_is_recorded_but_never_alerts(tmp_path, monkeypatch):
    _clock(monkeypatch, "T1", "T2", "T3")
    notes = Notifier()
    log = SmartLogger("host", log_dir=tmp_path, notifier=notes)
    log.record([_disk(tbw_tb=1.0)])
    log.record([_disk(tbw_tb=1.5)])                        # normal writing
    assert [h["tbw_tb"] for h in log.get_history("SER1")[1]] == [1.0, 1.5]
    assert notes.calls == []
    log.record([_disk(tbw_tb=1.5, reallocated=2)])         # real damage still alerts
    assert len(notes.calls) == 1 and "TBW" not in notes.calls[0][1]
