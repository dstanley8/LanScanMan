"""Drive-health reports for a local AI, and the Disk Health → chat flow."""

from datetime import datetime

import pytest

from lanscanman.core.drive_report import (
    SYSTEM_PROMPT,
    DiskData,
    HostData,
    disk_request,
    disks_for_host,
    fleet_request,
    host_request,
    rule_view,
    trends,
)

NOW = datetime(2026, 9, 23, 12, 0)


def _h(first, last, **attrs):
    base = {"first_seen": first, "last_seen": last, "reallocated": 0, "pending": 0,
            "uncorrectable": 0, "wear_pct_used": None, "tbw_tb": None, "power_on_hours": 1000}
    base.update(attrs)
    return base


def _disk(**kw):
    base = {"dev": "sda", "model": "Samsung SSD 870 EVO 1TB", "serial": "S0EXAMPLE00001A",
            "capacity_bytes": 1_000_204_886_016, "smart_ok": True, "smart_available": True,
            "smart_method": "smartctl", "temperature_c": 34, "power_on_hours": 21034,
            "reallocated": 0, "pending": 0, "uncorrectable": 0, "wear_pct_used": 3,
            "available_spare_pct": None, "tbw_tb": 20.0, "fs_used_bytes": 300_000_000_000,
            "fs_total_bytes": 1_000_000_000_000}
    base.update(kw)
    return base


# ── trends: LanScanMan does the maths ───────────────────────────────────────

def test_no_history():
    assert "No history" in trends([])[0]


def test_clean_history():
    t = trends([_h("2026-01-01T00:00:00", "2026-09-20T00:00:00")], NOW)
    assert t[0] == "History covers 2026-01-01 to 2026-09-20 (262 days, 1 recorded state(s))."
    assert "Reallocated sectors: 0 throughout." in t


def test_rising_bad_sectors_are_flagged_as_recent():
    t = trends([_h("2026-01-01T00:00:00", "2026-08-19T00:00:00"),
                _h("2026-08-20T00:00:00", "2026-09-05T00:00:00", reallocated=3),
                _h("2026-09-06T00:00:00", "2026-09-22T00:00:00", reallocated=8)], NOW)
    line = next(x for x in t if x.startswith("Reallocated"))
    assert line == ("Reallocated sectors: 0 → 8 (first non-zero on 2026-08-20); increased 2 "
                    "time(s), most recently 2026-09-06 — still rising recently.")


def test_old_bad_sectors_are_flagged_as_stable():
    t = trends([_h("2026-01-01T00:00:00", "2026-02-01T00:00:00"),
                _h("2026-02-02T00:00:00", "2026-09-22T00:00:00", pending=2)], NOW)
    assert any("stable for 233 days since" in x for x in t)


def test_wear_rate_and_projection():
    t = trends([_h("2026-01-01T00:00:00", "2026-01-31T00:00:00", wear_pct_used=10),
                _h("2026-07-01T00:00:00", "2026-09-22T00:00:00", wear_pct_used=16)], NOW)
    line = next(x for x in t if x.startswith("Wear used"))
    assert "10% → 16% over 5.9 months" in line and "about 1.01% per month" in line
    assert "reach 100% in about 6.9 years" in line


def test_tbw_per_year():
    t = trends([_h("2025-09-23T00:00:00", "2025-10-01T00:00:00", tbw_tb=10.0),
                _h("2026-09-23T00:00:00", "2026-09-23T00:00:00", tbw_tb=13.65)], NOW)
    line = next(x for x in t if x.startswith("Data written"))
    assert "3.6 TB per year" in line or "3.7 TB per year" in line


# ── LanScanMan's own view ───────────────────────────────────────────────────

@pytest.mark.parametrize("disk, expected", [
    (_disk(), "no problems found"),
    (_disk(smart_ok=False), "SMART self-assessment FAILED"),
    (_disk(reallocated=8), "bad sectors (not increasing) — reallocated sectors 8"),
    (_disk(wear_pct_used=85), "heavily worn (85% used)"),
    (_disk(temperature_c=58), "running hot (58 °C)"),
    (_disk(available_spare_pct=5), "low spare capacity (5%)"),
    (_disk(smart_available=False), "SMART data not available"),
    (None, "No current reading"),
])
def test_rule_view(disk, expected):
    assert expected in rule_view(disk, [])


def test_rule_view_notices_rising_sectors_from_history():
    history = [_h("2026-09-01T00:00:00", "2026-09-10T00:00:00"),
               _h("2026-09-11T00:00:00", "2026-09-22T00:00:00", reallocated=4)]
    assert "still increasing" in rule_view(_disk(reallocated=4), history)


# ── the reports ─────────────────────────────────────────────────────────────

def _host(disks, label="nas", ip="192.168.50.5"):
    return HostData(label, ip, disks, NOW)


def test_disk_report_contents():
    host = _host([])
    disk = DiskData("S0EXAMPLE00001A", "sda", _disk(), {}, [_h("2026-01-01T00:00:00", "2026-09-22T00:00:00")])
    text = disk_request(host, disk)
    assert text.startswith("Please assess the health of this disk")
    assert "Samsung SSD 870 EVO 1TB — /dev/sda on nas (192.168.50.5)" in text
    assert "Serial: S0EXAMPLE00001A" in text                      # included, by decision
    assert "Type: SATA SSD, 931.5 GB" in text
    assert "- Temperature: 34 °C" in text and "about 2.4 years powered on" in text
    assert "- Filesystems on it: 279.4 GB used of 931.3 GB (30%)" in text
    assert "LanScanMan's rule-based view: no problems found" in text
    assert "first seen | last seen | realloc" in text


def test_long_history_is_capped():
    history = [_h(f"2026-01-{d:02d}T00:00:00", f"2026-01-{d:02d}T12:00:00", tbw_tb=float(d))
               for d in range(1, 21)]
    text = disk_request(_host([]), DiskData("k", "sda", _disk(), {}, history))
    assert "(… 8 earlier row(s) omitted" in text
    assert text.count("2026-01-") < 20 * 2


def test_host_and_fleet_reports():
    a = DiskData("A", "sda", _disk(), {}, [])
    b = DiskData("B", "sdb", _disk(model="WDC WD20EFRX", wear_pct_used=None, reallocated=8), {}, [])
    old = DiskData("C", "", None, {"model": "Old HDD", "serial": "C"},
                   [_h("2025-01-01T00:00:00", "2025-06-01T00:00:00")])
    host = _host([a, b, old])
    text = host_request(host)
    assert "the 3 disk(s) in nas (192.168.50.5)" in text and "## nas (192.168.50.5)" in text
    assert "No current reading this session — history only." in text
    other = _host([DiskData("D", "nvme0n1", _disk(dev="nvme0n1", available_spare_pct=100), {}, [])],
                  label="desktop", ip="192.168.50.7")
    fleet = fleet_request([host, other, _host([], label="empty", ip="192.168.50.9")])
    assert "all 4 disk(s) across 2 host(s)" in fleet
    assert "## desktop (192.168.50.7)" in fleet and "NVMe SSD" in fleet and "empty" not in fleet


def test_disks_for_host_includes_history_only_disks():
    readings = [_disk(dev="sda", serial="A")]
    logged = {"A": ({"model": "x", "serial": "A"}, [_h("t", "t")]),
              "GONE": ({"model": "old", "serial": "GONE"}, [_h("t", "t")]),
              "EMPTY": ({}, [])}
    disks = disks_for_host(readings, logged, lambda d: d["serial"])
    assert [(d.key, d.reading is not None) for d in disks] == [("A", True), ("GONE", False)]


def test_system_prompt_rules():
    for phrase in ("Use only the data given", "don't recalculate", "LanScanMan will not run anything",
                   "Replace now"):
        assert phrase in SYSTEM_PROMPT


# ── the flow: Disk Health → chat window, unsent ─────────────────────────────

def test_chat_tree_sends_system_instructions_first():
    from lanscanman.core.chat_tree import ChatTree
    t = ChatTree(title="Disk health — nas")
    t.settings["system"] = SYSTEM_PROMPT
    u = t.add_user(None, "report")
    assert t.messages() == [{"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": "report"}]
    assert t.title == "Disk health — nas"                   # not replaced by the first message
    again = ChatTree.from_dict(t.to_dict())
    assert again.messages()[0]["role"] == "system" and u.id in again.nodes


def _ai_tab(qapp, services):
    from lanscanman.ui.tabs.ai_tab import AITab
    tab = AITab(lambda: [])
    for s in services:
        tab._add_service(s)
    return tab


def test_open_drive_chat_prefills_but_sends_nothing(qapp, fake_chat):
    from lanscanman.core.ai_discovery import CHAT, AIService
    FakeChatWorker = fake_chat
    FakeChatWorker.last = None
    svc = AIService("192.168.50.5", 11434, "Ollama", CHAT, models=["qwen3"])
    tab = _ai_tab(qapp, [svc])
    assert tab.open_drive_chat("Disk health — nas", "REPORT TEXT") is True
    win = tab._chats[-1]
    assert win._input.toPlainText() == "REPORT TEXT"
    assert FakeChatWorker.last is None                     # nothing sent until you press Send
    assert "nothing has been sent yet" in win._status.text()
    assert "Instructions sent to the AI" in win._transcript.toPlainText()
    assert win.tree.title == "Disk health — nas"
    win._send_or_stop()
    assert FakeChatWorker.last.messages[0] == {"role": "system", "content": SYSTEM_PROMPT}
    assert FakeChatWorker.last.messages[1] == {"role": "user", "content": "REPORT TEXT"}
    win.close()


def test_open_drive_chat_prefers_last_used_server(qapp, fake_chat):
    from lanscanman.core.ai_discovery import CHAT, AIService
    a = AIService("192.168.50.5", 11434, "Ollama", CHAT, models=["m"])
    b = AIService("192.168.50.60", 8080, "OpenAI-compatible", CHAT, models=["m"])
    tab = _ai_tab(qapp, [a, b])
    tab._open_chat(b)
    tab.open_drive_chat("t", "r")
    assert tab._chats[-1].service is b
    for w in tab._chats:
        w.close()


def test_open_drive_chat_without_any_server(qapp, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox
    shown = []
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: shown.append(a[1]))
    assert _ai_tab(qapp, []).open_drive_chat("t", "r") is False
    assert shown == ["No AI server found"]


def test_disk_dialog_asks_per_disk_and_per_host(qapp, isolated_config):
    from lanscanman.core.smart_history import SmartLogger
    from lanscanman.ui.dialogs.smart_disk import SmartDiskDialog
    SmartLogger("aa:bb:cc:dd:ee:ff", "nas").record([_disk(serial="S1")])
    asked = []
    dlg = SmartDiskDialog("192.168.50.5", "carol", "nas",
                          disks=[_disk(serial="S1"), _disk(dev="sdb", serial="S2", model="WDC WD20EFRX")],
                          profile_key="aa:bb:cc:dd:ee:ff", ask_ai=lambda t, r: asked.append((t, r)),
                          read_at=NOW)
    dlg._ask_ai(1)
    title, report = asked[-1]
    assert title == "Disk health — nas / WDC WD20EFRX" and "/dev/sdb on nas" in report
    assert "Samsung" not in report                          # just that disk
    dlg._ask_ai(None)
    title, report = asked[-1]
    assert title == "Disk health — nas" and "the 2 disk(s) in nas" in report
    assert "History covers" in report                        # history from the SMART log included
    dlg.deleteLater()


def test_fleet_report_from_the_disk_health_tab(qapp, isolated_config):
    from lanscanman.services.network_manager import NetworkManager
    from lanscanman.ui.tabs.smart_tab import SmartTab
    nm = NetworkManager()
    tab = SmartTab(nm)
    tab._add_row("nas", "192.168.50.5", "carol")
    tab._add_row("desktop", "192.168.50.7", "carol")
    tab._on_result("192.168.50.5", [_disk(serial="S1")])
    tab._on_result("192.168.50.7", [_disk(dev="nvme0n1", serial="N1", available_spare_pct=100)])
    asked = []
    tab.ask_ai = lambda t, r: asked.append((t, r))
    tab._ask_ai_fleet()
    title, report = asked[0]
    assert title == "Disk health — fleet (2 disks)"
    assert "## nas (192.168.50.5)" in report and "## desktop (192.168.50.7)" in report
    tab.deleteLater()
