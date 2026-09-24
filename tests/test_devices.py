"""New-device detection."""

import pytest
from conftest import FakeKeyring

from lanscanman import paths
from lanscanman.core.devices import DeviceRegistry, device_key, is_randomised_mac
from lanscanman.core.integrity import KeyUnavailable, TamperedError
from lanscanman.services.secret_store import SecretStore
from lanscanman.services.vault import Vault, get_vault, set_vault

NAS = {"ip": "192.168.50.5", "mac": "AA:BB:CC:00:00:05", "hostname": "nas", "vendor": "Synology"}
TV = {"ip": "192.168.50.9", "mac": "AA:BB:CC:00:00:09", "hostname": "", "vendor": "LG"}
PHONE = {"ip": "192.168.50.20", "mac": "DA:A1:19:12:34:56", "hostname": "", "vendor": "unknown"}


class Clock:
    t = 1_000_000.0

    def __call__(self):
        Clock.t += 60
        return Clock.t


def _reg():
    return DeviceRegistry(get_vault().signed_file(paths.DEVICES_FILE), clock=Clock())


def test_first_scan_is_the_baseline():
    reg = _reg()
    report = reg.observe([NAS, TV])
    assert report.baseline == 2 and report.new == []
    assert reg.flagged_ips() == {}


def test_new_device_is_flagged_until_acknowledged():
    reg = _reg()
    reg.observe([NAS])
    report = reg.observe([NAS, TV])
    assert [d["ip"] for d in report.new] == ["192.168.50.9"]
    assert report.new[0]["vendor"] == "LG" and report.new[0]["mac"] == "aa:bb:cc:00:00:09"
    again = _reg().observe([NAS, TV])                      # next app start, next scan
    assert [d["ip"] for d in again.new] == ["192.168.50.9"]    # still flagged
    reg2 = _reg()
    reg2.load()
    reg2.acknowledge([device_key("192.168.50.9", TV["mac"])])
    assert _reg().observe([NAS, TV]).new == []


def test_flagged_device_not_seen_this_scan_is_not_reported():
    reg = _reg()
    reg.observe([NAS])
    reg.observe([NAS, TV])
    assert reg.observe([NAS]).new == []
    assert "192.168.50.9" in reg.flagged_ips()                 # but still pending


def test_profiled_hosts_count_as_known():
    reg = _reg()
    reg.observe([NAS])
    assert reg.observe([NAS, TV], known_macs=[TV["mac"]]).new == []
    reg2 = _reg()
    reg2.observe([NAS])
    assert reg2.observe([PHONE], known_ips=["192.168.50.20"]).new == []


def test_unprivileged_scan_matches_known_ip():
    reg = _reg()
    reg.observe([NAS])
    no_mac = {"ip": "192.168.50.5", "mac": "", "hostname": "nas", "vendor": "unknown"}
    assert reg.observe([no_mac]).new == []                 # same IP as the known NAS


def test_ip_only_device_is_not_re_alerted_once_its_mac_is_seen():
    reg = _reg()
    reg.observe([NAS])
    stranger = {"ip": "192.168.50.33", "mac": "", "hostname": "", "vendor": "unknown"}
    report = reg.observe([stranger])
    assert report.new[0]["no_mac"]
    reg.acknowledge(["ip:192.168.50.33"])
    with_mac = dict(stranger, mac="AA:BB:CC:00:00:33")
    assert reg.observe([with_mac]).new == []               # folded into the MAC entry
    assert "ip:192.168.50.33" not in reg.devices


def test_randomised_macs_are_labelled():
    assert is_randomised_mac("da:a1:19:12:34:56")          # 0xDA: locally administered
    assert not is_randomised_mac("00:11:22:33:44:55")
    assert not is_randomised_mac("03:00:00:00:00:00")      # multicast, not a device
    reg = _reg()
    reg.observe([NAS])
    assert reg.observe([PHONE]).new[0]["randomised_mac"]


def test_list_is_signed():
    reg = _reg()
    reg.observe([NAS])
    reg.observe([NAS, TV])
    # Someone tries to hide their device by marking it known
    text = paths.DEVICES_FILE.read_text().replace('"acknowledged": false', '"acknowledged": true')
    paths.DEVICES_FILE.write_text(text)
    with pytest.raises(TamperedError):
        _reg().observe([NAS, TV])


def test_locked_keyring_skips_the_check():
    kr = FakeKeyring()
    set_vault(Vault(SecretStore(kr)))
    _reg().observe([NAS])
    kr.locked = True
    set_vault(Vault(SecretStore(kr)))
    with pytest.raises(KeyUnavailable):
        _reg().observe([NAS, TV])


def test_acknowledge_all():
    reg = _reg()
    reg.observe([NAS])
    reg.observe([NAS, TV, PHONE])
    assert reg.acknowledge_all() == 2 and reg.flagged_ips() == {}


# ── scanner UI ──────────────────────────────────────────────────────────────

def _scanner(qapp, monkeypatch):
    from lanscanman.app import LanScanManApp
    from lanscanman.ui.tabs import scanner_tab
    sent = []
    monkeypatch.setattr(scanner_tab, "notify", lambda title, body, **k: sent.append((title, body)))
    win = LanScanManApp()
    win._schedule_timer.stop()
    tab = win.scanner_page
    tab.run_background_pings = lambda: None
    return win, tab, sent


def _row(tab, ip):
    return next(r for r in range(tab.table.rowCount()) if tab.table.item(r, 0).text() == ip)


def _res(*hosts):
    return [dict(h, ssh="closed", services="None") for h in hosts]


def test_scanner_flags_new_devices(qapp, monkeypatch):
    win, tab, sent = _scanner(qapp, monkeypatch)
    tab._populate_results(_res(NAS))
    assert "known network" in win.status.text() and sent == []
    tab._populate_results(_res(NAS, TV))
    tv, nas = tab.table.item(_row(tab, "192.168.50.9"), 0), tab.table.item(_row(tab, "192.168.50.5"), 0)
    assert not tv.icon().isNull() and "New device" in tv.toolTip()
    assert nas.icon().isNull()
    assert sent and sent[0][0] == "New device on your network" and "192.168.50.9" in sent[0][1]
    assert "1 new device" in win.status.text()

    tab._acknowledge_device("192.168.50.9")
    assert tab.table.item(_row(tab, "192.168.50.9"), 0).icon().isNull()
    win.deleteLater()


def test_scanner_new_device_context_menu(qapp, monkeypatch):
    from PyQt6.QtWidgets import QMenu
    win, tab, _ = _scanner(qapp, monkeypatch)
    tab._populate_results(_res(NAS))
    tab._populate_results(_res(NAS, PHONE))
    labels = []

    def fake_exec(menu, *a):
        labels.extend(a.text() for a in menu.actions())
        return next(a for a in menu.actions() if a.text() == "✓ Mark as known device")
    monkeypatch.setattr(QMenu, "exec", fake_exec)
    row = _row(tab, "192.168.50.20")
    assert "randomised" in tab.table.item(row, 0).toolTip()
    tab.show_context_menu(tab.table.visualItemRect(tab.table.item(row, 0)).center())
    assert "✓ Mark as known device" in labels
    assert "192.168.50.20" not in win.net_manager.devices.flagged_ips()
    win.deleteLater()


def test_scanner_survives_locked_keyring(qapp, monkeypatch):
    win, tab, _ = _scanner(qapp, monkeypatch)
    kr = FakeKeyring(locked=True)
    locked = Vault(SecretStore(kr))
    win.net_manager.devices = DeviceRegistry(locked.signed_file(paths.DEVICES_FILE))
    tab._populate_results(_res(NAS))
    assert "keyring locked" in win.status.text()
    win.deleteLater()
