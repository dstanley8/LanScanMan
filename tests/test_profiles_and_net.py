import json

import pytest

from lanscanman.core.net import is_mac, magic_packet, parse_ping_latency, subnet_of
from lanscanman.core.profiles import ProfileStore
from lanscanman.core.wifi import (
    dbm_to_label,
    parse_proc_wireless,
    read_wifi,
    signal_quality,
)

MAC = "aa:bb:cc:dd:ee:ff"


# ── profiles ────────────────────────────────────────────────────────────────

@pytest.fixture
def store(tmp_path):
    return ProfileStore(tmp_path / "hosts.json")


def test_put_get_persist(store):
    store.put(MAC, "192.168.50.5", "nas", "NAS", "carol")
    assert store.get(MAC, "192.168.50.9")["alias"] == "NAS"          # keyed by MAC, IP can change
    reloaded = ProfileStore(store.path)
    assert reloaded.get(MAC, "")["last_ip"] == "192.168.50.5"


def test_profile_without_mac_is_keyed_by_ip(store):
    store.put("", "192.168.50.7", "", "Printer", "")
    assert "192.168.50.7" in store.profiles


def test_put_preserves_extra_users(store):
    store.put(MAC, "192.168.50.5", "nas", "NAS", "carol")
    assert store.add_extra_user(MAC, "192.168.50.5", "root")
    store.put(MAC, "192.168.50.5", "nas", "Renamed", "carol")
    assert store.all_users(MAC, "192.168.50.5") == ["carol", "root"]


def test_extra_user_rules(store):
    assert not store.add_extra_user(MAC, "192.168.50.5", "root")      # no profile
    store.put(MAC, "192.168.50.5", "nas", "NAS", "carol")
    assert not store.add_extra_user(MAC, "192.168.50.5", "carol")      # already primary
    assert store.add_extra_user(MAC, "192.168.50.5", "root")
    assert not store.add_extra_user(MAC, "192.168.50.5", "root")      # duplicate
    store.remove_extra_user(MAC, "192.168.50.5", "root")
    assert store.all_users(MAC, "192.168.50.5") == ["carol"]


def test_set_primary_user_swaps(store):
    store.put(MAC, "192.168.50.5", "nas", "NAS", "carol")
    store.add_extra_user(MAC, "192.168.50.5", "root")
    store.set_primary_user(MAC, "192.168.50.5", "root")
    assert store.all_users(MAC, "192.168.50.5") == ["root", "carol"]
    store.set_primary_user(MAC, "192.168.50.5", "nobody")               # not an extra: no-op
    assert store.all_users(MAC, "192.168.50.5") == ["root", "carol"]


def test_all_users_placeholder_primary(store):
    store.put(MAC, "192.168.50.5", "nas", "NAS", "—")
    assert store.all_users(MAC, "192.168.50.5") == []


def test_rekey_ip_to_mac(store):
    store.put("", "192.168.50.5", "nas", "NAS", "carol")
    assert store.rekey_ip_to_mac("192.168.50.5", MAC)
    assert MAC in store.profiles and "192.168.50.5" not in store.profiles
    assert not store.rekey_ip_to_mac("192.168.50.5", MAC)              # nothing left to move
    assert MAC in json.loads(store.path.read_text())


def test_delete_and_clear(store):
    store.put(MAC, "192.168.50.5", "nas", "NAS", "carol")
    store.put("", "192.168.50.7", "", "Printer", "")
    assert store.delete(MAC, "192.168.50.5")
    assert not store.delete(MAC, "192.168.50.5")
    assert store.delete("—", "192.168.50.7")               # placeholder MAC falls back to IP
    store.put(MAC, "192.168.50.5", "nas", "NAS", "carol")
    store.clear()
    assert store.profiles == {} and not store.path.exists()


def test_corrupt_profiles_file_loads_empty(tmp_path):
    p = tmp_path / "hosts.json"
    p.write_text("{oops")
    assert ProfileStore(p).profiles == {}


# ── net ─────────────────────────────────────────────────────────────────────

def test_magic_packet():
    pkt = magic_packet("AA:BB:CC:DD:EE:FF")
    assert len(pkt) == 102
    assert pkt[:6] == b"\xff" * 6
    assert pkt[6:12] == bytes.fromhex("AABBCCDDEEFF")
    assert magic_packet("aa-bb-cc-dd-ee-ff") == pkt


@pytest.mark.parametrize("value, ok", [
    ("aa:bb:cc:dd:ee:ff", True), ("AA-BB-CC-DD-EE-FF", True),
    ("—", False), ("", False), (None, False), ("aa:bb:cc", False),
])
def test_is_mac(value, ok):
    assert is_mac(value) is ok


def test_parse_ping_latency():
    out = ("PING 192.168.50.1 (192.168.50.1) 56(84) bytes of data.\n"
           "64 bytes from 192.168.50.1: icmp_seq=1 ttl=64 time=0.412 ms\n")
    assert parse_ping_latency(out) == "0.4ms"
    assert parse_ping_latency("1 packets transmitted, 0 received") is None


# ── wifi ────────────────────────────────────────────────────────────────────

PROC = """Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE
 face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22
wlp2s0: 0000   55.  -55.  -256        0      0      0      0     12        0
"""


def test_parse_proc_wireless():
    assert parse_proc_wireless(PROC) == ("wlp2s0", -55)
    assert parse_proc_wireless(PROC.replace("-55.", "0.")) == ("wlp2s0", None)
    assert parse_proc_wireless(PROC.splitlines()[0]) == (None, None)


def test_read_wifi_missing_file(tmp_path):
    assert read_wifi(tmp_path / "nope") == (None, None)


@pytest.mark.parametrize("dbm, bars, quality", [
    (-45, "▂▄▆█", "Excellent"), (-60, "▂▄▆_", "Good"), (-70, "▂▄__", "Fair"),
    (-80, "▂___", "Weak"), (-90, "____", "Very weak"),
])
def test_dbm_labels(dbm, bars, quality):
    assert dbm_to_label(dbm)[0].endswith(bars)
    assert signal_quality(dbm) == quality
    assert dbm_to_label(None)[0] == "WiFi: ?"


# ── Subnet detection ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("ip,subnet", [
    ("192.168.1.37", "192.168.1.0/24"), ("10.20.30.40", "10.20.30.0/24"),
    ("127.0.0.1", None), ("0.0.0.0", None), ("169.254.3.4", None),
    ("", None), (None, None), ("not an ip", None), ("fe80::1", None),
])
def test_subnet_of(ip, subnet):
    assert subnet_of(ip) == subnet


def _scanner_at(qapp, monkeypatch, ip):
    from lanscanman.app import LanScanManApp
    from lanscanman.ui.tabs import scanner_tab
    where = {"ip": ip}
    monkeypatch.setattr(scanner_tab, "_local_ipv4", lambda: where["ip"])
    win = LanScanManApp()
    win._schedule_timer.stop()
    return win, win.scanner_page, where


def test_subnet_detected_at_startup(qapp, monkeypatch):
    _, tab, _ = _scanner_at(qapp, monkeypatch, "192.168.7.20")
    assert tab.subnet_input.text() == "192.168.7.0/24"


def test_started_offline_follows_network_once_connected(qapp, monkeypatch):
    win, tab, where = _scanner_at(qapp, monkeypatch, None)
    assert tab.subnet_input.text() == "192.168.1.0/24"
    tab._follow_network()                              # still offline: no change
    assert tab.subnet_input.text() == "192.168.1.0/24"
    where["ip"] = "192.168.50.23"
    tab._follow_network()
    assert tab.subnet_input.text() == "192.168.50.0/24"
    assert "Network changed" in win.status.text()
    where["ip"] = "172.16.4.9"                         # switched networks
    tab._follow_network()
    assert tab.subnet_input.text() == "172.16.4.0/24"


def test_typed_subnet_is_never_overwritten_automatically(qapp, monkeypatch):
    _, tab, where = _scanner_at(qapp, monkeypatch, "192.168.7.20")
    tab.subnet_input.setText("10.8.0.0/16")
    where["ip"] = "192.168.50.23"
    tab._follow_network()
    assert tab.subnet_input.text() == "10.8.0.0/16"
    tab._subnet_btn.click()                            # ⟳ takes over again
    assert tab.subnet_input.text() == "192.168.50.0/24"
    where["ip"] = "172.16.4.9"
    tab._follow_network()
    assert tab.subnet_input.text() == "172.16.4.0/24"


def test_refresh_while_offline_keeps_subnet(qapp, monkeypatch):
    win, tab, where = _scanner_at(qapp, monkeypatch, "192.168.7.20")
    where["ip"] = None
    tab._subnet_btn.click()
    assert tab.subnet_input.text() == "192.168.7.0/24"
    assert "Not connected" in win.status.text()


def test_subnet_not_changed_during_a_scan(qapp, monkeypatch):
    _, tab, where = _scanner_at(qapp, monkeypatch, "192.168.7.20")
    tab._set_scanning_ui(True)
    where["ip"] = "192.168.50.23"
    tab._follow_network()
    assert tab.subnet_input.text() == "192.168.7.0/24"
