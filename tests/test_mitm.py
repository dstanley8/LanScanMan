"""Man-in-the-middle defences: first contact vs ~/.ssh/known_hosts, and the
host-key-changed decision."""

import paramiko
import pytest

from lanscanman.core.devices import key_change_context
from lanscanman.services import ssh


def _key():
    return paramiko.ECDSAKey.generate()


def _system_known_hosts(lines):
    path = ssh.SYSTEM_KNOWN_HOSTS[0]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(l + "\n" for l in lines))


def _line(host, key, hashed=False):
    name = paramiko.HostKeys.hash_host(host) if hashed else host
    return f"{name} {key.get_name()} {key.get_base64()}"


# ── A: first contact is checked against the user's own known_hosts ──────────

def test_first_contact_matching_system_key_is_trusted():
    real = _key()
    _system_known_hosts([_line("192.168.50.5", real)])
    ssh.prepare_cli_ssh("192.168.50.5", fetch=lambda *a, **k: real)
    assert ssh.trusted_host_keys().lookup("192.168.50.5")[real.get_name()].asbytes() == real.asbytes()


@pytest.mark.parametrize("hashed", [False, True])
def test_first_contact_contradicting_system_key_is_refused(hashed):
    real, impostor = _key(), _key()
    _system_known_hosts([_line("192.168.50.5", real, hashed)])
    with pytest.raises(ssh.HostKeyMismatchError) as err:
        ssh.prepare_cli_ssh("192.168.50.5", fetch=lambda *a, **k: impostor)
    e = err.value
    assert e.source == ssh.SYSTEM and e.new_key is impostor
    assert e.old_key.asbytes() == real.asbytes()
    assert ssh.trusted_host_keys().lookup("192.168.50.5") is None          # nothing pinned


def test_first_contact_asks_for_the_key_type_the_user_already_trusts():
    real = _key()
    _system_known_hosts([_line("192.168.50.5", real)])
    asked = {}

    def fetch(ip, port, key_types=None):
        asked["types"] = key_types
        return real
    ssh.prepare_cli_ssh("192.168.50.5", fetch=fetch)
    assert asked["types"] == [real.get_name()]


def test_unknown_host_is_plain_tofu():
    k = _key()
    ssh.prepare_cli_ssh("192.168.50.7", fetch=lambda *a, **kw: k)        # no system entry
    assert ssh.trusted_host_keys().lookup("192.168.50.7") is not None


def test_non_standard_port_uses_bracketed_name():
    real, impostor = _key(), _key()
    _system_known_hosts([_line("[192.168.50.5]:2222", real)])
    with pytest.raises(ssh.HostKeyMismatchError):
        ssh.prepare_cli_ssh("192.168.50.5", 2222, fetch=lambda *a, **k: impostor)
    ssh.prepare_cli_ssh("192.168.50.5", 22, fetch=lambda *a, **k: impostor)  # port 22 is a different entry


def test_paramiko_first_contact_is_checked_too():
    real, impostor = _key(), _key()
    _system_known_hosts([_line("192.168.50.5", real)])
    client = ssh.make_ssh_client()
    with pytest.raises(paramiko.BadHostKeyException) as err:
        ssh.LanScanManHostKeyPolicy().missing_host_key(client, "192.168.50.5", impostor)
    converted = ssh.mismatch_from(err.value)
    assert converted.source == ssh.SYSTEM and converted.new_key is impostor
    assert ssh.trusted_host_keys().lookup("192.168.50.5") is None


def test_malformed_lines_are_skipped_not_fatal():
    real, impostor = _key(), _key()
    _system_known_hosts(["this is not a known_hosts line", "|1|garbage",
                         "192.168.50.9 ssh-ed25519 !!!notbase64", _line("192.168.50.5", real)])
    k = _key()
    ssh.prepare_cli_ssh("192.168.50.8", fetch=lambda *a, **kw: k)          # still connects
    with pytest.raises(ssh.HostKeyMismatchError):                       # valid line still counts
        ssh.prepare_cli_ssh("192.168.50.5", fetch=lambda *a, **kw: impostor)


def test_trusting_the_new_key_pins_it_despite_system_entry():
    real, reinstalled = _key(), _key()
    _system_known_hosts([_line("192.168.50.5", real)])
    with pytest.raises(ssh.HostKeyMismatchError) as err:
        ssh.prepare_cli_ssh("192.168.50.5", fetch=lambda *a, **k: reinstalled)
    ssh.accept_new_key(err.value)                                      # user's explicit decision
    ssh.prepare_cli_ssh("192.168.50.5", fetch=lambda *a, **k: reinstalled)   # now fine


# ── B: the decision gets fingerprints and device context ────────────────────

def test_fingerprint_matches_openssh_format():
    import base64
    import hashlib
    k = _key()
    expected = base64.b64encode(hashlib.sha256(k.asbytes()).digest()).decode().rstrip("=")
    assert ssh.fingerprint(k) == "SHA256:" + expected


def test_mismatch_carries_both_keys():
    old, new = _key(), _key()
    ssh.add_host_key("192.168.50.5", old)
    with pytest.raises(ssh.HostKeyMismatchError) as err:
        ssh.prepare_cli_ssh("192.168.50.5", fetch=lambda *a, **k: new)
    assert err.value.old_key.asbytes() == old.asbytes() and err.value.new_key is new
    assert err.value.source == ssh.LANSCANMAN


def _devices(**entries):
    return {mac: {"ip": d[0], "ips": d[1], "last_seen": d[2]} for mac, d in entries.items()}


def test_context_ip_moved_to_another_device():
    devices = _devices(**{"aa:aa:aa:aa:aa:01": ("192.168.50.9", ["192.168.50.5", "192.168.50.9"], 100),
                          "aa:aa:aa:aa:aa:02": ("192.168.50.5", ["192.168.50.5"], 200)})
    kind, text = key_change_context(devices, "192.168.50.5")
    assert kind == "moved"
    assert "now belongs to aa:aa:aa:aa:aa:02 (previously aa:aa:aa:aa:aa:01)" in text


def test_context_same_device_new_key():
    devices = _devices(**{"aa:aa:aa:aa:aa:01": ("192.168.50.5", ["192.168.50.5"], 100)})
    kind, text = key_change_context(devices, "192.168.50.5")
    assert kind == "same" and "intercepting" in text


def test_context_unknown():
    assert key_change_context({}, "192.168.50.5")[0] == "unknown"


def test_device_registry_records_ip_history():
    from lanscanman import paths
    from lanscanman.core.devices import DeviceRegistry
    from lanscanman.services.vault import get_vault
    reg = DeviceRegistry(get_vault().signed_file(paths.DEVICES_FILE))
    a = {"ip": "192.168.50.5", "mac": "AA:AA:AA:AA:AA:01", "hostname": "", "vendor": ""}
    reg.observe([a])
    reg.observe([dict(a, ip="192.168.50.9"), {"ip": "192.168.50.5", "mac": "AA:AA:AA:AA:AA:02",
                                          "hostname": "", "vendor": ""}])
    assert reg.devices["aa:aa:aa:aa:aa:01"]["ips"] == ["192.168.50.5", "192.168.50.9"]
    assert key_change_context(reg.devices, "192.168.50.5")[0] == "moved"


def test_probe_worker_reports_the_mismatch_with_keys(monkeypatch):
    from lanscanman.workers import probes
    old, new = _key(), _key()

    def boom(*a, **k):
        raise paramiko.BadHostKeyException("192.168.50.5", new, old)
    monkeypatch.setattr(probes, "run_remote", boom)
    w = probes.ProbeWorker("192.168.50.5", "carol")
    got = []
    w.host_key_changed.connect(lambda ip, err: got.append((ip, err)))
    w.run()
    ip, err = got[0]
    assert ip == "192.168.50.5" and err.new_key is new and err.old_key is old


# ── the dialog ──────────────────────────────────────────────────────────────

def _answer(monkeypatch, label, shown):
    from PyQt6.QtWidgets import QMessageBox

    def fake_exec(box):
        shown.append((box.windowTitle(), box.text(), box.informativeText(),
                      box.defaultButton().text()))
        box._clicked = next(b for b in box.buttons() if b.text() == label)
    monkeypatch.setattr(QMessageBox, "exec", fake_exec)
    monkeypatch.setattr(QMessageBox, "clickedButton", lambda box: box._clicked)


def test_dialog_for_system_mismatch(qapp, monkeypatch):
    from lanscanman.ui.trust import confirm_host_key_change
    real, impostor = _key(), _key()
    shown = []
    _answer(monkeypatch, "Keep blocked", shown)
    err = ssh.HostKeyMismatchError("192.168.50.5", impostor, real, ssh.SYSTEM)
    assert confirm_host_key_change(None, err) is False
    title, text, info, default = shown[0]
    assert title == "Host key doesn't match your SSH settings"
    assert "~/.ssh/known_hosts" in text and default == "Keep blocked"
    assert f"In ~/.ssh/known_hosts:  {ssh.fingerprint(real)}" in info
    assert f"Now:  {ssh.fingerprint(impostor)}" in info


def test_dialog_shows_device_context(qapp, monkeypatch):
    from lanscanman import paths
    from lanscanman.core.devices import DeviceRegistry
    from lanscanman.services.vault import get_vault
    from lanscanman.ui.trust import confirm_host_key_change
    reg = DeviceRegistry(get_vault().signed_file(paths.DEVICES_FILE))
    reg.observe([{"ip": "192.168.50.5", "mac": "AA:AA:AA:AA:AA:01", "hostname": "", "vendor": ""}])
    shown = []
    _answer(monkeypatch, "Keep blocked", shown)
    confirm_host_key_change(None, ssh.HostKeyMismatchError("192.168.50.5", _key(), _key()))
    assert "The same device (aa:aa:aa:aa:aa:01)" in shown[0][2]


# ── C: strict mode — confirm new hosts' fingerprints ────────────────────────

from lanscanman.services import security_settings  # noqa: E402


def test_strict_mode_is_off_by_default():
    assert security_settings.confirm_first_contact() is False
    k = _key()
    ssh.prepare_cli_ssh("192.168.50.7", fetch=lambda *a, **kw: k)       # plain TOFU


def test_strict_mode_asks_before_pinning_a_new_host():
    security_settings.save(confirm_first_contact=True)
    k = _key()
    with pytest.raises(ssh.HostKeyMismatchError) as err:
        ssh.prepare_cli_ssh("192.168.50.7", fetch=lambda *a, **kw: k)
    e = err.value
    assert e.source == ssh.NEW and e.new_key is k and e.old_key is None
    assert ssh.trusted_host_keys().lookup("192.168.50.7") is None        # nothing pinned yet
    ssh.accept_new_key(e)                                            # user confirmed
    ssh.prepare_cli_ssh("192.168.50.7", fetch=lambda *a, **kw: k)        # now known: no prompt


def test_strict_mode_skips_hosts_verified_by_your_known_hosts():
    security_settings.save(confirm_first_contact=True)
    real = _key()
    _system_known_hosts([_line("192.168.50.5", real)])
    ssh.prepare_cli_ssh("192.168.50.5", fetch=lambda *a, **k: real)     # matched: no prompt


def test_strict_mode_paramiko_path():
    security_settings.save(confirm_first_contact=True)
    k = _key()
    client = ssh.make_ssh_client()
    with pytest.raises(paramiko.BadHostKeyException) as err:        # existing handlers catch it
        ssh.LanScanManHostKeyPolicy().missing_host_key(client, "192.168.50.7", k)
    assert "not yet confirmed" in str(err.value)
    converted = ssh.mismatch_from(err.value)
    assert converted.source == ssh.NEW and converted.new_key is k


def test_strict_setting_is_signed_and_fails_safe():
    from lanscanman import paths
    security_settings.save(confirm_first_contact=True)
    paths.SECURITY_FILE.write_text('{"confirm_first_contact": false}')   # tampered to switch it off
    assert security_settings.confirm_first_contact() is True           # strict assumed


def test_strict_mode_probe_worker_routes_to_the_dialog(monkeypatch):
    from lanscanman.workers import probes
    security_settings.save(confirm_first_contact=True)
    k = _key()

    def connect(*a, **kw):
        ssh.LanScanManHostKeyPolicy().missing_host_key(ssh.make_ssh_client(), "192.168.50.7", k)
    monkeypatch.setattr(probes, "run_remote", connect)
    got = []
    w = probes.ProbeWorker("192.168.50.7", "carol")
    w.host_key_changed.connect(lambda ip, err: got.append(err))
    w.run()
    assert got[0].source == ssh.NEW and got[0].new_key is k


def test_first_connection_dialog(qapp, monkeypatch):
    from lanscanman.ui.trust import confirm_host_key_change, host_key_file
    k = _key()
    shown = []
    _answer(monkeypatch, "Cancel", shown)
    err = ssh.HostKeyMismatchError("192.168.50.7", k, None, ssh.NEW)
    assert confirm_host_key_change(None, err) is False
    title, text, info, default = shown[0]
    assert title == "Confirm a new host" and "First connection" in text and default == "Cancel"
    assert f"Now:  {ssh.fingerprint(k)}" in info
    assert "ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub" in info       # matches the key type
    assert ssh.trusted_host_keys().lookup("192.168.50.7") is None

    _answer(monkeypatch, "Trust and connect", shown)
    assert confirm_host_key_change(None, err) is True
    assert ssh.trusted_host_keys().lookup("192.168.50.7") is not None
    assert host_key_file(paramiko.RSAKey.generate(1024)) == "/etc/ssh/ssh_host_rsa_key.pub"


def test_strict_toggle_in_scanner_menu(qapp, monkeypatch):
    from lanscanman.app import LanScanManApp
    win = LanScanManApp()
    win._schedule_timer.stop()
    win.scanner_page._set_strict_first_contact(True)
    assert security_settings.confirm_first_contact() is True
    assert "Strict mode on" in win.status.text()
    win.scanner_page._set_strict_first_contact(False)
    assert security_settings.confirm_first_contact() is False
    win.deleteLater()
