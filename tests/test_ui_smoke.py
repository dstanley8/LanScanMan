"""
Build the whole main window headlessly (QT_QPA_PLATFORM=offscreen) against
an empty config directory. Catches broken imports, missing names in UI
code paths that run at startup, and signal wiring errors. Nothing is
scanned or probed: with no profiles there is nothing to contact, and the
conftest guards fail the test if anything tries.
"""

import importlib
import os
import pkgutil

import pytest

pytest.importorskip("PyQt6.QtWidgets")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import lanscanman  # noqa: E402


def _all_modules():
    return [m.name for m in pkgutil.walk_packages(lanscanman.__path__, "lanscanman.")]


@pytest.mark.parametrize("name", _all_modules())
def test_module_imports(name):
    importlib.import_module(name)


@pytest.fixture(scope="module")
def qapp():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def test_main_window_builds(qapp):
    from lanscanman.app import LanScanManApp
    win = LanScanManApp()
    titles = [win.tabs.tabText(i) for i in range(win.tabs.count())]
    assert titles == ["Network Scanner", "Host Inspector", "Host Monitor",
                      "Disk Health", "File Transfers", "AI", "About"]
    win._next_tab()
    assert win.tabs.currentIndex() == 1
    win._prev_tab()
    win._prev_tab()
    assert win.tabs.currentIndex() == win.tabs.count() - 1
    win._schedule_timer.stop()
    win.deleteLater()


def test_about_page_loads_html(qapp):
    from lanscanman.ui.tabs.about_tab import _HTML_PATH
    assert "<h1>LanScanMan</h1>" in _HTML_PATH.read_text(encoding="utf-8")


def _scanner_with_row(qapp, hostname):
    from lanscanman.app import LanScanManApp
    win = LanScanManApp()
    win._schedule_timer.stop()
    tab = win.scanner_page
    tab.run_background_pings = lambda: None          # don't ping anything
    tab._populate_results([{"ip": "192.168.50.5", "hostname": hostname, "mac": "",
                            "vendor": "unknown", "ssh": "open", "services": "SSH"}])
    return win, tab


def _choose(monkeypatch, tab, label_prefix):
    """Open the row's context menu and 'click' the Copy entry starting with label_prefix."""
    from PyQt6.QtWidgets import QMenu
    seen = {}

    def fake_exec(menu, *a):
        copy = next(a.menu() for a in menu.actions() if a.menu() and a.text() == "Copy")
        seen["actions"] = {a.text(): a.isEnabled() for a in copy.actions()}
        return next((a for a in copy.actions() if a.text().startswith(label_prefix)), None)

    monkeypatch.setattr(QMenu, "exec", fake_exec)
    rect = tab.table.visualItemRect(tab.table.item(0, 0))
    tab.show_context_menu(rect.center())
    return seen["actions"]


def test_copy_ip_and_hostname(qapp, monkeypatch):
    from PyQt6.QtWidgets import QApplication
    win, tab = _scanner_with_row(qapp, "nas.lan")
    _choose(monkeypatch, tab, "IP Address")
    assert QApplication.clipboard().text() == "192.168.50.5"
    _choose(monkeypatch, tab, "Hostname")
    assert QApplication.clipboard().text() == "nas.lan"
    assert "Copied hostname" in win.status.text()
    win.deleteLater()


def test_copy_hostname_disabled_when_missing(qapp, monkeypatch):
    win, tab = _scanner_with_row(qapp, "")
    actions = _choose(monkeypatch, tab, "nothing")
    assert actions["Hostname  (none)"] is False
    assert actions["IP Address  (192.168.50.5)"] is True
    win.deleteLater()


# ── integrity dialogs ───────────────────────────────────────────────────────

def _click(monkeypatch, label):
    """Make QMessageBox.exec 'click' the button with this text."""
    from PyQt6.QtWidgets import QMessageBox
    shown = []

    def fake_exec(box):
        shown.append(box.text())
        btn = next(b for b in box.buttons() if b.text() == label)
        box._clicked = btn
        return 0

    monkeypatch.setattr(QMessageBox, "exec", fake_exec)
    monkeypatch.setattr(QMessageBox, "clickedButton", lambda box: box._clicked)
    return shown


def test_tamper_dialog_can_trust_current_file(qapp, monkeypatch, isolated_config):
    from lanscanman.core.integrity import TamperedError
    from lanscanman.services.network_manager import NetworkManager
    from lanscanman.ui.trust import show_integrity_problem
    nm = NetworkManager()
    nm.save_profile("aa:bb:cc:dd:ee:ff", "192.168.50.5", "nas", "NAS", "carol")
    (isolated_config / "hosts.json").write_text('{"x": {"alias": "edited by hand"}}')
    with pytest.raises(TamperedError) as err:
        nm.store.require_verified()

    shown = _click(monkeypatch, "Keep blocked")
    show_integrity_problem(None, err.value)
    assert "hosts.json" in shown[0]
    with pytest.raises(TamperedError):
        nm.store.require_verified()          # still blocked

    _click(monkeypatch, "Trust current file")
    show_integrity_problem(None, err.value)
    nm.store.require_verified()              # now accepted
    assert nm.profiles["x"]["alias"] == "edited by hand"


def test_changed_host_key_needs_confirmation(qapp, monkeypatch, isolated_config):
    import paramiko
    from PyQt6.QtWidgets import QMessageBox

    from lanscanman.services import ssh
    from lanscanman.ui import trust
    old, new = paramiko.ECDSAKey.generate(), paramiko.ECDSAKey.generate()
    ssh.add_host_key("192.168.50.5", old)
    real = ssh.prepare_cli_ssh
    monkeypatch.setattr(trust, "prepare_cli_ssh",
                        lambda ip, port=22: real(ip, port, fetch=lambda *a, **k: new))
    shown = []

    def answer(label):
        def fake_exec(box):
            shown.append((box.text(), box.informativeText(), box.defaultButton().text()))
            box._clicked = next(b for b in box.buttons() if b.text() == label)
        monkeypatch.setattr(QMessageBox, "exec", fake_exec)
        monkeypatch.setattr(QMessageBox, "clickedButton", lambda box: box._clicked)

    answer("Keep blocked")
    assert trust.pin_host_or_warn(None, "192.168.50.5") is False
    assert ssh.trusted_host_keys().lookup("192.168.50.5")[old.get_name()].asbytes() == old.asbytes()
    text, info, default = shown[0]
    assert "has changed" in text and default == "Keep blocked"
    assert f"Previously:  {ssh.fingerprint(old)}" in info and f"Now:  {ssh.fingerprint(new)}" in info

    answer("Trust the new key")
    assert trust.pin_host_or_warn(None, "192.168.50.5") is True
    assert ssh.trusted_host_keys().lookup("192.168.50.5")[new.get_name()].asbytes() == new.asbytes()


def test_excepthook_turns_integrity_errors_into_dialogs(qapp, monkeypatch):
    from lanscanman import app as app_module
    from lanscanman.core.integrity import KeyUnavailable
    seen = []
    monkeypatch.setattr(app_module, "show_integrity_problem", lambda parent, e: seen.append(e))
    err = KeyUnavailable("declined")
    app_module._excepthook(KeyUnavailable, err, None)
    assert seen == [err]


def test_monitor_health_column_and_dialog(qapp, isolated_config):
    from test_probe import REAL_HEALTH

    from lanscanman.core.probe import parse_probe_output
    from lanscanman.services.network_manager import NetworkManager
    from lanscanman.ui.dialogs.host_stats import HostStatsDialog
    from lanscanman.ui.tabs.monitor_tab import _COL_HEALTH, MonitorTab
    tab = MonitorTab(NetworkManager())
    tab._add_row("nas", "192.168.50.5", "carol")
    data = parse_probe_output(REAL_HEALTH)
    tab._on_result("192.168.50.5", data)
    cell = tab._table.item(0, _COL_HEALTH)
    assert cell.text().startswith("1 failed") and "vboxadd.service" in cell.toolTip()

    dlg = HostStatsDialog.__new__(HostStatsDialog)
    from PyQt6.QtWidgets import QDialog
    QDialog.__init__(dlg)
    from lanscanman.ui.widgets.common import value_label
    dlg._lbl_health = value_label("—")
    dlg._apply_health(data)
    text = dlg._lbl_health.text()
    assert "FAILED — vboxadd.service" in text and "3 pending, 1 security" in text
    assert "Reboot:  required" in text and "DOWN — backup, db" in text
