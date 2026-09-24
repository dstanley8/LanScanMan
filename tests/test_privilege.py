"""Privileged scans without handling the password — and without installing anything."""

import pytest

from lanscanman.core import privilege as P
from lanscanman.core.nmap_scan import host_scan_args, subnet_scan_args
from lanscanman.services import privilege, security_settings
from lanscanman.services.privilege import Capabilities

# ── argument check before asking for permission ─────────────────────────────

@pytest.mark.parametrize("args", [
    subnet_scan_args("192.168.1.0/24", True),
    subnet_scan_args("192.168.1.0/24", True, thorough=True),
    subnet_scan_args("10.0.0.0/8", False),
    host_scan_args("192.168.50.5", "quick", True),
    host_scan_args("192.168.50.5", "full", True),
    host_scan_args("192.168.50.5", "custom", True, "22,80,8000-8100"),
    host_scan_args("fe80::1", "quick", True),
])
def test_everything_lanscanman_generates_is_allowed(args):
    assert P.validate_scan_args(args) is None


@pytest.mark.parametrize("args, why", [
    (["-sS", "--script", "vuln", "-oX", "-", "192.168.50.5"], "--script"),
    (["-sS", "--script=vuln", "-oX", "-", "192.168.50.5"], "--script="),
    (["-sS", "-oN", "/etc/cron.d/x", "-oX", "-", "192.168.50.5"], "write a file as root"),
    (["-sS", "-oX", "/tmp/out.xml", "192.168.50.5"], "-oX to a file"),
    (["-sS", "-iL", "/etc/shadow", "-oX", "-", "192.168.50.5"], "read a file as root"),
    (["-sS", "--datadir", "/tmp/evil", "-oX", "-", "192.168.50.5"], "--datadir"),
    (["-sS", "--interactive", "-oX", "-", "192.168.50.5"], "--interactive"),
    (["-sS", "-oX", "-", "192.168.50.5", "192.168.50.6"], "two targets"),
    (["-sS", "-oX", "-", "evil.example.com"], "hostname target"),
    (["-sS", "-oX", "-", "--script"], "option as target"),
    (["-sS", "-p", "22;id", "-oX", "-", "192.168.50.5"], "shell junk in ports"),
    (["-sS", "-p", "0", "-oX", "-", "192.168.50.5"], "port 0"),
    (["-sS", "-p", "70000", "-oX", "-", "192.168.50.5"], "port too high"),
    (["-sS", "-p", "90-80", "-oX", "-", "192.168.50.5"], "backwards range"),
    (["-sS", "-p", "-oX", "-", "192.168.50.5"], "-p swallowing the next option"),
    (["-sS", "--version-intensity", "99", "-oX", "-", "192.168.50.5"], "bad intensity"),
    (["-sS", "--host-timeout", "15", "-oX", "-", "192.168.50.5"], "timeout without unit"),
    (["-sS", "-sT", "-oX", "-", "192.168.50.5"], "two scan types"),
    (["-sV", "-oX", "-", "192.168.50.5"], "no scan type"),
    (["-sS", "192.168.50.5"], "no XML to stdout"),
    ([], "nothing"),
])
def test_anything_else_is_refused(args, why):
    assert P.validate_scan_args(args) is not None, why


# ── the polkit policy ───────────────────────────────────────────────────────

# ── outcomes ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("method, code, err, outcome", [
    (P.PKEXEC, 0, "", P.OK),
    (P.PKEXEC, 126, "", P.CANCELLED),
    (P.PKEXEC, 127, "Error executing command as another user: Not authorized", P.DENIED),
    (P.PKEXEC, 127, "Error executing command as another user: No authentication agent found.", P.NO_AGENT),
    (P.ASKPASS, 1, "sudo: no password was provided", P.CANCELLED),
    (P.ASKPASS, 1, "sudo: 3 incorrect password attempts", P.DENIED),
    (P.PASSWORD, 1, "Sorry, try again.", P.DENIED),
    (P.PASSWORD, 1, "carol is not in the sudoers file.", P.DENIED),
    (P.PKEXEC, 1, "Failed to open socket", P.FAILED),
    (P.SUDO_CACHED, 0, "", P.OK),
    (P.SUDO_CACHED, 1, "sudo: a password is required", P.NEEDS_PASSWORD),
    (P.SUDO_CACHED, 1, "Failed to resolve", P.FAILED),
])
def test_classify(method, code, err, outcome):
    assert P.classify(method, code, err) == outcome


# ── detection and commands ──────────────────────────────────────────────────

def _caps(**kw):
    base = dict(pkexec="/usr/bin/pkexec", pkttyagent="/usr/bin/pkttyagent",
                terminal=["xterm", "-e", "bash", "-c"], sudo="/usr/bin/sudo",
                askpass="/usr/bin/ssh-askpass", nmap="/usr/bin/nmap")
    base.update(kw)
    return Capabilities(**base)


def test_detect(monkeypatch):
    monkeypatch.delenv("SUDO_ASKPASS", raising=False)
    found = {"pkexec": "/usr/bin/pkexec", "pkttyagent": "/usr/bin/pkttyagent",
             "sudo": "/usr/bin/sudo", "nmap": "/usr/bin/nmap"}

    caps = privilege.detect(which=found.get,
                            exists=lambda p: p == "/usr/bin/ksshaskpass",
                            terminal=lambda: ["konsole", "-e", "bash", "-c"])
    assert caps.pkexec == "/usr/bin/pkexec" and caps.askpass == "/usr/bin/ksshaskpass"
    assert caps.terminal[0] == "konsole"


def test_method_order_and_availability():
    assert privilege.methods(_caps()) == [P.PKEXEC, P.PKEXEC_TTY, P.ASKPASS]
    assert privilege.methods(_caps(terminal=None)) == [P.PKEXEC, P.ASKPASS]
    assert privilege.methods(_caps(pkexec=None)) == [P.ASKPASS]
    assert privilege.methods(_caps(pkexec=None, askpass=None)) == []      # → password box, if allowed
    assert privilege.methods(_caps(nmap=None)) == []
    # sudo mode: first "does sudo still remember me?", then askpass if any
    assert privilege.methods(_caps(), P.SUDO_MODE) == [P.SUDO_CACHED, P.ASKPASS]
    assert privilege.methods(_caps(askpass=None), P.SUDO_MODE) == [P.SUDO_CACHED]
    assert privilege.methods(_caps(sudo=None), P.SUDO_MODE) == []


def test_commands_per_method():
    args = subnet_scan_args("192.168.50.0/24", True)
    argv, env = privilege.command(P.PKEXEC, _caps(), args)
    assert argv == ["/usr/bin/pkexec", "/usr/bin/nmap", *args] and env == {}   # the system's nmap
    argv, env = privilege.command(P.ASKPASS, _caps(), args)
    assert argv[:3] == ["/usr/bin/sudo", "-A", "/usr/bin/nmap"]          # sudo may remember it
    assert env == {"SUDO_ASKPASS": "/usr/bin/ssh-askpass"}
    argv, _ = privilege.command(P.PASSWORD, _caps(), args)
    assert argv[:5] == ["/usr/bin/sudo", "-S", "-p", "", "/usr/bin/nmap"]
    argv, _ = privilege.command(P.SUDO_CACHED, _caps(), args)
    assert argv[:3] == ["/usr/bin/sudo", "-n", "/usr/bin/nmap"]          # never prompts


def test_tty_agent_is_for_this_process_only():
    launched = {}
    privilege.start_tty_agent(_caps(), pid=4242, popen=lambda argv, **k: launched.update(argv=argv))
    script = launched["argv"][-1]
    assert "/usr/bin/pkttyagent --process 4242 --fallback" in script
    assert f"timeout {privilege.TTY_AGENT_SECONDS}" in script
    assert launched["argv"][0] == "xterm"


# ── the worker's fallback chain ─────────────────────────────────────────────

def _thread(monkeypatch, caps, results, password=None, mode=P.POLKIT_MODE):
    from lanscanman.workers import scanner
    thread = scanner.ScannerThread("192.168.50.0/24", privileged=True, password=password, mode=mode)
    runs = []

    def fake_exec(argv, env, stdin_text):
        runs.append((argv, env, stdin_text))
        return results.pop(0)
    monkeypatch.setattr(scanner, "detect", lambda: caps)
    monkeypatch.setattr(thread, "_exec", fake_exec)
    monkeypatch.setattr(thread, "_parse", lambda xml: {"parsed": xml})
    monkeypatch.setattr(scanner.privilege, "start_tty_agent", lambda c: runs.append("agent"))
    monkeypatch.setattr(thread, "msleep", lambda ms: None)
    errors = []
    thread.error_occurred.connect(errors.append)
    return thread, runs, errors


def test_chain_falls_back_to_terminal_agent(monkeypatch):
    no_agent = (127, "", "No authentication agent found.")
    thread, runs, errors = _thread(monkeypatch, _caps(), [no_agent, (0, "<xml/>", "")])
    assert thread._run_nmap(subnet_scan_args("192.168.50.0/24", True)) == {"parsed": "<xml/>"}
    assert runs[0][0][0] == "/usr/bin/pkexec" and runs[1] == "agent" and runs[2][0][0] == "/usr/bin/pkexec"
    assert errors == []


def test_chain_stops_on_cancel(monkeypatch):
    thread, runs, errors = _thread(monkeypatch, _caps(), [(126, "", "")])
    assert thread._run_nmap(subnet_scan_args("192.168.50.0/24", True)) is None
    assert errors == ["Scan cancelled — permission was not granted."] and len(runs) == 1


def test_password_method_used_once_then_dropped(monkeypatch):
    thread, runs, errors = _thread(monkeypatch, _caps(pkexec=None, askpass=None),
                                   [(0, "<xml/>", "")], password="hunter2")
    thread._run_nmap(subnet_scan_args("192.168.50.0/24", True))
    assert runs[0][0][:2] == ["/usr/bin/sudo", "-S"] and runs[0][2] == "hunter2\n"
    assert thread.password is None


def test_invalid_arguments_never_reach_a_prompt(monkeypatch):
    thread, runs, errors = _thread(monkeypatch, _caps(), [])
    assert thread._run_nmap(["-sS", "--script", "x", "-oX", "-", "192.168.50.5"]) is None
    assert runs == [] and "not allowed" in errors[0]


def test_no_method_available(monkeypatch):
    thread, runs, errors = _thread(monkeypatch, _caps(pkexec=None, askpass=None), [])
    assert thread._run_nmap(subnet_scan_args("192.168.50.0/24", True)) is None
    assert "No way to run a privileged scan" in errors[0] and runs == []


def test_unprivileged_scans_are_unchanged(monkeypatch):
    from lanscanman.workers import scanner
    thread = scanner.ScannerThread("192.168.50.0/24", privileged=False)
    runs = []
    monkeypatch.setattr(thread, "_exec", lambda argv, env, s: runs.append(argv) or (0, "<x/>", ""))
    monkeypatch.setattr(thread, "_parse", lambda xml: {})
    thread._run_nmap(subnet_scan_args("192.168.50.0/24", False))
    assert runs[0][0] == "nmap" and "pkexec" not in runs[0] and "sudo" not in runs[0]


def test_exec_streams_output_and_handles_big_results(monkeypatch):
    """A scan producing more than a pipe buffer must not stall."""
    from lanscanman.workers import scanner
    thread = scanner.ScannerThread("192.168.50.0/24", privileged=False)
    result = thread._exec(["python3", "-c", "print('x' * 300000)"], {}, None)
    assert result[0] == 0 and len(result[1]) > 300000


# ── the UI ──────────────────────────────────────────────────────────────────

def _answer(monkeypatch, label=None):
    from PyQt6.QtWidgets import QMessageBox
    shown = []

    def fake_exec(box):
        shown.append(box.windowTitle())
        box._clicked = next((b for b in box.buttons() if b.text() == label), None)
    monkeypatch.setattr(QMessageBox, "exec", fake_exec)
    monkeypatch.setattr(QMessageBox, "clickedButton", lambda box: box._clicked)
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: shown.append(a[1]))
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: shown.append(a[1]))
    return shown


def test_prepare_goes_straight_through_when_ready(qapp, monkeypatch):
    from lanscanman.ui import privilege as ui
    monkeypatch.setattr(ui.privilege, "detect", lambda: _caps())
    shown = _answer(monkeypatch)
    assert ui.prepare_privileged_scan(None) == (True, None, "polkit") and shown == []


def test_sudo_mode_uses_what_sudo_remembers(monkeypatch):
    thread, runs, errors = _thread(monkeypatch, _caps(askpass=None), [(0, "<xml/>", "")],
                                   mode=P.SUDO_MODE)
    assert thread._run_nmap(subnet_scan_args("192.168.50.0/24", True)) == {"parsed": "<xml/>"}
    assert runs[0][0][:2] == ["/usr/bin/sudo", "-n"] and runs[0][2] is None   # no password sent


def test_sudo_mode_falls_back_to_askpass_when_forgotten(monkeypatch):
    forgotten = (1, "", "sudo: a password is required")
    thread, runs, errors = _thread(monkeypatch, _caps(), [forgotten, (0, "<xml/>", "")],
                                   mode=P.SUDO_MODE)
    assert thread._run_nmap(subnet_scan_args("192.168.50.0/24", True)) == {"parsed": "<xml/>"}
    assert runs[1][0][:2] == ["/usr/bin/sudo", "-A"] and errors == []


def test_sudo_mode_expired_while_waiting_asks_to_retry(monkeypatch):
    forgotten = (1, "", "sudo: a password is required")
    thread, runs, errors = _thread(monkeypatch, _caps(askpass=None), [forgotten], mode=P.SUDO_MODE)
    assert thread._run_nmap(subnet_scan_args("192.168.50.0/24", True)) is None
    assert "no longer remembers" in errors[0]


def test_sudo_use_is_forgotten_on_exit(monkeypatch):
    privilege._sudo_used = False
    thread, runs, errors = _thread(monkeypatch, _caps(), [(0, "<xml/>", "")], mode=P.SUDO_MODE)
    thread._run_nmap(subnet_scan_args("192.168.50.0/24", True))
    assert privilege._sudo_used
    ran = []
    monkeypatch.setattr(privilege, "detect", lambda: _caps())

    class R:
        returncode = 0
    privilege.forget_if_used(run=lambda argv, **k: ran.append(argv) or R())
    assert ran == [["/usr/bin/sudo", "-k"]] and not privilege._sudo_used
    privilege.forget_if_used(run=lambda argv, **k: ran.append(argv) or R())
    assert len(ran) == 1                                     # nothing to forget now


def test_polkit_use_does_not_mark_sudo(monkeypatch):
    privilege._sudo_used = False
    thread, runs, errors = _thread(monkeypatch, _caps(), [(0, "<xml/>", "")])
    thread._run_nmap(subnet_scan_args("192.168.50.0/24", True))
    assert not privilege._sudo_used


def test_sudo_remembers_check():
    class R:
        def __init__(self, code):
            self.returncode = code
    assert privilege.sudo_remembers(_caps(), run=lambda argv, **k: R(0))
    assert not privilege.sudo_remembers(_caps(), run=lambda argv, **k: R(1))
    assert not privilege.sudo_remembers(_caps(sudo=None))


def test_prepare_in_sudo_mode(qapp, monkeypatch):
    from lanscanman.ui import privilege as ui
    from lanscanman.ui.dialogs import host_dialogs
    security_settings.save(privilege_method="sudo")
    shown = _answer(monkeypatch)
    asked = []
    monkeypatch.setattr(host_dialogs.SudoDialog, "exec", lambda self: asked.append(1) or True)
    monkeypatch.setattr(host_dialogs.SudoDialog, "get_password", lambda self: "hunter2")

    monkeypatch.setattr(ui.privilege, "detect", lambda: _caps(askpass=None))
    monkeypatch.setattr(ui.privilege, "sudo_remembers", lambda caps: True)
    assert ui.prepare_privileged_scan(None) == (True, None, "sudo") and asked == []   # remembered

    monkeypatch.setattr(ui.privilege, "sudo_remembers", lambda caps: False)
    assert ui.prepare_privileged_scan(None) == (True, "hunter2", "sudo") and asked == [1]

    monkeypatch.setattr(ui.privilege, "detect", lambda: _caps())            # askpass installed
    assert ui.prepare_privileged_scan(None) == (True, None, "sudo") and asked == [1]
    assert shown == []


def test_prepare_polkit_mode_without_any_prompt(qapp, monkeypatch):
    from lanscanman.ui import privilege as ui
    monkeypatch.setattr(ui.privilege, "detect", lambda: _caps(pkexec=None, askpass=None))
    shown = _answer(monkeypatch)
    assert ui.prepare_privileged_scan(None) == (False, None, "polkit")
    assert shown == ["Privileged scan unavailable"]


def test_password_box_has_no_remember_option(qapp):
    from PyQt6.QtWidgets import QCheckBox

    from lanscanman.ui.dialogs.host_dialogs import SudoDialog
    dlg = SudoDialog()
    assert dlg.findChildren(QCheckBox) == []


def test_privilege_method_setting_is_signed_and_fails_safe():
    from lanscanman import paths
    assert security_settings.privilege_method() == "polkit"                 # default
    security_settings.save(privilege_method="sudo")
    assert security_settings.privilege_method() == "sudo"
    paths.SECURITY_FILE.write_text('{"privilege_method": "sudo"}')          # edited outside the app
    assert security_settings.privilege_method() == "polkit"
    security_settings.save(privilege_method="nonsense")
    assert security_settings.privilege_method() == "polkit"


def test_scanner_menu_switches_mode_and_forgets(qapp, monkeypatch):
    from lanscanman.app import LanScanManApp
    win = LanScanManApp()
    win._schedule_timer.stop()
    forgot = []
    monkeypatch.setattr(privilege, "forget", lambda *a, **k: forgot.append(1) or True)
    win.scanner_page._set_privilege_method("sudo")
    assert security_settings.privilege_method() == "sudo" and "15 minutes" in win.status.text()
    win.scanner_page._set_privilege_method("polkit")
    assert forgot == [1]                                   # leaving sudo mode clears its memory
    win.scanner_page._forget_permission()
    assert forgot == [1, 1] and "forgotten" in win.status.text().lower()
    win.deleteLater()


def test_no_app_wide_password_cache(qapp):
    from lanscanman.app import LanScanManApp
    win = LanScanManApp()
    win._schedule_timer.stop()
    assert not hasattr(win, "cached_password")
    win.deleteLater()




def test_nothing_is_installed():
    """LanScanMan only uses what the system has: no helper, no policy file,
    no install step anywhere in the privilege code."""
    import inspect

    from lanscanman.ui import privilege as ui
    for module in (P, privilege, ui):
        src = inspect.getsource(module).lower()
        assert "polkit-1/actions" not in src and "/usr/local/libexec" not in src
        assert "install -" not in src
    assert not hasattr(privilege, "install_command")


# ── INSECURE: remembered until the app closes ───────────────────────────────

@pytest.fixture
def clean_session():
    privilege.drop_session_password()
    yield
    privilege.drop_session_password()


def test_session_mode_asks_once_then_reuses(qapp, monkeypatch, clean_session):
    from lanscanman.ui import privilege as ui
    from lanscanman.ui.dialogs import host_dialogs
    security_settings.save(privilege_method="sudo_session")
    asked = []
    monkeypatch.setattr(host_dialogs.SudoDialog, "exec", lambda self: asked.append(1) or True)
    monkeypatch.setattr(host_dialogs.SudoDialog, "get_password", lambda self: "hunter2")
    monkeypatch.setattr(ui.privilege, "detect", lambda: _caps())   # askpass present: not used
    monkeypatch.setattr(ui.privilege, "sudo_remembers", lambda caps: False)
    assert ui.prepare_privileged_scan(None) == (True, "hunter2", "sudo_session")
    assert ui.prepare_privileged_scan(None) == (True, "hunter2", "sudo_session")
    assert asked == [1]                                        # asked only once
    monkeypatch.setattr(ui.privilege, "sudo_remembers", lambda caps: True)
    assert ui.prepare_privileged_scan(None) == (True, None, "sudo_session")   # sudo still remembers


def test_session_dialog_says_it_is_kept(qapp):
    from PyQt6.QtWidgets import QLabel

    from lanscanman.ui.dialogs.host_dialogs import SudoDialog
    dlg = SudoDialog(keep_for_session=True)
    texts = " ".join(label.text() for label in dlg.findChildren(QLabel))
    assert "keep this in memory until it closes" in texts and "never written to disk" in texts


def test_session_mode_skips_askpass_in_the_chain():
    assert privilege.methods(_caps(), P.SUDO_SESSION_MODE) == [P.SUDO_CACHED]


def test_rejected_held_password_is_dropped(monkeypatch, clean_session):
    privilege.remember_session_password("old-password")
    thread, runs, errors = _thread(monkeypatch, _caps(), [(1, "", "Sorry, try again.")],
                                   password="old-password", mode=P.SUDO_SESSION_MODE)
    thread._run_nmap(subnet_scan_args("192.168.50.0/24", True))
    assert privilege.session_password() is None and "Permission denied" in errors[0]


def test_forget_and_exit_drop_the_held_password(monkeypatch, clean_session):
    class R:
        returncode = 0
    monkeypatch.setattr(privilege, "detect", lambda: _caps())
    privilege.remember_session_password("hunter2")
    privilege.forget(run=lambda *a, **k: R())
    assert privilege.session_password() is None
    privilege.remember_session_password("hunter2")
    privilege.forget_if_used(run=lambda *a, **k: R())
    assert privilege.session_password() is None


def test_held_password_is_never_written_to_disk(qapp, monkeypatch, clean_session, isolated_config):
    from lanscanman.ui import privilege as ui
    from lanscanman.ui.dialogs import host_dialogs
    security_settings.save(privilege_method="sudo_session")
    monkeypatch.setattr(host_dialogs.SudoDialog, "exec", lambda self: True)
    monkeypatch.setattr(host_dialogs.SudoDialog, "get_password", lambda self: "Very-Secret-42")
    monkeypatch.setattr(ui.privilege, "detect", lambda: _caps())
    monkeypatch.setattr(ui.privilege, "sudo_remembers", lambda caps: False)
    ui.prepare_privileged_scan(None)
    for f in isolated_config.rglob("*"):
        if f.is_file():
            assert b"Very-Secret-42" not in f.read_bytes(), f


def test_insecure_mode_needs_confirmation(qapp, monkeypatch, clean_session):
    from lanscanman.app import LanScanManApp
    win = LanScanManApp()
    win._schedule_timer.stop()
    shown = _answer(monkeypatch, "Cancel")
    win.scanner_page._set_privilege_method("sudo_session")
    assert security_settings.privilege_method() == "polkit" and shown
    _answer(monkeypatch, "Remember until closed")
    win.scanner_page._set_privilege_method("sudo_session")
    assert security_settings.privilege_method() == "sudo_session"
    privilege.remember_session_password("hunter2")
    forgot = []
    monkeypatch.setattr(privilege, "forget", lambda *a, **k: forgot.append(1) or privilege.drop_session_password())
    win.scanner_page._set_privilege_method("sudo")             # leaving insecure mode drops it
    assert forgot and privilege.session_password() is None
    win.deleteLater()


def test_insecure_mode_cannot_be_switched_on_by_editing_files():
    from lanscanman import paths
    security_settings.save(privilege_method="polkit")
    paths.SECURITY_FILE.write_text('{"privilege_method": "sudo_session"}')
    assert security_settings.privilege_method() == "polkit"
