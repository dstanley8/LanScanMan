import shlex

import pytest

from lanscanman.core.connect import (
    PRESS_ENTER,
    SSH_OPTS,
    authorized_keys_commands,
    connection_url,
    get_terminal_command,
    guess_protocol,
    parse_tmux_ls,
    ssh_command,
    ssh_copy_id_command,
    terminal_argv,
    tmux_command,
)


def test_get_terminal_command_prefers_first_installed():
    installed = {"xterm", "konsole"}
    assert get_terminal_command(lambda b: b in installed) == ["konsole", "-e", "bash", "-c"]
    assert get_terminal_command(lambda b: False) is None


def test_terminal_argv_keeps_shell_open():
    assert terminal_argv(["xterm", "-e", "bash", "-c"], "ssh x") == \
        ["xterm", "-e", "bash", "-c", "ssh x; exec bash"]


def test_terminal_argv_single_string_terminals():
    # xfce4/mate/lxterminal: -e takes ONE string, so the script must be inside it
    argv = terminal_argv(["xfce4-terminal", "-e", "bash -c"], "ssh 'x y'@h")
    assert argv[:2] == ["xfce4-terminal", "-e"] and len(argv) == 3
    assert shlex.split(argv[2]) == ["bash", "-c", "ssh 'x y'@h; exec bash"]


def test_terminal_argv_custom_tail():
    argv = terminal_argv(["xterm", "-e", "bash", "-c"], "ssh-copy-id h", PRESS_ENTER)
    assert argv[-1] == "ssh-copy-id h" + PRESS_ENTER


def test_authorized_keys_commands_quote_the_key():
    key = "ssh-ed25519 AAAAC3Nza carol's laptop"
    last = authorized_keys_commands(key)[-1]
    words = shlex.split(last)
    assert words[:3] == ["grep", "-qxF", key]
    assert words[words.index("echo") + 1] == key


def test_ssh_command():
    assert ssh_command("carol", "192.168.50.5") == f"ssh {SSH_OPTS} carol@192.168.50.5"
    assert ssh_command("carol", "192.168.50.5", 2222).startswith("ssh -p 2222 ")


def test_ssh_command_quotes_hostile_input():
    cmd = ssh_command("x; rm -rf ~", "192.168.50.5")
    assert shlex.split(cmd)[-1] == "x; rm -rf ~@192.168.50.5"


def test_tmux_commands():
    new = tmux_command("carol", "192.168.50.5", "tmux_new", "work")
    assert new.startswith(f"ssh -t {SSH_OPTS} carol@192.168.50.5 ")
    assert shlex.split(new)[-1] == "tmux new -s work || tmux a"
    attach = tmux_command("carol", "192.168.50.5", "tmux_attach", "main")
    assert shlex.split(attach)[-1] == "tmux a -t main"
    assert shlex.split(tmux_command("carol", "192.168.50.5", "tmux_new"))[-1].startswith("tmux new -s LanScanMan")
    assert tmux_command("carol", "192.168.50.5", "ssh") == ssh_command("carol", "192.168.50.5")


@pytest.mark.parametrize("session", ["x;touch /tmp/pwned", "a b", "it's", "$(id)"])
def test_tmux_session_names_cannot_escape_to_local_shell(session):
    # The local shell must see exactly one remote-command word, and the
    # remote shell must see the session name as a single literal argument.
    for mode in ("tmux_new", "tmux_attach"):
        words = shlex.split(tmux_command("carol", "192.168.50.5", mode, session))
        assert words[:2] == ["ssh", "-t"] and words[-2] == "carol@192.168.50.5"
        remote = shlex.split(words[-1])
        assert remote[remote.index("-t" if mode == "tmux_attach" else "-s") + 1] == session


def test_ssh_copy_id_command():
    assert ssh_copy_id_command("carol", "192.168.50.5") == f"ssh-copy-id {SSH_OPTS} carol@192.168.50.5"


@pytest.mark.parametrize("out, expected", [
    ("main: 1 windows (created Mon)\nwork: 3 windows\nEXIT:0", (True, ["main", "work"])),
    ("EXIT:1", (True, [])),                     # tmux installed, no server running
    ("EXIT:127", (True, None)),                 # tmux not installed
    ("", (True, [])),
])
def test_parse_tmux_ls(out, expected):
    assert parse_tmux_ls(out) == expected


@pytest.mark.parametrize("service, port, proto", [
    ("vnc", 5901, "VNC"),
    ("ms-wbt-server", 3389, "RDP"),
    ("https-alt", 8443, "HTTPS"),
    ("http-proxy", 8080, "HTTP"),
    ("ssh", 2222, "SSH"),
    ("", 443, "HTTPS"),
    ("unknown", 9999, "SSH"),
])
def test_guess_protocol(service, port, proto):
    assert guess_protocol(service, port) == proto


def test_connection_url():
    assert connection_url("HTTPS", "192.168.50.5", 8443) == "https://192.168.50.5:8443"
