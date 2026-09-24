"""
Building the commands that open a connection to a host: the terminal
emulator to use, the ssh / tmux command line, and URLs for browser-based
protocols. Pure — callers do the launching.
"""

from __future__ import annotations

import shlex
import shutil

PROTO_PORTS: dict[str, int] = {
    "SSH":   22,
    "VNC":   5900,
    "RDP":   3389,
    "HTTP":  80,
    "HTTPS": 443,
}

# StrictHostKeyChecking=yes: the CLI may only *read* our known_hosts. New
# hosts are pinned (and the file re-signed) by services.ssh.prepare_cli_ssh
# before any of these commands run.
SSH_OPTS = (
    "-o StrictHostKeyChecking=yes "
    "-o UserKnownHostsFile=~/.config/LanScanMan/known_hosts"
)

# (binary, args that precede the command string)
TERMINALS = [
    ("gnome-terminal", ["--", "bash", "-c"]),
    ("konsole",        ["-e", "bash", "-c"]),
    ("xfce4-terminal", ["-e", "bash -c"]),
    ("mate-terminal",  ["-e", "bash -c"]),
    ("lxterminal",     ["-e", "bash -c"]),
    ("xterm",          ["-e", "bash", "-c"]),
]


def get_terminal_command(which=shutil.which) -> list[str] | None:
    """First installed terminal emulator as an argv prefix, or None."""
    for binary, args in TERMINALS:
        if which(binary):
            return [binary] + args
    return None


KEEP_OPEN = "; exec bash"
PRESS_ENTER = "; echo; echo 'Done — press Enter to close'; read"


def terminal_argv(term: list[str], shell_cmd: str, then: str = KEEP_OPEN) -> list[str]:
    """
    argv that runs shell_cmd in the terminal, then `then` (by default, leave
    a shell open). Terminals whose -e takes a single string (prefix ends in
    "bash -c") get the script quoted into that string instead of as a
    separate argument, which they would ignore.
    """
    script = shell_cmd + then
    if " " in term[-1]:
        return term[:-1] + [f"{term[-1]} {shlex.quote(script)}"]
    return term + [script]


def ssh_command(user: str, ip: str, port: int = 22) -> str:
    """Plain interactive ssh. user and ip are shell-quoted."""
    port_opt = f"-p {int(port)} " if port != 22 else ""
    return f"ssh {port_opt}{SSH_OPTS} {shlex.quote(user)}@{shlex.quote(ip)}"


def tmux_command(user: str, ip: str, mode: str, session: str | None = None) -> str:
    """
    mode: "tmux_new"    — create (or fall back to attaching) a named session
          "tmux_attach" — attach to an existing session
          anything else — plain ssh
    """
    base = f"ssh -t {SSH_OPTS} {shlex.quote(user)}@{shlex.quote(ip)}"
    if mode == "tmux_new":
        remote = f"tmux new -s {shlex.quote(session or 'LanScanMan')} || tmux a"
    elif mode == "tmux_attach":
        remote = f"tmux a -t {shlex.quote(session or '')}"
    else:
        return ssh_command(user, ip)
    # Quote the whole remote command as one word. Session names can come from
    # the remote host's `tmux ls`, so they must never reach the local shell.
    return f"{base} {shlex.quote(remote)}"


def ssh_copy_id_command(user: str, ip: str) -> str:
    """Interactive key install; the password is typed into the terminal, never seen by us."""
    return f"ssh-copy-id {SSH_OPTS} {shlex.quote(user)}@{shlex.quote(ip)}"


def authorized_keys_commands(pub_key: str) -> list[str]:
    """Remote commands that append pub_key to authorized_keys once."""
    q = shlex.quote(pub_key)
    return [
        "mkdir -p ~/.ssh",
        "chmod 700 ~/.ssh",
        "touch ~/.ssh/authorized_keys",
        "chmod 600 ~/.ssh/authorized_keys",
        f"grep -qxF {q} ~/.ssh/authorized_keys || echo {q} >> ~/.ssh/authorized_keys",
    ]


def parse_tmux_ls(output: str) -> tuple[bool, list[str] | None]:
    """
    Parse the output of `tmux ls 2>/dev/null; echo EXIT:$?`.
    Returns (True, None) when tmux is not installed (exit 127),
    otherwise (True, [session names]).
    """
    lines = output.strip().splitlines()
    exit_line = next((l for l in lines if l.startswith("EXIT:")), "EXIT:0")
    if int(exit_line.split(":")[1]) == 127:
        return True, None
    return True, [l.split(":")[0] for l in lines
                  if not l.startswith("EXIT:") and ":" in l]


def guess_protocol(service: str, port: int) -> str:
    """Pick a connection protocol from an nmap service name, then the port."""
    svc = service.lower()
    if "vnc" in svc:
        return "VNC"
    if "rdp" in svc or "ms-wbt" in svc:
        return "RDP"
    if "https" in svc:
        return "HTTPS"
    if "http" in svc:
        return "HTTP"
    if "ssh" in svc:
        return "SSH"
    for proto, default in PROTO_PORTS.items():
        if port == default:
            return proto
    return "SSH"


def connection_url(proto: str, ip: str, port: int) -> str:
    """URL for the browser-launched protocols (HTTP, HTTPS, VNC, RDP)."""
    return f"{proto.lower()}://{ip}:{port}"
