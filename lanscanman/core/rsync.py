"""
rsync command construction and progress-output parsing. Pure — no Qt, no
subprocess. RsyncWorker (workers/rsync.py) runs what build_command returns.

Three topologies:
  local  -> local     plain rsync
  local <-> remote    local rsync over ssh (--rsh uses LanScanMan's known_hosts)
  All ssh here runs with StrictHostKeyChecking=yes; keys are pinned first.
  remote -> remote    ssh -A into the sender and run rsync there; the sender
                      authenticates to the receiver with the *local* agent
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from lanscanman import paths
from lanscanman.core.formatting import fmt_bytes

LOCALHOST = "127.0.0.1"

# bytes  percentage  speed  eta   (from --info=progress2)
PROGRESS_RE = re.compile(
    r"([\d,]+)\s+(\d+)%\s+([0-9.]+[a-zA-Z]+/s)\s+(\d+:\d+:\d+|\d+:\d+)")

# rsync exit status when killed by a signal (our Cancel button)
EXIT_CANCELLED = 20


def is_remote_to_remote(data: dict) -> bool:
    return (data.get("sender_ip", LOCALHOST) != LOCALHOST
            and data.get("receiver_ip", LOCALHOST) != LOCALHOST)


def build_command(data: dict, known_hosts: str | None = None) -> list[str]:
    """
    Build the argv to run for a transfer dict with keys full_source,
    full_dest, src_path, args, sender_ip, sender_user, receiver_ip.
    """
    known_hosts = known_hosts or str(paths.KNOWN_HOSTS)
    args = list(data.get("args", []))

    if is_remote_to_remote(data):
        # rsync runs ON the sender, so the source is the sender's bare local
        # path — not user@host:/path. full_dest (user@receiver:/path) is as-is.
        rsync_flags = f"--info=progress2,name {' '.join(args)}"
        rsync_cmd = (f"rsync {rsync_flags} "
                     f"{shlex.quote(data['src_path'])} {shlex.quote(data['full_dest'])}")
        ssh_target = f"{shlex.quote(data.get('sender_user', ''))}@{shlex.quote(data['sender_ip'])}"
        return ["ssh", "-A",
                "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={known_hosts}",
                ssh_target, f"bash -lc {shlex.quote(rsync_cmd)}"]

    # --rsh points rsync's ssh at our (signed, read-only) known_hosts. The
    # remote host's key is pinned by RsyncWorker before this runs.
    ssh_cmd = (f"ssh -o StrictHostKeyChecking=yes "
               f"-o UserKnownHostsFile={shlex.quote(known_hosts)}")
    return (["rsync", "--info=progress2,name", f"--rsh={ssh_cmd}"] + args
            + [data["full_source"], data["full_dest"]])


@dataclass
class Progress:
    percent: int
    transferred: int        # bytes so far
    total_estimate: int     # bytes, extrapolated from percent (== transferred at 0%)
    speed: str              # e.g. "45.20MB/s"
    eta: str                # raw rsync "H:MM:SS"

    @property
    def size_display(self) -> str:
        if self.percent > 0:
            return f"{fmt_bytes(self.transferred)} / {fmt_bytes(self.total_estimate)}"
        return fmt_bytes(self.transferred)


def parse_progress(line: str) -> Progress | None:
    """Parse one --info=progress2 line, or None if it is not a progress line."""
    m = PROGRESS_RE.search(line)
    if not m:
        return None
    size_raw, pct, speed, eta = m.groups()
    pct_int = int(pct)
    transferred = int(size_raw.replace(",", ""))
    total = int(transferred / (pct_int / 100)) if pct_int > 0 else transferred
    return Progress(pct_int, transferred, total, speed, eta)


def split_output(buf: str) -> tuple[list[str], str]:
    """
    rsync rewrites its progress line with \\r, so output must be split on both
    \\r and \\n. Returns (complete_lines, leftover_partial_line).
    """
    parts = re.split(r"[\r\n]", buf)
    return parts[:-1], parts[-1]
