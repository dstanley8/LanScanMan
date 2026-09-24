"""Desktop notifications via notify-send. Silently does nothing if it is absent."""

import subprocess


def notify(title: str, body: str, critical: bool = False) -> None:
    cmd = ["notify-send", "-a", "LanScanMan"]
    if critical:
        cmd += ["-u", "critical"]
    try:
        subprocess.Popen(cmd + [title, body],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
