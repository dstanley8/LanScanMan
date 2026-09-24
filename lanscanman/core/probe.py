"""
Remote host probing: the read-only shell script sent over SSH, and the parser
for what comes back. Used by the Host Monitor tab.

Output from the remote script is divided by `###TAG###` sentinel lines so
each section can be found even when a command prints nothing.
"""

import json
import re

PROBE_CMD = r"""
echo "###DISTRO###"
cat /etc/os-release 2>/dev/null | grep "^PRETTY_NAME" | cut -d= -f2 | tr -d '"' || true
echo "###CPU_MODEL###"
grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || true
echo "###CPU_CORES###"
grep -c "^processor" /proc/cpuinfo 2>/dev/null || true
echo "###STAT1###"
cat /proc/stat 2>/dev/null | head -1
sleep 1
echo "###STAT2###"
cat /proc/stat 2>/dev/null | head -1
echo "###MEM###"
grep -E "^(MemTotal|MemAvailable):" /proc/meminfo 2>/dev/null
echo "###UPTIME###"
cat /proc/uptime 2>/dev/null
echo "###CPU_TEMP###"
for d in /sys/class/hwmon/hwmon*/; do
    name=$(cat "$d/name" 2>/dev/null)
    if echo "$name" | grep -qiE "^(coretemp|k10temp|zenpower|acpitz)$"; then
        temp=$(cat "$d/temp1_input" 2>/dev/null)
        if [ -n "$temp" ]; then echo "$temp"; break; fi
    fi
done 2>/dev/null || true
echo "###AMD_GPU_BUSY###"
cat /sys/class/drm/card0/device/gpu_busy_percent 2>/dev/null || true
echo "###AMD_GPU_MEM_USED###"
cat /sys/class/drm/card0/device/mem_info_vram_used 2>/dev/null || true
echo "###AMD_GPU_MEM_TOTAL###"
cat /sys/class/drm/card0/device/mem_info_vram_total 2>/dev/null || true
echo "###AMD_GPU_TEMP###"
cat /sys/class/drm/card0/device/hwmon/hwmon*/temp1_input 2>/dev/null | head -1 || true
echo "###NVIDIA###"
nvidia-smi --query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu --format=csv,noheader,nounits 2>/dev/null || true
echo "###LSPCI###"
lspci 2>/dev/null | grep -iE "VGA|3D|Display" | head -1 || true
echo "###FAILED_UNITS###"
if command -v systemctl >/dev/null 2>&1; then
    systemctl list-units --failed --output=json --no-pager 2>/dev/null \
        || systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}'
else
    echo "NO_SYSTEMD"
fi
echo "###UPDATES###"
if command -v apt >/dev/null 2>&1; then
    apt list --upgradable 2>/dev/null | grep -F '[upgradable' || true
else
    echo "NO_APT"
fi
echo "###REBOOT###"
if [ -f /var/run/reboot-required ]; then echo yes; elif [ -d /var/run ]; then echo no; fi
echo "###DOCKER###"
if command -v docker >/dev/null 2>&1; then
    docker ps -a --format '{{json .}}' 2>/dev/null || echo "DOCKER_DENIED"
else
    echo "DOCKER_ABSENT"
fi
"""


def split_sections(raw: str) -> dict[str, str]:
    """Split `###TAG###`-delimited output into {TAG: stripped text}.
    Lines before the first tag are dropped."""
    sections: dict[str, list] = {}
    current = None
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("###") and stripped.endswith("###"):
            current = stripped.strip("#")
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)
    return {k: "\n".join(v).strip() for k, v in sections.items()}


def calc_cpu_usage(stat1: str, stat2: str):
    """CPU usage % from two /proc/stat `cpu` headline samples, or None if unparseable."""
    try:
        v1 = [int(x) for x in stat1.split()[1:]]
        v2 = [int(x) for x in stat2.split()[1:]]
        delta_total = sum(v2) - sum(v1)
        delta_idle  = v2[3] - v1[3]
        if delta_total == 0:
            return 0.0
        return round(100.0 * (1.0 - delta_idle / delta_total), 1)
    except Exception:
        return None


def _millideg(value: str):
    """hwmon reports millidegrees; some drivers report whole degrees."""
    raw = int(value.strip())
    return round(raw / 1000) if raw > 1000 else raw


def parse_probe_output(raw: str) -> dict:
    """Convert raw PROBE_CMD output into a flat dict. Every field may be None."""
    s = split_sections(raw)
    r: dict = {}

    r["distro"]    = s.get("DISTRO") or None
    r["cpu_model"] = s.get("CPU_MODEL") or None
    try:
        r["cpu_cores"] = int(s["CPU_CORES"])
    except Exception:
        r["cpu_cores"] = None
    r["cpu_usage"] = calc_cpu_usage(s.get("STAT1", ""), s.get("STAT2", ""))

    # RAM — /proc/meminfo values are in kB
    mem_total = mem_avail = None
    for line in s.get("MEM", "").splitlines():
        try:
            if line.startswith("MemTotal:"):
                mem_total = int(line.split()[1])
            elif line.startswith("MemAvailable:"):
                mem_avail = int(line.split()[1])
        except Exception:
            pass
    r["mem_total_kb"] = mem_total
    r["mem_avail_kb"] = mem_avail

    try:
        r["cpu_temp_c"] = _millideg(s.get("CPU_TEMP", ""))
    except Exception:
        r["cpu_temp_c"] = None

    try:
        r["uptime_seconds"] = float(s["UPTIME"].split()[0])
    except Exception:
        r["uptime_seconds"] = None

    # GPU — NVIDIA first (richest data), then AMD /sys, then lspci for the name
    r["gpu_name"] = r["gpu_usage"] = r["gpu_mem_used_mb"] = r["gpu_mem_total_mb"] = None
    r["gpu_temp_c"] = None

    nvidia_raw = s.get("NVIDIA", "")
    if nvidia_raw and "," in nvidia_raw:
        parts = [p.strip() for p in nvidia_raw.split(",")]
        if len(parts) >= 4:
            try:
                r["gpu_name"]         = parts[0]
                r["gpu_usage"]        = int(parts[1])
                r["gpu_mem_used_mb"]  = int(parts[2])
                r["gpu_mem_total_mb"] = int(parts[3])
            except Exception:
                pass
        if len(parts) >= 5:
            try:
                r["gpu_temp_c"] = int(parts[4])
            except Exception:
                pass

    if r["gpu_usage"] is None:
        amd_busy = s.get("AMD_GPU_BUSY", "").strip()
        if amd_busy and amd_busy.isdigit():
            r["gpu_usage"] = int(amd_busy)
            try:
                used  = int(s.get("AMD_GPU_MEM_USED",  "").strip())
                total = int(s.get("AMD_GPU_MEM_TOTAL", "").strip())
                r["gpu_mem_used_mb"]  = used  // (1024 ** 2)
                r["gpu_mem_total_mb"] = total // (1024 ** 2)
            except Exception:
                pass

    if r["gpu_temp_c"] is None:
        try:
            r["gpu_temp_c"] = _millideg(s.get("AMD_GPU_TEMP", ""))
        except Exception:
            pass

    if r["gpu_name"] is None:
        m = re.search(r"(?:VGA|3D|Display)[^:]*:\s*(.*)", s.get("LSPCI", ""), re.IGNORECASE)
        if m:
            r["gpu_name"] = m.group(1).strip()

    r.update(parse_health(s))
    return r


# ── Health checks (all read-only) ────────────────────────────────────────────

def parse_health(s: dict) -> dict:
    """
    failed_units    list[str] | None   systemd units in a failed state (None: no systemd)
    updates         int | None         apt packages with updates (None: not apt / unknown)
    security_updates int | None        of those, from a -security pocket
    reboot_required bool | None        Debian/Ubuntu reboot-required flag (None: unknown)
    docker          "ok" | "denied" | "absent" | None
    containers      list[{name, state, status}]
    """
    r: dict = {}
    units = s.get("FAILED_UNITS")
    if units is None or units.strip() == "NO_SYSTEMD":
        r["failed_units"] = None
    elif units.strip().startswith("["):
        # systemd 246+: JSON; older systemd: one unit name per line
        try:
            r["failed_units"] = [u["unit"] for u in json.loads(units) if isinstance(u, dict)
                                 and u.get("unit")]
        except ValueError:
            r["failed_units"] = None
    else:
        r["failed_units"] = [u for u in units.split() if u.strip()]

    updates = s.get("UPDATES")
    if updates is None or updates.strip() == "NO_APT":
        r["updates"] = r["security_updates"] = None
    else:
        lines = [l for l in updates.splitlines() if "[upgradable" in l]
        r["updates"] = len(lines)
        r["security_updates"] = sum(1 for l in lines if "-security" in l.split(" ")[0])

    reboot = (s.get("REBOOT") or "").strip()
    r["reboot_required"] = True if reboot == "yes" else False if reboot == "no" else None

    docker = s.get("DOCKER")
    r["containers"] = []
    if docker is None:
        r["docker"] = None
    elif docker.strip() == "DOCKER_ABSENT":
        r["docker"] = "absent"
    elif docker.strip() == "DOCKER_DENIED":
        r["docker"] = "denied"
    else:
        r["docker"] = "ok"
        for line in docker.splitlines():
            line = line.strip()
            if line.startswith("{"):                       # docker ps --format '{{json .}}'
                try:
                    c = json.loads(line)
                except ValueError:
                    continue
                if c.get("Names"):
                    r["containers"].append({"name": c["Names"], "state": c.get("State", ""),
                                            "status": c.get("Status", "")})
                continue
            parts = line.split("\t")                     # older tab-separated format
            if len(parts) >= 2 and parts[0]:
                r["containers"].append({"name": parts[0], "state": parts[1],
                                        "status": parts[2] if len(parts) > 2 else ""})
    return r


# Containers that exited on their own terms aren't a problem; these are
_BAD_STATES = {"exited", "dead", "restarting"}


def unhealthy_containers(containers: list[dict]) -> list[dict]:
    """Containers that are stopped, restarting or report (unhealthy)."""
    return [c for c in containers
            if (c["state"] in _BAD_STATES and not c["status"].startswith("Exited (0)"))
            or "(unhealthy)" in c.get("status", "")]


def health_summary(r: dict) -> tuple[str, str, list[str]]:
    """(short text for the table, severity "good"|"warn"|"bad"|"unknown",
    one line per finding for the tooltip / detail view)."""
    problems: list[tuple[str, str]] = []       # (severity, text)
    failed = r.get("failed_units")
    if failed:
        problems.append(("bad", f"{len(failed)} failed service(s): " + ", ".join(failed[:5])
                         + (" …" if len(failed) > 5 else "")))
    bad_containers = unhealthy_containers(r.get("containers") or [])
    if bad_containers:
        problems.append(("bad", f"{len(bad_containers)} container(s) down: "
                         + ", ".join(c["name"] for c in bad_containers[:5])))
    if r.get("reboot_required"):
        problems.append(("warn", "reboot required"))
    ups, sec = r.get("updates"), r.get("security_updates")
    if ups:
        problems.append(("warn" if not sec else "bad",
                         f"{ups} update(s)" + (f", {sec} security" if sec else "")))

    known = [k for k in ("failed_units", "updates", "reboot_required") if r.get(k) is not None]
    if not problems:
        return ("OK" if known else "—"), ("good" if known else "unknown"), []
    severity = "bad" if any(p[0] == "bad" for p in problems) else "warn"
    short = []
    if failed:
        short.append(f"{len(failed)} failed")
    if bad_containers:
        short.append(f"{len(bad_containers)} container{'s' if len(bad_containers) > 1 else ''} down")
    if ups:
        short.append(f"{ups} upd" + (f" ({sec} sec)" if sec else ""))
    if r.get("reboot_required"):
        short.append("reboot")
    return " · ".join(short), severity, [p[1] for p in problems]


# ── Hardware brand detection (drives the coloured badges in the UI) ──────────

BRANDS = {
    "intel":   {"label": "INTEL",   "color": "#1e90ff", "bg": "#071728", "border": "#1060bb"},
    "amd":     {"label": "AMD",     "color": "#e84040", "bg": "#210a0a", "border": "#a02020"},
    "nvidia":  {"label": "NVIDIA",  "color": "#76b900", "bg": "#0d1c00", "border": "#4a7500"},
    "unknown": {"label": "UNKNOWN", "color": "#9AA4AF", "bg": "#1B1F24", "border": "#3A4452"},
}


def detect_cpu_brand(model: str | None) -> dict:
    s = (model or "").upper()
    if "INTEL" in s:
        return BRANDS["intel"]
    if "AMD" in s:
        return BRANDS["amd"]
    return BRANDS["unknown"]


def detect_gpu_brand(name: str | None) -> dict:
    s = (name or "").upper()
    if not s:
        return BRANDS["unknown"]
    if any(k in s for k in ("NVIDIA", "GEFORCE", "QUADRO", "TESLA", "RTX", "GTX")):
        return BRANDS["nvidia"]
    if "AMD" in s or "RADEON" in s:
        return BRANDS["amd"]
    if any(k in s for k in ("INTEL", "UHD GRAPHICS", "IRIS", "ARC")):
        return BRANDS["intel"]
    return BRANDS["unknown"]
