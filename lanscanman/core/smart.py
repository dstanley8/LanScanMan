"""
Disk health: the read-only SMART probe script sent over SSH and the parsers
that turn smartctl / udisksctl / lsblk / df output into per-disk dicts.
Used by the Disk Health tab. Pure Python — no Qt, no paramiko.

The probe tries `sudo -n smartctl` first, then plain `smartctl`, and falls
back to the `udisksctl dump` captured at the top of the script when neither
produces real SMART output (the disk section then contains METHOD:UDISKS).
"""

import json
import math
import re

from lanscanman.core.formatting import BAD, GOOD, MUTED, WARN
from lanscanman.core.probe import split_sections

SMART_PROBE_CMD = r"""
echo "###LSBLK_JSON###"
lsblk -J -b -d -o NAME,SIZE,TYPE,MODEL 2>/dev/null
echo "###LSBLK###"
lsblk -d -n -b -o NAME,SIZE,TYPE,MODEL 2>/dev/null | grep -vE "^(loop|sr|rom|fd|zram)"
echo "###LSBLK_TREE###"
lsblk -n -l -p -o NAME,PKNAME 2>/dev/null
echo "###DF###"
df -B1 2>/dev/null | grep "^/dev/" | grep -vE "tmpfs|devtmpfs|udev|overlay|squash"
echo "###UDISKS_DUMP###"
udisksctl dump 2>/dev/null || true
DISKS=$(lsblk -d -n -o NAME,TYPE 2>/dev/null | awk '$2=="disk"{print $1}' | grep -vE "^(loop|sr|fd|zram)")

# Marker that only appears in real smartctl output, not its permission-error banner.
# smartctl without root still prints its version header to stdout, making the
# output non-empty — so we grep for real content rather than testing -n.
_SMART_MARKER="SMART overall-health\|Model Family\|Device Model\|Serial Number\|NVM Express\|Critical Warning\|\"model_name\"\|\"smart_status\"\|\"serial_number\""

# smartmontools 7.0+ can print JSON (-j), which is parsed instead of the text
SMJ=""
if smartctl -j --version >/dev/null 2>&1 || sudo -n smartctl -j --version >/dev/null 2>&1; then
    SMJ="-j"
fi

for dev in $DISKS; do
    echo "###SMART_START:${dev}###"
    SMART_OUT=$(sudo -n smartctl $SMJ -iAH /dev/$dev 2>/dev/null)
    if ! echo "$SMART_OUT" | grep -q "$_SMART_MARKER"; then
        SMART_OUT=$(smartctl $SMJ -iAH /dev/$dev 2>/dev/null)
    fi
    if echo "$SMART_OUT" | grep -q "$_SMART_MARKER"; then
        echo "$SMART_OUT"
    else
        # Signal the Python parser to look this disk up in the udisksctl dump
        # that was already captured above. No further shell query needed.
        echo "METHOD:UDISKS"
    fi
    echo "###SMART_END:${dev}###"
done
"""

def kelvin_to_c(k: float) -> int:
    """Convert Kelvin to Celsius. udisksctl stores temperature in Kelvin."""
    return round(k - 273.15) if k > 100 else round(k)


def parse_udisks_dump(dump: str) -> dict[str, dict]:
    """
    Parse the full output of `udisksctl dump` into a {'/dev/sdX': smart_fields} map.

    udisksctl dump emits all D-Bus objects sequentially.  We need two object
    types and one join:

      /org/freedesktop/UDisks2/block_devices/sdX   → Device: /dev/sdX
                                                      Drive:  '<drive_obj_path>'
      /org/freedesktop/UDisks2/drives/<name>        → Smart* fields

    Strategy
    --------
    1. Split output into object sections (lines starting with /org/…).
    2. From block_device sections extract Device and Drive path.
    3. From drive sections extract every Smart* field we care about —
       handling both the SATA (Drive.Ata) and NVMe (NVMe.Controller) variants.
    4. Join: device_path → smart_fields dict.
    """
    # ── 1. Split into {obj_path: section_text} ───────────────────────────────
    obj_sections: dict[str, str] = {}
    current_obj: str | None = None
    current_lines: list[str] = []

    for line in dump.splitlines():
        if line.startswith("/org/freedesktop/UDisks2/"):
            if current_obj is not None:
                obj_sections[current_obj] = "\n".join(current_lines)
            current_obj = line.rstrip(":")
            current_lines = []
        elif current_obj is not None:
            current_lines.append(line)
    if current_obj is not None:
        obj_sections[current_obj] = "\n".join(current_lines)

    # ── 2. Extract SMART fields from drive objects ────────────────────────────
    drive_smart: dict[str, dict] = {}   # drive_obj_path → smart fields

    for obj_path, content in obj_sections.items():
        if "/drives/" not in obj_path:
            continue

        smart: dict = {}

        # ── SATA / ATA fields (org.freedesktop.UDisks2.Drive.Ata) ────────────
        m = re.search(r"SmartFailing:\s+(true|false)", content, re.IGNORECASE)
        if m:
            smart["smart_ok"] = (m.group(1).lower() == "false")

        m = re.search(r"SmartNumBadSectors:\s+(\d+)", content)
        if m:
            smart["uncorrectable"] = int(m.group(1))

        m = re.search(r"SmartPowerOnSeconds:\s+(\d+)", content)
        if m:
            smart["power_on_hours"] = int(m.group(1)) // 3600

        # ── NVMe fields (org.freedesktop.UDisks2.NVMe.Controller) ────────────
        m = re.search(r"SmartPowerOnHours:\s+(\d+)", content)
        if m:
            smart["power_on_hours"] = int(m.group(1))

        # SmartCriticalWarning: empty string or absent = healthy for NVMe.
        # udisksctl serialises an empty D-Bus byte array as a null byte \x00,
        # which str.strip() does NOT remove — so we strip it explicitly.
        # Any non-zero, non-null value means a real warning is active.
        m = re.search(r"SmartCriticalWarning:\s*(.*)", content)
        if m:
            warning = m.group(1).strip().strip("\x00").strip()
            if "smart_ok" not in smart:   # don't override ATA SmartFailing
                smart["smart_ok"] = (not warning or warning == "0x00")

        # ── Temperature — both SATA and NVMe store Kelvin ────────────────────
        m = re.search(r"SmartTemperature:\s+([\d.]+)", content)
        if m:
            smart["temperature_c"] = kelvin_to_c(float(m.group(1)))

        if smart:
            drive_smart[obj_path] = smart

    # ── 3. Map block devices → drive smart fields ─────────────────────────────
    result: dict[str, dict] = {}   # /dev/sdX → smart fields

    for obj_path, content in obj_sections.items():
        if "/block_devices/" not in obj_path:
            continue

        m = re.search(r"Device:\s+(/dev/\S+)", content)
        if not m:
            continue
        dev_path = m.group(1)   # e.g. /dev/sda

        m = re.search(r"Drive:\s+'([^']+)'", content)
        if not m:
            continue
        drive_obj = m.group(1)  # e.g. /org/freedesktop/UDisks2/drives/WDC_...

        if drive_obj in drive_smart:
            result[dev_path] = drive_smart[drive_obj]

    return result


def _three_significant(x: float) -> float:
    """smartctl's text output shows written data to 3 significant digits
    ("[58.1 TB]"); JSON values are rounded the same way so switching formats
    doesn't register as a change in the SMART history."""
    if x <= 0:
        return 0.0
    digits = 2 - math.floor(math.log10(x))
    return float(round(x, max(digits, 0)))


def _apply_smartctl_json(d: dict, data: dict) -> None:
    """Fill a disk dict from `smartctl -j -iAH` output (smartmontools 7.0+)."""
    d["model"] = data.get("model_name") or d["model"]
    d["serial"] = data.get("serial_number") or d["serial"]
    cap = (data.get("user_capacity") or {}).get("bytes")
    if isinstance(cap, int):
        d["capacity_bytes"] = cap
    status = data.get("smart_status") or {}
    if isinstance(status.get("passed"), bool):
        d["smart_ok"] = status["passed"]
    temp = (data.get("temperature") or {}).get("current")
    if isinstance(temp, int):
        d["temperature_c"] = temp
    hours = (data.get("power_on_time") or {}).get("hours")
    if isinstance(hours, int):
        d["power_on_hours"] = hours

    nvme = data.get("nvme_smart_health_information_log")
    if isinstance(nvme, dict):
        if nvme.get("critical_warning"):
            d["smart_ok"] = False
        for src, dst in (("percentage_used", "wear_pct_used"),
                         ("available_spare", "available_spare_pct"),
                         ("media_errors", "uncorrectable")):
            if isinstance(nvme.get(src), int):
                d[dst] = nvme[src]
        if d["temperature_c"] is None and isinstance(nvme.get("temperature"), int):
            d["temperature_c"] = nvme["temperature"]
        if d["power_on_hours"] is None and isinstance(nvme.get("power_on_hours"), int):
            d["power_on_hours"] = nvme["power_on_hours"]
        units = nvme.get("data_units_written")
        if isinstance(units, int):
            # one NVMe data unit = 1000 x 512 bytes; TB as smartctl shows it
            d["tbw_tb"] = _three_significant(units * 512_000 / 1e12)

    table = (data.get("ata_smart_attributes") or {}).get("table") or []
    for attr in table:
        if not isinstance(attr, dict):
            continue
        attr_id = attr.get("id")
        raw = attr.get("raw") or {}
        raw_val = raw.get("value")
        # Some raw values pack extra fields (e.g. temperature min/max); the
        # displayed string starts with the real number
        leading = raw.get("string", "").split(" ")[0].split("h")[0]
        if attr_id in (190, 194, 9) and leading.isdigit():
            raw_val = int(leading)
        if not isinstance(raw_val, int):
            continue
        if attr_id == 5:
            d["reallocated"] = raw_val
        elif attr_id == 9 and d["power_on_hours"] is None:
            d["power_on_hours"] = raw_val
        elif attr_id in (190, 194) and d["temperature_c"] is None:
            d["temperature_c"] = raw_val
        elif attr_id == 177 and isinstance(attr.get("value"), int):
            d["wear_pct_used"] = 100 - attr["value"]
        elif attr_id == 197:
            d["pending"] = raw_val
        elif attr_id == 198:
            d["uncorrectable"] = raw_val
        elif attr_id == 241 and d["tbw_tb"] is None:
            d["tbw_tb"] = round(raw_val * 512 / (1024 ** 4), 2)     # same as the text path


def parse_one_disk(dev: str, smart_raw: str,
                    udisks_map: dict[str, dict] | None = None) -> dict:
    """Parse smartctl -iAH output (JSON from smartmontools 7.0+, text for
    older versions) for a single device into a flat dict."""
    d: dict = {
        "dev":                 dev,
        "model":               None,
        "serial":              None,
        "capacity_bytes":      None,
        "smart_ok":            None,   # True / False / None = unknown
        "smart_available":     True,
        "smart_method":        "smartctl",  # "smartctl" | "udisks" | None
        "temperature_c":       None,
        "power_on_hours":      None,
        "tbw_tb":              None,   # terabytes written
        "reallocated":         None,
        "pending":             None,
        "uncorrectable":       None,
        "wear_pct_used":       None,   # 0-100; higher = more worn (NVMe "Percentage Used")
        "available_spare_pct": None,   # NVMe only
    }

    if "SMART_UNAVAILABLE" in smart_raw or not smart_raw.strip():
        d["smart_available"] = False
        d["smart_method"]    = None
        return d

    # ── UDisks fallback path ──────────────────────────────────────────────────
    # METHOD:UDISKS means smartctl couldn't run — look the disk up in the
    # udisksctl dump that was parsed before this function was called.
    if "METHOD:UDISKS" in smart_raw:
        d["smart_method"] = "udisks"
        fields = (udisks_map or {}).get(f"/dev/{dev}", {})
        if not fields:
            # udisksctl dump had no entry for this device either
            d["smart_available"] = False
            d["smart_method"]    = None
            return d
        d["smart_ok"]       = fields.get("smart_ok")
        d["uncorrectable"]  = fields.get("uncorrectable")
        d["power_on_hours"] = fields.get("power_on_hours")
        d["temperature_c"]  = fields.get("temperature_c")
        return d

    stripped = smart_raw.strip()
    if stripped.startswith("{"):
        try:
            _apply_smartctl_json(d, json.loads(stripped))
            d["smart_format"] = "json"
            return d
        except ValueError:
            pass                                    # fall through to text parsing

    # ── Health ───────────────────────────────────────────────────────────────
    if "SMART overall-health self-assessment test result: PASSED" in smart_raw:
        d["smart_ok"] = True
    elif "SMART overall-health self-assessment test result: FAILED" in smart_raw:
        d["smart_ok"] = False
    else:
        # NVMe — critical warning byte 0x00 means healthy
        m = re.search(r"Critical Warning:\s+(0x[0-9a-fA-F]+)", smart_raw)
        if m:
            d["smart_ok"] = (m.group(1) == "0x00")

    # ── Info section ─────────────────────────────────────────────────────────
    for pattern, key in [
        (r"Device Model:\s+(.+)",  "model"),
        (r"Model Number:\s+(.+)",  "model"),    # NVMe
        (r"Serial Number:\s+(.+)", "serial"),
    ]:
        m = re.search(pattern, smart_raw)
        if m:
            d[key] = m.group(1).strip()

    m = re.search(r"User Capacity:\s+([\d,]+) bytes", smart_raw)
    if m:
        d["capacity_bytes"] = int(m.group(1).replace(",", ""))

    # ── NVMe plain-text fields ────────────────────────────────────────────────
    m = re.search(r"Temperature:\s+(\d+)\s+Celsius", smart_raw)
    if m:
        d["temperature_c"] = int(m.group(1))

    m = re.search(r"Power On Hours:\s+([\d,]+)", smart_raw)
    if m:
        d["power_on_hours"] = int(m.group(1).replace(",", ""))

    m = re.search(r"Percentage Used:\s+(\d+)%", smart_raw)
    if m:
        d["wear_pct_used"] = int(m.group(1))

    m = re.search(r"Available Spare:\s+(\d+)%", smart_raw)
    if m:
        d["available_spare_pct"] = int(m.group(1))

    # NVMe Data Units Written: 12,345 [6.32 TB]  (1 unit = 512 KB)
    m = re.search(r"Data Units Written:\s+[\d,]+\s+\[([\d.]+)\s+(\w+)\]", smart_raw)
    if m:
        val, unit = float(m.group(1)), m.group(2).upper()
        factor = {"TB": 1.0, "GB": 1e-3, "PB": 1e3}.get(unit, 1.0)
        d["tbw_tb"] = round(val * factor, 2)

    m = re.search(r"Media and Data Integrity Errors:\s+(\d+)", smart_raw)
    if m:
        d["uncorrectable"] = int(m.group(1))

    # ── SATA attribute table ──────────────────────────────────────────────────
    # Each line: ID  NAME  FLAG  VALUE  WORST  THRESH  TYPE  UPDATED  WHEN_FAILED  RAW_VALUE
    for line in smart_raw.splitlines():
        parts = line.split()
        if len(parts) < 10 or not parts[0].isdigit():
            continue
        try:
            attr_id = int(parts[0])
            # RAW_VALUE is parts[9]; strip any trailing annotation
            raw_val = int(re.match(r"(\d+)", parts[9].replace(",", "")).group(1))
        except Exception:
            continue

        if attr_id == 5:
            d["reallocated"] = raw_val
        elif attr_id == 9 and d["power_on_hours"] is None:
            d["power_on_hours"] = raw_val
        elif attr_id in (190, 194) and d["temperature_c"] is None:
            d["temperature_c"] = raw_val
        elif attr_id == 177:
            # Wear_Leveling_Count: raw is wear events; normalised VALUE (parts[3])
            # shows % remaining (100 = new, 0 = worn). Convert to "% used".
            try:
                d["wear_pct_used"] = 100 - int(parts[3])
            except Exception:
                pass
        elif attr_id == 197:
            d["pending"] = raw_val
        elif attr_id == 198:
            d["uncorrectable"] = raw_val
        elif attr_id == 241 and d["tbw_tb"] is None:
            # Total_LBAs_Written: 1 LBA = 512 B
            d["tbw_tb"] = round(raw_val * 512 / (1024 ** 4), 2)

    return d


_SKIP_DEVICES = ("loop", "sr", "rom", "fd", "zram")


def parse_lsblk_json(text: str) -> dict[str, dict]:
    """`lsblk -J -b -d -o NAME,SIZE,TYPE,MODEL` -> {name: {size_bytes, model}}
    for whole disks. Older lsblk prints sizes as strings; both are handled."""
    try:
        devices = json.loads(text).get("blockdevices") or []
    except (ValueError, AttributeError):
        return {}
    out: dict[str, dict] = {}
    for dev in devices:
        name = dev.get("name") or ""
        if not name or name.startswith(_SKIP_DEVICES) or dev.get("type") not in ("disk", None):
            continue
        size = dev.get("size")
        try:
            size = int(size) if size is not None else None
        except (TypeError, ValueError):
            size = None
        model = (dev.get("model") or "").strip() or None
        out[name] = {"size_bytes": size, "model": model}
    return out


_PARTITION_RE = re.compile(r"/dev/(nvme\d+n\d+|mmcblk\d+|[a-z]+)")


def parse_lsblk_tree(text: str) -> dict[str, str]:
    """`lsblk -n -l -p -o NAME,PKNAME` -> {device: parent}. Devices with no
    parent (whole disks) are omitted. For a device with several parents (an LV
    spanning disks) the first one listed is kept."""
    parents: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            parents.setdefault(parts[0], parts[1])
    return parents


def disk_for_device(dev_path: str, parents: dict[str, str]) -> str | None:
    """
    Physical disk name for a df device: /dev/sda1 -> sda, /dev/nvme0n1p2 ->
    nvme0n1, /dev/mmcblk0p1 -> mmcblk0, /dev/mapper/vg-root -> whatever disk
    the LVM/LUKS stack sits on (via the lsblk tree). None if unknown.
    """
    seen = set()
    while dev_path in parents and dev_path not in seen:
        seen.add(dev_path)
        dev_path = parents[dev_path]
    if dev_path.startswith("/dev/mapper/"):
        return None      # no lsblk tree (older probe output) — can't resolve
    m = _PARTITION_RE.match(dev_path)
    return m.group(1) if m else None


def parse_smart_probe(raw: str) -> list[dict]:
    """
    Parse the full probe output into a list of per-disk dicts.
    Also annotates each disk with used/total bytes from df.
    """
    sections = split_sections(raw)

    # ── udisksctl dump — parse once, used as fallback for all disks ───────────
    udisks_map = parse_udisks_dump(sections.get("UDISKS_DUMP", ""))

    # ── lsblk: physical disks (JSON when available, text otherwise) ──────────
    disk_meta = parse_lsblk_json(sections.get("LSBLK_JSON", ""))
    for line in ([] if disk_meta else sections.get("LSBLK", "").splitlines()):
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[0]
        try:
            size_b = int(parts[1])
        except Exception:
            size_b = None
        model = " ".join(parts[3:]).strip() if len(parts) > 3 else None
        disk_meta[name] = {"size_bytes": size_b, "model": model or None}

    # ── df: partition usage → aggregate per physical disk ────────────────────
    disk_usage: dict[str, dict] = {}
    parents = parse_lsblk_tree(sections.get("LSBLK_TREE", ""))
    for line in sections.get("DF", "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            total_b = int(parts[1])
            used_b  = int(parts[2])
        except Exception:
            continue
        base = disk_for_device(parts[0], parents)
        if base is None:
            continue
        usage = disk_usage.setdefault(base, {"used": 0, "total": 0})
        usage["used"]  += used_b
        usage["total"] += total_b

    # ── Assemble per-disk records ─────────────────────────────────────────────
    disks = []
    for dev, meta in disk_meta.items():
        smart_raw = sections.get(f"SMART_START:{dev}", "")
        disk = parse_one_disk(dev, smart_raw, udisks_map)

        # Prefer lsblk capacity (always available) over smartctl's string parse
        if meta.get("size_bytes"):
            disk["capacity_bytes"] = meta["size_bytes"]
        # Fill model from lsblk if smartctl didn't find one
        if not disk["model"] and meta.get("model"):
            disk["model"] = meta["model"]

        usage = disk_usage.get(dev, {})
        disk["fs_used_bytes"]  = usage.get("used")
        disk["fs_total_bytes"] = usage.get("total")

        disks.append(disk)

    return disks

def smart_color(ok) -> str:
    if ok is True:
        return GOOD
    if ok is False:
        return BAD
    return MUTED


def smart_text(ok, available) -> str:
    if not available:
        return "N/A"
    if ok is True:
        return "PASSED"
    if ok is False:
        return "FAILED!"
    return "?"


def overall_health(disks: list) -> tuple[str, str]:
    """Return (summary_text, colour) for the SmartTab row."""
    if not disks:
        return "No disks", MUTED
    smart_disks = [d for d in disks if d.get("smart_available")]
    if not smart_disks:
        return f"{len(disks)} disk(s) — no SMART", MUTED
    failed = [d for d in smart_disks if d.get("smart_ok") is False]
    unknown = [d for d in smart_disks if d.get("smart_ok") is None]
    if failed:
        return f"⚠  {len(failed)} FAILED", BAD
    if unknown:
        return f"{len(smart_disks)} disk(s) — partial", WARN
    return f"{len(smart_disks)} disk(s) — all OK", GOOD
