import re

import paramiko
from PyQt6.QtCore import Qt, QThread, pyqtSignal, pyqtSlot, QTimer
from PyQt6.QtGui import QColor, QBrush, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QHBoxLayout, QHeaderView,
    QLabel, QMessageBox, QPushButton, QSpinBox, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from manager import HostKeyMismatchError, _make_ssh_client, remove_host_from_known_hosts
from tabs.smart_log import SmartLogger, SmartHistoryDialog, smart_log_key


# ─────────────────────────────────────────────────────────────────────────────
# Remote probe command
#
# Discovers physical disks via lsblk, grabs partition usage via df, then
# runs smartctl (trying passwordless sudo first, then without) for each disk.
# Every section is bounded by ###TAG### sentinels so the output can be split
# reliably even when individual commands emit nothing.
# ─────────────────────────────────────────────────────────────────────────────

_SMART_PROBE_CMD = r"""
echo "###LSBLK###"
lsblk -d -n -b -o NAME,SIZE,TYPE,MODEL 2>/dev/null | grep -vE "^(loop|sr|rom|fd|zram)"
echo "###DF###"
df -B1 2>/dev/null | grep "^/dev/" | grep -vE "tmpfs|devtmpfs|udev|overlay|squash"
echo "###UDISKS_DUMP###"
udisksctl dump 2>/dev/null || true
DISKS=$(lsblk -d -n -o NAME,TYPE 2>/dev/null | awk '$2=="disk"{print $1}' | grep -vE "^(loop|sr|fd|zram)")

# Marker that only appears in real smartctl output, not its permission-error banner.
# smartctl without root still prints its version header to stdout, making the
# output non-empty — so we grep for real content rather than testing -n.
_SMART_MARKER="SMART overall-health\|Model Family\|Device Model\|Serial Number\|NVM Express\|Critical Warning"

for dev in $DISKS; do
    echo "###SMART_START:${dev}###"
    SMART_OUT=$(sudo -n smartctl -iAH /dev/$dev 2>/dev/null)
    if ! echo "$SMART_OUT" | grep -q "$_SMART_MARKER"; then
        SMART_OUT=$(smartctl -iAH /dev/$dev 2>/dev/null)
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


# ─────────────────────────────────────────────────────────────────────────────
# Parsing
# ─────────────────────────────────────────────────────────────────────────────

def _split_sections(raw: str) -> dict:
    """Split ###TAG### delimited output into {tag: text} dict."""
    sections: dict[str, list] = {}
    current = None
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith("###") and s.endswith("###"):
            current = s.strip("#")
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)
    return {k: "\n".join(v).strip() for k, v in sections.items()}


def _kelvin_to_c(k: float) -> int:
    """Convert Kelvin to Celsius. udisksctl stores temperature in Kelvin."""
    return round(k - 273.15) if k > 100 else round(k)


def _parse_udisks_dump(dump: str) -> dict[str, dict]:
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
            smart["temperature_c"] = _kelvin_to_c(float(m.group(1)))

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


def _parse_one_disk(dev: str, smart_raw: str,
                    udisks_map: dict[str, dict] | None = None) -> dict:
    """Parse smartctl -iAH output for a single device into a flat dict."""
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


def parse_smart_probe(raw: str) -> list[dict]:
    """
    Parse the full probe output into a list of per-disk dicts.
    Also annotates each disk with used/total bytes from df.
    """
    sections = _split_sections(raw)

    # ── udisksctl dump — parse once, used as fallback for all disks ───────────
    udisks_map = _parse_udisks_dump(sections.get("UDISKS_DUMP", ""))

    # ── lsblk: physical disks ────────────────────────────────────────────────
    disk_meta: dict[str, dict] = {}
    for line in sections.get("LSBLK", "").splitlines():
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
    # Partition /dev/sda1 → base key "sda"; /dev/nvme0n1p1 → "nvme0n1"
    disk_usage: dict[str, dict] = {}
    _nvme_re = re.compile(r"/dev/(nvme\d+n\d+)")
    _sata_re = re.compile(r"/dev/([a-z]+)")
    for line in sections.get("DF", "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        dev_path = parts[0]
        try:
            total_b = int(parts[1])
            used_b  = int(parts[2])
        except Exception:
            continue
        m = _nvme_re.match(dev_path) or _sata_re.match(dev_path)
        if not m:
            continue
        base = m.group(1)
        if base not in disk_usage:
            disk_usage[base] = {"used": 0, "total": 0}
        disk_usage[base]["used"]  += used_b
        disk_usage[base]["total"] += total_b

    # ── Assemble per-disk records ─────────────────────────────────────────────
    disks = []
    for dev, meta in disk_meta.items():
        smart_raw = sections.get(f"SMART_START:{dev}", "")
        disk = _parse_one_disk(dev, smart_raw, udisks_map)

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


# ─────────────────────────────────────────────────────────────────────────────
# Worker thread
# ─────────────────────────────────────────────────────────────────────────────

class SmartProbeWorker(QThread):
    result_ready     = pyqtSignal(str, list)   # (ip, list[disk_dict])
    probe_error      = pyqtSignal(str, str)    # (ip, message)
    host_key_changed = pyqtSignal(str)         # (ip)

    def __init__(self, ip: str, username: str, parent=None):
        super().__init__(parent)
        self.ip       = ip
        self.username = username

    def run(self):
        try:
            ssh = _make_ssh_client()
            ssh.connect(self.ip, username=self.username, timeout=10,
                        look_for_keys=True, allow_agent=True)
            _, stdout, _ = ssh.exec_command(_SMART_PROBE_CMD, timeout=30)
            raw = stdout.read().decode(errors="replace")
            ssh.close()
            self.result_ready.emit(self.ip, parse_smart_probe(raw))
        except paramiko.BadHostKeyException:
            self.host_key_changed.emit(self.ip)
        except Exception as e:
            self.probe_error.emit(self.ip, str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Formatting helpers
# ─────────────────────────────────────────────────────────────────────────────

def _fmt_bytes(n) -> str:
    if n is None:
        return "?"
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _fmt_hours(h) -> str:
    if h is None:
        return "?"
    h = int(h)
    days  = h // 24
    hours = h %  24
    if days >= 365:
        years = days // 365
        rem   = days %  365
        return f"{years}y {rem}d"
    if days:
        return f"{days}d {hours}h"
    return f"{hours}h"


def _temp_color(c) -> str:
    if c is None:
        return "#9AA4AF"
    if c < 40:
        return "#27ae60"
    if c < 55:
        return "#f39c12"
    return "#c0392b"


def _wear_color(pct_used) -> str:
    """pct_used = 0 (new) … 100 (fully worn)."""
    if pct_used is None:
        return "#9AA4AF"
    if pct_used < 50:
        return "#27ae60"
    if pct_used < 80:
        return "#f39c12"
    return "#c0392b"


def _bad_sector_color(n) -> str:
    if n is None:
        return "#9AA4AF"
    return "#c0392b" if n > 0 else "#27ae60"


def _smart_color(ok) -> str:
    if ok is True:
        return "#27ae60"
    if ok is False:
        return "#c0392b"
    return "#9AA4AF"


def _smart_text(ok, available) -> str:
    if not available:
        return "N/A"
    if ok is True:
        return "PASSED"
    if ok is False:
        return "FAILED!"
    return "?"


def _overall_health(disks: list) -> tuple[str, str]:
    """Return (summary_text, colour) for the SmartTab row."""
    if not disks:
        return "No disks", "#9AA4AF"
    smart_disks = [d for d in disks if d.get("smart_available")]
    if not smart_disks:
        return f"{len(disks)} disk(s) — no SMART", "#9AA4AF"
    failed = [d for d in smart_disks if d.get("smart_ok") is False]
    unknown = [d for d in smart_disks if d.get("smart_ok") is None]
    if failed:
        return f"⚠  {len(failed)} FAILED", "#c0392b"
    if unknown:
        return f"{len(smart_disks)} disk(s) — partial", "#f39c12"
    return f"{len(smart_disks)} disk(s) — all OK", "#27ae60"


# ─────────────────────────────────────────────────────────────────────────────
# Disk detail dialog
# ─────────────────────────────────────────────────────────────────────────────

# Column indices for the disk table inside the dialog
_D_DEV      = 0
_D_MODEL    = 1
_D_CAP      = 2
_D_USED     = 3
_D_SMART    = 4
_D_TEMP     = 5
_D_HOURS    = 6
_D_TBW      = 7
_D_BAD      = 8
_D_WEAR     = 9


class SmartDiskDialog(QDialog):
    def __init__(self, ip: str, username: str, alias: str = "",
                 disks: list | None = None, profile_key: str = "",
                 parent=None):
        super().__init__(parent)
        self.ip          = ip
        self.username    = username
        self.alias       = alias or ip
        self.profile_key = profile_key or ip
        self.setWindowTitle(f"Disk Health — {self.alias}")
        self.setMinimumSize(1100, 400)
        self.resize(1260, 440)
        self._worker: SmartProbeWorker | None = None

        self._build_ui()
        if disks is not None:
            self._apply_disks(disks)
        else:
            self._set_status("⏳  Probing disks…", "#f39c12")

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(30_000)
        if disks is None:
            self._refresh()

    # ── Layout ───────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(8)

        # Header
        hdr = QHBoxLayout()
        title = QLabel(
            f"<b>{self.alias}</b>"
            f"  <span style='color:#9AA4AF;font-size:12px;'>{self.ip}</span>"
        )
        title.setStyleSheet("font-size: 14px;")
        self._lbl_status = QLabel("Initialising…")
        self._lbl_status.setStyleSheet("color: #9AA4AF; font-size: 11px;")
        hdr.addWidget(title)
        hdr.addStretch()
        hdr.addWidget(self._lbl_status)
        root.addLayout(hdr)

        # SMART notes banner (hidden by default, shown when no sudo)
        self._lbl_note = QLabel(
            "ℹ  Some disks show no SMART data. "
            "Grant passwordless sudo for smartctl on the remote host to enable full access: "
            "echo 'username ALL=(root) NOPASSWD: /usr/bin/smartctl' | sudo tee /etc/sudoers.d/smartctl"
        )
        self._lbl_note.setWordWrap(True)
        self._lbl_note.setStyleSheet(
            "color: #f39c12; background: #1e1a0a; border: 1px solid #5a4a00; "
            "border-radius: 4px; padding: 5px; font-size: 11px;"
        )
        self._lbl_note.setVisible(False)
        root.addWidget(self._lbl_note)

        # Disk table
        self._table = QTableWidget(0, 10)
        self._table.setHorizontalHeaderLabels([
            "Device", "Model", "Capacity", "Used (fs)",
            "SMART", "Temp", "Power On", "TBW", "Bad Sectors", "Wear",
        ])
        self._table.verticalHeader().setDefaultSectionSize(38)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        hdr_view = self._table.horizontalHeader()
        hdr_view.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hdr_view.setSectionResizeMode(_D_MODEL, QHeaderView.ResizeMode.Stretch)
        for col, w in [(_D_DEV, 130), (_D_CAP, 90), (_D_USED, 135), (_D_SMART, 100),
                       (_D_TEMP, 65), (_D_HOURS, 95), (_D_TBW, 90),
                       (_D_BAD, 105), (_D_WEAR, 75)]:
            hdr_view.resizeSection(col, w)

        # Tooltip hints for abbreviated column headers
        tips = {
            _D_TBW:  "Total Terabytes Written — total data written to the drive lifetime",
            _D_BAD:  "Bad Sectors — sum of Reallocated + Pending + Uncorrectable sectors",
            _D_WEAR: "Wear — for SSDs: percentage of rated write endurance consumed",
            _D_HOURS:"Power-on time (days / hours)",
        }
        for col, tip in tips.items():
            self._table.horizontalHeaderItem(col).setToolTip(tip)

        root.addWidget(self._table)

        # Right-click for history; double-click also opens history
        from PyQt6.QtCore import Qt as _Qt
        self._table.setContextMenuPolicy(_Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_disk_menu)
        self._table.itemDoubleClicked.connect(
            lambda item: self._open_history(item.row()))

        # Footer
        footer = QHBoxLayout()
        self._auto_cb   = QCheckBox("Auto-refresh")
        self._auto_cb.setChecked(True)
        self._spin      = QSpinBox()
        self._spin.setRange(15, 300)
        self._spin.setValue(30)
        self._spin.setSuffix(" s")
        self._spin.setFixedWidth(72)
        self._auto_cb.toggled.connect(self._toggle_auto)
        self._spin.valueChanged.connect(self._update_interval)

        refresh_btn = QPushButton("Refresh Now")
        refresh_btn.clicked.connect(self._refresh)
        close_btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close_btn.rejected.connect(self.reject)

        footer.addWidget(self._auto_cb)
        footer.addWidget(self._spin)
        footer.addStretch()
        footer.addWidget(refresh_btn)
        footer.addWidget(close_btn)
        root.addLayout(footer)

    # ── Data ─────────────────────────────────────────────────────────────────

    def _apply_disks(self, disks: list):
        self._set_status("● Live", "#27ae60")
        self._table.setRowCount(0)
        self._disk_devs: list[str] = []   # kernel device names per row (display only)
        self._disk_keys: list[str] = []   # stable log keys per row (serial or dev fallback)

        any_unavailable = False
        any_udisks      = False
        for disk in disks:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._disk_devs.append(disk.get("dev", ""))
            self._disk_keys.append(smart_log_key(disk.get("dev", ""), disk.get("serial")))

            if not disk.get("smart_available"):
                any_unavailable = True
            if disk.get("smart_method") == "udisks":
                any_udisks = True

            # SMART cell text — annotate udisks results so user knows it's limited
            smart_method = disk.get("smart_method")
            if smart_method == "udisks":
                smart_display = _smart_text(disk.get("smart_ok"), True) + " ¹"
            else:
                smart_display = _smart_text(disk.get("smart_ok"), disk.get("smart_available"))

            # Bad sectors: sum of whichever counters are present
            bad_parts = [disk.get("reallocated"), disk.get("pending"), disk.get("uncorrectable")]
            known     = [v for v in bad_parts if v is not None]
            bad_total = sum(known) if known else None

            # Used space from df
            used_b  = disk.get("fs_used_bytes")
            total_b = disk.get("fs_total_bytes")
            if used_b is not None and total_b:
                used_str = f"{_fmt_bytes(used_b)} / {_fmt_bytes(total_b)}"
            elif used_b is not None:
                used_str = _fmt_bytes(used_b)
            else:
                used_str = "?"

            wear = disk.get("wear_pct_used")
            wear_str = f"{wear}%" if wear is not None else "?"

            cells = [
                (f"/dev/{disk['dev']}",                "#E6E6E6"),
                (disk.get("model") or "Unknown",        "#E6E6E6"),
                (_fmt_bytes(disk.get("capacity_bytes")), "#9AA4AF"),
                (used_str,                              "#9AA4AF"),
                (smart_display,                         _smart_color(disk.get("smart_ok"))),
                (f"{disk['temperature_c']}°C" if disk.get("temperature_c") is not None else "?",
                 _temp_color(disk.get("temperature_c"))),
                (_fmt_hours(disk.get("power_on_hours")),  "#9AA4AF"),
                (f"{disk['tbw_tb']:.1f} TB" if disk.get("tbw_tb") is not None else "?",
                 "#9AA4AF"),
                (str(bad_total) if bad_total is not None else "?",
                 _bad_sector_color(bad_total)),
                (wear_str, _wear_color(wear)),
            ]

            for col, (text, color) in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setForeground(QBrush(QColor(color)))
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self._table.setItem(row, col, item)

            # Left-align device name and model
            for col in (_D_DEV, _D_MODEL):
                self._table.item(row, col).setTextAlignment(
                    Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

            # Bold the SMART cell
            smart_item = self._table.item(row, _D_SMART)
            font = smart_item.font()
            font.setBold(True)
            smart_item.setFont(font)

            # Tooltip for bad sectors breakdown
            if any(v is not None for v in bad_parts):
                r_str = str(disk.get("reallocated")) if disk.get("reallocated") is not None else "?"
                p_str = str(disk.get("pending"))     if disk.get("pending")     is not None else "?"
                u_str = str(disk.get("uncorrectable"))if disk.get("uncorrectable")is not None else "?"
                self._table.item(row, _D_BAD).setToolTip(
                    f"Reallocated: {r_str}\nPending: {p_str}\nUncorrectable: {u_str}"
                )

        self._lbl_note.setVisible(any_unavailable or any_udisks)
        if any_udisks and not any_unavailable:
            self._lbl_note.setText(
                "¹  Some disks are showing basic health via UDisks (kernel-cached SMART) "
                "because smartctl requires root access. Deep metrics (TBW, wear, full bad-sector counts) "
                "are unavailable for those drives. To enable full SMART access:\n"
                "echo 'username ALL=(root) NOPASSWD: /usr/bin/smartctl' "
                "| sudo tee /etc/sudoers.d/smartctl"
            )
        else:
            self._lbl_note.setText(
                "ℹ  Some disks show no SMART data at all. "
                "Grant passwordless sudo for smartctl to enable full access:\n"
                "echo 'username ALL=(root) NOPASSWD: /usr/bin/smartctl' "
                "| sudo tee /etc/sudoers.d/smartctl"
            )

    def _show_disk_menu(self, pos):
        from PyQt6.QtWidgets import QMenu
        from PyQt6.QtGui import QCursor
        item = self._table.itemAt(pos)
        if not item:
            return
        row = item.row()
        menu = QMenu(self)
        hist_act = menu.addAction("View SMART History…")
        hist_act.triggered.connect(lambda: self._open_history(row))
        menu.exec(QCursor.pos())

    def _open_history(self, row: int):
        if row < 0 or row >= len(getattr(self, "_disk_devs", [])):
            return
        dev = self._disk_devs[row]
        key = self._disk_keys[row] if row < len(getattr(self, "_disk_keys", [])) else dev
        if not dev:
            return
        logger = SmartLogger(self.profile_key, self.alias)
        if not logger.has_history(key):
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.information(self, "No History",
                f"No SMART history has been recorded for /dev/{dev} yet.\n\n"
                "History is logged automatically each time a probe completes. "
                "Try refreshing and checking back.")
            return
        dlg = SmartHistoryDialog(dev, logger, key=key, parent=self)
        dlg.exec()

    def _set_status(self, text: str, color: str):
        self._lbl_status.setText(text)
        self._lbl_status.setStyleSheet(f"color: {color}; font-size: 11px;")

    # ── Refresh ───────────────────────────────────────────────────────────────

    def _refresh(self):
        if self._worker and self._worker.isRunning():
            return
        self._set_status("⏳  Probing…", "#f39c12")
        self._worker = SmartProbeWorker(self.ip, self.username)
        self._worker.result_ready.connect(self._on_result)
        self._worker.probe_error.connect(self._on_error)
        self._worker.host_key_changed.connect(self._on_key_change)
        self._worker.start()

    @pyqtSlot(str, list)
    def _on_result(self, _ip, disks):
        self._apply_disks(disks)

    @pyqtSlot(str, str)
    def _on_error(self, _ip, msg):
        self._set_status(f"✖  {msg[:70]}", "#c0392b")

    @pyqtSlot(str)
    def _on_key_change(self, ip):
        self._timer.stop()
        reply = QMessageBox.question(self, "Host Key Changed",
            f"The SSH host key for {ip} has changed.\n\n"
            "Remove the old key and trust the new one?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            remove_host_from_known_hosts(ip)
            self._refresh()
        if self._auto_cb.isChecked():
            self._timer.start()

    def _toggle_auto(self, checked: bool):
        if checked:
            self._timer.start(self._spin.value() * 1000)
        else:
            self._timer.stop()

    def _update_interval(self, value: int):
        if self._auto_cb.isChecked():
            self._timer.start(value * 1000)

    def closeEvent(self, event):
        self._timer.stop()
        if self._worker:
            try:
                self._worker.result_ready.disconnect(self._on_result)
                self._worker.probe_error.disconnect(self._on_error)
                self._worker.host_key_changed.disconnect(self._on_key_change)
            except Exception:
                pass
            if self._worker.isRunning():
                self._worker.wait(8000)
        super().closeEvent(event)


# ─────────────────────────────────────────────────────────────────────────────
# SmartTab — main tab, one row per configured host
# ─────────────────────────────────────────────────────────────────────────────

_T_STATUS  = 0
_T_ALIAS   = 1
_T_IP      = 2
_T_DISKS   = 3
_T_HEALTH  = 4
_T_UPDATED = 5


class SmartTab(QWidget):
    def __init__(self, net_manager, parent=None):
        super().__init__(parent)
        self.net_manager   = net_manager
        self.parent_window = parent
        self._workers: dict[str, SmartProbeWorker] = {}
        self._cache:   dict[str, list]              = {}   # ip -> last disk list
        self._setup_ui()
        self._auto_timer = QTimer(self)
        self._auto_timer.timeout.connect(self._refresh_all)

    # ── Layout ────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        root = QVBoxLayout(self)

        bar = QHBoxLayout()
        self._refresh_btn = QPushButton("Refresh All")
        self._refresh_btn.clicked.connect(self._refresh_all)

        self._auto_cb = QCheckBox("Auto-refresh")
        self._auto_cb.toggled.connect(self._toggle_auto)
        self._spin = QSpinBox()
        self._spin.setRange(30, 600)
        self._spin.setValue(120)
        self._spin.setSuffix(" s")
        self._spin.setFixedWidth(78)
        self._spin.setToolTip("Auto-refresh interval")
        self._spin.valueChanged.connect(self._update_interval)

        self._lbl_info = QLabel(
            "Double-click a row to view per-disk SMART details.  "
            "Requires smartctl on the remote host (sudo NOPASSWD recommended)."
        )
        self._lbl_info.setStyleSheet("color: #9AA4AF; font-size: 11px;")

        bar.addWidget(self._refresh_btn)
        bar.addSpacing(8)
        bar.addWidget(self._auto_cb)
        bar.addWidget(self._spin)
        bar.addStretch()
        bar.addWidget(self._lbl_info)
        root.addLayout(bar)

        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels([
            "Status", "Alias", "IP", "Disks", "Overall Health", "Last Updated",
        ])
        self._table.verticalHeader().setDefaultSectionSize(40)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hdr.setSectionResizeMode(_T_ALIAS,   QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(_T_HEALTH,  QHeaderView.ResizeMode.Stretch)
        for col, w in [(_T_STATUS, 80), (_T_IP, 130),
                       (_T_DISKS, 140), (_T_UPDATED, 110)]:
            hdr.resizeSection(col, w)

        self._table.itemDoubleClicked.connect(self._on_double_click)
        root.addWidget(self._table)

        QShortcut(QKeySequence("F5"), self).activated.connect(self._refresh_all)

    def showEvent(self, event):
        super().showEvent(event)
        self._populate()

    def _populate(self):
        """Sync rows with net_manager.profiles without wiping existing data."""
        # Build the set of IPs that should be present
        wanted: dict[str, tuple] = {}   # ip -> (alias, username)
        for key, profile in self.net_manager.profiles.items():
            username = profile.get("username", "").strip()
            if not username or username == "—":
                continue
            alias = profile.get("alias", "").strip() or key
            ip    = profile.get("last_ip", key)
            wanted[ip] = (alias, username)

        # Remove rows whose host is no longer in profiles
        for row in range(self._table.rowCount() - 1, -1, -1):
            s  = self._table.item(row, _T_STATUS)
            ip = s.data(Qt.ItemDataRole.UserRole) if s else None
            if ip not in wanted:
                self._table.removeRow(row)

        # Collect IPs already rendered
        existing: set[str] = set()
        for row in range(self._table.rowCount()):
            s  = self._table.item(row, _T_STATUS)
            ip = s.data(Qt.ItemDataRole.UserRole) if s else None
            if ip:
                existing.add(ip)

        # Add rows for newly configured hosts, re-applying any cached result
        for ip, (alias, username) in wanted.items():
            if ip not in existing:
                self._add_row(alias, ip, username)
                if ip in self._cache:
                    self._on_result(ip, self._cache[ip])

        if self._table.rowCount() == 0:
            self._set_statusbar(
                "No configured hosts. Set an alias and username in the Scanner tab.")
        else:
            self._set_statusbar(
                f"{self._table.rowCount()} host(s) — click Refresh All to probe SMART data.")

    def _add_row(self, alias: str, ip: str, username: str):
        row = self._table.rowCount()
        self._table.insertRow(row)

        status_item = QTableWidgetItem("—")
        status_item.setData(Qt.ItemDataRole.UserRole,     ip)
        status_item.setData(Qt.ItemDataRole.UserRole + 1, username)
        status_item.setData(Qt.ItemDataRole.UserRole + 2, alias)
        status_item.setForeground(QBrush(QColor("#9AA4AF")))

        self._table.setItem(row, _T_STATUS,  status_item)
        self._table.setItem(row, _T_ALIAS,   QTableWidgetItem(alias))
        self._table.setItem(row, _T_IP,      QTableWidgetItem(ip))
        self._table.setItem(row, _T_DISKS,   QTableWidgetItem("—"))
        self._table.setItem(row, _T_HEALTH,  QTableWidgetItem("—"))
        self._table.setItem(row, _T_UPDATED, QTableWidgetItem("—"))

        self._table.item(row, _T_ALIAS).setForeground(QBrush(QColor("#3498db")))

    # ── Probing ───────────────────────────────────────────────────────────────

    def _refresh_all(self):
        for row in range(self._table.rowCount()):
            self._probe_row(row)

    def _probe_row(self, row: int):
        s        = self._table.item(row, _T_STATUS)
        ip       = s.data(Qt.ItemDataRole.UserRole)
        username = s.data(Qt.ItemDataRole.UserRole + 1)
        if not ip or not username:
            return
        if ip in self._workers and self._workers[ip].isRunning():
            return

        s.setText("Probing…")
        s.setForeground(QBrush(QColor("#f39c12")))

        worker = SmartProbeWorker(ip, username)
        worker.result_ready.connect(self._on_result)
        worker.probe_error.connect(self._on_error)
        worker.host_key_changed.connect(self._on_key_change)
        worker.finished.connect(lambda _ip=ip: self._workers.pop(_ip, None))
        self._workers[ip] = worker
        worker.start()

    # ── Worker callbacks ──────────────────────────────────────────────────────

    @pyqtSlot(str, list)
    def _on_result(self, ip: str, disks: list):
        self._cache[ip] = disks
        row = self._find_row(ip)
        if row == -1:
            return

        # ── Log SMART history ─────────────────────────────────────────────────
        # Resolve profile key (prefer MAC so log file survives IP changes)
        alias   = self._table.item(row, _T_ALIAS).text() if row != -1 else ip
        profile_key = ip
        for key, profile in self.net_manager.profiles.items():
            if profile.get("last_ip") == ip:
                profile_key = key
                break
        SmartLogger(profile_key, alias).record(disks)

        from datetime import datetime
        health_text, health_color = _overall_health(disks)

        # Sum raw capacity bytes across all disks for the overview column
        total_bytes = sum(d.get("capacity_bytes") or 0 for d in disks)
        if total_bytes:
            disks_txt = f"{len(disks)}  ·  {_fmt_bytes(total_bytes)}"
        else:
            disks_txt = str(len(disks))

        self._set_cell(row, _T_STATUS,  "Online",     "#27ae60")
        self._set_cell(row, _T_DISKS,   disks_txt,    "#9AA4AF")
        self._set_cell(row, _T_HEALTH,  health_text,  health_color)
        self._set_cell(row, _T_UPDATED, datetime.now().strftime("%H:%M:%S"), "#9AA4AF")

        font = self._table.item(row, _T_HEALTH).font()
        font.setBold(True)
        self._table.item(row, _T_HEALTH).setFont(font)

        self._set_statusbar(f"SMART probe complete for {ip}.")

    @pyqtSlot(str, str)
    def _on_error(self, ip: str, msg: str):
        row = self._find_row(ip)
        if row == -1:
            return
        s = self._table.item(row, _T_STATUS)
        s.setText("Error")
        s.setForeground(QBrush(QColor("#c0392b")))
        s.setToolTip(msg)
        self._set_statusbar(f"Could not reach {ip}: {msg[:80]}")

    @pyqtSlot(str)
    def _on_key_change(self, ip: str):
        row = self._find_row(ip)
        if row != -1:
            self._set_cell(row, _T_STATUS, "Key Changed", "#c0392b")

        reply = QMessageBox.question(self, "Host Key Changed",
            f"The SSH host key for {ip} has changed.\n\n"
            "Remove the old key and trust the new one?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            remove_host_from_known_hosts(ip)
            if row != -1:
                self._probe_row(row)

    # ── Double-click ──────────────────────────────────────────────────────────

    def _on_double_click(self, item):
        row      = item.row()
        s        = self._table.item(row, _T_STATUS)
        ip       = s.data(Qt.ItemDataRole.UserRole)
        username = s.data(Qt.ItemDataRole.UserRole + 1)
        alias    = s.data(Qt.ItemDataRole.UserRole + 2)

        # Resolve profile key for SMART log lookup
        profile_key = ip
        for key, profile in self.net_manager.profiles.items():
            if profile.get("last_ip") == ip:
                profile_key = key
                break

        dlg = SmartDiskDialog(
            ip=ip, username=username, alias=alias,
            disks=self._cache.get(ip),
            profile_key=profile_key,
            parent=self,
        )
        dlg.exec()

    # ── Auto-refresh ──────────────────────────────────────────────────────────

    def _toggle_auto(self, checked: bool):
        if checked:
            self._auto_timer.start(self._spin.value() * 1000)
        else:
            self._auto_timer.stop()

    def _update_interval(self, value: int):
        if self._auto_cb.isChecked():
            self._auto_timer.start(value * 1000)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _find_row(self, ip: str) -> int:
        for row in range(self._table.rowCount()):
            item = self._table.item(row, _T_STATUS)
            if item and item.data(Qt.ItemDataRole.UserRole) == ip:
                return row
        return -1

    def _set_cell(self, row: int, col: int, text: str, color: str):
        item = self._table.item(row, col)
        if item is None:
            item = QTableWidgetItem()
            self._table.setItem(row, col, item)
        item.setText(text)
        item.setForeground(QBrush(QColor(color)))

    def _set_statusbar(self, msg: str):
        if self.parent_window:
            self.parent_window.status.setText(msg)