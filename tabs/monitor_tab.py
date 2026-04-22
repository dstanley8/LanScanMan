import re
import time
from datetime import timedelta

import paramiko
from PyQt6.QtCore import Qt, QThread, pyqtSignal, pyqtSlot, QTimer
from PyQt6.QtGui import QColor, QBrush, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFormLayout,
    QGroupBox, QHBoxLayout, QHeaderView, QLabel, QMessageBox,
    QProgressBar, QPushButton, QSpinBox, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from manager import HostKeyMismatchError, _make_ssh_client, remove_host_from_known_hosts

# ─────────────────────────────────────────────────────────────────────────────
# Shell command executed on the remote host via exec_command.
# Each section is bracketed by a ###TAG### sentinel line so we can parse
# the output reliably even when individual commands emit nothing.
# The `|| true` suppressor keeps the exit status clean when a tool is absent.
# ─────────────────────────────────────────────────────────────────────────────
_PROBE_CMD = r"""
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
"""


# ─────────────────────────────────────────────────────────────────────────────
# Parsing helpers
# ─────────────────────────────────────────────────────────────────────────────

def _split_sections(raw: str) -> dict:
    """Split tagged probe output into a {TAG: content} dict."""
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


def _calc_cpu_usage(stat1: str, stat2: str):
    """Return CPU usage % from two consecutive /proc/stat headline values."""
    try:
        v1 = [int(x) for x in stat1.split()[1:]]
        v2 = [int(x) for x in stat2.split()[1:]]
        total1, total2 = sum(v1), sum(v2)
        idle1, idle2   = v1[3], v2[3]
        delta_total = total2 - total1
        delta_idle  = idle2  - idle1
        if delta_total == 0:
            return 0.0
        return round(100.0 * (1.0 - delta_idle / delta_total), 1)
    except Exception:
        return None


def _fmt_uptime(seconds: float) -> str:
    td = timedelta(seconds=int(seconds))
    days    = td.days
    hours   = td.seconds // 3600
    minutes = (td.seconds % 3600) // 60
    parts   = []
    if days:    parts.append(f"{days}d")
    if hours:   parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def _fmt_mb(mb) -> str:
    if mb is None:
        return "?"
    if mb >= 1024:
        return f"{mb / 1024:.1f} GB"
    return f"{mb} MB"


def parse_probe_output(raw: str) -> dict:
    """Convert raw probe output into a structured dict. All fields optional."""
    s = _split_sections(raw)
    r: dict = {}

    # Distro
    r["distro"] = s.get("DISTRO") or None

    # CPU
    r["cpu_model"] = s.get("CPU_MODEL") or None
    try:
        r["cpu_cores"] = int(s["CPU_CORES"])
    except Exception:
        r["cpu_cores"] = None

    r["cpu_usage"] = _calc_cpu_usage(s.get("STAT1", ""), s.get("STAT2", ""))

    # RAM — /proc/meminfo values are in kB
    mem_total = mem_avail = None
    for line in s.get("MEM", "").splitlines():
        if line.startswith("MemTotal:"):
            try:
                mem_total = int(line.split()[1])
            except Exception:
                pass
        elif line.startswith("MemAvailable:"):
            try:
                mem_avail = int(line.split()[1])
            except Exception:
                pass
    r["mem_total_kb"]  = mem_total
    r["mem_avail_kb"]  = mem_avail

    # CPU temp — hwmon reports millidegrees Celsius
    try:
        raw_temp = int(s.get("CPU_TEMP", "").strip())
        r["cpu_temp_c"] = round(raw_temp / 1000) if raw_temp > 1000 else raw_temp
    except Exception:
        r["cpu_temp_c"] = None

    # Uptime
    try:
        r["uptime_seconds"] = float(s["UPTIME"].split()[0])
    except Exception:
        r["uptime_seconds"] = None

    # GPU — try NVIDIA first (has the richest data), then AMD /sys, then lspci name only
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

    if r["gpu_usage"] is None:                          # Try AMD /sys
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

    if r["gpu_temp_c"] is None:                         # AMD GPU temp via hwmon
        try:
            raw_gt = int(s.get("AMD_GPU_TEMP", "").strip())
            r["gpu_temp_c"] = round(raw_gt / 1000) if raw_gt > 1000 else raw_gt
        except Exception:
            pass

    if r["gpu_name"] is None:                           # Name from lspci fallback
        lspci = s.get("LSPCI", "")
        m = re.search(r"(?:VGA|3D|Display)[^:]*:\s*(.*)", lspci, re.IGNORECASE)
        if m:
            r["gpu_name"] = m.group(1).strip()

    return r


# ─────────────────────────────────────────────────────────────────────────────
# Worker thread
# ─────────────────────────────────────────────────────────────────────────────

class ProbeWorker(QThread):
    """Connects via SSH, runs the probe command, emits parsed results."""
    result_ready = pyqtSignal(str, dict)   # (ip, parsed_data)
    probe_error  = pyqtSignal(str, str)    # (ip, error_message)
    host_key_changed = pyqtSignal(str)     # (ip)

    def __init__(self, ip: str, username: str, parent=None):
        super().__init__(parent)
        self.ip       = ip
        self.username = username

    def run(self):
        try:
            ssh = _make_ssh_client()
            ssh.connect(self.ip, username=self.username, timeout=8,
                        look_for_keys=True, allow_agent=True)
            _, stdout, _ = ssh.exec_command(_PROBE_CMD, timeout=15)
            raw = stdout.read().decode(errors="replace")
            ssh.close()
            self.result_ready.emit(self.ip, parse_probe_output(raw))
        except paramiko.BadHostKeyException:
            self.host_key_changed.emit(self.ip)
        except Exception as e:
            self.probe_error.emit(self.ip, str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Shared UI helpers
# ─────────────────────────────────────────────────────────────────────────────

def _usage_color(pct) -> str:
    """Return a hex colour string based on a 0-100 usage percentage."""
    if pct is None:
        return "#9AA4AF"
    if pct < 60:
        return "#27ae60"
    if pct < 85:
        return "#f39c12"
    return "#c0392b"


def _make_bar(pct, label: str = "") -> QProgressBar:
    """Return a styled QProgressBar for a 0-100 percentage."""
    bar = QProgressBar()
    bar.setRange(0, 100)
    bar.setValue(int(pct) if pct is not None else 0)
    bar.setTextVisible(True)
    bar.setFormat(label if label else f"{pct:.1f}%" if pct is not None else "N/A")
    color = _usage_color(pct)
    bar.setStyleSheet(f"""
        QProgressBar {{
            border: 1px solid #2A313B;
            border-radius: 5px;
            background-color: #15181C;
            color: #E6E6E6;
            text-align: center;
            height: 18px;
        }}
        QProgressBar::chunk {{
            background-color: {color};
            border-radius: 4px;
        }}
    """)
    return bar


def _section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        "color: #3498db; font-weight: bold; font-size: 11px; "
        "letter-spacing: 1px; text-transform: uppercase;"
    )
    return lbl


def _value_label(text: str, muted: bool = False) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(f"color: {'#9AA4AF' if muted else '#E6E6E6'}; font-size: 12px;")
    lbl.setWordWrap(True)
    return lbl


def _hw_temp_color(c) -> str:
    """Colour for CPU/GPU hardware temperatures (run naturally hotter than disks)."""
    if c is None:
        return "#9AA4AF"
    if c < 65:
        return "#27ae60"
    if c < 85:
        return "#f39c12"
    return "#c0392b"


# ─────────────────────────────────────────────────────────────────────────────
# Brand detection & styling
# ─────────────────────────────────────────────────────────────────────────────

_BRANDS = {
    "intel":  {"label": "INTEL",   "color": "#1e90ff", "bg": "#071728", "border": "#1060bb"},
    "amd":    {"label": "AMD",     "color": "#e84040", "bg": "#210a0a", "border": "#a02020"},
    "nvidia": {"label": "NVIDIA",  "color": "#76b900", "bg": "#0d1c00", "border": "#4a7500"},
    "unknown":{"label": "UNKNOWN", "color": "#9AA4AF", "bg": "#1B1F24", "border": "#3A4452"},
}

def _detect_cpu_brand(model: str | None) -> dict:
    if not model:
        return _BRANDS["unknown"]
    s = model.upper()
    if "INTEL" in s:
        return _BRANDS["intel"]
    if "AMD" in s:
        return _BRANDS["amd"]
    return _BRANDS["unknown"]

def _detect_gpu_brand(name: str | None) -> dict:
    if not name:
        return _BRANDS["unknown"]
    s = name.upper()
    if "NVIDIA" in s or "GEFORCE" in s or "QUADRO" in s or "TESLA" in s or "RTX" in s or "GTX" in s:
        return _BRANDS["nvidia"]
    if "AMD" in s or "RADEON" in s:
        return _BRANDS["amd"]
    if "INTEL" in s or "UHD GRAPHICS" in s or "IRIS" in s or "ARC" in s:
        return _BRANDS["intel"]
    return _BRANDS["unknown"]

def _make_badge() -> QLabel:
    """Return a blank badge label — text and style applied later via _apply_brand."""
    lbl = QLabel("")
    lbl.setFixedHeight(20)
    lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    return lbl

def _apply_brand(group: "QGroupBox", badge: QLabel, name_lbl: QLabel, brand: dict):
    """Paint a hardware section with its brand colour: top border, badge pill, name tint."""
    c  = brand["color"]
    bg = brand["bg"]
    bd = brand["border"]

    # Coloured top-border on the group box
    group.setStyleSheet(f"""
        QGroupBox {{
            border: 1px solid #2A313B;
            border-top: 2px solid {c};
            border-radius: 6px;
            padding: 10px;
            margin-top: 1px;
        }}
    """)

    # Pill badge
    badge.setText(brand["label"])
    badge.setStyleSheet(f"""
        QLabel {{
            color: {c};
            background-color: {bg};
            border: 1px solid {bd};
            border-radius: 4px;
            padding: 1px 7px;
            font-size: 9px;
            font-weight: bold;
            letter-spacing: 1.5px;
        }}
    """)

    # Name label tinted to brand colour
    name_lbl.setStyleSheet(f"color: {c}; font-size: 12px;")


# ─────────────────────────────────────────────────────────────────────────────
# Detail dialog — opens on double-click, auto-refreshes
# ─────────────────────────────────────────────────────────────────────────────

class HostStatsDialog(QDialog):
    def __init__(self, ip: str, username: str, alias: str = "", data: dict = None, parent=None):
        super().__init__(parent)
        self.ip       = ip
        self.username = username
        self.alias    = alias or ip
        self.setWindowTitle(f"Host Monitor — {self.alias}")
        self.setMinimumSize(520, 580)
        self.resize(560, 620)
        self._worker: ProbeWorker | None = None

        self._build_ui()
        if data:
            self._apply_data(data)
        else:
            self._set_probing_state()

        # Auto-refresh timer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(10_000)       # default 10 s
        if not data:
            self._refresh()

    # ── Layout ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(10)

        # ── Header ──────────────────────────────────────────────────────────
        header_row = QHBoxLayout()
        self._lbl_title = QLabel(f"<b>{self.alias}</b>  <span style='color:#9AA4AF;font-size:12px;'>{self.ip}</span>")
        self._lbl_title.setStyleSheet("font-size: 15px;")
        self._lbl_uptime = QLabel("Uptime: —")
        self._lbl_uptime.setStyleSheet("color: #9AA4AF; font-size: 12px;")
        self._lbl_distro = QLabel("")
        self._lbl_distro.setStyleSheet("color: #9AA4AF; font-size: 12px; font-style: italic;")
        header_row.addWidget(self._lbl_title)
        header_row.addStretch()
        header_row.addWidget(self._lbl_distro)
        root.addLayout(header_row)
        root.addWidget(self._lbl_uptime)

        self._separator(root)

        # ── CPU ─────────────────────────────────────────────────────────────
        self._cpu_group = QGroupBox()
        self._cpu_group.setStyleSheet(
            "QGroupBox { border: 1px solid #2A313B; border-radius: 6px; padding: 10px; }")
        cpu_layout = QVBoxLayout(self._cpu_group)
        cpu_layout.setSpacing(6)

        cpu_header = QHBoxLayout()
        cpu_header.addWidget(_section_label("CPU"))
        cpu_header.addStretch()
        self._cpu_badge = _make_badge()
        cpu_header.addWidget(self._cpu_badge)
        cpu_layout.addLayout(cpu_header)

        self._lbl_cpu_model = _value_label("—")
        self._lbl_cpu_temp  = QLabel("—")
        self._lbl_cpu_temp.setStyleSheet("color: #9AA4AF; font-size: 12px; font-weight: bold;")
        self._bar_cpu        = _make_bar(None, "N/A")
        cpu_layout.addWidget(self._lbl_cpu_model)
        cpu_layout.addWidget(self._lbl_cpu_temp)
        cpu_layout.addWidget(self._bar_cpu)
        root.addWidget(self._cpu_group)

        # ── RAM ─────────────────────────────────────────────────────────────
        ram_group = QGroupBox()
        ram_group.setStyleSheet("QGroupBox { border: 1px solid #2A313B; border-radius: 6px; padding: 10px; }")
        ram_layout = QVBoxLayout(ram_group)
        ram_layout.setSpacing(6)
        ram_layout.addWidget(_section_label("Memory"))
        self._lbl_ram = _value_label("—", muted=True)
        self._bar_ram  = _make_bar(None, "N/A")
        ram_layout.addWidget(self._lbl_ram)
        ram_layout.addWidget(self._bar_ram)
        root.addWidget(ram_group)

        # ── GPU ─────────────────────────────────────────────────────────────
        self._gpu_group = QGroupBox()
        self._gpu_group.setStyleSheet(
            "QGroupBox { border: 1px solid #2A313B; border-radius: 6px; padding: 10px; }")
        gpu_layout = QVBoxLayout(self._gpu_group)
        gpu_layout.setSpacing(6)

        gpu_header = QHBoxLayout()
        gpu_header.addWidget(_section_label("GPU"))
        gpu_header.addStretch()
        self._gpu_badge = _make_badge()
        gpu_header.addWidget(self._gpu_badge)
        gpu_layout.addLayout(gpu_header)

        self._lbl_gpu_name  = _value_label("—")
        self._lbl_gpu_temp  = QLabel("—")
        self._lbl_gpu_temp.setStyleSheet("color: #9AA4AF; font-size: 12px; font-weight: bold;")
        self._bar_gpu        = _make_bar(None, "N/A")
        self._lbl_gpu_vram  = _value_label("—", muted=True)
        self._bar_gpu_vram  = _make_bar(None, "N/A")
        gpu_layout.addWidget(self._lbl_gpu_name)
        gpu_layout.addWidget(self._lbl_gpu_temp)
        gpu_layout.addWidget(self._bar_gpu)
        gpu_layout.addWidget(self._lbl_gpu_vram)
        gpu_layout.addWidget(self._bar_gpu_vram)
        root.addWidget(self._gpu_group)

        # Use spacing instead of stretch so the layout collapses cleanly
        # when the GPU group is hidden (no large empty gap at the bottom).
        root.addSpacing(8)
        self._separator(root)

        # ── Footer controls ─────────────────────────────────────────────────
        footer = QHBoxLayout()
        self._lbl_status = QLabel("Ready")
        self._lbl_status.setStyleSheet("color: #9AA4AF; font-size: 11px;")

        self._auto_cb   = QCheckBox("Auto-refresh")
        self._auto_cb.setChecked(True)
        self._interval_spin = QSpinBox()
        self._interval_spin.setRange(5, 120)
        self._interval_spin.setValue(10)
        self._interval_spin.setSuffix(" s")
        self._interval_spin.setFixedWidth(70)
        self._interval_spin.valueChanged.connect(self._update_interval)
        self._auto_cb.toggled.connect(self._toggle_auto)

        refresh_btn = QPushButton("Refresh Now")
        refresh_btn.clicked.connect(self._refresh)

        close_btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close_btn.rejected.connect(self.reject)

        footer.addWidget(self._lbl_status)
        footer.addStretch()
        footer.addWidget(self._auto_cb)
        footer.addWidget(self._interval_spin)
        footer.addWidget(refresh_btn)
        footer.addWidget(close_btn)
        root.addLayout(footer)

    @staticmethod
    def _separator(layout: QVBoxLayout):
        line = QWidget()
        line.setFixedHeight(1)
        line.setStyleSheet("background-color: #2A313B;")
        layout.addWidget(line)

    # ── Data application ─────────────────────────────────────────────────────

    def _set_probing_state(self):
        self._lbl_status.setText("⏳  Probing…")
        self._lbl_status.setStyleSheet("color: #f39c12; font-size: 11px;")

    def _apply_data(self, d: dict):
        self._lbl_status.setText("● Live")
        self._lbl_status.setStyleSheet("color: #27ae60; font-size: 11px;")

        # Header
        if d.get("distro"):
            self._lbl_distro.setText(d["distro"])
        if d.get("uptime_seconds") is not None:
            self._lbl_uptime.setText(f"Uptime: {_fmt_uptime(d['uptime_seconds'])}")

        # CPU
        cpu_model = d.get("cpu_model") or "Unknown CPU"
        cores_str = f"  •  {d['cpu_cores']} cores" if d.get("cpu_cores") else ""
        self._lbl_cpu_model.setText(cpu_model + cores_str)
        cpu_brand = _detect_cpu_brand(cpu_model)
        _apply_brand(self._cpu_group, self._cpu_badge, self._lbl_cpu_model, cpu_brand)
        ct = d.get("cpu_temp_c")
        self._lbl_cpu_temp.setText(f"🌡  {ct}°C" if ct is not None else "🌡  —")
        self._lbl_cpu_temp.setStyleSheet(
            f"color: {_hw_temp_color(ct)}; font-size: 12px; font-weight: bold;")
        self._replace_bar("_bar_cpu", d.get("cpu_usage"),
                          f"{d['cpu_usage']:.1f}%" if d.get("cpu_usage") is not None else "N/A")

        # RAM
        total_kb = d.get("mem_total_kb")
        avail_kb = d.get("mem_avail_kb")
        if total_kb and avail_kb is not None:
            used_kb  = total_kb - avail_kb
            pct      = round(100.0 * used_kb / total_kb, 1)
            used_mb  = used_kb // 1024
            total_mb = total_kb // 1024
            self._lbl_ram.setText(f"{_fmt_mb(used_mb)} used / {_fmt_mb(total_mb)} total")
            self._replace_bar("_bar_ram", pct, f"{pct:.1f}%")
        else:
            self._lbl_ram.setText("N/A")
            self._replace_bar("_bar_ram", None, "N/A")

        # GPU
        has_any_gpu = bool(d.get("gpu_name")) or (d.get("gpu_usage") is not None)
        self._gpu_group.setVisible(has_any_gpu)
        if has_any_gpu:
            gpu_name = d.get("gpu_name") or "Unknown GPU"
            self._lbl_gpu_name.setText(gpu_name)
            gpu_brand = _detect_gpu_brand(gpu_name)
            _apply_brand(self._gpu_group, self._gpu_badge, self._lbl_gpu_name, gpu_brand)
            gt = d.get("gpu_temp_c")
            self._lbl_gpu_temp.setText(f"🌡  {gt}°C" if gt is not None else "🌡  —")
            self._lbl_gpu_temp.setStyleSheet(
                f"color: {_hw_temp_color(gt)}; font-size: 12px; font-weight: bold;")
            self._replace_bar("_bar_gpu", d.get("gpu_usage"),
                              f"{d['gpu_usage']}%" if d.get("gpu_usage") is not None else "N/A")
            used_mb  = d.get("gpu_mem_used_mb")
            total_mb = d.get("gpu_mem_total_mb")
            if used_mb is not None and total_mb:
                vram_pct = round(100.0 * used_mb / total_mb, 1)
                self._lbl_gpu_vram.setText(
                    f"VRAM  {_fmt_mb(used_mb)} / {_fmt_mb(total_mb)}"
                )
                self._replace_bar("_bar_gpu_vram", vram_pct, f"{vram_pct:.1f}%")
            else:
                self._lbl_gpu_vram.setVisible(False)
                self._bar_gpu_vram.setVisible(False)

    def _replace_bar(self, attr: str, pct, label: str):
        """Swap an existing QProgressBar in place (update value + colour)."""
        old_bar: QProgressBar = getattr(self, attr)
        old_bar.setValue(int(pct) if pct is not None else 0)
        old_bar.setFormat(label)
        color = _usage_color(pct)
        old_bar.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid #2A313B;
                border-radius: 5px;
                background-color: #15181C;
                color: #E6E6E6;
                text-align: center;
                height: 18px;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 4px;
            }}
        """)

    # ── Refresh logic ────────────────────────────────────────────────────────

    def _refresh(self):
        if self._worker and self._worker.isRunning():
            return                          # Already in flight
        self._set_probing_state()
        self._worker = ProbeWorker(self.ip, self.username)
        self._worker.result_ready.connect(self._on_result)
        self._worker.probe_error.connect(self._on_error)
        self._worker.host_key_changed.connect(self._on_key_change)
        self._worker.start()

    @pyqtSlot(str, dict)
    def _on_result(self, _ip, data):
        self._apply_data(data)

    @pyqtSlot(str, str)
    def _on_error(self, _ip, msg):
        self._lbl_status.setText(f"✖  {msg[:60]}")
        self._lbl_status.setStyleSheet("color: #c0392b; font-size: 11px;")

    @pyqtSlot(str)
    def _on_key_change(self, ip):
        self._timer.stop()
        reply = QMessageBox.question(self, "Host Key Changed",
            f"The SSH host key for {ip} has changed.\n\n"
            "This may be normal after an OS reinstall, or could indicate a security issue.\n\n"
            "Remove the old key and trust the new one?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            remove_host_from_known_hosts(ip)
            self._refresh()
        if self._auto_cb.isChecked():
            self._timer.start()

    def _toggle_auto(self, checked: bool):
        if checked:
            self._timer.start(self._interval_spin.value() * 1000)
        else:
            self._timer.stop()

    def _update_interval(self, value: int):
        if self._auto_cb.isChecked():
            self._timer.start(value * 1000)

    def closeEvent(self, event):
        self._timer.stop()
        if self._worker:
            # Disconnect first so a late signal can't fire into a half-destroyed dialog.
            try:
                self._worker.result_ready.disconnect(self._on_result)
                self._worker.probe_error.disconnect(self._on_error)
                self._worker.host_key_changed.disconnect(self._on_key_change)
            except Exception:
                pass
            # Block until the thread is done (SSH probe takes ~1-2 s at most).
            # Without wait() Qt destroys the QThread object while it's still
            # running, which causes the "Destroyed while thread is still running"
            # abort.
            if self._worker.isRunning():
                self._worker.wait(6000)
        super().closeEvent(event)


# ─────────────────────────────────────────────────────────────────────────────
# MonitorTab — table listing all hosts that have a saved profile + username
# ─────────────────────────────────────────────────────────────────────────────

# Table column indices
_COL_STATUS  = 0
_COL_ALIAS   = 1
_COL_IP      = 2
_COL_DISTRO  = 3
_COL_CPU     = 4
_COL_RAM     = 5
_COL_GPU     = 6
_COL_UPTIME  = 7
_COL_UPDATED = 8


class MonitorTab(QWidget):
    def __init__(self, net_manager, parent=None):
        super().__init__(parent)
        self.net_manager   = net_manager
        self.parent_window = parent
        self._workers: dict[str, ProbeWorker] = {}   # ip -> active worker
        self._cache:   dict[str, dict]         = {}   # ip -> last parsed data
        self._setup_ui()
        self._auto_timer = QTimer(self)
        self._auto_timer.timeout.connect(self._refresh_all)

    # ── UI ───────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        root = QVBoxLayout(self)

        # ── Controls bar ────────────────────────────────────────────────────
        bar = QHBoxLayout()

        self._refresh_btn = QPushButton("Refresh All")
        self._refresh_btn.clicked.connect(self._refresh_all)

        self._auto_cb = QCheckBox("Auto-refresh")
        self._auto_cb.toggled.connect(self._toggle_auto)

        self._spin = QSpinBox()
        self._spin.setRange(10, 300)
        self._spin.setValue(30)
        self._spin.setSuffix(" s")
        self._spin.setFixedWidth(75)
        self._spin.setToolTip("Auto-refresh interval")
        self._spin.valueChanged.connect(self._update_interval)

        self._lbl_info = QLabel("Double-click a row to open the live stats panel.")
        self._lbl_info.setStyleSheet("color: #9AA4AF; font-size: 11px;")

        bar.addWidget(self._refresh_btn)
        bar.addSpacing(8)
        bar.addWidget(self._auto_cb)
        bar.addWidget(self._spin)
        bar.addStretch()
        bar.addWidget(self._lbl_info)
        root.addLayout(bar)

        # ── Table ────────────────────────────────────────────────────────────
        self._table = QTableWidget(0, 9)
        self._table.setHorizontalHeaderLabels([
            "Status", "Alias", "IP", "OS / Distro",
            "CPU % · °C", "RAM %", "GPU % · °C", "Uptime", "Last Updated",
        ])
        self._table.verticalHeader().setDefaultSectionSize(42)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hdr.setSectionResizeMode(_COL_ALIAS,   QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(_COL_DISTRO,  QHeaderView.ResizeMode.Stretch)
        hdr.resizeSection(_COL_STATUS,  80)
        hdr.resizeSection(_COL_IP,     120)
        hdr.resizeSection(_COL_CPU,    105)
        hdr.resizeSection(_COL_RAM,     70)
        hdr.resizeSection(_COL_GPU,    105)
        hdr.resizeSection(_COL_UPTIME, 100)
        hdr.resizeSection(_COL_UPDATED,120)

        self._table.itemDoubleClicked.connect(self._on_double_click)
        root.addWidget(self._table)

        QShortcut(QKeySequence("F5"), self).activated.connect(self._refresh_all)

    # ── Population ───────────────────────────────────────────────────────────

    def showEvent(self, event):
        """Sync rows with profiles whenever the tab becomes visible."""
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
            s  = self._table.item(row, _COL_STATUS)
            ip = s.data(Qt.ItemDataRole.UserRole) if s else None
            if ip not in wanted:
                self._table.removeRow(row)

        # Collect IPs already rendered
        existing: set[str] = set()
        for row in range(self._table.rowCount()):
            s  = self._table.item(row, _COL_STATUS)
            ip = s.data(Qt.ItemDataRole.UserRole) if s else None
            if ip:
                existing.add(ip)

        # Add rows for newly configured hosts, re-applying cached data immediately
        for ip, (alias, username) in wanted.items():
            if ip not in existing:
                self._add_row(alias, ip, username)
                if ip in self._cache:
                    self._on_result(ip, self._cache[ip])

        if self._table.rowCount() == 0:
            self._set_status_bar(
                "No configured hosts found. Add an alias and username in the Scanner tab.")
        else:
            self._set_status_bar(
                f"{self._table.rowCount()} host(s) — click Refresh All to probe.")

    def _add_row(self, alias: str, ip: str, username: str):
        row = self._table.rowCount()
        self._table.insertRow(row)

        status_item = QTableWidgetItem("—")
        status_item.setData(Qt.ItemDataRole.UserRole,     ip)        # ip
        status_item.setData(Qt.ItemDataRole.UserRole + 1, username)  # username
        status_item.setData(Qt.ItemDataRole.UserRole + 2, alias)     # alias
        status_item.setForeground(QBrush(QColor("#9AA4AF")))

        self._table.setItem(row, _COL_STATUS,  status_item)
        self._table.setItem(row, _COL_ALIAS,   QTableWidgetItem(alias))
        self._table.setItem(row, _COL_IP,      QTableWidgetItem(ip))
        self._table.setItem(row, _COL_DISTRO,  QTableWidgetItem("—"))
        self._table.setItem(row, _COL_CPU,     QTableWidgetItem("—"))
        self._table.setItem(row, _COL_RAM,     QTableWidgetItem("—"))
        self._table.setItem(row, _COL_GPU,     QTableWidgetItem("—"))
        self._table.setItem(row, _COL_UPTIME,  QTableWidgetItem("—"))
        self._table.setItem(row, _COL_UPDATED, QTableWidgetItem("—"))

        self._table.item(row, _COL_ALIAS).setForeground(QBrush(QColor("#3498db")))

    # ── Refresh orchestration ─────────────────────────────────────────────────

    def _refresh_all(self):
        for row in range(self._table.rowCount()):
            self._probe_row(row)

    def _probe_row(self, row: int):
        status_item = self._table.item(row, _COL_STATUS)
        if status_item is None:
            return
        ip       = status_item.data(Qt.ItemDataRole.UserRole)
        username = status_item.data(Qt.ItemDataRole.UserRole + 1)

        if ip in self._workers and self._workers[ip].isRunning():
            return                              # Already probing this host

        status_item.setText("Probing…")
        status_item.setForeground(QBrush(QColor("#f39c12")))

        worker = ProbeWorker(ip, username)
        worker.result_ready.connect(self._on_result)
        worker.probe_error.connect(self._on_error)
        worker.host_key_changed.connect(self._on_key_change)
        # Remove from dict only after run() has fully returned — not in the
        # result/error slots, where the thread may still be in its cleanup phase.
        worker.finished.connect(lambda _ip=ip: self._workers.pop(_ip, None))
        self._workers[ip] = worker
        worker.start()

    # ── Worker callbacks ──────────────────────────────────────────────────────

    @pyqtSlot(str, dict)
    def _on_result(self, ip: str, data: dict):
        # Don't pop self._workers here — the finished signal handles that
        # once run() has truly returned, avoiding a destroy-while-running crash.
        self._cache[ip] = data
        row = self._find_row(ip)
        if row == -1:
            return

        # Status cell
        s = self._table.item(row, _COL_STATUS)
        s.setText("Online")
        s.setForeground(QBrush(QColor("#27ae60")))

        # Distro
        self._set_cell(row, _COL_DISTRO, data.get("distro") or "—", "#9AA4AF")

        # CPU — show usage and temperature together in one cell
        cpu_pct  = data.get("cpu_usage")
        cpu_temp = data.get("cpu_temp_c")
        if cpu_pct is not None and cpu_temp is not None:
            cpu_txt   = f"{cpu_pct:.1f}%  ·  {cpu_temp}°C"
            cpu_color = _hw_temp_color(cpu_temp)
        elif cpu_pct is not None:
            cpu_txt   = f"{cpu_pct:.1f}%"
            cpu_color = _usage_color(cpu_pct)
        else:
            cpu_txt, cpu_color = "—", "#9AA4AF"
        self._set_cell(row, _COL_CPU, cpu_txt, cpu_color)

        # RAM
        total_kb = data.get("mem_total_kb")
        avail_kb = data.get("mem_avail_kb")
        if total_kb and avail_kb is not None:
            used_kb = total_kb - avail_kb
            ram_pct = round(100.0 * used_kb / total_kb, 1)
            self._set_cell(row, _COL_RAM, f"{ram_pct:.1f}%", _usage_color(ram_pct))
        else:
            self._set_cell(row, _COL_RAM, "—", "#9AA4AF")

        # GPU — show usage and temperature together in one cell
        gpu_pct  = data.get("gpu_usage")
        gpu_temp = data.get("gpu_temp_c")
        if gpu_pct is not None and gpu_temp is not None:
            gpu_txt   = f"{gpu_pct}%  ·  {gpu_temp}°C"
            gpu_color = _hw_temp_color(gpu_temp)
        elif gpu_pct is not None:
            gpu_txt   = f"{gpu_pct}%"
            gpu_color = _usage_color(gpu_pct)
        else:
            gpu_txt, gpu_color = "—", "#9AA4AF"
        self._set_cell(row, _COL_GPU, gpu_txt, gpu_color)

        # Uptime
        up = data.get("uptime_seconds")
        self._set_cell(row, _COL_UPTIME, _fmt_uptime(up) if up else "—", "#9AA4AF")

        # Timestamp
        from datetime import datetime
        self._set_cell(row, _COL_UPDATED,
                       datetime.now().strftime("%H:%M:%S"), "#9AA4AF")

        self._set_status_bar(f"Probe complete for {ip}.")

    @pyqtSlot(str, str)
    def _on_error(self, ip: str, msg: str):
        # Don't pop self._workers here — the finished signal handles that.
        row = self._find_row(ip)
        if row == -1:
            return
        s = self._table.item(row, _COL_STATUS)
        s.setText("Error")
        s.setForeground(QBrush(QColor("#c0392b")))
        s.setToolTip(msg)
        for col in [_COL_DISTRO, _COL_CPU, _COL_RAM, _COL_GPU, _COL_UPTIME]:
            self._set_cell(row, col, "—", "#9AA4AF")
        self._set_status_bar(f"Could not reach {ip}: {msg[:80]}")

    @pyqtSlot(str)
    def _on_key_change(self, ip: str):
        # Don't pop self._workers here — the finished signal handles that.
        row = self._find_row(ip)
        if row != -1:
            s = self._table.item(row, _COL_STATUS)
            s.setText("Key Changed")
            s.setForeground(QBrush(QColor("#c0392b")))

        reply = QMessageBox.question(self, "Host Key Changed",
            f"The SSH host key for {ip} has changed.\n\n"
            "This may be normal after an OS reinstall, or could indicate a security issue.\n\n"
            "Remove the old key and trust the new one?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            remove_host_from_known_hosts(ip)
            if row != -1:
                self._probe_row(row)

    # ── Double-click ─────────────────────────────────────────────────────────

    def _on_double_click(self, item):
        row = item.row()
        s        = self._table.item(row, _COL_STATUS)
        ip       = s.data(Qt.ItemDataRole.UserRole)
        username = s.data(Qt.ItemDataRole.UserRole + 1)
        alias    = s.data(Qt.ItemDataRole.UserRole + 2)

        dlg = HostStatsDialog(
            ip       = ip,
            username = username,
            alias    = alias,
            data     = self._cache.get(ip),   # Pass cached data so dialog isn't blank
            parent   = self,
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

    # ── Utilities ────────────────────────────────────────────────────────────

    def _find_row(self, ip: str) -> int:
        for row in range(self._table.rowCount()):
            item = self._table.item(row, _COL_STATUS)
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

    def _set_status_bar(self, msg: str):
        if self.parent_window:
            self.parent_window.status.setText(msg)