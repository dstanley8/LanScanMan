"""Per-host CPU / RAM / GPU detail dialog, opened from the Host Monitor tab."""


from PyQt6.QtCore import Qt, QTimer, pyqtSlot
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from lanscanman.core.formatting import (
    BAD,
    GOOD,
    MUTED,
    WARN,
    fmt_mb,
    fmt_uptime,
    hw_temp_color,
    usage_color,
)
from lanscanman.core.probe import (
    detect_cpu_brand,
    detect_gpu_brand,
    health_summary,
    unhealthy_containers,
)
from lanscanman.ui.trust import confirm_host_key_change
from lanscanman.ui.widgets.common import (
    apply_brand,
    make_badge,
    make_bar,
    section_label,
    value_label,
)
from lanscanman.workers.probes import ProbeWorker


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
        cpu_header.addWidget(section_label("CPU"))
        cpu_header.addStretch()
        self._cpu_badge = make_badge()
        cpu_header.addWidget(self._cpu_badge)
        cpu_layout.addLayout(cpu_header)

        self._lbl_cpu_model = value_label("—")
        self._lbl_cpu_temp  = QLabel("—")
        self._lbl_cpu_temp.setStyleSheet("color: #9AA4AF; font-size: 12px; font-weight: bold;")
        self._bar_cpu        = make_bar(None, "N/A")
        cpu_layout.addWidget(self._lbl_cpu_model)
        cpu_layout.addWidget(self._lbl_cpu_temp)
        cpu_layout.addWidget(self._bar_cpu)
        root.addWidget(self._cpu_group)

        # ── RAM ─────────────────────────────────────────────────────────────
        ram_group = QGroupBox()
        ram_group.setStyleSheet("QGroupBox { border: 1px solid #2A313B; border-radius: 6px; padding: 10px; }")
        ram_layout = QVBoxLayout(ram_group)
        ram_layout.setSpacing(6)
        ram_layout.addWidget(section_label("Memory"))
        self._lbl_ram = value_label("—", muted=True)
        self._bar_ram  = make_bar(None, "N/A")
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
        gpu_header.addWidget(section_label("GPU"))
        gpu_header.addStretch()
        self._gpu_badge = make_badge()
        gpu_header.addWidget(self._gpu_badge)
        gpu_layout.addLayout(gpu_header)

        self._lbl_gpu_name  = value_label("—")
        self._lbl_gpu_temp  = QLabel("—")
        self._lbl_gpu_temp.setStyleSheet("color: #9AA4AF; font-size: 12px; font-weight: bold;")
        self._bar_gpu        = make_bar(None, "N/A")
        self._lbl_gpu_vram  = value_label("—", muted=True)
        self._bar_gpu_vram  = make_bar(None, "N/A")
        gpu_layout.addWidget(self._lbl_gpu_name)
        gpu_layout.addWidget(self._lbl_gpu_temp)
        gpu_layout.addWidget(self._bar_gpu)
        gpu_layout.addWidget(self._lbl_gpu_vram)
        gpu_layout.addWidget(self._bar_gpu_vram)
        root.addWidget(self._gpu_group)

        # ── Health ─────────────────────────────────────────────────────────
        self._separator(root)
        root.addWidget(section_label("Health"))
        self._lbl_health = value_label("—")
        self._lbl_health.setTextFormat(Qt.TextFormat.PlainText)
        root.addWidget(self._lbl_health)

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
            self._lbl_uptime.setText(f"Uptime: {fmt_uptime(d['uptime_seconds'])}")

        # CPU
        cpu_model = d.get("cpu_model") or "Unknown CPU"
        cores_str = f"  •  {d['cpu_cores']} cores" if d.get("cpu_cores") else ""
        self._lbl_cpu_model.setText(cpu_model + cores_str)
        cpu_brand = detect_cpu_brand(cpu_model)
        apply_brand(self._cpu_group, self._cpu_badge, self._lbl_cpu_model, cpu_brand)
        ct = d.get("cpu_temp_c")
        self._lbl_cpu_temp.setText(f"🌡  {ct}°C" if ct is not None else "🌡  —")
        self._lbl_cpu_temp.setStyleSheet(
            f"color: {hw_temp_color(ct)}; font-size: 12px; font-weight: bold;")
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
            self._lbl_ram.setText(f"{fmt_mb(used_mb)} used / {fmt_mb(total_mb)} total")
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
            gpu_brand = detect_gpu_brand(gpu_name)
            apply_brand(self._gpu_group, self._gpu_badge, self._lbl_gpu_name, gpu_brand)
            gt = d.get("gpu_temp_c")
            self._lbl_gpu_temp.setText(f"🌡  {gt}°C" if gt is not None else "🌡  —")
            self._lbl_gpu_temp.setStyleSheet(
                f"color: {hw_temp_color(gt)}; font-size: 12px; font-weight: bold;")
            self._replace_bar("_bar_gpu", d.get("gpu_usage"),
                              f"{d['gpu_usage']}%" if d.get("gpu_usage") is not None else "N/A")
            used_mb  = d.get("gpu_mem_used_mb")
            total_mb = d.get("gpu_mem_total_mb")
            if used_mb is not None and total_mb:
                vram_pct = round(100.0 * used_mb / total_mb, 1)
                self._lbl_gpu_vram.setText(
                    f"VRAM  {fmt_mb(used_mb)} / {fmt_mb(total_mb)}"
                )
                self._replace_bar("_bar_gpu_vram", vram_pct, f"{vram_pct:.1f}%")
            else:
                self._lbl_gpu_vram.setVisible(False)
                self._bar_gpu_vram.setVisible(False)

        self._apply_health(d)

    def _apply_health(self, d: dict):
        lines = []
        failed = d.get("failed_units")
        lines.append("Services:  " + ("systemd not found" if failed is None else
                     "all running" if not failed else "FAILED — " + ", ".join(failed)))
        ups, sec = d.get("updates"), d.get("security_updates")
        lines.append("Updates:  " + ("unknown (not an apt system)" if ups is None else
                     "up to date" if not ups else f"{ups} pending" + (f", {sec} security" if sec else "")))
        reboot = d.get("reboot_required")
        lines.append("Reboot:  " + ("unknown" if reboot is None else "required" if reboot else "not needed"))
        docker = d.get("docker")
        if docker == "ok":
            containers = d.get("containers") or []
            down = unhealthy_containers(containers)
            lines.append(f"Docker:  {len(containers)} container(s)"
                         + (", DOWN — " + ", ".join(c['name'] for c in down) if down else ", all fine"))
        elif docker == "denied":
            lines.append("Docker:  installed, but this user can't query it (not in the docker group)")
        self._lbl_health.setText("\n".join(lines))
        _, severity, _ = health_summary(d)
        colour = {"good": GOOD, "warn": WARN, "bad": BAD}.get(severity, MUTED)
        self._lbl_health.setStyleSheet(f"color: {colour}; font-size: 12px;")

    def _replace_bar(self, attr: str, pct, label: str):
        """Swap an existing QProgressBar in place (update value + colour)."""
        old_bar: QProgressBar = getattr(self, attr)
        old_bar.setValue(int(pct) if pct is not None else 0)
        old_bar.setFormat(label)
        color = usage_color(pct)
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
    def _on_key_change(self, ip, err=None):
        self._timer.stop()
        if confirm_host_key_change(self, err or ip):
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
