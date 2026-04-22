import os
import re
import shlex
import signal
import stat
import subprocess
from pathlib import Path

import paramiko
from PyQt6.QtCore import Qt, QThread, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QBrush, QColor, QCursor, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QButtonGroup, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFileDialog, QFrame, QGroupBox, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMenu, QPlainTextEdit, QProgressBar, QPushButton,
    QRadioButton, QSpinBox, QStackedWidget, QTabWidget, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from manager import (
    KNOWN_HOSTS, HostKeyMismatchError, _make_ssh_client,
    remove_host_from_known_hosts,
)
from schedule_manager import ScheduleManager
from tabs.schedule_ui import SchedulesWidget, build_add_to_list_menu

import json

# ── Table column indices ──────────────────────────────────────────────────────
_C_STATUS   = 0   # status text
_C_NAME     = 1   # file / folder name
_C_ROUTE    = 2   # "sender → receiver"
_C_PROGRESS = 3   # QProgressBar via setCellWidget
_C_SIZE     = 4   # "4.2 GB / 10.9 GB"
_C_SPEED    = 5   # "45.2 MB/s  ·  2m 14s"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _format_size(byte_str: str) -> str:
    """Convert a byte count string (possibly with commas) to human-readable."""
    try:
        b = int(byte_str.replace(",", ""))
    except Exception:
        return byte_str
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def _fmt_eta(raw: str) -> str:
    """Convert rsync HH:MM:SS or MM:SS ETA to a friendlier string."""
    try:
        parts = [int(p) for p in raw.split(":")]
        if len(parts) == 3:
            h, m, s = parts
            if h:   return f"{h}h {m}m"
            if m:   return f"{m}m {s}s"
            return  f"{s}s"
        if len(parts) == 2:
            m, s = parts
            if m:   return f"{m}m {s}s"
            return  f"{s}s"
    except Exception:
        pass
    return raw


def _fmt_speed_eta(speed: str, eta: str) -> str:
    parts = []
    if speed: parts.append(speed)
    if eta:   parts.append(_fmt_eta(eta))
    return "  ·  ".join(parts) if parts else "—"


def _notify(title: str, body: str):
    """Fire a desktop notification — silently ignored if notify-send absent."""
    try:
        subprocess.Popen(
            ["notify-send", "-a", "LanScanMan", title, body],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# SFTP Browser Dialog  (unchanged from original — it's good as-is)
# ─────────────────────────────────────────────────────────────────────────────

class SFTPBrowserDialog(QDialog):
    def __init__(self, ip, username="", start_path="/", parent=None):
        super().__init__(parent)
        self.ip           = ip
        self.username     = username
        self.setWindowTitle(f"Remote Browser: {ip}")
        self.setMinimumSize(660, 580)
        self.selected_path = ""
        self.current_dir   = start_path if (start_path and start_path.startswith("/")) else "/"
        self._setup_ui()
        self._load(self.current_dir)

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        nav = QHBoxLayout()
        self._back_btn = QPushButton("⬅ Back")
        self._back_btn.setFixedWidth(80)
        self._back_btn.clicked.connect(self._go_up)
        self._path_lbl = QLabel(f"📁 {self.current_dir}")
        self._path_lbl.setStyleSheet("font-weight: bold; color: #3498db;")
        nav.addWidget(self._back_btn)
        nav.addWidget(self._path_lbl)
        nav.addStretch()
        layout.addLayout(nav)

        self._list = QTableWidget(0, 4)
        self._list.setHorizontalHeaderLabels(["Name", "Ext", "Size", "Modified"])
        self._list.verticalHeader().setVisible(False)
        self._list.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in (1, 2, 3):
            self._list.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents)
        self._list.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._list.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._list.itemDoubleClicked.connect(self._on_double_click)
        layout.addWidget(self._list)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def _fmt_size(self, n):
        if n is None: return "—"
        for u in ["B","KB","MB","GB","TB"]:
            if n < 1024: return f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} PB"

    def _fmt_mtime(self, t):
        if t is None: return "—"
        from datetime import datetime
        return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")

    def _load(self, path):
        try:
            ssh = _make_ssh_client()
            ssh.connect(self.ip, username=self.username, timeout=5,
                        look_for_keys=True, allow_agent=True)
            sftp = ssh.open_sftp()
            if not path: path = "/"
            try:
                if not stat.S_ISDIR(sftp.stat(path).st_mode):
                    path = os.path.dirname(path)
            except Exception:
                path = "/"
            self.current_dir = path
            self._path_lbl.setText(f"📁 {self.current_dir}")
            files = sorted(sftp.listdir_attr(path),
                           key=lambda x: (not stat.S_ISDIR(x.st_mode),
                                          x.filename.lower()))
            self._list.setRowCount(0)
            for f in files:
                is_dir = stat.S_ISDIR(f.st_mode)
                icon   = "📁" if is_dir else "📄"
                ext    = "—" if is_dir else (os.path.splitext(f.filename)[1].lstrip(".").upper() or "—")
                size   = "—" if is_dir else self._fmt_size(f.st_size)
                mtime  = self._fmt_mtime(f.st_mtime)
                row = self._list.rowCount()
                self._list.insertRow(row)
                items = [
                    QTableWidgetItem(f"{icon} {f.filename}"),
                    QTableWidgetItem(ext),
                    QTableWidgetItem(size),
                    QTableWidgetItem(mtime),
                ]
                color = "#3498db" if is_dir else None
                for col, item in enumerate(items):
                    if color: item.setForeground(QBrush(QColor(color)))
                    elif col in (1, 3): item.setForeground(QBrush(QColor("#9AA4AF")))
                    self._list.setItem(row, col, item)
            sftp.close()
            ssh.close()
            self._back_btn.setEnabled(self.current_dir != "/")
        except paramiko.BadHostKeyException:
            from PyQt6.QtWidgets import QMessageBox
            reply = QMessageBox.question(self, "Host Key Changed",
                f"Host key for {self.ip} has changed. Trust the new one?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                remove_host_from_known_hosts(self.ip)
                self._load(path)
        except Exception as e:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.critical(self, "Connection Error", str(e))

    def _go_up(self):
        self._load(os.path.dirname(self.current_dir.rstrip("/")) or "/")

    def _on_double_click(self, item):
        row     = item.row()
        raw     = self._list.item(row, 0).text()
        name    = raw.split(" ", 1)[1] if " " in raw else raw
        is_dir  = raw.startswith("📁")
        full    = os.path.join(self.current_dir, name)
        if is_dir:
            self._load(full)
        else:
            self.selected_path = full
            self.accept()


# ─────────────────────────────────────────────────────────────────────────────
# Add / Configure Transfer Dialog  (redesigned)
# ─────────────────────────────────────────────────────────────────────────────

class AddTransferDialog(QDialog):
    def __init__(self, online_devices, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configure Transfer")
        self.setMinimumWidth(680)
        self.setSizeGripEnabled(True)
        self.online_devices = online_devices            # list of (alias, ip, username)
        self.ip_to_user     = {ip: u for _, ip, u in online_devices}
        self._setup_ui()

    def _device_options(self):
        return ["Local Machine"] + [f"{a}  ({ip})" for a, ip, _ in self.online_devices]

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(10)
        root.setContentsMargins(12, 12, 12, 12)

        # ── Source ───────────────────────────────────────────────────────────
        src_group = QGroupBox("SOURCE")
        src_group.setStyleSheet(
            "QGroupBox { border: 1px solid #2A313B; border-top: 2px solid #3498db; "
            "border-radius: 6px; margin-top: 6px; }"
            "QGroupBox::title { color: #3498db; font-size: 11px; "
            "letter-spacing: 1px; subcontrol-origin: margin; left: 10px; }")
        src_lay = QVBoxLayout(src_group)
        src_lay.setContentsMargins(10, 10, 10, 10)
        src_lay.setSpacing(7)

        # Device row
        dev_row = QHBoxLayout()
        dev_row.addWidget(QLabel("Device:"))
        self._src_device = QComboBox()
        self._src_device.addItems(self._device_options())
        self._src_device.currentIndexChanged.connect(self._on_src_device_changed)
        dev_row.addWidget(self._src_device, 1)
        src_lay.addLayout(dev_row)

        # Transfer type radios
        type_row = QHBoxLayout()
        type_row.addWidget(QLabel("Type:"))
        self._type_group = QButtonGroup(self)
        for i, label in enumerate(["File", "Folder", "Wildcard  (*.ext)"]):
            rb = QRadioButton(label)
            if i == 0: rb.setChecked(True)
            self._type_group.addButton(rb, i)
            type_row.addWidget(rb)
        type_row.addStretch()
        self._type_group.idToggled.connect(self._on_type_changed)
        src_lay.addLayout(type_row)

        # Path row
        path_row = QHBoxLayout()
        self._src_path = QLineEdit()
        self._src_path.setPlaceholderText("Source path…")
        self._src_browse = QPushButton("Browse…")
        self._src_browse.setMinimumWidth(85)
        self._src_browse.clicked.connect(self._browse_src)
        path_row.addWidget(self._src_path)
        path_row.addWidget(self._src_browse)
        src_lay.addLayout(path_row)

        # Wildcard "in directory" row (hidden by default)
        self._wc_frame = QFrame()
        wc_lay = QHBoxLayout(self._wc_frame)
        wc_lay.setContentsMargins(0, 0, 0, 0)
        wc_lay.addWidget(QLabel("In directory:"))
        self._wc_dir = QLineEdit()
        self._wc_dir.setPlaceholderText("Directory containing files…")
        self._wc_browse = QPushButton("Browse…")
        self._wc_browse.setMinimumWidth(85)
        self._wc_browse.clicked.connect(self._browse_wc_dir)
        wc_lay.addWidget(self._wc_dir)
        wc_lay.addWidget(self._wc_browse)
        self._wc_frame.setVisible(False)
        src_lay.addWidget(self._wc_frame)

        root.addWidget(src_group)

        # ── Arrow ─────────────────────────────────────────────────────────────
        arrow = QLabel("↓  rsync  ↓")
        arrow.setAlignment(Qt.AlignmentFlag.AlignCenter)
        arrow.setStyleSheet("color: #9AA4AF; font-size: 13px; font-weight: bold; margin: 2px 0;")
        root.addWidget(arrow)

        # ── Destination ───────────────────────────────────────────────────────
        dst_group = QGroupBox("DESTINATION")
        dst_group.setStyleSheet(
            "QGroupBox { border: 1px solid #2A313B; border-top: 2px solid #27ae60; "
            "border-radius: 6px; margin-top: 6px; }"
            "QGroupBox::title { color: #27ae60; font-size: 11px; "
            "letter-spacing: 1px; subcontrol-origin: margin; left: 10px; }")
        dst_lay = QVBoxLayout(dst_group)
        dst_lay.setContentsMargins(10, 10, 10, 10)
        dst_lay.setSpacing(7)

        dev_row2 = QHBoxLayout()
        dev_row2.addWidget(QLabel("Device:"))
        self._dst_device = QComboBox()
        self._dst_device.addItems(self._device_options())
        self._dst_device.currentIndexChanged.connect(self._on_dst_device_changed)
        dev_row2.addWidget(self._dst_device, 1)
        dst_lay.addLayout(dev_row2)

        path_row2 = QHBoxLayout()
        self._dst_path = QLineEdit()
        self._dst_path.setPlaceholderText("Destination folder…")
        self._dst_browse = QPushButton("Browse…")
        self._dst_browse.setMinimumWidth(85)
        self._dst_browse.clicked.connect(self._browse_dst)
        path_row2.addWidget(self._dst_path)
        path_row2.addWidget(self._dst_browse)
        dst_lay.addLayout(path_row2)

        root.addWidget(dst_group)

        # ── Options ───────────────────────────────────────────────────────────
        opt_group = QGroupBox("Options")
        opt_group.setStyleSheet(
            "QGroupBox { border: 1px solid #2A313B; border-radius: 6px; "
            "margin-top: 6px; }"
            "QGroupBox::title { color: #9AA4AF; font-size: 11px; "
            "letter-spacing: 1px; subcontrol-origin: margin; left: 10px; }")
        opt_lay = QVBoxLayout(opt_group)
        opt_lay.setContentsMargins(10, 10, 10, 10)
        opt_lay.setSpacing(6)

        # Basic flags
        basic_row = QHBoxLayout()
        self._cb_archive  = QCheckBox("-a  Archive")
        self._cb_compress = QCheckBox("-z  Compress")
        self._cb_compress.setChecked(True)
        self._cb_recursive = QCheckBox("-r  Recursive")
        self._cb_recursive.setVisible(False)
        basic_row.addWidget(self._cb_archive)
        basic_row.addWidget(self._cb_compress)
        basic_row.addWidget(self._cb_recursive)
        basic_row.addStretch()
        opt_lay.addLayout(basic_row)

        # Advanced toggle
        self._adv_btn = QPushButton("▶  Advanced Options")
        self._adv_btn.setStyleSheet(
            "QPushButton { border: none; color: #9AA4AF; text-align: left; "
            "padding: 2px 0; font-size: 11px; }"
            "QPushButton:hover { color: #3498db; }")
        self._adv_btn.setCheckable(True)
        self._adv_btn.toggled.connect(self._toggle_advanced)
        opt_lay.addWidget(self._adv_btn)

        # Advanced frame (hidden by default)
        self._adv_frame = QFrame()
        self._adv_frame.setStyleSheet(
            "QFrame { background: #171B21; border: 1px solid #2A313B; "
            "border-radius: 4px; }")
        adv_lay = QVBoxLayout(self._adv_frame)
        adv_lay.setSpacing(8)

        self._cb_delete   = QCheckBox("--delete    Remove files from destination not present in source")
        self._cb_delete.setStyleSheet("QCheckBox { color: #f39c12; }")
        self._cb_checksum = QCheckBox("--checksum    Verify by content rather than size+timestamp (slower)")
        self._cb_dryrun   = QCheckBox("--dry-run    Preview only — no files will be transferred")
        self._cb_dryrun.setStyleSheet("QCheckBox { color: #3498db; }")

        bw_row = QHBoxLayout()
        self._cb_bwlimit = QCheckBox("--bwlimit")
        self._spin_bw    = QSpinBox()
        self._spin_bw.setRange(1, 10_000)
        self._spin_bw.setValue(10)
        self._spin_bw.setSuffix(" MB/s")
        self._spin_bw.setFixedWidth(110)
        self._spin_bw.setEnabled(False)
        self._cb_bwlimit.toggled.connect(self._spin_bw.setEnabled)
        bw_row.addWidget(self._cb_bwlimit)
        bw_row.addWidget(self._spin_bw)
        bw_row.addStretch()

        delete_warn = QLabel(
            "  ⚠  --delete permanently removes files at the destination. "
            "Verify paths carefully before proceeding.")
        delete_warn.setWordWrap(True)
        delete_warn.setStyleSheet("color: #f39c12; font-size: 11px;")

        adv_lay.addWidget(self._cb_delete)
        adv_lay.addWidget(delete_warn)
        adv_lay.addWidget(self._cb_checksum)
        adv_lay.addWidget(self._cb_dryrun)
        adv_lay.addLayout(bw_row)
        self._adv_frame.setVisible(False)
        opt_lay.addWidget(self._adv_frame)

        root.addWidget(opt_group)

        # ── Agent forwarding warning ───────────────────────────────────────────
        self._agent_warn = QLabel(
            "⚠  Remote → Remote transfer uses SSH agent forwarding (-A).  "
            "The sender host can access your SSH agent while the transfer runs.  "
            "Only use with machines you trust.")
        self._agent_warn.setWordWrap(True)
        self._agent_warn.setStyleSheet(
            "color: #c0392b; background: #1e0808; border: 1px solid #7a1a1a; "
            "border-left: 3px solid #c0392b; border-radius: 4px; "
            "padding: 6px 10px; font-size: 11px;")
        self._agent_warn.setVisible(False)
        root.addWidget(self._agent_warn)

        # ── Buttons ───────────────────────────────────────────────────────────
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self._validate)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)

        # Connect device combos for agent warning
        self._src_device.currentIndexChanged.connect(self._update_agent_warn)
        self._dst_device.currentIndexChanged.connect(self._update_agent_warn)
        self._update_agent_warn()

    # ── Validation ────────────────────────────────────────────────────────────

    def _validate(self):
        btn_id = self._type_group.checkedId()

        # Source path check
        if btn_id == 2:   # wildcard
            src = self._wc_dir.text().strip()
            src_label = "Wildcard directory"
        else:
            src = self._src_path.text().strip()
            src_label = "Source path"

        if not src:
            QMessageBox.warning(self, "Missing Source",
                f"{src_label} is required.")
            return

        # Destination path check
        if not self._dst_path.text().strip():
            QMessageBox.warning(self, "Missing Destination",
                "Please enter a destination folder path.")
            return

        self.accept()

    # ── Callbacks ─────────────────────────────────────────────────────────────

    def _on_type_changed(self, btn_id, checked):
        if not checked: return
        is_wc     = (btn_id == 2)
        is_folder = (btn_id == 1)
        self._wc_frame.setVisible(is_wc)
        self._cb_recursive.setVisible(is_folder or is_wc)
        self._cb_recursive.setChecked(is_folder or is_wc)
        if is_wc:
            self._src_path.setPlaceholderText("Pattern  (e.g. *.fastq)")
        elif is_folder:
            self._src_path.setPlaceholderText("Source folder…")
        else:
            self._src_path.setPlaceholderText("Source file…")

    def _toggle_advanced(self, checked: bool):
        self._adv_frame.setVisible(checked)
        self._adv_btn.setText(
            "▼  Advanced Options" if checked else "▶  Advanced Options")
        if checked:
            # Record the current size before expanding so we can restore it exactly
            self._pre_expand_size = self.size()
            self.adjustSize()
        else:
            # Restore the exact size from before the panel opened
            if hasattr(self, "_pre_expand_size"):
                self.resize(self._pre_expand_size)
            else:
                self.adjustSize()

    def _update_agent_warn(self):
        s = self._extract_ip(self._src_device.currentText())
        d = self._extract_ip(self._dst_device.currentText())
        self._agent_warn.setVisible(s != "127.0.0.1" and d != "127.0.0.1")

    def _on_src_device_changed(self):
        self._update_agent_warn()

    def _on_dst_device_changed(self):
        self._update_agent_warn()

    def _extract_ip(self, text):
        if text == "Local Machine": return "127.0.0.1"
        m = re.search(r"\(([^)]+)\)", text)
        return m.group(1) if m else "127.0.0.1"

    def _browse(self, target_line, browse_type, device_combo):
        machine = device_combo.currentText()
        if machine == "Local Machine":
            if browse_type == "file":
                path, _ = QFileDialog.getOpenFileName(self, "Select File")
            else:
                path = QFileDialog.getExistingDirectory(self, "Select Folder")
            if path: target_line.setText(path)
        else:
            ip      = self._extract_ip(machine)
            current = target_line.text()
            browser = SFTPBrowserDialog(
                ip, username=self.ip_to_user.get(ip, ""),
                start_path=current, parent=self)
            if browser.exec():
                path = browser.selected_path or browser.current_dir
                target_line.setText(path)

    def _browse_src(self):
        btn_id = self._type_group.checkedId()
        btype  = "folder" if btn_id == 1 else "file"
        self._browse(self._src_path, btype, self._src_device)

    def _browse_wc_dir(self):
        self._browse(self._wc_dir, "folder", self._src_device)

    def _browse_dst(self):
        self._browse(self._dst_path, "folder", self._dst_device)

    # ── Data extraction ───────────────────────────────────────────────────────

    def get_transfer_data(self) -> dict:
        def fmt(ip, path, user):
            if ip == "127.0.0.1": return path
            return f"{user}@{ip}:{path}" if user else f"{ip}:{path}"

        btn_id      = self._type_group.checkedId()
        sender_ip   = self._extract_ip(self._src_device.currentText())
        receiver_ip = self._extract_ip(self._dst_device.currentText())
        sender_user = self.ip_to_user.get(sender_ip, "")
        recv_user   = self.ip_to_user.get(receiver_ip, "")

        if btn_id == 2:   # wildcard
            src_path = os.path.join(self._wc_dir.text(), self._src_path.text())
        else:
            src_path = self._src_path.text()

        dst_path = self._dst_path.text()

        args = []
        if self._cb_archive.isChecked():   args.append("-a")
        if self._cb_compress.isChecked():  args.append("-z")
        # Check isChecked() only — NOT isVisible(). isVisible() returns False
        # once the dialog closes, so by the time RsyncWorker reads args the
        # recursive flag would silently be dropped even if the user had it ticked.
        if self._cb_recursive.isChecked(): args.append("-r")
        if self._cb_delete.isChecked():    args.append("--delete")
        if self._cb_checksum.isChecked():  args.append("--checksum")
        if self._cb_dryrun.isChecked():    args.append("--dry-run")
        if self._cb_bwlimit.isChecked():
            args.append(f"--bwlimit={self._spin_bw.value() * 1024}")

        return {
            "name":         os.path.basename(src_path.rstrip("/")) or src_path,
            "sender_ip":    sender_ip,
            "sender_user":  sender_user,
            "receiver_ip":  receiver_ip,
            "receiver_user": recv_user,
            "src_path":     src_path,
            "dst_path":     dst_path,
            "full_source":  fmt(sender_ip,   src_path, sender_user),
            "full_dest":    fmt(receiver_ip, dst_path, recv_user),
            "args":         args,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Transfer Tab
# ─────────────────────────────────────────────────────────────────────────────

class TransferTab(QWidget):
    def __init__(self, net_manager, parent=None,
                 schedule_manager: "ScheduleManager | None" = None,
                 schedule_integrity_failed: bool = False):
        super().__init__(parent)
        self.net_manager    = net_manager
        self.parent_window  = parent
        self.schedule_manager = schedule_manager
        self._schedule_integrity_failed = schedule_integrity_failed
        self.active_workers: dict[int, "RsyncWorker"] = {}
        self._progress_bars: dict[int, QProgressBar]  = {}
        self._output_bufs:   dict[int, list[str]]     = {}  # tid → rsync stdout lines
        self._next_id       = 0
        self._session_completed = 0
        self._session_bytes     = 0
        self.history_file = Path.home() / ".config" / "LanScanMan" / "transfer_history.json"
        self._setup_ui()
        self._load_history()

    def _new_id(self) -> int:
        self._next_id += 1
        return self._next_id

    # ── Layout ────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setSpacing(6)
        outer.setContentsMargins(0, 0, 0, 0)

        # ── Toggle bar: Queue / Schedules ─────────────────────────────────────
        toggle_bar = QHBoxLayout()
        toggle_bar.setContentsMargins(6, 4, 6, 0)
        toggle_bar.setSpacing(0)

        self._toggle_queue = QPushButton("Queue")
        self._toggle_queue.setCheckable(True)
        self._toggle_queue.setChecked(True)
        self._toggle_schedules = QPushButton("Schedules")
        self._toggle_schedules.setCheckable(True)

        self._toggle_group = QButtonGroup(self)
        self._toggle_group.setExclusive(True)
        self._toggle_group.addButton(self._toggle_queue, 0)
        self._toggle_group.addButton(self._toggle_schedules, 1)
        self._toggle_group.idClicked.connect(self._on_toggle_clicked)

        for b in (self._toggle_queue, self._toggle_schedules):
            b.setStyleSheet("""
                QPushButton {
                    background: #20262E; color: #9AA4AF; border: 1px solid #2A313B;
                    padding: 6px 16px; font-size: 12px;
                }
                QPushButton:checked {
                    background: #2A313B; color: #E6E6E6;
                    border-bottom: 2px solid #3498db;
                }
                QPushButton:hover:!checked { color: #E6E6E6; }
            """)

        toggle_bar.addWidget(self._toggle_queue)
        toggle_bar.addWidget(self._toggle_schedules)
        toggle_bar.addStretch()
        outer.addLayout(toggle_bar)

        # ── Stacked widget: Queue section | Schedules section ────────────────
        self._stack = QStackedWidget()
        self._queue_widget = self._build_queue_widget()
        self._stack.addWidget(self._queue_widget)

        if self.schedule_manager is not None:
            self._schedules_widget = SchedulesWidget(
                self.schedule_manager,
                integrity_failed=self._schedule_integrity_failed,
                parent=self,
            )
            self._schedules_widget.changed.connect(self._on_schedules_changed)
            self._stack.addWidget(self._schedules_widget)
        else:
            self._schedules_widget = None
            # Placeholder so the toggle still works
            placeholder = QLabel(
                "Schedules are unavailable — schedule manager failed to initialise.")
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            placeholder.setStyleSheet("color: #9AA4AF; padding: 40px;")
            self._stack.addWidget(placeholder)

        outer.addWidget(self._stack)

        QShortcut(QKeySequence("Ctrl+N"), self).activated.connect(self._open_dialog)

    def _build_queue_widget(self) -> QWidget:
        """Build the existing Queue UI inside a container widget."""
        qw = QWidget()
        root = QVBoxLayout(qw)
        root.setSpacing(6)

        # Controls bar
        bar = QHBoxLayout()
        self._add_btn = QPushButton("Add Transfer")
        self._add_btn.clicked.connect(self._open_dialog)
        self._clear_btn = QPushButton("Clear Finished")
        self._clear_btn.clicked.connect(self._clear_finished)
        self._summary_lbl = QLabel("")
        self._summary_lbl.setStyleSheet("color: #9AA4AF; font-size: 11px;")
        bar.addWidget(self._add_btn)
        bar.addWidget(self._clear_btn)
        bar.addStretch()
        bar.addWidget(self._summary_lbl)
        root.addLayout(bar)

        # Table
        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels([
            "Status", "Name", "Route", "Progress", "Size", "Speed / ETA",
        ])
        self._table.verticalHeader().setDefaultSectionSize(46)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        self._table.currentItemChanged.connect(self._on_selection_changed)

        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hdr.setSectionResizeMode(_C_NAME,     QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(_C_PROGRESS, QHeaderView.ResizeMode.Fixed)
        hdr.resizeSection(_C_STATUS,   150)
        hdr.resizeSection(_C_ROUTE,    220)
        hdr.resizeSection(_C_PROGRESS, 200)
        hdr.resizeSection(_C_SIZE,     180)
        hdr.resizeSection(_C_SPEED,    200)

        root.addWidget(self._table)

        # ── Detail panel — tabbed output + error view ─────────────────────────
        self._detail = QFrame()
        self._detail.setFixedHeight(130)
        self._detail.setStyleSheet(
            "QFrame { background: #1B1F24; border-top: 1px solid #2A313B; }")
        dl = QVBoxLayout(self._detail)
        dl.setContentsMargins(10, 6, 10, 6)
        dl.setSpacing(3)

        # Src / Dst labels
        self._det_src = QLabel("—")
        self._det_dst = QLabel("—")
        for lbl in (self._det_src, self._det_dst):
            lbl.setStyleSheet("color: #9AA4AF; font-size: 11px;")
            lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        dl.addWidget(self._det_src)
        dl.addWidget(self._det_dst)

        # Tabbed area: Output (rsync file list) | Errors (stderr)
        _tab_style = """
            QTabWidget::pane {
                border: none;
                background: transparent;
            }
            QTabBar::tab {
                background: #20262E;
                color: #9AA4AF;
                padding: 2px 10px;
                font-size: 10px;
                border: none;
                border-top-left-radius: 3px;
                border-top-right-radius: 3px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #2A313B;
                color: #E6E6E6;
            }
        """
        _pte_style = lambda border_color: f"""
            QPlainTextEdit {{
                color: #E6E6E6;
                font-size: 11px;
                font-family: monospace;
                background: transparent;
                border: none;
                border-left: 2px solid {border_color};
                padding-left: 6px;
            }}
            QScrollBar:vertical {{
                background: #1B1F24; width: 6px; border-radius: 3px;
            }}
            QScrollBar::handle:vertical {{
                background: #3A4452; border-radius: 3px; min-height: 16px;
            }}
            QScrollBar::handle:vertical:hover {{ background: #3498db; }}
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {{ height: 0px; }}
        """

        self._det_tabs = QTabWidget()
        self._det_tabs.setStyleSheet(_tab_style)

        self._det_out = QPlainTextEdit()
        self._det_out.setReadOnly(True)
        self._det_out.setStyleSheet(_pte_style("#3498db"))
        self._det_out.setPlaceholderText("rsync output will appear here during transfer…")

        self._det_err = QPlainTextEdit()
        self._det_err.setReadOnly(True)
        self._det_err.setStyleSheet(_pte_style("#c0392b"))
        self._det_err.setPlaceholderText("Errors will appear here if the transfer fails…")

        self._det_tabs.addTab(self._det_out, "Output")
        self._det_tabs.addTab(self._det_err, "Errors")
        dl.addWidget(self._det_tabs)
        root.addWidget(self._detail)

        return qw

    # ── Toggle / schedules helpers ───────────────────────────────────────────

    def _on_toggle_clicked(self, idx: int):
        self._stack.setCurrentIndex(idx)

    def _on_schedules_changed(self):
        """Persist schedule changes immediately."""
        if self.schedule_manager is not None:
            try:
                self.schedule_manager.save()
            except Exception as e:
                from log import log
                log.exception(f"failed to save schedules: {e}")

    def refresh_schedules_view(self):
        """Called externally (e.g. after a timer-driven run updates state)."""
        if self._schedules_widget is not None:
            self._schedules_widget.refresh()

    def run_schedule_by_id(self, schedule_id: str, skip_confirm_dialog: bool = False):
        """Called by the main window timer when a schedule is due."""
        if self._schedules_widget is None or self.schedule_manager is None:
            return
        sched = self.schedule_manager.find(schedule_id)
        if sched is None:
            return
        self._schedules_widget.run_schedule(
            sched,
            skip_confirm_dialog=skip_confirm_dialog,
            triggered_by_timer=True,
        )

    # ── Detail panel ─────────────────────────────────────────────────────────

    def _on_selection_changed(self, current, _prev):
        if current is None:
            self._det_src.setText("—")
            self._det_dst.setText("—")
            self._det_out.setPlainText("")
            self._det_err.setPlainText("")
            return
        row  = current.row()
        s_item = self._table.item(row, _C_STATUS)
        data   = s_item.data(Qt.ItemDataRole.UserRole)
        err    = s_item.data(Qt.ItemDataRole.UserRole + 1)
        tid    = s_item.data(Qt.ItemDataRole.UserRole + 2)

        if data:
            self._det_src.setText(f"Src:  {data.get('full_source', '—')}")
            self._det_dst.setText(f"Dst:  {data.get('full_dest',   '—')}")
        else:
            self._det_src.setText("—")
            self._det_dst.setText("—")

        # Output tab — show buffered rsync stdout for this transfer
        lines = self._output_bufs.get(tid, [])
        self._det_out.setPlainText("\n".join(lines))
        if lines:
            # Scroll to bottom to show most recent output
            self._det_out.moveCursor(
                self._det_out.textCursor().MoveOperation.End)

        # Errors tab
        self._det_err.setPlainText(err or "")
        if err:
            self._det_err.moveCursor(
                self._det_err.textCursor().MoveOperation.Start)
            # Switch to Errors tab automatically when there's an error
            self._det_tabs.setCurrentIndex(1)

    # ── History ───────────────────────────────────────────────────────────────

    def _save_history(self):
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        rows = []
        for r in range(self._table.rowCount()):
            s = self._table.item(r, _C_STATUS)
            if s is None: continue
            rows.append({
                "status":   s.text(),
                "name":     self._table.item(r, _C_NAME).text()  if self._table.item(r, _C_NAME)  else "",
                "route":    self._table.item(r, _C_ROUTE).text() if self._table.item(r, _C_ROUTE) else "",
                "size":     self._table.item(r, _C_SIZE).text()  if self._table.item(r, _C_SIZE)  else "",
                "raw_data": s.data(Qt.ItemDataRole.UserRole),
            })
        with open(self.history_file, "w") as f:
            json.dump(rows, f, indent=4)

    def _load_history(self):
        if not self.history_file.exists(): return
        try:
            with open(self.history_file) as f:
                history = json.load(f)
            for entry in history:
                status = entry.get("status", "Unknown")
                if status not in ("Completed", "Failed", "Cancelled"):
                    status = "Interrupted"
                data = entry.get("raw_data") or {}
                tid  = self._new_id()
                self._add_row(
                    status=status,
                    name=entry.get("name", "—"),
                    route=entry.get("route", "—"),
                    size=entry.get("size", "—"),
                    raw_data=data,
                    transfer_id=tid,
                )
                row = self._table.rowCount() - 1
                self._apply_status_colour(row, status)
        except Exception as e:
            print(f"History load error: {e}")

    # ── Row management ────────────────────────────────────────────────────────

    def _find_row(self, tid: int) -> int:
        for r in range(self._table.rowCount()):
            item = self._table.item(r, _C_STATUS)
            if item and item.data(Qt.ItemDataRole.UserRole + 2) == tid:
                return r
        return -1

    def _get_alias(self, ip: str) -> str:
        for profile in self.net_manager.profiles.values():
            if profile.get("last_ip") == ip:
                alias = profile.get("alias", "").strip()
                if alias: return alias
        return ip

    def _make_route(self, data: dict) -> str:
        sip = data.get("sender_ip", "127.0.0.1")
        rip = data.get("receiver_ip", "127.0.0.1")
        s   = "Local" if sip == "127.0.0.1" else self._get_alias(sip)
        r   = "Local" if rip == "127.0.0.1" else self._get_alias(rip)
        return f"{s}  →  {r}"

    def _make_progress_bar(self, pct: int = 0, is_dry: bool = False) -> QProgressBar:
        bar   = QProgressBar()
        color = "#3498db" if not is_dry else "#f39c12"
        bar.setRange(0, 100)
        bar.setValue(pct)
        bar.setFormat("Queued" if pct == 0 else f"{pct}%")
        bar.setTextVisible(True)
        bar.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid #2A313B; border-radius: 4px;
                background: #0d1117; color: #E6E6E6; text-align: center;
            }}
            QProgressBar::chunk {{ background: {color}; border-radius: 3px; }}
        """)
        return bar

    def _add_row(self, status: str, name: str, route: str, size: str,
                 raw_data: dict | None = None, transfer_id: int | None = None,
                 speed: str = "—"):
        row = self._table.rowCount()
        self._table.insertRow(row)

        s_item = QTableWidgetItem(status)
        if raw_data:
            s_item.setData(Qt.ItemDataRole.UserRole, raw_data)
        if transfer_id is not None:
            s_item.setData(Qt.ItemDataRole.UserRole + 2, transfer_id)

        is_dry = "--dry-run" in (raw_data or {}).get("args", [])
        pct    = 100 if status == "Completed" else 0

        bar = self._make_progress_bar(pct, is_dry)
        if transfer_id is not None:
            self._progress_bars[transfer_id] = bar

        self._table.setItem(row, _C_STATUS,   s_item)
        self._table.setItem(row, _C_NAME,     QTableWidgetItem(name))
        self._table.setItem(row, _C_ROUTE,    QTableWidgetItem(route))
        self._table.setItem(row, _C_PROGRESS, QTableWidgetItem(""))
        self._table.setCellWidget(row, _C_PROGRESS, bar)
        self._table.setItem(row, _C_SIZE,     QTableWidgetItem(size))
        self._table.setItem(row, _C_SPEED,    QTableWidgetItem(speed))

        # Colour the route column
        route_item = self._table.item(row, _C_ROUTE)
        route_item.setForeground(QBrush(QColor("#9AA4AF")))

    def _apply_status_colour(self, row: int, status: str):
        item = self._table.item(row, _C_STATUS)
        if status == "Completed":
            item.setForeground(QBrush(QColor("#27ae60")))
        elif status.startswith("Failed") or status == "Interrupted":
            item.setForeground(QBrush(QColor("#c0392b")))
        elif status in ("Cancelled",):
            item.setForeground(QBrush(QColor("#9AA4AF")))
        else:
            item.setForeground(QBrush(QColor("#E6E6E6")))

    def _update_session_summary(self):
        if self._session_completed == 0:
            self._summary_lbl.setText("")
            return
        size_str = _format_size(str(self._session_bytes))
        self._summary_lbl.setText(
            f"Session:  {self._session_completed} completed  ·  {size_str} transferred")

    # ── Dialog + launch ───────────────────────────────────────────────────────

    def _open_dialog(self):
        scanner_tab = self.parent_window.scanner_page
        devices = []
        for r in range(scanner_tab.table.rowCount()):
            ip_item    = scanner_tab.table.item(r, 0)
            alias_item = scanner_tab.table.item(r, 1)
            mac_item   = scanner_tab.table.item(r, 4)
            if not ip_item: continue
            ip    = ip_item.text()
            mac   = mac_item.text() if mac_item else ""
            alias = alias_item.text().strip() if alias_item else ""
            # Strip any "+N" suffix that _username_display adds to the table cell
            alias = alias.split("  +")[0].strip() if alias else ""
            if not alias or alias == "—":
                continue

            profile     = self.net_manager.get_profile(mac, ip)
            primary     = profile.get("username", "").strip()
            extra_users = profile.get("extra_users", [])

            # Primary user — label is plain alias when no extras, qualified when there are
            if primary:
                label = f"{alias} — {primary}" if extra_users else alias
                devices.append((label, ip, primary))

            # Secondary users — always qualified with the username
            for user in extra_users:
                devices.append((f"{alias} — {user}", ip, user))

        dlg = AddTransferDialog(devices, self)
        if dlg.exec():
            self._process_new(dlg.get_transfer_data())

    def _process_new(self, data: dict):
        tid   = self._new_id()
        route = self._make_route(data)
        is_dry = "--dry-run" in data.get("args", [])
        status = "Dry Run — Queued" if is_dry else "Queued"

        self._add_row(
            status=status,
            name=data["name"],
            route=route,
            size="Calculating…",
            raw_data=data,
            transfer_id=tid,
        )

        worker = RsyncWorker(tid, data)
        worker.progress_update.connect(self._on_progress)
        worker.output_line.connect(self._on_output_line)
        worker.finished.connect(self._on_finished)
        self._output_bufs[tid] = []
        self.active_workers[tid] = worker
        worker.start()
        self._save_history()

    # ── Worker callbacks ──────────────────────────────────────────────────────

    @pyqtSlot(int, str)
    def _on_output_line(self, tid: int, line: str):
        """Buffer a stdout line from rsync and append to output panel if selected."""
        buf = self._output_bufs.get(tid)
        if buf is not None:
            buf.append(line)
        # Live-append to panel if this transfer is the currently selected row
        row = self._find_row(tid)
        if row != -1 and row == self._table.currentRow():
            self._det_out.appendPlainText(line)

    @pyqtSlot(int, str, str, str, str, str)
    def _on_progress(self, tid, status, percent, size, speed, eta):
        row = self._find_row(tid)
        if row == -1: return

        self._table.item(row, _C_STATUS).setText(status)
        self._table.item(row, _C_SIZE).setText(size)
        self._table.item(row, _C_SPEED).setText(_fmt_speed_eta(speed, eta))

        bar = self._progress_bars.get(tid)
        if bar:
            try:
                pv = int(percent.replace("%", ""))
                bar.setValue(pv)
                bar.setFormat(f"{pv}%")
            except ValueError:
                pass

    @pyqtSlot(int, str, str, int)
    def _on_finished(self, tid: int, final_status: str, error: str, total_bytes: int):
        row = self._find_row(tid)
        if row != -1:
            s_item = self._table.item(row, _C_STATUS)
            if error:
                short = error.splitlines()[0][:70]
                s_item.setText(f"Failed: {short}")
                s_item.setData(Qt.ItemDataRole.UserRole + 1, error)
                s_item.setForeground(QBrush(QColor("#c0392b")))
                _notify("Transfer Failed", self._table.item(row, _C_NAME).text())
                # Update detail panel if this row is selected
                self._det_err.setPlainText(error)
                # Scroll to the top so the first line (the most useful one)
                # is visible rather than the end of a long stderr dump
                self._det_err.moveCursor(self._det_err.textCursor().MoveOperation.Start)
            else:
                data   = s_item.data(Qt.ItemDataRole.UserRole) or {}
                is_dry = "--dry-run" in data.get("args", [])
                s_item.setText("Dry Run — Done" if is_dry else final_status)
                self._apply_status_colour(row, final_status)
                bar = self._progress_bars.get(tid)
                if bar:
                    bar.setValue(100)
                    bar.setFormat("Done (dry)" if is_dry else "100%")
                if final_status == "Completed":
                    # Clean up size display "x / x" → just total
                    size_txt = self._table.item(row, _C_SIZE).text()
                    if "/" in size_txt:
                        self._table.item(row, _C_SIZE).setText(size_txt.split("/")[-1].strip())
                    self._table.item(row, _C_SPEED).setText("—")
                    if not is_dry:
                        _notify("Transfer Complete",
                                self._table.item(row, _C_NAME).text())

            # Session stats
            if final_status == "Completed":
                self._session_completed += 1
                self._session_bytes     += total_bytes
                self._update_session_summary()

        worker = self.active_workers.pop(tid, None)
        if worker:
            worker.wait()
        self._save_history()

    # ── Context menu ──────────────────────────────────────────────────────────

    def _show_context_menu(self, pos):
        item = self._table.itemAt(pos)
        if not item: return
        row    = item.row()
        status = self._table.item(row, _C_STATUS).text()
        active = "Transferring" in status or "Queued" in status or "Checking" in status

        menu = QMenu(self)
        act_cancel  = menu.addAction("Cancel Transfer")
        act_cancel.setEnabled(active)
        act_cancel.triggered.connect(lambda: self._cancel(row))

        act_restart = menu.addAction("Restart Transfer")
        act_restart.setEnabled(not active)
        act_restart.triggered.connect(lambda: self._restart(row))

        # Add to schedule list submenu — only if schedule manager is present
        if self.schedule_manager is not None:
            menu.addSeparator()
            data = self._table.item(row, _C_STATUS).data(Qt.ItemDataRole.UserRole)
            if isinstance(data, dict):
                submenu = build_add_to_list_menu(
                    parent=self,
                    manager=self.schedule_manager,
                    transfer_data=data,
                    on_changed=self._on_schedules_changed_from_queue,
                )
                menu.addMenu(submenu)

        menu.addSeparator()
        act_delete = menu.addAction("Delete Row")
        act_delete.setEnabled(not active)
        act_delete.triggered.connect(lambda: self._delete_row(row))

        menu.exec(QCursor.pos())

    def _on_schedules_changed_from_queue(self):
        """Called when a transfer is added to a schedule via the queue context menu."""
        self._on_schedules_changed()
        if self._schedules_widget is not None:
            self._schedules_widget.refresh()

    def _cancel(self, row: int):
        tid = self._table.item(row, _C_STATUS).data(Qt.ItemDataRole.UserRole + 2)
        worker = self.active_workers.get(tid)
        if worker:
            worker.stop()
            self._table.item(row, _C_STATUS).setText("Cancelling…")

    def _restart(self, row: int):
        s_item = self._table.item(row, _C_STATUS)
        data   = s_item.data(Qt.ItemDataRole.UserRole)
        tid    = s_item.data(Qt.ItemDataRole.UserRole + 2)
        if not data or not tid: return
        s_item.setText("Queued")
        s_item.setForeground(QBrush(QColor("#E6E6E6")))
        s_item.setData(Qt.ItemDataRole.UserRole + 1, None)
        self._det_err.setPlainText("")
        self._det_out.setPlainText("")
        self._output_bufs[tid] = []   # clear previous run's output
        bar = self._progress_bars.get(tid)
        if bar:
            bar.setValue(0)
            bar.setFormat("Queued")
        worker = RsyncWorker(tid, data)
        worker.progress_update.connect(self._on_progress)
        worker.output_line.connect(self._on_output_line)
        worker.finished.connect(self._on_finished)
        self.active_workers[tid] = worker
        worker.start()

    def _delete_row(self, row: int):
        tid = self._table.item(row, _C_STATUS).data(Qt.ItemDataRole.UserRole + 2)
        if tid in self.active_workers: return
        self._progress_bars.pop(tid, None)
        self._output_bufs.pop(tid, None)
        self._table.removeRow(row)
        self._save_history()

    def _clear_finished(self):
        for r in range(self._table.rowCount() - 1, -1, -1):
            s = self._table.item(r, _C_STATUS)
            if s is None: continue
            txt = s.text()
            if txt in ("Completed", "Cancelled", "Interrupted") or \
               txt.startswith("Failed") or txt.startswith("Dry Run"):
                tid = s.data(Qt.ItemDataRole.UserRole + 2)
                self._progress_bars.pop(tid, None)
                self._output_bufs.pop(tid, None)
                self._table.removeRow(r)
        self._save_history()


# ─────────────────────────────────────────────────────────────────────────────
# Rsync Worker Thread
# ─────────────────────────────────────────────────────────────────────────────

class RsyncWorker(QThread):
    progress_update = pyqtSignal(int, str, str, str, str, str)
    output_line     = pyqtSignal(int, str)              # tid, line of rsync stdout
    finished        = pyqtSignal(int, str, str, int)    # tid, status, error, total_bytes

    def __init__(self, tid: int, data: dict, parent=None):
        super().__init__()
        self.tid     = tid
        self.data    = data
        self.process = None

    def run(self):
        sip  = self.data.get("sender_ip",   "127.0.0.1")
        rip  = self.data.get("receiver_ip", "127.0.0.1")
        suser = self.data.get("sender_user", "")
        args  = list(self.data.get("args", []))   # copy so we can mutate
        is_dry = "--dry-run" in args
        total_bytes = 0

        KNOWN_HOSTS_PATH = os.path.expanduser("~/.config/LanScanMan/known_hosts")

        # ── Preflight: source path exists + detect if it's a directory ────────
        # If the source is a directory and -r / -a aren't already set we add -r
        # automatically. Without it rsync silently transfers nothing and exits 0,
        # which looks like an instant "Completed" with no files moved.
        src = self.data.get("src_path", "")
        if "*" not in src and "?" not in src:
            if sip == "127.0.0.1":
                if not os.path.exists(src):
                    self.finished.emit(self.tid, "Failed",
                        f"Source path does not exist: {src}", 0)
                    return
            else:
                try:
                    ssh = _make_ssh_client()
                    ssh.connect(sip, username=suser, timeout=8,
                                look_for_keys=True, allow_agent=True)
                    sftp = ssh.open_sftp()
                    check      = src.rstrip("/") or "/"
                    sftp.stat(check)
                    sftp.close()
                    ssh.close()
                except FileNotFoundError:
                    self.finished.emit(self.tid, "Failed",
                        f"Source path does not exist on {sip}: {src}", 0)
                    return
                except Exception as e:
                    self.finished.emit(self.tid, "Failed",
                        f"Could not verify source path: {e}", 0)
                    return

        # ── Build rsync command ───────────────────────────────────────────────
        # NOTE: we intentionally do NOT pre-test sender→receiver SSH connectivity
        # for remote-to-remote transfers. The actual transfer uses agent forwarding
        # (-A), so the sender authenticates to the receiver using the LOCAL
        # machine's key tunnelled through the agent — not the sender's own keys.
        # A preflight test run from here (without agent forwarding) would test the
        # wrong auth path and block transfers that would actually succeed.
        # If the real connection fails, rsync's stderr is captured and shown.
        try:
            flag_str    = " ".join(args)
            # progress2 = overall transfer progress (bytes/speed/eta)
            # name      = print each filename as it's transferred
            # Without 'name', rsync suppresses per-file output entirely
            rsync_flags = f"--info=progress2,name {flag_str}"
            src_q       = shlex.quote(self.data["full_source"])
            dst_q       = shlex.quote(self.data["full_dest"])
            rsync_cmd   = f"rsync {rsync_flags} {src_q} {dst_q}"

            if sip != "127.0.0.1" and rip != "127.0.0.1":
                # rsync runs ON the sender via SSH with agent forwarding.
                # The source must be the bare local path — NOT user@host:/path —
                # because relative to the sender machine the source is local.
                # full_dest (user@receiver:/path) is correct as-is.
                src_q_remote = shlex.quote(self.data["src_path"])
                rsync_cmd    = (f"rsync {rsync_flags} "
                                f"{src_q_remote} {dst_q}")
                ssh_target   = f"{shlex.quote(suser)}@{shlex.quote(sip)}"
                cmd = ["ssh", "-A",
                       "-o", "StrictHostKeyChecking=accept-new",
                       "-o", f"UserKnownHostsFile={KNOWN_HOSTS_PATH}",
                       ssh_target, f"bash -lc {shlex.quote(rsync_cmd)}"]
            else:
                # Local rsync (one side may be remote via SSH).
                # Must pass --rsh so rsync uses LanScanMan's known_hosts and
                # accepts new/link-local host keys rather than hitting the system
                # known_hosts with StrictHostKeyChecking=yes and failing.
                # shlex.quote on the path handles home directories with spaces.
                ssh_cmd = (
                    f"ssh -o StrictHostKeyChecking=accept-new "
                    f"-o UserKnownHostsFile={shlex.quote(KNOWN_HOSTS_PATH)}"
                )
                cmd = ["rsync", "--info=progress2,name", f"--rsh={ssh_cmd}"] + args + [
                    self.data["full_source"], self.data["full_dest"]]

            status_label = "Dry Run…" if is_dry else "Transferring…"
            self.progress_update.emit(self.tid, status_label, "0%", "—", "—", "—")

            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, preexec_fn=os.setsid,
            )

            # Emit the command as the first output line so the user can see
            # exactly what was run — useful for debugging and verification
            self.output_line.emit(self.tid, "$ " + " ".join(cmd))
            self.output_line.emit(self.tid, "")

            # Drain stderr in a background thread so it never fills its pipe
            # buffer and deadlocks rsync. This is the classic subprocess gotcha:
            # if nobody reads stderr while stdout is being consumed, the OS pipe
            # buffer (~64 KB) fills up, rsync blocks trying to write, stdout
            # blocks waiting for rsync to emit progress, and the whole process
            # hangs permanently — especially visible on large transfers.
            import threading
            stderr_lines: list[str] = []
            def _drain_stderr():
                for line in self.process.stderr:
                    stderr_lines.append(line)
            stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
            stderr_thread.start()

            # Regex: bytes  percentage  speed  eta
            prog_re = re.compile(
                r"([\d,]+)\s+(\d+)%\s+([0-9.]+[a-zA-Z]+/s)\s+(\d+:\d+:\d+|\d+:\d+)")

            # rsync --info=progress2 uses \r to overwrite the progress line
            # in a terminal. Reading line-by-line (which splits on \n only)
            # blocks until rsync finishes, giving us zero live updates.
            # Instead we read in small chunks and split on both \r and \n.
            buf = ""
            while True:
                chunk = self.process.stdout.read(256)
                if not chunk:
                    break
                buf += chunk
                parts = re.split(r"[\r\n]", buf)
                buf   = parts[-1]
                for line in parts[:-1]:
                    m = prog_re.search(line)
                    if m:
                        size_raw, pct, speed, eta = m.groups()
                        pct_int     = int(pct)
                        transferred = int(size_raw.replace(",", ""))
                        total_bytes = transferred

                        if pct_int > 0:
                            total_est   = int(transferred / (pct_int / 100))
                            size_disp   = f"{_format_size(size_raw)} / {_format_size(str(total_est))}"
                            total_bytes = total_est
                        else:
                            size_disp = _format_size(size_raw)

                        self.progress_update.emit(
                            self.tid, status_label, f"{pct}%",
                            size_disp, speed, eta)
                    elif line.strip():
                        # Non-progress lines are file names being transferred,
                        # summaries, or dry-run previews — emit them for display
                        self.output_line.emit(self.tid, line.rstrip())

            # Process any remaining buffer content
            if buf:
                m = prog_re.search(buf)
                if m:
                    size_raw, pct, speed, eta = m.groups()
                    pct_int     = int(pct)
                    transferred = int(size_raw.replace(",", ""))
                    if pct_int > 0:
                        total_est   = int(transferred / (pct_int / 100))
                        size_disp   = f"{_format_size(size_raw)} / {_format_size(str(total_est))}"
                        total_bytes = total_est
                    else:
                        size_disp = _format_size(size_raw)

            # Wait for both stderr drain and process to finish
            stderr_thread.join()
            self.process.wait()
            err = "".join(stderr_lines).strip()

            if self.process.returncode == 0:
                self.finished.emit(self.tid, "Completed", "", total_bytes)
            elif self.process.returncode == 20:
                # rsync exit code 20 = cancelled by signal
                self.finished.emit(self.tid, "Cancelled", "", 0)
            else:
                self.finished.emit(self.tid, "Failed", err, 0)

        except Exception as e:
            self.finished.emit(self.tid, "Failed", str(e), 0)

    def stop(self):
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            except Exception:
                try:
                    self.process.terminate()
                except Exception:
                    pass