"""Dialogs for the File Transfers tab: add a transfer, browse a remote host over SFTP."""

import os
import re
import stat

import paramiko
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QBrush, QColor
from PyQt6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from lanscanman.services.ssh import make_ssh_client, mismatch_from
from lanscanman.ui.trust import confirm_host_key_change


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
            ssh = make_ssh_client()
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
        except paramiko.BadHostKeyException as e:
            if confirm_host_key_change(self, mismatch_from(e)):
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
            "While it runs, anyone with root on the sender can use your SSH key "
            "to log in to any machine it opens, not just the receiver.  "
            "If the sender might be compromised, don't do this: transfer "
            "Remote → Local, then Local → Remote instead.")
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
