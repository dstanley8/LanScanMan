"""
AI tab: finds local AI servers and opens the right interface for each.

After a network scan, opening this tab checks every scanned host (and this
machine) on the usual AI ports. Servers with their own web page — Open
WebUI, ComfyUI, AUTOMATIC1111, llama.cpp — are opened in the browser;
servers without one (Ollama, LM Studio, bare OpenAI-compatible APIs) get
LanScanMan's chat window.
"""

from __future__ import annotations

import socket
import webbrowser

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QCursor
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QMenu,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from lanscanman.core.ai_discovery import (
    CHAT,
    FRONTEND,
    IMAGE,
    AIService,
    is_lan_address,
    parse_server_address,
    primary_action,
)
from lanscanman.core.chat_tree import ChatTree
from lanscanman.core.drive_report import SYSTEM_PROMPT
from lanscanman.ui.dialogs.chat_history import ChatHistoryDialog
from lanscanman.ui.dialogs.chat_window import ChatWindow, service_for
from lanscanman.workers.ai import AIDiscoveryWorker

LOCALHOST = "127.0.0.1"

_KIND_LABEL = {CHAT: "Chat", IMAGE: "Image generation", FRONTEND: "Chat web UI"}

_C_HOST, _C_ADDR, _C_SOFTWARE, _C_KIND, _C_MODELS, _C_ACTION = range(6)


class AITab(QWidget):
    def __init__(self, host_source, parent=None):
        """host_source() -> [(ip, label)], normally ScannerTab.current_hosts."""
        super().__init__(parent)
        self._host_source = host_source
        self._labels: dict[str, str] = {}
        self._services: list[AIService] = []
        self._worker: AIDiscoveryWorker | None = None
        self._stale = True
        self._pending_add: str | None = None
        self._last_service: AIService | None = None
        self._chats: list[ChatWindow] = []
        self._build_ui()

    # ── UI ───────────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        bar = QHBoxLayout()
        self._status = QLabel("Run a network scan, then open this tab to find AI servers.")
        self._status.setWordWrap(True)
        bar.addWidget(self._status, 1)
        self._find_btn = QPushButton("Find AI servers")
        self._find_btn.setToolTip("Check this machine and every scanned host on common AI ports")
        self._find_btn.clicked.connect(lambda: self.discover())
        bar.addWidget(self._find_btn)
        chats_btn = QPushButton("Saved chats…")
        chats_btn.setToolTip("Open, rename or delete saved conversations")
        chats_btn.clicked.connect(self._saved_chats)
        bar.addWidget(chats_btn)
        add_btn = QPushButton("Add server…")
        add_btn.setToolTip("Check a specific host:port (for servers on unusual ports)")
        add_btn.clicked.connect(self._add_server)
        bar.addWidget(add_btn)
        root.addLayout(bar)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Host", "Address", "Software", "Type", "Models", ""])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(_C_MODELS, QHeaderView.ResizeMode.Stretch)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.doubleClicked.connect(lambda idx: self._activate(idx.row()))
        root.addWidget(self.table)

        note = QLabel("Discovery only makes read-only web requests to hosts from your "
                      "last scan. Saved chats are encrypted with a key from your keyring.")
        note.setStyleSheet("color: #9AA4AF; font-size: 11px;")
        root.addWidget(note)

    # ── Discovery ────────────────────────────────────────────────────────────

    def mark_stale(self):
        """The scanner's host list changed; rediscover next time we're shown."""
        self._stale = True

    def showEvent(self, event):
        super().showEvent(event)
        if self._stale and self._worker is None:
            self.discover()

    def _hosts(self) -> list[str]:
        hosts = self._host_source() or []
        self._labels = {ip: label for ip, label in hosts}
        if not self._labels.get(LOCALHOST):
            self._labels[LOCALHOST] = "This machine"
        return [LOCALHOST] + [ip for ip, _ in hosts if ip != LOCALHOST]

    def discover(self, hosts: list[str] | None = None, ports=None, scheme: str = "http"):
        if self._worker is not None:
            return
        full = hosts is None
        hosts = hosts if hosts is not None else self._hosts()
        if full:
            self._stale = False
            self._services.clear()
            self.table.setRowCount(0)
        self._find_btn.setEnabled(False)
        self._status.setText(f"Checking {len(hosts)} host(s) for AI servers…")
        self._worker = AIDiscoveryWorker(hosts, ports, self, scheme=scheme)
        self._worker.service_found.connect(self._add_service)
        self._worker.progress.connect(
            lambda d, t: self._status.setText(f"Checking for AI servers… {d}/{t}"))
        self._worker.finished.connect(self._discovery_done)
        self._worker.start()

    def _discovery_done(self):
        self._worker = None
        self._find_btn.setEnabled(True)
        pending, self._pending_add = self._pending_add, None
        if pending is not None:
            if not any(s.base_url == pending for s in self._services):
                hint = (" If it uses a self-signed certificate, LanScanMan can't verify it — "
                        "add that certificate to your system's trusted certificates first."
                        if pending.startswith("https://") else "")
                self._status.setText(f"No AI server answered at {pending}.{hint}")
            else:
                self._status.setText(f"Added {pending}.")
            return
        n = len(self._services)
        scanned = len(self._host_source() or [])
        where = f"this machine and {scanned} scanned host(s)" if scanned else "this machine"
        if n:
            self._status.setText(f"Found {n} AI server(s) on {where}.")
        else:
            self._status.setText(
                f"No AI servers found on {where}."
                + ("" if scanned else " Run a network scan to check the rest of your network."))

    def _add_service(self, svc: AIService):
        if any((s.host, s.port) == (svc.host, svc.port) for s in self._services):
            return
        self._services.append(svc)
        row = self.table.rowCount()
        self.table.insertRow(row)
        label = self._labels.get(svc.host, "")
        self.table.setItem(row, _C_HOST, QTableWidgetItem(label or svc.host))
        addr = QTableWidgetItem(("🔒 " if svc.encrypted else "") + f"{svc.host}:{svc.port}")
        addr.setToolTip("HTTPS — traffic to this server is encrypted" if svc.encrypted else
                        "Plain HTTP — chats and API keys cross the network unencrypted")
        self.table.setItem(row, _C_ADDR, addr)
        self.table.setItem(row, _C_SOFTWARE, QTableWidgetItem(svc.software))
        self.table.setItem(row, _C_KIND, QTableWidgetItem(_KIND_LABEL.get(svc.kind, svc.kind)))
        if svc.models:
            models = QTableWidgetItem(f"{len(svc.models)}: " + ", ".join(svc.models[:3])
                                      + (" …" if len(svc.models) > 3 else ""))
            models.setToolTip("\n".join(svc.models))
        else:
            models = QTableWidgetItem("key required" if svc.needs_key else "—")
        self.table.setItem(row, _C_MODELS, models)
        btn = QPushButton("Open Web UI" if primary_action(svc) == "open_ui" else "Chat")
        btn.clicked.connect(lambda _=False, s=svc: self._activate_service(s))
        self.table.setCellWidget(row, _C_ACTION, btn)

    def _add_server(self):
        text, ok = QInputDialog.getText(
            self, "Add AI server",
            "Address — host:port, or a URL such as https://ai.home.lan\n"
            "(use https:// if the server supports it, so chats and keys are encrypted):")
        if not ok or not text.strip():
            return
        try:
            scheme, host, port = parse_server_address(text)
        except ValueError as e:
            QMessageBox.warning(self, "Add AI server", f"That address didn't work: {e}")
            return
        addresses = self._resolve(host)
        if not addresses:
            QMessageBox.warning(self, "Add AI server", f"Couldn't find an address for {host}.")
            return
        outside = [a for a in addresses if not is_lan_address(a)]
        if outside:
            QMessageBox.warning(
                self, "Add AI server",
                f"{host} is at {outside[0]}, which is on the internet.\n\n"
                "LanScanMan only talks to AI servers on your own network (private "
                "addresses, this machine or your VPN), so your chats and drive data never "
                "leave it.")
            return
        self._pending_add = f"{scheme}://{host}:{port}"
        self.discover(hosts=[host], ports=[port], scheme=scheme)

    @staticmethod
    def _resolve(host: str) -> list[str]:
        """Every address a host name resolves to (an IP resolves to itself)."""
        try:
            return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
        except OSError:
            return []

    # ── Drive-health chats (called from the Disk Health tab) ─────────────────

    def open_drive_chat(self, title: str, report: str) -> bool:
        """Open a chat with the drive-health instructions and the report
        placed in the message box, unsent, for the user to review."""
        services = self.chat_services()
        if not services:
            QMessageBox.information(
                self, "No AI server found",
                "No chat-capable AI server has been found yet.\n\n"
                "Run a network scan, then open the AI tab (or use Add server…) — "
                "LanScanMan will find AI servers on your network.")
            return False
        svc = self._last_service if self._last_service in services else services[0]
        tree = ChatTree(title=title)
        tree.settings["system"] = SYSTEM_PROMPT
        self._open_chat(svc, tree, draft=report)
        return True

    # ── Actions ──────────────────────────────────────────────────────────────

    def _activate(self, row: int):
        if 0 <= row < len(self._services):
            self._activate_service(self._services[row])

    def _activate_service(self, svc: AIService):
        if primary_action(svc) == "open_ui":
            self._open_ui(svc)
        else:
            self._open_chat(svc)

    def _open_ui(self, svc: AIService):
        webbrowser.open(svc.ui_url)
        self._status.setText(f"Opened {svc.ui_url}")

    def chat_services(self) -> list[AIService]:
        return [s for s in self._services if s.chat_capable]

    def _saved_chats(self):
        ChatHistoryDialog(self._open_saved, self).exec()

    def _open_saved(self, tree: ChatTree):
        svc = service_for(tree.last_server(), self.chat_services())
        if svc is None:
            known = self.chat_services()
            if not known:
                QMessageBox.information(
                    self, "Saved chats",
                    "That chat has no server recorded and no chat servers have been found. "
                    "Click Find AI servers first.")
                return
            svc = known[0]
        self._open_chat(svc, tree)

    def _open_chat(self, svc: AIService, tree: ChatTree | None = None, draft: str = ""):
        self._last_service = svc
        win = ChatWindow(svc, self, services=self.chat_services, tree=tree, draft=draft)
        win.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self._chats.append(win)
        win.destroyed.connect(lambda _=None, w=win: self._chats.remove(w) if w in self._chats else None)
        win.show()

    def _context_menu(self, pos):
        row = self.table.rowAt(pos.y())
        if not 0 <= row < len(self._services):
            return
        svc = self._services[row]
        menu = QMenu(self)
        ui_act = menu.addAction("Open Web UI") if svc.has_ui else None
        chat_act = menu.addAction("Open chat window") if svc.chat_capable else None
        menu.addSeparator()
        copy_act = menu.addAction(f"Copy endpoint URL  ({svc.base_url})")
        action = menu.exec(QCursor.pos())
        if action is None:
            return
        if action == ui_act:
            self._open_ui(svc)
        elif action == chat_act:
            self._open_chat(svc)
        elif action == copy_act:
            QApplication.clipboard().setText(svc.base_url)
            self._status.setText(f"Copied {svc.base_url}")
