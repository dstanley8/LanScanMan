"""
LanScanMan's own chat window, for AI servers that have no web UI of their
own (Ollama, LM Studio, bare OpenAI-compatible servers).

- Server + model pickers: carry a conversation across hosts and models.
- Thinking: a level (Default / Off / Low / Medium / High) sent as
  reasoning_effort, and a "Show thinking" toggle that shows it in grey.
- Branching (core/chat_tree.py): ↻ Regenerate a reply, ✎ Edit an earlier
  message, ◀ n/m ▶ to switch between alternatives.
- Pictures for vision models: 📎, paste (Ctrl+V) or drag and drop.
- Chats save automatically, encrypted (services/chat_crypto.py).

Model output is inserted as plain text; the only links in the transcript
are LanScanMan's own lsm: action links.
"""

from __future__ import annotations

from typing import Callable

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import (
    QColor,
    QKeySequence,
    QPixmap,
    QShortcut,
    QTextCharFormat,
    QTextCursor,
    QTextDocument,
)
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTextBrowser,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from lanscanman.core import ai_chat
from lanscanman.core.ai_chat import user_content
from lanscanman.core.ai_discovery import (
    CHAT,
    AIService,
    keyring_name,
    sends_key_in_clear,
)
from lanscanman.core.chat_tree import THINKING_LEVELS, ChatTree, Server
from lanscanman.core.integrity import IntegrityError, KeyUnavailable
from lanscanman.log import log
from lanscanman.services.chat_crypto import chat_store
from lanscanman.services.secret_store import SecretStoreError
from lanscanman.services.vault import get_vault
from lanscanman.ui import images
from lanscanman.workers.ai import (
    CapabilityWorker,
    ChatWorker,
    ModelListWorker,
    keep_alive,
)

THINKING_COLOR = "#7F8A96"
LINK_COLOR = "#3498db"


def service_for(server: Server | None, known: list[AIService]) -> AIService | None:
    """The discovered service matching a saved server, or a stand-in for it."""
    if server is None:
        return None
    for svc in known:
        if (svc.scheme, svc.host, svc.port) == (server.scheme, server.host, server.port):
            return svc
    return AIService(server.host, server.port, server.software or "OpenAI-compatible", CHAT,
                     scheme=server.scheme)


class _Input(QPlainTextEdit):
    """Message box that accepts pasted images."""
    def __init__(self, on_image, parent=None):
        super().__init__(parent)
        self._on_image = on_image

    def canInsertFromMimeData(self, source):
        return source.hasImage() or super().canInsertFromMimeData(source)

    def insertFromMimeData(self, source):
        if source.hasImage():
            self._on_image(source.imageData())
            return
        if source.hasUrls() and all(u.isLocalFile() and images.is_image_file(u.toLocalFile())
                                    for u in source.urls()):
            for u in source.urls():
                self._on_image(u.toLocalFile())
            return
        super().insertFromMimeData(source)


class ChatWindow(QDialog):
    def __init__(self, service: AIService, parent=None,
                 services: Callable[[], list[AIService]] | None = None,
                 tree: ChatTree | None = None, draft: str = ""):
        """draft: text placed in the message box, not sent — e.g. a drive
        report the user reviews first."""
        super().__init__(parent)
        self.service = service
        self._services = services or (lambda: [])
        self.tree = tree or ChatTree()
        self.pending: list[tuple[str, object]] = []       # (data URL, thumbnail QImage)
        self.capabilities: dict[tuple[str, str], set | None] = {}
        self.context_max: dict[tuple[str, str], int | None] = {}   # Ollama models' max context
        self._size_warned: set[str] = set()                        # servers warned about size
        self._thumbs: dict[str, object] = {}
        self._worker: ChatWorker | None = None
        self._stream: dict | None = None                    # reply being received
        self._edit_parent: str | None = None
        self._editing = False
        self._model_worker: ModelListWorker | None = None
        self._store = get_vault().store
        self._img_n = 0
        self.resize(820, 700)
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        self.setAcceptDrops(True)
        self._build_ui()
        self._populate_servers()
        self._load_saved_key()
        last_model = self.tree.last_model()
        self._set_models(service.models, prefer=last_model)
        self._thinking.setCurrentText(self.tree.settings.get("thinking", "default").capitalize())
        self._update_title()
        self._render()
        if draft:
            self._input.setPlainText(draft)
            self._input.setFixedHeight(220)          # room to review a report
            self._status.setText("Review the message below — nothing has been sent yet. "
                                 "Edit it if you like, then press Send.")

    # ── UI ───────────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)

        top = QHBoxLayout()
        top.addWidget(QLabel("Server:"))
        self._server = QComboBox()
        self._server.setMinimumWidth(200)
        self._server.activated.connect(self._on_server_chosen)
        top.addWidget(self._server)
        top.addWidget(QLabel("Model:"))
        self._model = QComboBox()
        self._model.setEditable(True)            # type one if the list is unavailable
        self._model.setMinimumWidth(220)
        self._model.currentTextChanged.connect(self._on_model_changed)
        top.addWidget(self._model, 1)
        self._refresh_models_btn = QPushButton("↻")
        self._refresh_models_btn.setToolTip("Reload the model list (uses the API key if given)")
        self._refresh_models_btn.clicked.connect(self._refresh_models)
        top.addWidget(self._refresh_models_btn)
        root.addLayout(top)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Thinking:"))
        self._thinking = QComboBox()
        self._thinking.addItems([t.capitalize() for t in THINKING_LEVELS])
        self._thinking.setToolTip(
            "How hard a reasoning model should think (sent as reasoning_effort).\n"
            "Default sends nothing. Some servers or models ignore or reject levels.")
        self._thinking.currentTextChanged.connect(
            lambda t: self.tree.settings.update(thinking=t.lower()))
        row2.addWidget(self._thinking)
        self._show_thinking = QCheckBox("Show thinking")
        self._show_thinking.setToolTip("Show a reasoning model's thinking (in grey) above its answer")
        self._show_thinking.toggled.connect(lambda _: self._render())
        row2.addWidget(self._show_thinking)
        row2.addSpacing(16)
        row2.addWidget(QLabel("API key:"))
        self._cleartext_ok: set[str] = set()          # servers the user OK'd plain-HTTP keys for
        self._key = QLineEdit()
        self._key.setEchoMode(QLineEdit.EchoMode.Password)
        self._key.setPlaceholderText("Only if the server needs one")
        row2.addWidget(self._key, 1)
        self._remember = QCheckBox("Remember")
        self._remember.setToolTip("Remember the key in your keyring")
        if not self._store.available:
            self._remember.setEnabled(False)
            self._remember.setToolTip("No desktop keyring available — the key is kept "
                                      "only while this window is open.")
        row2.addWidget(self._remember)
        self._forget_btn = QPushButton("Forget")
        self._forget_btn.setToolTip("Remove the saved key from your keyring")
        self._forget_btn.clicked.connect(self._forget_key)
        self._forget_btn.setVisible(False)
        row2.addWidget(self._forget_btn)
        root.addLayout(row2)

        self._clear_warning = QLabel(
            "⚠ Plain HTTP: this API key (and the conversation) will cross your network "
            "unencrypted — anyone on it could read them. Use an https:// address if the "
            "server supports it.")
        self._clear_warning.setWordWrap(True)
        self._clear_warning.setStyleSheet("color: #f39c12; font-size: 11px;")
        self._clear_warning.setVisible(False)
        root.addWidget(self._clear_warning)
        self._key.textChanged.connect(lambda _: self._update_clear_warning())

        self._transcript = QTextBrowser()
        self._transcript.setOpenLinks(False)
        self._transcript.setOpenExternalLinks(False)
        self._transcript.anchorClicked.connect(self._on_link)
        root.addWidget(self._transcript, 1)

        self._status = QLabel("")
        self._status.setStyleSheet("color: #9AA4AF;")
        self._status.setWordWrap(True)
        root.addWidget(self._status)

        self._edit_banner = QWidget()
        eb = QHBoxLayout(self._edit_banner)
        eb.setContentsMargins(0, 0, 0, 0)
        eb_lbl = QLabel("✎ Editing an earlier message — Send starts a new branch from there.")
        eb_lbl.setStyleSheet(f"color: {LINK_COLOR};")
        eb.addWidget(eb_lbl, 1)
        cancel = QPushButton("Cancel edit")
        cancel.clicked.connect(self._cancel_edit)
        eb.addWidget(cancel)
        self._edit_banner.setVisible(False)
        root.addWidget(self._edit_banner)

        self._attach_row = QHBoxLayout()
        self._attach_row.addStretch(1)
        self._attach_box = QWidget()
        self._attach_box.setLayout(self._attach_row)
        self._attach_box.setVisible(False)
        root.addWidget(self._attach_box)

        input_row = QHBoxLayout()
        self._attach_btn = QPushButton("📎")
        self._attach_btn.setToolTip("Attach pictures (or paste / drag them in)")
        self._attach_btn.setFixedWidth(40)
        self._attach_btn.clicked.connect(self._choose_images)
        input_row.addWidget(self._attach_btn, 0, Qt.AlignmentFlag.AlignTop)
        self._input = _Input(self.add_image)
        self._input.setPlaceholderText("Type a message — Ctrl+Enter to send")
        self._input.setFixedHeight(80)
        input_row.addWidget(self._input, 1)
        buttons = QVBoxLayout()
        self._send_btn = QPushButton("Send")
        self._send_btn.clicked.connect(self._send_or_stop)
        buttons.addWidget(self._send_btn)
        new_btn = QPushButton("New chat")
        new_btn.setToolTip("Start a new conversation (this one stays in Saved chats)")
        new_btn.clicked.connect(self._new_chat)
        buttons.addWidget(new_btn)
        input_row.addLayout(buttons)
        root.addLayout(input_row)

        for seq in ("Ctrl+Return", "Ctrl+Enter"):
            QShortcut(QKeySequence(seq), self._input, activated=self._send_or_stop)

    def _update_title(self):
        title = self.tree.title or "New chat"
        self.setWindowTitle(f"{title} — {self.service.software} at {self.service.host}:{self.service.port}")

    # ── Servers ──────────────────────────────────────────────────────────────

    def _server_list(self) -> list[AIService]:
        known = [s for s in self._services() if s.chat_capable]
        if not any((s.host, s.port) == (self.service.host, self.service.port) for s in known):
            known.insert(0, self.service)
        return known

    def _populate_servers(self):
        self._server.clear()
        for svc in self._server_list():
            self._server.addItem(f"{svc.software} — {svc.host}:{svc.port}", svc)
            if (svc.host, svc.port) == (self.service.host, self.service.port):
                self._server.setCurrentIndex(self._server.count() - 1)

    def _on_server_chosen(self, index: int):
        svc = self._server.itemData(index)
        if svc is None or svc is self.service:
            return
        model = self._model.currentText()
        self.service = svc
        self._key.clear()
        self._remember.setChecked(False)
        self._forget_btn.setVisible(False)
        self._load_saved_key()
        self._set_models(svc.models, prefer=model)
        self._update_title()
        self._update_clear_warning()
        if not svc.models:
            self._refresh_models()

    # ── API key ──────────────────────────────────────────────────────────────

    def _load_saved_key(self):
        if not self._store.available:
            return
        try:
            saved = self._store.get(keyring_name(self.service))
        except SecretStoreError as e:
            log.warning(f"could not read saved API key: {e}")
            return
        if saved:
            self._key.setText(saved)
            self._remember.setChecked(True)
            self._forget_btn.setVisible(True)

    def _save_key_if_asked(self) -> None:
        if not (self._remember.isChecked() and self._store.available):
            return
        key = self._key.text().strip()
        if not key:
            return
        try:
            if self._store.get(keyring_name(self.service)) != key:
                self._store.set(keyring_name(self.service), key)
            self._forget_btn.setVisible(True)
        except SecretStoreError as e:
            self._status.setText(f"Could not save the key to your keyring: {e}")

    def _forget_key(self):
        try:
            self._store.delete(keyring_name(self.service))
        except SecretStoreError as e:
            self._status.setText(f"Could not remove the key: {e}")
            return
        self._remember.setChecked(False)
        self._forget_btn.setVisible(False)
        self._status.setText("Saved key removed from your keyring.")

    def _api_key(self) -> str | None:
        return self._key.text().strip() or None

    def _update_clear_warning(self):
        self._clear_warning.setVisible(sends_key_in_clear(self.service, self._api_key()))

    def _key_may_be_sent(self) -> bool:
        """Once per server per window: confirm before an API key goes out over
        plain HTTP to another machine."""
        if not sends_key_in_clear(self.service, self._api_key()):
            return True
        if self.service.base_url in self._cleartext_ok:
            return True
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Send API key unencrypted?")
        box.setText(f"{self.service.base_url} uses plain HTTP.")
        box.setInformativeText(
            "Your API key would be sent unencrypted. Anyone on your network — or anything "
            "pretending to be this server — could read it and use it.\n\n"
            "If the server supports HTTPS, add it as https://… in the AI tab instead.")
        send = box.addButton("Send anyway", QMessageBox.ButtonRole.AcceptRole)
        cancel = box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(cancel)
        box.setEscapeButton(cancel)
        box.exec()
        if box.clickedButton() is not send:
            self._status.setText("Not sent — the API key would have gone out unencrypted.")
            return False
        self._cleartext_ok.add(self.service.base_url)
        return True

    # ── Models and what they can do ──────────────────────────────────────────

    def _set_models(self, models: list[str], prefer: str = ""):
        current = prefer or self._model.currentText()
        self._model.blockSignals(True)
        self._model.clear()
        self._model.addItems(models)
        self._model.blockSignals(False)
        if current and current in models:
            self._model.setCurrentText(current)
        elif not models:
            self._model.setEditText(current)
        if not models:
            self._status.setText(
                "No model list — the server may need an API key. Enter it and press ↻, "
                "or type a model name.")
        else:
            self._status.setText(f"{len(models)} model(s) available on {self.service.host}.")
        self._on_model_changed(self._model.currentText())

    def _refresh_models(self):
        if not self._key_may_be_sent():
            return
        self._refresh_models_btn.setEnabled(False)
        self._status.setText("Loading models…")
        self._model_worker = keep_alive(ModelListWorker(self.service, self._api_key()))
        self._model_worker.models_ready.connect(self._on_models)
        self._model_worker.start()

    def _on_models(self, models: list):
        self._refresh_models_btn.setEnabled(True)
        if models:
            self.service.models = list(models)
            self._save_key_if_asked()
        self._set_models(models)

    def _cap_key(self, model: str | None = None):
        return (self.service.base_url, (model or self._model.currentText()).strip())

    def _on_model_changed(self, model: str):
        model = model.strip()
        if not model:
            return
        key = self._cap_key(model)
        if self.service.software == "Ollama" and key not in self.capabilities:
            self.capabilities[key] = None
            w = keep_alive(CapabilityWorker(self.service.base_url, model, self._api_key()))
            w.capabilities_ready.connect(self._on_capabilities_from)
            w.context_ready.connect(self._on_context_from)
            w.start()
        self._update_vision()

    def _on_context_from(self, base_url: str, model: str, length):
        self.context_max[(base_url, model)] = length

    def _on_capabilities_from(self, base_url: str, model: str, caps):
        self._on_capabilities(model, caps, base_url)

    def _on_capabilities(self, model: str, caps, base_url: str | None = None):
        self.capabilities[(base_url or self.service.base_url, model)] = caps
        self._update_vision()

    def can_see_images(self, model: str | None = None) -> bool | None:
        """True / False when the server told us, None when unknown."""
        caps = self.capabilities.get(self._cap_key(model))
        if caps is None:
            return None
        return "vision" in caps

    def _update_vision(self):
        vision = self.can_see_images()
        self._attach_btn.setEnabled(vision is not False)
        self._attach_btn.setToolTip(
            "This model can't see images — pick a vision model to attach pictures."
            if vision is False else "Attach pictures (or paste / drag them in)")

    # ── Attachments ──────────────────────────────────────────────────────────

    def add_image(self, source) -> bool:
        if self.can_see_images() is False:
            self._status.setText("This model can't see images — pick a vision model first.")
            return False
        try:
            url, thumb = images.prepare(source)
        except images.ImageError as e:
            self._status.setText(str(e))
            return False
        self._thumbs[url] = thumb
        self.pending.append((url, thumb))
        self._refresh_attachments()
        return True

    def _choose_images(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Attach pictures", "",
            "Images (*.png *.jpg *.jpeg *.gif *.bmp *.webp *.tif *.tiff)")
        for p in paths:
            self.add_image(p)

    def _remove_pending(self, index: int):
        if 0 <= index < len(self.pending):
            del self.pending[index]
            self._refresh_attachments()

    def _refresh_attachments(self):
        while self._attach_row.count() > 1:
            item = self._attach_row.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for i, (_, thumb) in enumerate(self.pending):
            cell = QWidget()
            lay = QHBoxLayout(cell)
            lay.setContentsMargins(0, 0, 4, 0)
            pic = QLabel()
            pic.setPixmap(QPixmap.fromImage(thumb).scaledToHeight(56))
            lay.addWidget(pic)
            x = QToolButton()
            x.setText("✕")
            x.setToolTip("Remove this picture")
            x.clicked.connect(lambda _=False, n=i: self._remove_pending(n))
            lay.addWidget(x, 0, Qt.AlignmentFlag.AlignTop)
            self._attach_row.insertWidget(self._attach_row.count() - 1, cell)
        self._attach_box.setVisible(bool(self.pending))

    def dragEnterEvent(self, event):
        md = event.mimeData()
        if md.hasImage() or (md.hasUrls() and any(
                u.isLocalFile() and images.is_image_file(u.toLocalFile()) for u in md.urls())):
            event.acceptProposedAction()

    def dropEvent(self, event):
        md = event.mimeData()
        if md.hasImage():
            self.add_image(md.imageData())
        for u in md.urls():
            if u.isLocalFile() and images.is_image_file(u.toLocalFile()):
                self.add_image(u.toLocalFile())
        event.acceptProposedAction()

    def _thumb(self, url: str):
        if url not in self._thumbs:
            try:
                self._thumbs[url] = images.thumbnail_from_data_url(url)
            except images.ImageError:
                self._thumbs[url] = None
        return self._thumbs[url]

    # ── Transcript ───────────────────────────────────────────────────────────

    def _fmt(self, bold=False, thinking=False, href: str | None = None) -> QTextCharFormat:
        f = QTextCharFormat()
        f.setFontWeight(700 if bold else 400)
        if thinking:
            f.setForeground(QColor(THINKING_COLOR))
            f.setFontItalic(True)
        if href:
            f.setAnchor(True)
            f.setAnchorHref(href)
            f.setForeground(QColor(LINK_COLOR))
            f.setFontPointSize(max(7.0, self._transcript.font().pointSizeF() - 1))
        return f

    def _end(self) -> QTextCursor:
        c = self._transcript.textCursor()
        c.movePosition(QTextCursor.MoveOperation.End)
        return c

    def _header(self, c: QTextCursor, text: str):
        if not self._transcript.document().isEmpty():
            c.insertBlock()
            c.insertBlock()
        c.insertText(f"{text}\n", self._fmt(bold=True))

    def _write_images(self, c: QTextCursor, urls: list[str]):
        doc = self._transcript.document()
        for url in urls:
            thumb = self._thumb(url)
            if thumb is None:
                c.insertText("[picture] ", self._fmt())
                continue
            self._img_n += 1
            name = f"lanscanman-img-{self._img_n}"
            doc.addResource(QTextDocument.ResourceType.ImageResource, QUrl(name), thumb)
            c.insertImage(name)
            c.insertText(" ", self._fmt())
        if urls:
            c.insertText("\n", self._fmt())

    def _write_links(self, c: QTextCursor, node):
        links = []
        idx, count = self.tree.sibling_position(node.id)
        if node.role == "assistant":
            links.append(("↻ Regenerate", f"lsm:regen:{node.id}"))
        else:
            links.append(("✎ Edit", f"lsm:edit:{node.id}"))
        if count > 1:
            links.append(("◀", f"lsm:prev:{node.id}"))
            links.append((f"{idx}/{count}", None))
            links.append(("▶", f"lsm:next:{node.id}"))
        c.insertText("\n", self._fmt())
        for label, href in links:
            c.insertText(label, self._fmt(href=href) if href else self._fmt(thinking=True))
            c.insertText("   ", self._fmt())

    def _who(self, node) -> str:
        if node.role == "user":
            return "You"
        where = f" · {node.server.host}" if node.server else ""
        return f"{node.model or 'Assistant'}{where}"

    def _render(self):
        """Redraw the current branch (plus any reply still streaming)."""
        self._transcript.clear()
        c = self._end()
        system = self.tree.settings.get("system")
        if system:
            # Transparency: show exactly what instructions the AI is given
            c.insertText("Instructions sent to the AI with every message:\n", self._fmt(bold=True))
            c.insertText(system, self._fmt(thinking=True))
        for node in self.tree.path():
            self._header(c, self._who(node))
            self._write_images(c, node.image_urls)
            if node.reasoning and self._show_thinking.isChecked():
                c.insertText(node.reasoning, self._fmt(thinking=True))
                if node.text:
                    c.insertText("\n\n", self._fmt())
            c.insertText(node.text, self._fmt())
            self._write_links(c, node)
        if self._stream is not None:
            s = self._stream
            self._header(c, f"{s['model']} · {s['server'].host}")
            if s["reasoning"] and self._show_thinking.isChecked():
                c.insertText(s["reasoning"], self._fmt(thinking=True))
                if s["text"]:
                    c.insertText("\n\n", self._fmt())
            c.insertText(s["text"], self._fmt())
        self._transcript.setTextCursor(c)
        self._transcript.ensureCursorVisible()

    def _append(self, text: str, thinking: bool = False):
        c = self._end()
        c.insertText(text, self._fmt(thinking=thinking))
        self._transcript.setTextCursor(c)
        self._transcript.ensureCursorVisible()

    # ── Branch actions ───────────────────────────────────────────────────────

    def _on_link(self, url: QUrl):
        parts = url.toString().split(":", 2)
        if len(parts) != 3 or parts[0] != "lsm" or parts[2] not in self.tree.nodes:
            return
        if self._worker is not None:
            self._status.setText("Wait for the reply to finish (or press Stop) first.")
            return
        action, node_id = parts[1], parts[2]
        if action == "regen":
            self.regenerate(node_id)
        elif action == "edit":
            self.start_edit(node_id)
        elif action in ("prev", "next"):
            self.tree.switch_sibling(node_id, -1 if action == "prev" else 1)
            self._render()
            self._save()

    def regenerate(self, assistant_id: str):
        parent = self.tree.nodes[assistant_id].parent
        if not self._fits(self.tree.messages(parent)):
            return
        self.tree.select(parent)
        self._start_reply(parent, new_user=False)

    def start_edit(self, user_id: str):
        node = self.tree.nodes[user_id]
        self._edit_parent = node.parent
        self._editing = True
        self._input.setPlainText(node.text)
        self.pending = [(u, self._thumb(u)) for u in node.image_urls if self._thumb(u) is not None]
        self._refresh_attachments()
        self._edit_banner.setVisible(True)
        self._input.setFocus()

    def _cancel_edit(self):
        self._editing = False
        self._edit_parent = None
        self._edit_banner.setVisible(False)
        self._input.clear()
        self.pending.clear()
        self._refresh_attachments()

    # ── Sending ──────────────────────────────────────────────────────────────

    def _send_or_stop(self):
        if self._worker is not None:
            self._worker.stop()
            return
        text = self._input.toPlainText().strip()
        model = self._model.currentText().strip()
        if not text and not self.pending:
            return
        if not model:
            self._status.setText("Choose or type a model first.")
            return
        if self.pending and self.can_see_images(model) is False:
            self._status.setText("This model can't see images — pick a vision model "
                                 "or remove the pictures.")
            return
        if not self._key_may_be_sent():
            return
        parent = self._edit_parent if self._editing else self.tree.current
        prospective = self.tree.messages(parent) + [
            {"role": "user", "content": user_content(text, [u for u, _ in self.pending])}]
        if not self._fits(prospective):
            return
        user = self.tree.add_user(parent, user_content(text, [u for u, _ in self.pending]))
        self._input.clear()
        self._input.setFixedHeight(80)             # back to normal after a long draft
        self.pending.clear()
        self._refresh_attachments()
        self._editing = False
        self._edit_parent = None
        self._edit_banner.setVisible(False)
        self._update_title()
        self._start_reply(user.id, new_user=True)

    # ── Will it fit? ─────────────────────────────────────────────────────────

    def _is_ollama(self) -> bool:
        return self.service.software == "Ollama"

    def _num_ctx_for(self, messages: list[dict]) -> int | None:
        return ai_chat.ollama_context(ai_chat.estimate_tokens(messages), self.context_max.get(self._cap_key()),
                                      self.tree.settings.get("num_ctx"))

    def _fits(self, messages: list[dict]) -> bool:
        """Warn before sending something the model can't take in whole — Ollama
        would otherwise silently drop the start (instructions included)."""
        needed = ai_chat.estimate_tokens(messages) + ai_chat.REPLY_BUDGET
        model = self._model.currentText().strip()
        if self._is_ollama():
            limit = self.context_max.get(self._cap_key())
            if not limit or needed <= limit:
                return True
            text = (f"This conversation is about {needed:,} tokens including room for the "
                    f"reply, but {model} can hold at most {limit:,}.\n\n"
                    "The beginning would be cut off — including the instructions and the start "
                    "of any report — and the AI would answer without it.\n\n"
                    "Try a smaller report (one host or one disk), a New chat, or a model with a "
                    "larger context.")
        else:
            if needed <= 8192 or self.service.base_url in self._size_warned:
                return True
            text = (f"This conversation is about {needed:,} tokens including room for the "
                    "reply.\n\nLanScanMan can't check this server's context limit. If it's "
                    "set smaller, the beginning will be cut off and the AI may make things up.")
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Too long for the model?")
        box.setText(text)
        send = box.addButton("Send anyway", QMessageBox.ButtonRole.AcceptRole)
        cancel = box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(cancel)
        box.exec()
        if box.clickedButton() is not send:
            self._status.setText("Not sent — too long for the model.")
            return False
        self._size_warned.add(self.service.base_url)
        return True

    def _start_reply(self, user_id: str, new_user: bool):
        if not new_user and not self._key_may_be_sent():      # regenerate
            return
        model = self._model.currentText().strip()
        if not model:
            self._status.setText("Choose or type a model first.")
            return
        svc = self.service
        self._stream = {"parent": user_id, "model": model, "text": "", "reasoning": "",
                        "server": Server(svc.host, svc.port, svc.software, svc.scheme),
                        "new_user": new_user}
        self._render()
        self._status.setText("Waiting for reply…")
        self._send_btn.setText("Stop")
        messages = self.tree.messages(user_id)
        num_ctx = self._num_ctx_for(messages) if self._is_ollama() else None
        if num_ctx:
            self.tree.settings["num_ctx"] = num_ctx      # never shrink within a chat
            self._status.setText(f"Waiting for reply… (about "
                                 f"{ai_chat.estimate_tokens(messages):,} tokens sent; "
                                 f"context window set to {num_ctx:,})")
        self._worker = keep_alive(ChatWorker(svc.base_url, model, messages, self._api_key(),
                                             thinking=self.tree.settings["thinking"],
                                             ollama=self._is_ollama(), num_ctx=num_ctx))
        self._worker.token.connect(self._on_token)
        self._worker.reasoning.connect(self._on_reasoning)
        self._worker.failed.connect(self._on_failed)
        self._worker.done.connect(self._on_done)
        self._worker.start()

    def _on_reasoning(self, text: str):
        if self._stream is None:
            return
        self._stream["reasoning"] += text
        if self._show_thinking.isChecked():
            self._append(text, thinking=True)
        else:
            self._status.setText("Thinking… (tick “Show thinking” to watch)")

    def _on_token(self, text: str):
        s = self._stream
        if s is None:
            return
        if not s["text"]:
            self._status.setText("Replying…")
            if s["reasoning"] and self._show_thinking.isChecked():
                self._append("\n\n")
        s["text"] += text
        self._append(text)

    def _finish(self) -> dict:
        s, self._stream, self._worker = self._stream, None, None
        self._send_btn.setText("Send")
        return s

    def _undo_new_user(self, s: dict):
        """A new message that got no reply: take it back so it can be resent."""
        node = self.tree.nodes.get(s["parent"])
        if s["new_user"] and node is not None and not self.tree.children.get(node.id):
            if not self._input.toPlainText().strip():
                self._input.setPlainText(node.text)
                self.pending = [(u, self._thumb(u)) for u in node.image_urls
                                if self._thumb(u) is not None]
                self._refresh_attachments()
            self.tree.remove_leaf(node.id)

    def _on_done(self, reply: str):
        s = self._finish()
        if s is None:
            return
        if reply:
            self.tree.add_assistant(s["parent"], reply, s["reasoning"], s["model"], s["server"])
            self._save_key_if_asked()
            self._status.setText("")
            self._save()
        else:
            self._undo_new_user(s)
            self._status.setText("Stopped, or the server sent an empty reply.")
        self._render()

    def _on_failed(self, message: str):
        s = self._finish()
        if s is None:
            return
        self._undo_new_user(s)
        self._render()
        self._status.setText(f"⚠ {message}\nNothing was added to the conversation — "
                             "fix the problem and send again.")
        if "API key" in message:
            self._key.setFocus()

    # ── Saving ───────────────────────────────────────────────────────────────

    def _save(self):
        try:
            chat_store().save(self.tree)
        except KeyUnavailable:
            self._status.setText("Not saved — the keyring is locked. It will ask again "
                                 "after the next reply.")
        except IntegrityError as e:
            self._status.setText(f"Not saved: {e}")
        except OSError as e:
            log.exception("saving chat failed")
            self._status.setText(f"Not saved: {e}")

    def _new_chat(self):
        if self._worker is not None:
            self._worker.stop()
        self._cancel_edit()
        self.tree = ChatTree()
        self.tree.settings["thinking"] = self._thinking.currentText().lower()
        self._update_title()
        self._render()
        self._status.setText("New conversation.")

    def closeEvent(self, event):
        if self._worker is not None:
            self._worker.stop()
        super().closeEvent(event)
