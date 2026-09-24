"""Saved chats: list, open, rename, delete. Everything is read through the
encrypted store, so a locked keyring asks to be unlocked here."""

from __future__ import annotations

from datetime import datetime
from typing import Callable

from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from lanscanman.core.chat_tree import ChatTree
from lanscanman.core.integrity import IntegrityError
from lanscanman.log import log
from lanscanman.services.chat_crypto import chat_store
from lanscanman.ui.trust import show_integrity_problem


class ChatHistoryDialog(QDialog):
    def __init__(self, on_open: Callable[[ChatTree], None], parent=None):
        super().__init__(parent)
        self._on_open = on_open
        self._summaries: list[dict] = []
        self.setWindowTitle("Saved chats")
        self.resize(760, 420)

        root = QVBoxLayout(self)
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["Title", "Last model", "Server", "Updated", "Messages"])
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        h = self._table.horizontalHeader()
        h.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.doubleClicked.connect(lambda _: self._open())
        root.addWidget(self._table)

        note = QLabel("Chats are encrypted on disk with a key kept in your keyring.")
        note.setStyleSheet("color: #9AA4AF; font-size: 11px;")
        root.addWidget(note)

        row = QHBoxLayout()
        for label, fn in [("Open", self._open), ("Rename…", self._rename), ("Delete…", self._delete)]:
            b = QPushButton(label)
            b.clicked.connect(fn)
            row.addWidget(b)
        row.addStretch(1)
        close = QPushButton("Close")
        close.clicked.connect(self.reject)
        row.addWidget(close)
        root.addLayout(row)
        self.refresh()

    def refresh(self) -> bool:
        try:
            self._summaries = chat_store().list()
        except IntegrityError as e:
            show_integrity_problem(self, e)
            return False
        self._table.setRowCount(0)
        for s in self._summaries:
            r = self._table.rowCount()
            self._table.insertRow(r)
            when = datetime.fromtimestamp(s.get("updated", 0)).strftime("%Y-%m-%d %H:%M")
            for col, val in enumerate([s.get("title", ""), s.get("model", ""),
                                       s.get("server", ""), when, str(s.get("messages", 0))]):
                self._table.setItem(r, col, QTableWidgetItem(val))
        if self._summaries:
            self._table.selectRow(0)
        return True

    def _selected(self) -> dict | None:
        rows = self._table.selectionModel().selectedRows()
        return self._summaries[rows[0].row()] if rows else None

    def _open(self):
        s = self._selected()
        if not s:
            return
        try:
            tree = chat_store().load(s["id"])
        except IntegrityError as e:
            show_integrity_problem(self, e)
            return
        except (OSError, ValueError) as e:
            log.exception("opening saved chat failed")
            QMessageBox.critical(self, "Saved chats", f"Couldn't open that chat: {e}")
            return
        self.accept()
        self._on_open(tree)

    def _rename(self):
        s = self._selected()
        if not s:
            return
        title, ok = QInputDialog.getText(self, "Rename chat", "Title:", text=s.get("title", ""))
        if ok and title.strip():
            try:
                chat_store().rename(s["id"], title)
            except IntegrityError as e:
                show_integrity_problem(self, e)
            self.refresh()

    def _delete(self):
        s = self._selected()
        if not s:
            return
        if QMessageBox.question(self, "Delete chat",
                                f"Delete “{s.get('title', '')}” permanently?") \
                != QMessageBox.StandardButton.Yes:
            return
        try:
            chat_store().delete(s["id"])
        except IntegrityError as e:
            show_integrity_problem(self, e)
        self.refresh()
