"""
Saved chats: one encrypted file per chat under chats/, plus an encrypted
index of summaries so the list opens without decrypting every chat.

Encryption is supplied by the caller (`seal`/`unseal` byte functions —
services/chat_crypto.py derives the key from the keyring). Titles are part
of the encrypted index, so nothing about a conversation is readable on disk.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Callable

from lanscanman.core.chat_tree import ChatTree
from lanscanman.log import log

_ID_RE = re.compile(r"^[0-9a-f-]{36}$")
INDEX = "index.bin"


class ChatStore:
    def __init__(self, directory: Path, seal: Callable[[bytes], bytes],
                 unseal: Callable[[bytes], bytes]):
        self.dir = Path(directory)
        self._seal, self._unseal = seal, unseal

    def _path(self, chat_id: str) -> Path:
        if not _ID_RE.match(chat_id):
            raise ValueError(f"bad chat id {chat_id!r}")      # no path tricks
        return self.dir / f"{chat_id}.chat"

    def _write(self, path: Path, data: bytes) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)

    # ── index ────────────────────────────────────────────────────────────────

    def _read_index(self) -> dict[str, dict]:
        path = self.dir / INDEX
        if not path.exists():
            return {}
        try:
            data = json.loads(self._unseal(path.read_bytes()))
            return data if isinstance(data, dict) else {}
        except ValueError as e:
            log.warning(f"chat index unreadable, rebuilding: {e}")
            return self._rebuild_index()

    def _write_index(self, index: dict[str, dict]) -> None:
        self._write(self.dir / INDEX, self._seal(json.dumps(index).encode()))

    def _rebuild_index(self) -> dict[str, dict]:
        index = {}
        for f in self.dir.glob("*.chat"):
            try:
                tree = self._load_file(f)
                index[tree.id] = tree.summary()
            except Exception as e:
                log.warning(f"skipping unreadable chat {f.name}: {e}")
        return index

    # ── chats ────────────────────────────────────────────────────────────────

    def _load_file(self, path: Path) -> ChatTree:
        return ChatTree.from_dict(json.loads(self._unseal(path.read_bytes())))

    def save(self, tree: ChatTree) -> None:
        if not tree.nodes:
            return
        self._write(self._path(tree.id), self._seal(json.dumps(tree.to_dict()).encode()))
        index = self._read_index()
        index[tree.id] = tree.summary()
        self._write_index(index)

    def load(self, chat_id: str) -> ChatTree:
        return self._load_file(self._path(chat_id))

    def list(self) -> list[dict]:
        """Summaries, most recently updated first."""
        return sorted(self._read_index().values(), key=lambda s: s.get("updated", 0), reverse=True)

    def rename(self, chat_id: str, title: str) -> None:
        tree = self.load(chat_id)
        tree.title = title.strip() or tree.title
        self.save(tree)

    def delete(self, chat_id: str) -> None:
        path = self._path(chat_id)
        if path.exists():
            path.unlink()
        index = self._read_index()
        index.pop(chat_id, None)
        self._write_index(index)
