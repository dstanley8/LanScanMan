"""
A chat as a tree of messages, so conversations can branch.

    user "hi" ── assistant "Hello!"  ── user "tell me a joke" ── assistant …
             └─ assistant "Hey."          (regenerated reply: a sibling)
    user "hey" (edited first message: a sibling of "hi", its own branch)

The conversation you see — and send — is the path from the root to the
current leaf. Regenerating adds a sibling reply; editing a message adds a
sibling user message; ◀ ▶ switch between siblings. Every node remembers
which model and server produced it, so a chat can move between hosts.

Pure data: serialisable with to_dict()/from_dict(), no Qt, no I/O.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field

SCHEMA_VERSION = 1
THINKING_LEVELS = ["default", "off", "low", "medium", "high"]


def _now() -> float:
    return time.time()


@dataclass
class Server:
    host: str = ""
    port: int = 0
    software: str = ""
    scheme: str = "http"

    @property
    def base_url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}"


@dataclass
class Node:
    id: str
    parent: str | None
    role: str                         # "user" | "assistant"
    content: object                   # str, or OpenAI multi-part list (text + images)
    reasoning: str = ""
    model: str = ""
    server: Server | None = None
    created: float = field(default_factory=_now)

    @property
    def text(self) -> str:
        if isinstance(self.content, str):
            return self.content
        return "".join(p.get("text", "") for p in self.content if p.get("type") == "text")

    @property
    def image_urls(self) -> list[str]:
        if isinstance(self.content, str):
            return []
        return [p["image_url"]["url"] for p in self.content if p.get("type") == "image_url"]


class ChatTree:
    def __init__(self, chat_id: str | None = None, title: str = ""):
        self.id = chat_id or str(uuid.uuid4())
        self.title = title
        self.created = _now()
        self.updated = self.created
        self.nodes: dict[str, Node] = {}
        self.children: dict[str | None, list[str]] = {None: []}
        self.current: str | None = None          # current leaf
        self.settings: dict = {"thinking": "default"}

    # ── building ─────────────────────────────────────────────────────────────

    def _add(self, node: Node) -> Node:
        if node.parent is not None and node.parent not in self.nodes:
            raise KeyError(f"unknown parent {node.parent}")
        self.nodes[node.id] = node
        self.children.setdefault(node.parent, []).append(node.id)
        self.children.setdefault(node.id, [])
        self.current = node.id
        self.updated = _now()
        if not self.title and node.role == "user" and node.text.strip():
            self.title = " ".join(node.text.split())[:60]
        return node

    def add_user(self, parent: str | None, content) -> Node:
        return self._add(Node(str(uuid.uuid4()), parent, "user", content))

    def add_assistant(self, parent: str, text: str, reasoning: str = "",
                      model: str = "", server: Server | None = None) -> Node:
        return self._add(Node(str(uuid.uuid4()), parent, "assistant", text,
                              reasoning, model, server))

    def remove_leaf(self, node_id: str) -> None:
        """Drop a message with no replies (e.g. one that failed to send)."""
        if self.children.get(node_id):
            raise ValueError("node has replies")
        node = self.nodes.pop(node_id)
        self.children[node.parent].remove(node_id)
        self.children.pop(node_id, None)
        if self.current == node_id:
            self.current = node.parent
        self.updated = _now()

    # ── navigating ───────────────────────────────────────────────────────────

    def path(self, leaf: str | None = None) -> list[Node]:
        """Root → leaf (default: the current leaf)."""
        out = []
        node_id = self.current if leaf is None else leaf
        while node_id is not None:
            node = self.nodes[node_id]
            out.append(node)
            node_id = node.parent
        return out[::-1]

    def siblings(self, node_id: str) -> list[str]:
        return self.children[self.nodes[node_id].parent]

    def sibling_position(self, node_id: str) -> tuple[int, int]:
        """(1-based index, count) among messages sharing this node's parent."""
        sibs = self.siblings(node_id)
        return sibs.index(node_id) + 1, len(sibs)

    def latest_leaf(self, node_id: str) -> str:
        """Follow the most recently added child down to a leaf."""
        while self.children.get(node_id):
            node_id = max(self.children[node_id], key=lambda c: self.nodes[c].created)
        return node_id

    def switch_sibling(self, node_id: str, step: int) -> str:
        """Show the previous/next alternative for this message; returns it."""
        sibs = self.siblings(node_id)
        target = sibs[(sibs.index(node_id) + step) % len(sibs)]
        self.current = self.latest_leaf(target)
        return target

    def select(self, node_id: str) -> None:
        """Make the conversation end at node_id (e.g. before regenerating)."""
        if node_id is not None and node_id not in self.nodes:
            raise KeyError(node_id)
        self.current = node_id

    # ── for the API ──────────────────────────────────────────────────────────

    def messages(self, leaf: str | None = None) -> list[dict]:
        """OpenAI-style messages along the path, after the chat's system
        instructions if it has any. Thinking is not included — it is never
        sent back. Content objects are passed through untouched so re-sent
        history stays byte-identical (server prompt caches)."""
        system = self.settings.get("system")
        head = [{"role": "system", "content": system}] if system else []
        return head + [{"role": n.role, "content": n.content} for n in self.path(leaf)]

    def last_server(self) -> Server | None:
        for node in reversed(self.path()):
            if node.server is not None:
                return node.server
        return None

    def last_model(self) -> str:
        for node in reversed(self.path()):
            if node.model:
                return node.model
        return ""

    # ── serialisation ────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "version": SCHEMA_VERSION,
            "id": self.id,
            "title": self.title,
            "created": self.created,
            "updated": self.updated,
            "current": self.current,
            "settings": dict(self.settings),
            "nodes": [asdict(n) for n in sorted(self.nodes.values(), key=lambda n: n.created)],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ChatTree":
        tree = cls(data["id"], data.get("title", ""))
        tree.created = data.get("created", tree.created)
        for raw in data.get("nodes", []):
            server = raw.get("server")
            node = Node(raw["id"], raw.get("parent"), raw["role"], raw["content"],
                        raw.get("reasoning", ""), raw.get("model", ""),
                        Server(**server) if server else None, raw.get("created", 0.0))
            tree.nodes[node.id] = node
            tree.children.setdefault(node.parent, []).append(node.id)
            tree.children.setdefault(node.id, [])
        current = data.get("current")
        tree.current = current if current in tree.nodes else None
        tree.settings.update(data.get("settings") or {})
        tree.updated = data.get("updated", tree.created)
        return tree

    def summary(self) -> dict:
        """What the saved-chats list shows (no message content beyond the title)."""
        server = self.last_server()
        return {
            "id": self.id,
            "title": self.title or "Untitled chat",
            "updated": self.updated,
            "messages": len(self.nodes),
            "model": self.last_model(),
            "server": f"{server.host}:{server.port}" if server else "",
        }
