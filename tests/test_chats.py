"""Saved chats, branching and thinking levels."""

import json

import pytest
from conftest import FakeChatWorker, FakeKeyring
from test_ai import _png, _say

from lanscanman import paths
from lanscanman.core import ai_chat
from lanscanman.core.ai_discovery import CHAT, AIService
from lanscanman.core.chat_store import ChatStore
from lanscanman.core.chat_tree import ChatTree, Server
from lanscanman.core.integrity import KeyUnavailable
from lanscanman.services import chat_crypto
from lanscanman.services.secret_store import SecretStore
from lanscanman.services.vault import Vault, set_vault

NAS = Server("192.168.50.5", 11434, "Ollama")
BOX = Server("192.168.50.60", 8080, "OpenAI-compatible")


# ── the tree ────────────────────────────────────────────────────────────────

def _chat():
    t = ChatTree()
    u1 = t.add_user(None, "What is DNS?")
    a1 = t.add_assistant(u1.id, "A phone book.", "user wants simple", "llama3", NAS)
    u2 = t.add_user(a1.id, "Shorter?")
    a2 = t.add_assistant(u2.id, "Names to IPs.", "", "qwen3", BOX)
    return t, u1, a1, u2, a2


def test_path_messages_and_title():
    t, u1, a1, u2, a2 = _chat()
    assert [n.id for n in t.path()] == [u1.id, a1.id, u2.id, a2.id]
    assert t.messages()[1] == {"role": "assistant", "content": "A phone book."}   # no thinking
    assert t.title == "What is DNS?"
    assert (t.last_model(), t.last_server()) == ("qwen3", BOX)


def test_regenerate_makes_a_sibling_and_keeps_the_old_reply():
    t, u1, a1, u2, a2 = _chat()
    t.select(u2.id)
    a2b = t.add_assistant(u2.id, "Name → IP.", model="qwen3", server=BOX)
    assert t.sibling_position(a2b.id) == (2, 2)
    assert t.messages()[-1]["content"] == "Name → IP."
    t.switch_sibling(a2b.id, -1)
    assert t.messages()[-1]["content"] == "Names to IPs."


def test_edit_branches_from_an_earlier_message():
    t, u1, a1, u2, a2 = _chat()
    u1b = t.add_user(None, "What is DHCP?")                 # edited first question
    assert t.messages() == [{"role": "user", "content": "What is DHCP?"}]
    assert t.sibling_position(u1b.id) == (2, 2)
    t.switch_sibling(u1b.id, 1)                           # wraps back to the original
    assert [n.id for n in t.path()] == [u1.id, a1.id, u2.id, a2.id]   # its latest leaf


def test_switch_picks_most_recent_leaf_of_a_branch():
    t, u1, a1, u2, a2 = _chat()
    t.select(u2.id)
    t.add_assistant(u2.id, "second answer")
    t.select(a1.id)
    other = t.add_user(a1.id, "different follow-up")
    t.switch_sibling(other.id, -1)
    assert t.path()[-1].content == "second answer"


def test_remove_leaf_only_without_replies():
    t, u1, a1, u2, a2 = _chat()
    with pytest.raises(ValueError):
        t.remove_leaf(u2.id)
    t.remove_leaf(a2.id)
    assert t.current == u2.id and a2.id not in t.nodes


def test_roundtrip_preserves_everything():
    t, u1, a1, u2, a2 = _chat()
    t.add_user(a2.id, [{"type": "text", "text": "look"},
                                  {"type": "image_url", "image_url": {"url": "data:image/png;base64,AA=="}}])
    t.settings["thinking"] = "high"
    again = ChatTree.from_dict(json.loads(json.dumps(t.to_dict())))
    assert again.messages() == t.messages()
    assert again.current == t.current and again.settings["thinking"] == "high"
    assert again.nodes[a1.id].reasoning == "user wants simple"
    assert again.nodes[a2.id].server == BOX
    assert again.path()[-1].image_urls == ["data:image/png;base64,AA=="]


def test_summary_has_no_message_bodies():
    t, *_ = _chat()
    s = t.summary()
    assert s["title"] == "What is DNS?" and s["model"] == "qwen3" and s["server"] == "192.168.50.60:8080"
    assert "phone book" not in json.dumps(s)


# ── encryption ──────────────────────────────────────────────────────────────

def test_seal_roundtrip_and_tamper():
    blob = chat_crypto.seal(b"secret chat", b"k" * 32)
    assert blob.startswith(b"LSMC1") and b"secret chat" not in blob
    assert chat_crypto.unseal(blob, b"k" * 32) == b"secret chat"
    with pytest.raises(ValueError):
        chat_crypto.unseal(blob, b"x" * 32)                 # wrong key
    with pytest.raises(ValueError):
        chat_crypto.unseal(blob[:-1] + bytes([blob[-1] ^ 1]), b"k" * 32)   # flipped bit
    with pytest.raises(ValueError):
        chat_crypto.unseal(b"plain json", b"k" * 32)


def test_chat_key_is_not_the_signing_key():
    assert chat_crypto._chat_key(b"k" * 32) != b"k" * 32


# ── store ───────────────────────────────────────────────────────────────────

def _store(tmp_path, key=b"k" * 32):
    return ChatStore(tmp_path / "chats", lambda d: chat_crypto.seal(d, key),
                     lambda b: chat_crypto.unseal(b, key))


def test_store_save_list_load_rename_delete(tmp_path):
    store = _store(tmp_path)
    t, *_ = _chat()
    store.save(t)
    other = ChatTree()
    other.add_user(None, "Second chat")
    store.save(other)
    assert [s["title"] for s in store.list()] == ["Second chat", "What is DNS?"]   # newest first
    assert store.load(t.id).messages() == t.messages()
    store.rename(t.id, "DNS basics")
    assert {s["title"] for s in store.list()} == {"Second chat", "DNS basics"}
    store.delete(other.id)
    assert [s["id"] for s in store.list()] == [t.id]


def test_nothing_readable_on_disk(tmp_path):
    store = _store(tmp_path)
    t, *_ = _chat()
    store.save(t)
    for f in (tmp_path / "chats").iterdir():
        raw = f.read_bytes()
        assert b"DNS" not in raw and b"phone book" not in raw and b"192.168.50.5" not in raw
        assert f.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "chats").stat().st_mode & 0o777 == 0o700


def test_damaged_index_is_rebuilt(tmp_path):
    store = _store(tmp_path)
    t, *_ = _chat()
    store.save(t)
    (tmp_path / "chats" / "index.bin").write_bytes(b"garbage")
    assert [s["id"] for s in store.list()] == [t.id]


def test_empty_chat_is_not_saved(tmp_path):
    store = _store(tmp_path)
    store.save(ChatTree())
    assert store.list() == []


def test_bad_ids_cannot_escape_the_folder(tmp_path):
    with pytest.raises(ValueError):
        _store(tmp_path).load("../../hosts")


def test_locked_keyring_blocks_saving():
    kr = FakeKeyring()
    set_vault(Vault(SecretStore(kr)))
    t, *_ = _chat()
    chat_crypto.chat_store().save(t)                       # unlocked: fine
    kr.locked = True
    set_vault(Vault(SecretStore(kr)))
    with pytest.raises(KeyUnavailable):
        chat_crypto.chat_store().list()


# ── thinking levels ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("level, effort", [
    ("default", None), ("off", "none"), ("low", "low"), ("medium", "medium"), ("high", "high"),
])
def test_reasoning_effort(level, effort):
    body = json.loads(ai_chat.request_body("m", [], level))
    assert body.get("reasoning_effort") == effort
    assert ("reasoning_effort" in body) == (effort is not None)


def test_thinking_hint_only_when_a_level_was_set():
    assert ai_chat.thinking_hint("default") == ""
    assert "Default" in ai_chat.thinking_hint("high")


# ── the window ──────────────────────────────────────────────────────────────

def _win(services=(), tree=None, service=None):
    from lanscanman.ui.dialogs.chat_window import ChatWindow
    set_vault(Vault(SecretStore(None), key_file=paths.HMAC_KEY))
    service = service or AIService("192.168.50.5", 11434, "Ollama", CHAT, models=["llama3", "qwen3"])
    return ChatWindow(service, services=lambda: list(services), tree=tree)


def _links(win):
    doc = win._transcript.document()
    hrefs = []
    block = doc.begin()
    while block.isValid():
        it = block.begin()
        while not it.atEnd():
            f = it.fragment()
            if f.charFormat().isAnchor():
                hrefs.append(f.charFormat().anchorHref())
            it += 1
        block = block.next()
    return hrefs


def _click(win, action, node_id):
    from PyQt6.QtCore import QUrl
    win._on_link(QUrl(f"lsm:{action}:{node_id}"))


def test_replies_are_autosaved_and_reload(qapp, fake_chat):
    win = _win()
    _say(win, "hello").done.emit("hi there")
    saved = chat_crypto.chat_store().list()
    assert [s["title"] for s in saved] == ["hello"]
    tree = chat_crypto.chat_store().load(saved[0]["id"])
    assert tree.messages()[-1] == {"role": "assistant", "content": "hi there"}
    assert tree.path()[-1].server == Server("192.168.50.5", 11434, "Ollama")


def test_regenerate_link(qapp, fake_chat):
    win = _win()
    _say(win, "joke?").done.emit("first joke")
    a1 = win.tree.current
    assert f"lsm:regen:{a1}" in _links(win)
    _click(win, "regen", a1)
    w = FakeChatWorker.last
    assert w.messages == [{"role": "user", "content": "joke?"}]        # re-asked from the question
    w.done.emit("second joke")
    assert win.tree.messages()[-1]["content"] == "second joke"
    new = win.tree.current
    assert win.tree.sibling_position(new) == (2, 2)
    assert f"lsm:prev:{new}" in _links(win)
    _click(win, "prev", new)
    assert win.tree.messages()[-1]["content"] == "first joke"
    assert "1/2" in win._transcript.toPlainText()


def test_edit_link_branches(qapp, fake_chat):
    win = _win()
    _say(win, "capital of France?").done.emit("Paris")
    first_q = win.tree.path()[0].id
    _say(win, "and Spain?").done.emit("Madrid")
    _click(win, "edit", first_q)
    assert win._edit_banner.isVisibleTo(win) and win._input.toPlainText() == "capital of France?"
    w = _say(win, "capital of Italy?")
    assert w.messages == [{"role": "user", "content": "capital of Italy?"}]  # branch from the top
    w.done.emit("Rome")
    assert [m["content"] for m in win.tree.messages()] == ["capital of Italy?", "Rome"]
    assert not win._edit_banner.isVisibleTo(win)
    _click(win, "prev", win.tree.path()[0].id)
    assert [m["content"] for m in win.tree.messages()][-1] == "Madrid"


def test_edit_keeps_pictures(qapp, fake_chat):
    win = _win()
    win.add_image(_png())
    _say(win, "what is this?").done.emit("a red square")
    _click(win, "edit", win.tree.path()[0].id)
    assert len(win.pending) == 1
    win._cancel_edit()
    assert win.pending == [] and not win._edit_banner.isVisibleTo(win)


def test_links_ignored_while_replying(qapp, fake_chat):
    win = _win()
    _say(win, "q").done.emit("a")
    a = win.tree.current
    _say(win, "q2")                                         # reply in progress
    _click(win, "regen", a)
    assert "Wait for the reply" in win._status.text()


def test_stop_while_thinking_adds_nothing(qapp, fake_chat):
    win = _win()
    w = _say(win, "hard question")
    w.reasoning.emit("hmm…")
    w.done.emit("")                                         # stopped before any answer
    assert win.tree.nodes == {}
    assert win._input.toPlainText() == "hard question"


def test_thinking_level_is_sent_and_saved(qapp, fake_chat):
    win = _win()
    win._thinking.setCurrentText("High")
    w = _say(win, "q")
    assert w.thinking == "high"
    w.done.emit("a")
    saved = chat_crypto.chat_store().load(win.tree.id)
    assert saved.settings["thinking"] == "high"
    again = _win(tree=saved)
    assert again._thinking.currentText() == "High"


def test_continue_saved_chat_on_another_server(qapp, fake_chat):
    ollama = AIService("192.168.50.5", 11434, "Ollama", CHAT, models=["llama3"])
    swap = AIService("192.168.50.60", 8080, "OpenAI-compatible", CHAT, models=["qwen3"])
    win = _win(services=[ollama, swap], service=ollama)
    _say(win, "hi").done.emit("hello from ollama")
    saved = chat_crypto.chat_store().load(win.tree.id)

    from lanscanman.ui.dialogs.chat_window import service_for
    reopened = _win(services=[ollama, swap], tree=saved,
                    service=service_for(saved.last_server(), [ollama, swap]))
    assert "hello from ollama" in reopened._transcript.toPlainText()
    idx = next(i for i in range(reopened._server.count())
               if reopened._server.itemData(i) is swap)
    reopened._server.setCurrentIndex(idx)
    reopened._on_server_chosen(idx)
    assert reopened._model.currentText() == "qwen3"
    w = _say(reopened, "and you?")
    assert w.base_url == "http://192.168.50.60:8080"
    assert [m["content"] for m in w.messages] == ["hi", "hello from ollama", "and you?"]
    w.done.emit("hello from llama-swap")
    last = reopened.tree.path()[-1]
    assert (last.model, last.server.host) == ("qwen3", "192.168.50.60")
    assert "qwen3 · 192.168.50.60" in reopened._transcript.toPlainText()


def test_service_for_unknown_server_makes_a_stand_in():
    from lanscanman.ui.dialogs.chat_window import service_for
    svc = service_for(BOX, [])
    assert (svc.host, svc.port, svc.software, svc.chat_capable) == ("192.168.50.60", 8080,
                                                                    "OpenAI-compatible", True)
    assert service_for(None, []) is None


def test_history_dialog_open_rename_delete(qapp, fake_chat, monkeypatch):
    from PyQt6.QtWidgets import QInputDialog, QMessageBox

    from lanscanman.ui.dialogs.chat_history import ChatHistoryDialog
    win = _win()
    _say(win, "first").done.emit("a")
    win._new_chat()
    _say(win, "second").done.emit("b")
    opened = []
    dlg = ChatHistoryDialog(opened.append)
    assert dlg._table.rowCount() == 2 and dlg._table.item(0, 0).text() == "second"
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("Renamed", True))
    dlg._rename()
    assert dlg._table.item(0, 0).text() == "Renamed"
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    dlg._delete()
    assert dlg._table.rowCount() == 1
    dlg._table.selectRow(0)
    dlg._open()
    assert [t.title for t in opened] == ["first"]
