"""AI tab: server recognition, the chat protocol, workers and UI — all against fakes."""

import json
import urllib.request

import pytest
from conftest import FakeChatWorker, FakeKeyring

from lanscanman.core import ai_chat
from lanscanman.core.ai_discovery import (
    CHAT,
    FRONTEND,
    IMAGE,
    AIService,
    identify,
    keyring_name,
    list_models,
    primary_action,
)
from lanscanman.services import http
from lanscanman.services.secret_store import SERVICE, SecretStore


def _json(obj, status=200):
    return (status, "application/json", json.dumps(obj).encode())


HTML = (200, "text/html; charset=utf-8", b"<html></html>")


def fake_server(routes: dict):
    """fetch() that serves `routes` {path: response}; unknown paths 404."""
    calls = []

    def fetch(url, headers):
        calls.append((url, dict(headers)))
        path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
        if path in routes:
            r = routes[path]
            if isinstance(r, Exception):
                raise r
            return r
        return (404, "text/plain", b"not found")
    fetch.calls = calls
    return fetch


def refused(url, headers):
    raise ConnectionRefusedError()


# ── recognising servers ─────────────────────────────────────────────────────

def test_ollama():
    svc = identify("192.168.50.5", 11434, fake_server({
        "/api/tags": _json({"models": [{"name": "llama3:8b"}, {"name": "qwen2.5:14b"}]}),
        "/": (200, "text/plain", b"Ollama is running"),
    }))
    assert (svc.software, svc.kind, svc.has_ui) == ("Ollama", CHAT, False)
    assert svc.models == ["llama3:8b", "qwen2.5:14b"]
    assert primary_action(svc) == "chat"


def test_llama_cpp_with_builtin_ui():
    svc = identify("192.168.50.5", 8080, fake_server({
        "/v1/models": _json({"object": "list", "data": [{"id": "qwen3-8b"}]}),
        "/": HTML,
    }))
    assert (svc.software, svc.kind, svc.has_ui) == ("OpenAI-compatible", CHAT, True)
    assert primary_action(svc) == "open_ui"        # hand off to its own UI


def test_lm_studio_without_ui_gets_our_chat():
    svc = identify("192.168.50.5", 1234, fake_server({
        "/v1/models": _json({"data": [{"id": "a"}, {"id": "b"}]}),
    }))
    assert svc.models == ["a", "b"] and primary_action(svc) == "chat"


def test_openai_compatible_needing_a_key():
    svc = identify("192.168.50.5", 8000, fake_server({
        "/v1/models": _json({"error": {"message": "Invalid API key"}}, 401),
    }))
    assert svc.needs_key and svc.models == [] and primary_action(svc) == "chat"


@pytest.mark.parametrize("routes, software", [
    ({"/system_stats": _json({"system": {"os": "posix"}, "devices": []}), "/": HTML}, "ComfyUI"),
    ({"/sdapi/v1/sd-models": _json([{"model_name": "sdxl", "title": "sdxl.safetensors"}]), "/": HTML},
     "Stable Diffusion WebUI"),
    ({"/api/v1/app/version": _json({"version": "4.2.0"}), "/": HTML}, "InvokeAI"),
])
def test_image_generators_open_their_ui(routes, software):
    svc = identify("192.168.50.7", 7860, fake_server(routes))
    assert (svc.software, svc.kind) == (software, IMAGE)
    assert primary_action(svc) == "open_ui" and svc.ui_url == "http://192.168.50.7:7860/"


def test_open_webui_is_a_frontend():
    svc = identify("192.168.50.8", 3000, fake_server({
        "/api/config": _json({"name": "Open WebUI", "version": "0.6"}), "/": HTML}))
    assert (svc.software, svc.kind) == ("Open WebUI", FRONTEND)
    assert primary_action(svc) == "open_ui" and not svc.chat_capable


@pytest.mark.parametrize("routes", [
    {"/": HTML},                                                   # router admin page
    {"/v1/models": (401, "text/html", b"<h1>Login</h1>"), "/": HTML},  # generic 401 page
    {"/v1/models": _json({"unrelated": True})},
    {"/api/tags": (200, "text/html", b"<html>")},
])
def test_non_ai_web_servers_are_ignored(routes):
    assert identify("192.168.1.1", 8080, fake_server(routes)) is None


def test_unreachable_host():
    assert identify("192.168.50.9", 11434, refused) is None


def test_list_models_sends_key():
    fetch = fake_server({"/v1/models": _json({"data": [{"id": "m"}]})})
    svc = AIService("192.168.50.5", 8080, "OpenAI-compatible", CHAT)
    assert list_models(svc, fetch, "sk-123") == ["m"]
    assert fetch.calls[-1][1] == {"Authorization": "Bearer sk-123"}


def test_urls_and_keyring_names():
    svc = AIService("fe80::1", 11434, "Ollama", CHAT)
    assert svc.base_url == "http://[fe80::1]:11434"
    assert keyring_name(AIService("192.168.50.5", 8080, "x", CHAT)) == "api-key http://192.168.50.5:8080"


# ── chat protocol ───────────────────────────────────────────────────────────

def test_request():
    body = json.loads(ai_chat.request_body("m", [{"role": "user", "content": "hi"}]))
    assert body == {"model": "m", "messages": [{"role": "user", "content": "hi"}], "stream": True}
    assert ai_chat.request_headers("k")["Authorization"] == "Bearer k"
    assert "Authorization" not in ai_chat.request_headers(None)


@pytest.mark.parametrize("line, expected", [
    ('data: {"choices":[{"delta":{"content":"Hel"}}]}', ai_chat.Chunk(content="Hel")),
    ('data: {"choices":[{"delta":{"reasoning_content":"hmm"}}]}', ai_chat.Chunk(reasoning="hmm")),
    ('data: {"choices":[{"delta":{},"finish_reason":"stop"}]}', ai_chat.Chunk(done=True)),
    ("data: [DONE]", ai_chat.Chunk(done=True)),
    ('data: {"error":{"message":"model not found"}}', ai_chat.Chunk(error="model not found")),
    (": keep-alive", None),
    ("", None),
    ("data: not json", None),
])
def test_parse_stream_line(line, expected):
    assert ai_chat.parse_stream_line(line) == expected


def test_error_messages():
    assert "API key" in ai_chat.error_message(401, b'{"error":{"message":"bad key"}}')
    assert ai_chat.error_message(500, b'{"error":"boom"}') == "HTTP 500: boom"
    assert ai_chat.error_message(502, b"Bad Gateway") == "HTTP 502: Bad Gateway"


# ── http helper ─────────────────────────────────────────────────────────────

def _redirect(old, new):
    handler = http._SameHostRedirects()
    req = urllib.request.Request(old)
    return handler.redirect_request(req, None, 302, "Found", {}, new)


def test_redirects_stay_on_the_same_host():
    assert _redirect("http://192.168.50.5:8080/", "http://192.168.50.5:8080/ui") is not None
    assert _redirect("http://192.168.50.5:8080/", "http://evil.example/") is None
    assert _redirect("http://192.168.50.5:8080/", "http://192.168.50.5:9999/") is None


def test_http_ignores_proxy_settings(monkeypatch):
    import importlib
    monkeypatch.setenv("http_proxy", "http://proxy.invalid:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
    fresh = importlib.reload(http)
    assert not any(isinstance(h, urllib.request.ProxyHandler) and h.proxies
                   for h in fresh._opener.handlers)
    # control: a default opener *would* pick the proxy up
    assert any(isinstance(h, urllib.request.ProxyHandler) and h.proxies
               for h in urllib.request.build_opener().handlers)


# ── workers ─────────────────────────────────────────────────────────────────

class FakeStream:
    def __init__(self, lines):
        self.lines = [l.encode() + b"\n" for l in lines]
        self.closed = False

    def __iter__(self):
        return iter(self.lines)

    def close(self):
        self.closed = True


def _run_chat(monkeypatch, stream=None, error=None, **kw):
    from lanscanman.workers import ai
    sent = {}

    def post_stream(url, body, headers, timeout=300.0):
        sent.update(url=url, body=json.loads(body), headers=headers)
        if error:
            raise error
        return stream
    monkeypatch.setattr(ai.http, "post_stream", post_stream)
    w = ai.ChatWorker("http://192.168.50.5:11434", "llama3", [{"role": "user", "content": "hi"}], "k", **kw)
    out = {"tokens": [], "failed": None, "done": None, "reasoning": []}
    w.token.connect(out["tokens"].append)
    w.failed.connect(lambda m: out.update(failed=m))
    w.done.connect(lambda r: out.update(done=r))
    w.reasoning.connect(out["reasoning"].append)
    w.run()
    return out, sent


def test_chat_worker_streams(monkeypatch):
    stream = FakeStream([
        'data: {"choices":[{"delta":{"reasoning_content":"let me think"}}]}',
        'data: {"choices":[{"delta":{"content":"Hel"}}]}',
        'data: {"choices":[{"delta":{"content":"lo"}}]}',
        "data: [DONE]",
    ])
    out, sent = _run_chat(monkeypatch, stream)
    assert out["tokens"] == ["Hel", "lo"] and out["done"] == "Hello"
    assert out["reasoning"] == ["let me think"]
    assert sent["url"] == "http://192.168.50.5:11434/v1/chat/completions"
    assert sent["body"]["model"] == "llama3" and sent["headers"]["Authorization"] == "Bearer k"
    assert stream.closed


def test_chat_worker_reports_auth_errors(monkeypatch):
    import io
    import urllib.error
    err = urllib.error.HTTPError("u", 401, "Unauthorized", {}, io.BytesIO(b'{"error":{"message":"no"}}'))
    out, _ = _run_chat(monkeypatch, error=err)
    assert "API key" in out["failed"] and out["done"] is None


def test_chat_worker_reports_stream_errors(monkeypatch):
    out, _ = _run_chat(monkeypatch, FakeStream(['data: {"error":{"message":"model not loaded"}}']))
    assert out["failed"] == "model not loaded"


def test_discovery_worker_only_reports_ai(monkeypatch):
    from lanscanman.workers import ai
    open_ports = {("192.168.50.5", 11434), ("192.168.50.1", 8080)}
    monkeypatch.setattr(ai, "_port_open", lambda h, p: (h, p) in open_ports)
    servers = {
        ("192.168.50.5", 11434): fake_server({"/api/tags": _json({"models": [{"name": "m"}]})}),
        ("192.168.50.1", 8080): fake_server({"/": HTML}),                # router
    }

    def fetch(url, headers):
        host, port = url.split("//")[1].split("/")[0].rsplit(":", 1)
        return servers[(host, int(port))](url, headers)
    monkeypatch.setattr(ai.http, "fetch", fetch)
    found = []
    w = ai.AIDiscoveryWorker(["192.168.50.5", "192.168.50.1", "192.168.50.5"])
    w.service_found.connect(found.append)
    w.run()
    assert [(s.host, s.port, s.software) for s in found] == [("192.168.50.5", 11434, "Ollama")]


# ── UI ──────────────────────────────────────────────────────────────────────

def _tab(qapp, hosts=()):
    from lanscanman.ui.tabs.ai_tab import AITab
    return AITab(lambda: list(hosts))


def test_tab_buttons_follow_primary_action(qapp):
    tab = _tab(qapp)
    tab._add_service(AIService("192.168.50.5", 11434, "Ollama", CHAT, models=["m"]))
    tab._add_service(AIService("192.168.50.7", 8188, "ComfyUI", IMAGE, has_ui=True))
    tab._add_service(AIService("192.168.50.5", 11434, "Ollama", CHAT))      # duplicate ignored
    assert tab.table.rowCount() == 2
    assert tab.table.cellWidget(0, 5).text() == "Chat"
    assert tab.table.cellWidget(1, 5).text() == "Open Web UI"


def test_tab_opens_browser_or_chat(qapp, monkeypatch):
    from lanscanman.ui.tabs import ai_tab
    opened = []
    monkeypatch.setattr(ai_tab.webbrowser, "open", opened.append)
    tab = _tab(qapp)
    tab._activate_service(AIService("192.168.50.7", 8188, "ComfyUI", IMAGE, has_ui=True))
    assert opened == ["http://192.168.50.7:8188/"]
    tab._activate_service(AIService("192.168.50.5", 11434, "Ollama", CHAT, models=["m"]))
    assert len(tab._chats) == 1 and tab._chats[0].isVisible()
    tab._chats[0].close()


def test_find_button_discovers_scanned_hosts(qapp, monkeypatch):
    from lanscanman.ui.tabs import ai_tab
    started = []

    class FakeWorker:
        def __init__(self, hosts, ports, parent, scheme="http"):
            started.append((hosts, ports))
            self.service_found = self.progress = self.finished = type(
                "Sig", (), {"connect": lambda *a: None})()

        def start(self):
            pass
    monkeypatch.setattr(ai_tab, "AIDiscoveryWorker", FakeWorker)
    tab = _tab(qapp, [("192.168.50.5", "nas")])
    tab._find_btn.click()
    assert started == [(["127.0.0.1", "192.168.50.5"], None)]


def test_tab_host_list_includes_this_machine(qapp):
    tab = _tab(qapp, [("192.168.50.5", "nas"), ("127.0.0.1", "")])
    assert tab._hosts() == ["127.0.0.1", "192.168.50.5"]
    assert tab._labels["192.168.50.5"] == "nas" and tab._labels["127.0.0.1"] == "This machine"


def _chat_window(qapp, keyring=None, models=("a", "b")):
    from lanscanman.services.vault import Vault, set_vault
    from lanscanman.ui.dialogs.chat_window import ChatWindow
    set_vault(Vault(SecretStore(keyring)))
    return ChatWindow(AIService("192.168.50.5", 8080, "OpenAI-compatible", CHAT, models=list(models)))


def _say(win, text):
    win._input.setPlainText(text)
    win._send_or_stop()
    return FakeChatWorker.last


def test_chat_window_model_picker_and_reply_flow(qapp, fake_chat):
    win = _chat_window(qapp)
    assert [win._model.itemText(i) for i in range(win._model.count())] == ["a", "b"]
    w = _say(win, "hi")
    assert w.model == "a" and w.messages == [{"role": "user", "content": "hi"}]
    w.token.emit("Hel")
    w.token.emit("lo")
    w.done.emit("Hello")
    assert win.tree.messages()[-1] == {"role": "assistant", "content": "Hello"}
    assert "Hello" in win._transcript.toPlainText()
    w2 = _say(win, "again")
    # the whole history is re-sent, earlier messages unchanged (prompt cache stays valid)
    assert w2.messages[:2] == w.messages + [{"role": "assistant", "content": "Hello"}]


def test_chat_window_error_keeps_question_retryable(qapp, fake_chat):
    win = _chat_window(qapp)
    _say(win, "hi").failed.emit("The server needs an API key (or the key was rejected).")
    assert win.tree.messages() == [] and win.tree.nodes == {}
    assert "API key" in win._status.text()
    assert win._input.toPlainText() == "hi"            # given back for a retry


def test_thinking_hidden_by_default_and_toggles(qapp, fake_chat):
    win = _chat_window(qapp)
    w = _say(win, "why?")
    w.reasoning.emit("secret musings")
    assert "secret musings" not in win._transcript.toPlainText()
    assert "Thinking" in win._status.text()
    w.token.emit("Because.")
    w.done.emit("Because.")
    win._show_thinking.setChecked(True)            # tick: shown, greyed
    assert "secret musings" in win._transcript.toPlainText()
    win._show_thinking.setChecked(False)           # untick: hidden again
    assert "secret musings" not in win._transcript.toPlainText()
    assert "Because." in win._transcript.toPlainText()
    # thinking is never sent back to the model
    assert win.tree.messages()[-1] == {"role": "assistant", "content": "Because."}


def test_thinking_streams_live_when_shown(qapp, fake_chat):
    win = _chat_window(qapp)
    win._show_thinking.setChecked(True)
    w = _say(win, "why?")
    w.reasoning.emit("hmm ")
    w.reasoning.emit("ok")
    assert "hmm ok" in win._transcript.toPlainText()


# ── pictures ────────────────────────────────────────────────────────────────

def _png(w=40, h=30, color="red"):
    from PyQt6.QtGui import QColor, QImage
    img = QImage(w, h, QImage.Format.Format_RGB32)
    img.fill(QColor(color))
    return img


def _jpeg_with_exif(img) -> bytes:
    from PyQt6.QtCore import QBuffer, QByteArray, QIODevice
    data = QByteArray()
    buf = QBuffer(data)
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    img.save(buf, "JPEG", 90)
    raw = bytes(data)
    payload = b"Exif\x00\x00" + b"GPS-LAT-51.5007-LON-0.1246" * 4
    app1 = b"\xff\xe1" + (len(payload) + 2).to_bytes(2, "big") + payload
    return raw[:2] + app1 + raw[2:]                      # right after SOI


def test_images_are_shrunk_and_stripped(qapp):
    import base64

    from lanscanman.ui import images
    big = _jpeg_with_exif(_png(4000, 3000))
    assert b"GPS-LAT" in big
    url, thumb = images.prepare(big)
    mime, b64 = url[5:].split(";base64,")
    data = base64.b64decode(b64)
    assert b"GPS-LAT" not in data                        # metadata gone
    out = images.load(data)
    assert max(out.width(), out.height()) == images.MAX_SIDE
    assert (out.width(), out.height()) == (1536, 1152)   # aspect kept
    assert max(thumb.width(), thumb.height()) <= images.THUMB_SIDE


def test_small_screenshots_stay_png(qapp):
    from lanscanman.ui import images
    url, _ = images.prepare(_png())
    assert url.startswith("data:image/png;base64,")


def test_bad_image_is_rejected(qapp):
    from lanscanman.ui import images
    with pytest.raises(images.ImageError):
        images.prepare(b"not an image")


def test_attach_send_and_resend_identically(qapp, fake_chat):
    win = _chat_window(qapp)
    assert win.add_image(_png())
    assert len(win.pending) == 1 and win._attach_box.isVisibleTo(win)
    w = _say(win, "what colour?")
    content = w.messages[0]["content"]
    assert content[0] == {"type": "text", "text": "what colour?"}
    assert content[1]["type"] == "image_url" and content[1]["image_url"]["url"].startswith("data:image/")
    assert win.pending == [] and not win._attach_box.isVisibleTo(win)
    w.done.emit("Red.")
    w2 = _say(win, "sure?")
    assert w2.messages[0] == w.messages[0]               # same bytes -> cache hit


def test_paste_image_into_message_box(qapp):
    from PyQt6.QtCore import QMimeData
    win = _chat_window(qapp)
    md = QMimeData()
    md.setImageData(_png())
    win._input.insertFromMimeData(md)
    assert len(win.pending) == 1


def test_remove_pending_image(qapp):
    win = _chat_window(qapp)
    win.add_image(_png(color="red"))
    win.add_image(_png(color="blue"))
    win._remove_pending(0)
    assert len(win.pending) == 1


def test_text_only_model_greys_out_attach(qapp, fake_chat):
    win = _chat_window(qapp, models=("llama3", "gemma3"))
    win._on_capabilities("llama3", {"completion"})
    win._on_capabilities("gemma3", {"completion", "vision"})
    win._model.setCurrentText("llama3")
    assert not win._attach_btn.isEnabled() and not win.add_image(_png())
    win._model.setCurrentText("gemma3")
    assert win._attach_btn.isEnabled() and win.add_image(_png())
    win._model.setCurrentText("llama3")                  # switched after attaching
    win._input.setPlainText("look")
    win._send_or_stop()
    assert "can't see images" in win._status.text() and len(win.pending) == 1


def test_unknown_capabilities_leave_attach_enabled(qapp):
    win = _chat_window(qapp)                              # not Ollama: nobody says
    assert win.can_see_images() is None and win._attach_btn.isEnabled()


def test_capability_request_only_for_ollama(qapp, monkeypatch):
    from lanscanman.services.vault import Vault, set_vault
    from lanscanman.ui.dialogs import chat_window
    started = []

    class FakeCap:
        def __init__(self, base, model, key=None, parent=None):
            started.append(model)
            self.capabilities_ready = self.context_ready = self.finished = type("S", (), {"connect": lambda *a: None})()

        def start(self):
            pass

        def wait(self, *_):
            pass
    monkeypatch.setattr(chat_window, "CapabilityWorker", FakeCap)
    set_vault(Vault(SecretStore(None)))
    chat_window.ChatWindow(AIService("192.168.50.5", 11434, "Ollama", CHAT, models=["gemma3"]))
    chat_window.ChatWindow(AIService("192.168.50.5", 8080, "OpenAI-compatible", CHAT, models=["x"]))
    assert started == ["gemma3"]


def test_parse_capabilities():
    assert ai_chat.parse_capabilities(b'{"capabilities":["completion","vision"]}') == {"completion", "vision"}
    assert ai_chat.parse_capabilities(b'{"modelfile":"..."}') is None
    assert ai_chat.parse_capabilities(b"garbage") is None


def test_user_content_formats():
    assert ai_chat.user_content("hi") == "hi"
    assert ai_chat.user_content("", ["data:x"]) == [{"type": "image_url", "image_url": {"url": "data:x"}}]


def _click_box(monkeypatch, label, shown=None):
    from PyQt6.QtWidgets import QMessageBox

    def fake_exec(box):
        if shown is not None:
            shown.append(box.windowTitle())
        box._clicked = next(b for b in box.buttons() if b.text() == label)
    monkeypatch.setattr(QMessageBox, "exec", fake_exec)
    monkeypatch.setattr(QMessageBox, "clickedButton", lambda box: box._clicked)


def test_chat_window_remembers_key_only_when_asked(qapp, fake_chat, monkeypatch):
    _click_box(monkeypatch, "Send anyway")          # 192.168.50.5 is plain HTTP
    kr = FakeKeyring()
    item = (SERVICE, "api-key http://192.168.50.5:8080")
    win = _chat_window(qapp, kr)
    win._key.setText("sk-secret")
    _say(win, "q1").done.emit("reply")                     # not ticked: not saved
    assert item not in kr.items
    win._remember.setChecked(True)
    _say(win, "q2").done.emit("reply")
    assert kr.items[item] == "sk-secret"
    again = _chat_window(qapp, kr)                         # reopened: key restored
    assert again._key.text() == "sk-secret" and again._remember.isChecked()
    again._forget_key()
    assert item not in kr.items


def test_chat_window_without_keyring_disables_remember(qapp):
    win = _chat_window(qapp, None)
    assert not win._remember.isEnabled()


def test_chat_window_without_models_lets_you_type_one(qapp):
    win = _chat_window(qapp, models=())
    assert win._model.isEditable() and "API key" in win._status.text()


def test_thinking_is_greyed_out(qapp, fake_chat):
    from lanscanman.ui.dialogs.chat_window import THINKING_COLOR
    win = _chat_window(qapp)
    win._show_thinking.setChecked(True)
    w = _say(win, "q")
    w.reasoning.emit("pondering")
    w.token.emit("answer")
    doc = win._transcript.document()
    colours = {}
    block = doc.begin()
    while block.isValid():
        it = block.begin()
        while not it.atEnd():
            frag = it.fragment()
            colours[frag.text().strip()] = (frag.charFormat().foreground().color().name(),
                                            frag.charFormat().fontItalic())
            it += 1
        block = block.next()
    assert colours["pondering"] == (THINKING_COLOR.lower(), True)
    assert colours["answer"][0] != THINKING_COLOR.lower()


def test_capability_worker_asks_ollama(monkeypatch):
    from lanscanman.workers import ai
    sent = {}

    def post(url, body, headers=None, timeout=5.0):
        sent.update(url=url, body=json.loads(body))
        return 200, "application/json", b'{"capabilities":["completion","vision"]}'
    monkeypatch.setattr(ai.http, "post", post)
    got = []
    w = ai.CapabilityWorker("http://192.168.50.5:11434", "gemma3")
    w.capabilities_ready.connect(lambda b, m, c: got.append((m, c)))
    w.run()
    assert sent == {"url": "http://192.168.50.5:11434/api/show", "body": {"model": "gemma3"}}
    assert got == [("gemma3", {"completion", "vision"})]


def test_capability_worker_unknown_on_error(monkeypatch):
    from lanscanman.workers import ai
    monkeypatch.setattr(ai.http, "post", lambda *a, **k: (404, "", b"not found"))
    got = []
    w = ai.CapabilityWorker("http://192.168.50.5:8080", "x")
    w.capabilities_ready.connect(lambda b, m, c: got.append(c))
    w.run()
    assert got == [None]


def test_closing_chat_window_mid_request_does_not_crash(qapp, monkeypatch):
    """Regression: a chat window destroyed while its capability request was
    still running aborted the whole process (QThread destroyed while running)."""
    import gc
    import time

    from lanscanman.services.vault import Vault, set_vault
    from lanscanman.ui.dialogs.chat_window import ChatWindow
    from lanscanman.workers import ai

    def slow_post(*a, **k):
        time.sleep(0.4)
        return 200, "application/json", b'{"capabilities":["vision"]}'
    monkeypatch.setattr(ai.http, "post", slow_post)
    set_vault(Vault(SecretStore(None)))
    for _ in range(3):
        win = ChatWindow(AIService("192.168.50.5", 11434, "Ollama", CHAT, models=["gemma3"]))
        win.close()
        win.deleteLater()
        del win
        gc.collect()
        qapp.processEvents()
    assert ai._running                           # requests still in flight, owned by the registry
    ai.wait_for_all()
    qapp.processEvents()                         # their results arrive after the windows are gone
    assert not ai._running


# ── plain HTTP / HTTPS ──────────────────────────────────────────────────────

from lanscanman.core.ai_discovery import (  # noqa: E402
    is_local,
    parse_server_address,
    sends_key_in_clear,
)


@pytest.mark.parametrize("text, expected", [
    ("192.168.1.5:8080", ("http", "192.168.1.5", 8080)),
    ("http://ai.lan:11434", ("http", "ai.lan", 11434)),
    ("https://ai.home.lan", ("https", "ai.home.lan", 443)),
    ("https://ai.home.lan:8443/", ("https", "ai.home.lan", 8443)),
    ("https://[fe80::1]:8443", ("https", "fe80::1", 8443)),
])
def test_parse_server_address(text, expected):
    assert parse_server_address(text) == expected


@pytest.mark.parametrize("text", ["ai.lan", "ftp://x:21", "http://", ""])
def test_parse_server_address_rejects(text):
    with pytest.raises(ValueError):
        parse_server_address(text)


def test_when_keys_would_travel_in_clear():
    lan_http = AIService("192.168.50.5", 8080, "x", CHAT)
    lan_https = AIService("192.168.50.5", 8443, "x", CHAT, scheme="https")
    local = AIService("127.0.0.1", 11434, "x", CHAT)
    assert sends_key_in_clear(lan_http, "k")
    assert not sends_key_in_clear(lan_http, None)          # no key, nothing to leak
    assert not sends_key_in_clear(lan_https, "k")
    assert not sends_key_in_clear(local, "k")              # never leaves the machine
    assert is_local("localhost") and is_local("::1") and not is_local("192.168.50.5")
    assert lan_https.base_url == "https://192.168.50.5:8443"


def test_https_discovery_uses_https_urls():
    fetch = fake_server({"/v1/models": _json({"data": [{"id": "m"}]})})
    svc = identify("ai.lan", 8443, fetch, scheme="https")
    assert svc.encrypted and svc.base_url == "https://ai.lan:8443"
    assert all(url.startswith("https://") for url, _ in fetch.calls)


def test_plain_http_key_warning_and_confirmation(qapp, fake_chat, monkeypatch):
    shown = []
    _click_box(monkeypatch, "Cancel", shown)
    win = _chat_window(qapp)                                  # http://192.168.50.5:8080
    assert not win._clear_warning.isVisibleTo(win)
    win._key.setText("sk-secret")
    assert win._clear_warning.isVisibleTo(win)
    FakeChatWorker.last = None
    win._input.setPlainText("hi")
    win._send_or_stop()
    assert shown == ["Send API key unencrypted?"]
    assert FakeChatWorker.last is None and win.tree.nodes == {}   # nothing sent
    assert "unencrypted" in win._status.text()

    _click_box(monkeypatch, "Send anyway", shown)
    w = _say(win, "hi")
    assert w is not None and w.api_key == "sk-secret"
    w.done.emit("ok")
    _say(win, "again")                                        # asked only once per server
    assert shown.count("Send API key unencrypted?") == 2


def test_no_confirmation_without_a_key_or_over_https(qapp, fake_chat, monkeypatch):
    from lanscanman.services.vault import Vault, set_vault
    from lanscanman.ui.dialogs.chat_window import ChatWindow
    shown = []
    _click_box(monkeypatch, "Cancel", shown)
    win = _chat_window(qapp)
    _say(win, "no key").done.emit("fine")                     # no key: no prompt
    set_vault(Vault(SecretStore(None)))
    secure = ChatWindow(AIService("ai.lan", 8443, "OpenAI-compatible", CHAT,
                                  models=["m"], scheme="https"))
    secure._key.setText("sk-secret")
    assert not secure._clear_warning.isVisibleTo(secure)
    _say(secure, "hi")
    assert shown == []
    assert FakeChatWorker.last.base_url == "https://ai.lan:8443"


def test_saved_chats_remember_https(qapp):
    from lanscanman.core.chat_tree import ChatTree, Server
    t = ChatTree()
    u = t.add_user(None, "q")
    t.add_assistant(u.id, "a", server=Server("ai.lan", 8443, "x", "https"))
    again = ChatTree.from_dict(t.to_dict())
    assert again.last_server().base_url == "https://ai.lan:8443"
    old = t.to_dict()
    for n in old["nodes"]:
        if n.get("server"):
            n["server"].pop("scheme")                         # chats saved before https support
    assert ChatTree.from_dict(old).last_server().scheme == "http"


def test_add_server_reports_unreachable_https(qapp, monkeypatch):
    from PyQt6.QtWidgets import QInputDialog

    from lanscanman.ui.tabs import ai_tab
    started = []

    class FakeWorker:
        def __init__(self, hosts, ports, parent, scheme="http"):
            started.append((hosts, ports, scheme))
            self.service_found = self.progress = self.finished = type(
                "Sig", (), {"connect": lambda *a: None})()

        def start(self):
            pass
    monkeypatch.setattr(ai_tab, "AIDiscoveryWorker", FakeWorker)
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("https://ai.home.lan", True))
    tab = _tab(qapp)
    monkeypatch.setattr(tab, "_resolve", lambda host: ["192.168.1.40"])
    tab._add_server()
    assert started == [(["ai.home.lan"], [443], "https")]
    tab._discovery_done()
    assert "No AI server answered at https://ai.home.lan:443" in tab._status.text()
    assert "self-signed" in tab._status.text()


# ── AI servers must be on your own network ──────────────────────────────────

from lanscanman.core.ai_discovery import is_lan_address  # noqa: E402


@pytest.mark.parametrize("addr, lan", [
    ("192.168.1.5", True), ("10.20.30.40", True), ("172.20.1.1", True), ("127.0.0.1", True),
    ("::1", True), ("fe80::1", True), ("fd12:3456::1", True), ("169.254.10.1", True),
    ("100.101.102.103", True),                     # Tailscale / CGNAT
    ("::ffff:192.168.1.5", True),
    ("8.8.8.8", False), ("104.18.32.47", False), ("2606:4700::6810:84e5", False),
    ("::ffff:8.8.8.8", False), ("not-an-ip", False),
])
def test_is_lan_address(addr, lan):
    assert is_lan_address(addr) is lan


def _add(qapp, monkeypatch, text, addresses):
    from PyQt6.QtWidgets import QInputDialog, QMessageBox

    from lanscanman.ui.tabs import ai_tab
    started, warnings = [], []

    class FakeWorker:
        def __init__(self, hosts, ports, parent, scheme="http"):
            started.append((hosts, ports, scheme))
            self.service_found = self.progress = self.finished = type(
                "Sig", (), {"connect": lambda *a: None})()

        def start(self):
            pass
    monkeypatch.setattr(ai_tab, "AIDiscoveryWorker", FakeWorker)
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: (text, True))
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: warnings.append(a[2]))
    tab = _tab(qapp)
    monkeypatch.setattr(tab, "_resolve", lambda host: addresses)
    tab._add_server()
    return started, warnings


def test_add_server_refuses_internet_addresses(qapp, monkeypatch):
    started, warnings = _add(qapp, monkeypatch, "https://api.openai.com", ["104.18.32.47"])
    assert started == [] and "on the internet" in warnings[0]


def test_add_server_refuses_a_name_with_any_internet_address(qapp, monkeypatch):
    started, warnings = _add(qapp, monkeypatch, "ai.example:8080", ["192.168.1.5", "93.184.216.34"])
    assert started == [] and "93.184.216.34" in warnings[0]


def test_add_server_accepts_lan_and_vpn(qapp, monkeypatch):
    started, _ = _add(qapp, monkeypatch, "http://nas.lan:11434", ["192.168.1.5"])
    assert started == [(["nas.lan"], [11434], "http")]
    started, _ = _add(qapp, monkeypatch, "100.101.102.103:8080", ["100.101.102.103"])
    assert started == [(["100.101.102.103"], [8080], "http")]


def test_add_server_unresolvable(qapp, monkeypatch):
    started, warnings = _add(qapp, monkeypatch, "nowhere.invalid:8080", [])
    assert started == [] and "Couldn't find an address" in warnings[0]


def test_dns_is_blocked_in_tests():
    import socket
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo("example.com", 80)
    assert socket.getaddrinfo("127.0.0.1", 80)


# ── Context size (Ollama truncates silently) ─────────────────────────────────

def test_estimate_tokens_counts_text_and_images():
    assert ai_chat.estimate_tokens([{"role": "user", "content": "x" * 300}]) == 108
    img = [{"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}]
    assert ai_chat.estimate_tokens([{"role": "user", "content": img}]) >= 1000


def test_ollama_context_buckets_caps_and_never_shrinks():
    assert ai_chat.ollama_context(3000, None) is None             # default is fine
    assert ai_chat.ollama_context(3500, None) == 8192
    assert ai_chat.ollama_context(20000, None) == 32768           # 20000 + reply room
    assert ai_chat.ollama_context(20000, 16384) == 16384          # model max
    assert ai_chat.ollama_context(1000, None, previous=32768) == 32768


def test_parse_context_length():
    body = json.dumps({"model_info": {"general.architecture": "qwen3",
                                      "qwen3.context_length": 40960}}).encode()
    assert ai_chat.parse_context_length(body) == 40960
    assert ai_chat.parse_context_length(b"{}") is None
    assert ai_chat.parse_context_length(b"junk") is None


def test_ollama_request_body():
    msgs = [{"role": "user", "content": [
        {"type": "text", "text": "what is this"},
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,QUJD"}}]}]
    body = json.loads(ai_chat.ollama_request_body("gemma3", msgs, "off", num_ctx=16384))
    assert body["options"] == {"num_ctx": 16384} and body["think"] is False and body["stream"]
    assert body["messages"] == [{"role": "user", "content": "what is this", "images": ["QUJD"]}]
    plain = json.loads(ai_chat.ollama_request_body("qwen3", [{"role": "user", "content": "hi"}]))
    assert "options" not in plain and "think" not in plain
    assert json.loads(ai_chat.ollama_request_body("gpt-oss:20b", [], "high"))["think"] == "high"
    assert json.loads(ai_chat.ollama_request_body("qwen3", [], "high"))["think"] is True


def test_chat_worker_ollama_native(monkeypatch):
    stream = FakeStream([
        '{"message":{"role":"assistant","content":"","thinking":"hmm"},"done":false}',
        '{"message":{"role":"assistant","content":"Hel"},"done":false}',
        '{"message":{"role":"assistant","content":"lo"},"done":false}',
        '{"message":{"role":"assistant","content":""},"done":true}',
    ])
    out, sent = _run_chat(monkeypatch, stream, ollama=True, num_ctx=16384)
    assert sent["url"] == "http://192.168.50.5:11434/api/chat"
    assert sent["body"]["options"] == {"num_ctx": 16384}
    assert out["tokens"] == ["Hel", "lo"] and out["done"] == "Hello" and out["reasoning"] == ["hmm"]


def test_chat_worker_ollama_error_line(monkeypatch):
    out, _ = _run_chat(monkeypatch, FakeStream(['{"error":"model not found"}']), ollama=True)
    assert "model not found" in out["failed"] and out["done"] is None


def _ollama_window(qapp, context_max=None):
    from lanscanman.services.vault import Vault, set_vault
    from lanscanman.ui.dialogs.chat_window import ChatWindow
    set_vault(Vault(SecretStore(None)))
    win = ChatWindow(AIService("127.0.0.1", 11434, "Ollama", CHAT, models=["qwen3"]))
    win.context_max[win._cap_key()] = context_max
    return win


def test_short_ollama_chat_sends_no_context_size(qapp, fake_chat):
    w = _say(_ollama_window(qapp, 40960), "hi")
    assert w.ollama and w.num_ctx is None


def test_long_ollama_chat_asks_for_enough_context(qapp, fake_chat):
    win = _ollama_window(qapp, 40960)
    w = _say(win, "x" * 30000)                  # ~10k tokens + reply room
    assert w.num_ctx == 16384 and win.tree.settings["num_ctx"] == 16384
    w.done.emit("ok")
    assert _say(win, "short").num_ctx == 16384  # never shrinks mid-chat


def test_too_long_for_ollama_model_warns_and_keeps_text(qapp, fake_chat, monkeypatch):
    shown = []
    _click_box(monkeypatch, "Cancel", shown)
    win = _ollama_window(qapp, 8192)
    FakeChatWorker.last = None
    assert _say(win, "x" * 30000) is None
    assert shown == ["Too long for the model?"]
    assert win._input.toPlainText() == "x" * 30000 and win.tree.messages() == []


def test_too_long_send_anyway_caps_at_model_max(qapp, fake_chat, monkeypatch):
    _click_box(monkeypatch, "Send anyway")
    w = _say(_ollama_window(qapp, 8192), "x" * 30000)
    assert w.num_ctx == 8192


def test_other_servers_warn_once_about_large_messages(qapp, fake_chat, monkeypatch):
    shown = []
    _click_box(monkeypatch, "Send anyway", shown)
    win = _chat_window(qapp)
    shown.clear()
    w = _say(win, "x" * 30000)
    assert w.num_ctx is None and not w.ollama
    titles = [t for t in shown if t == "Too long for the model?"]
    assert len(titles) == 1
    w.done.emit("ok")
    _say(win, "y" * 30000)
    assert len([t for t in shown if t == "Too long for the model?"]) == 1
