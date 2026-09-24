import socket
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt6 import sip
from PyQt6.QtCore import QThread, pyqtSignal

from lanscanman.core import ai_chat
from lanscanman.core.ai_discovery import AI_PORTS, identify, list_models
from lanscanman.services import http

CONNECT_TIMEOUT = 0.6
MAX_PARALLEL = 32

# Threads started by short-lived windows are owned here, not by the window:
# a QThread destroyed while running aborts the whole process, and a chat
# window can be closed (or the app quit) while a request is in flight.
# Results are delivered to bound methods, which Qt disconnects automatically
# when the receiving window is gone.
_running: set[QThread] = set()


def keep_alive(thread: QThread) -> QThread:
    _running.add(thread)
    thread.finished.connect(lambda t=thread: _running.discard(t))
    return thread


def wait_for_all(timeout_ms: int = 3000) -> None:
    """At shutdown: let in-flight requests finish (or give up after a while).
    A finished worker can already have been deleted by Qt before its queued
    'finished' reached us; those are simply dropped."""
    for t in list(_running):
        if isinstance(t, QThread) and sip.isdeleted(t):
            _running.discard(t)
            continue
        if hasattr(t, "stop"):
            t.stop()
        t.wait(timeout_ms)


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            return True
    except OSError:
        return False


class AIDiscoveryWorker(QThread):
    """Check every host on every AI port; emit each AI server found.
    A quick TCP connect filters closed ports before any HTTP is sent."""
    service_found = pyqtSignal(object)        # AIService
    progress      = pyqtSignal(int, int)      # done, total

    def __init__(self, hosts: list[str], ports=None, parent=None, scheme: str = "http"):
        super().__init__(parent)
        self.hosts = list(dict.fromkeys(hosts))          # de-dupe, keep order
        self.ports = list(ports or AI_PORTS)
        self.scheme = scheme

    def _probe(self, host: str, port: int):
        if self.isInterruptionRequested() or not _port_open(host, port):
            return None
        return identify(host, port, lambda url, headers: http.fetch(url, headers), self.scheme)

    def run(self):
        jobs = [(h, p) for h in self.hosts for p in self.ports]
        done = 0
        with ThreadPoolExecutor(max_workers=MAX_PARALLEL) as pool:
            futures = [pool.submit(self._probe, h, p) for h, p in jobs]
            for fut in as_completed(futures):
                done += 1
                self.progress.emit(done, len(jobs))
                try:
                    svc = fut.result()
                except Exception:
                    svc = None
                if svc is not None:
                    self.service_found.emit(svc)
                if self.isInterruptionRequested():
                    for f in futures:
                        f.cancel()
                    break


class ModelListWorker(QThread):
    models_ready = pyqtSignal(list)

    def __init__(self, service, api_key=None, parent=None):
        super().__init__(parent)
        self.service, self.api_key = service, api_key

    def run(self):
        try:
            models = list_models(self.service, lambda u, h: http.fetch(u, h), self.api_key)
        except Exception:
            models = []
        self.models_ready.emit(models)


class CapabilityWorker(QThread):
    """Ask Ollama what a model can do (vision, thinking, …). Emits None when
    the server doesn't say, so the UI can leave features enabled."""
    capabilities_ready = pyqtSignal(str, str, object)     # base_url, model, set[str] | None
    context_ready      = pyqtSignal(str, str, object)     # base_url, model, max context | None

    def __init__(self, base_url: str, model: str, api_key=None, parent=None):
        super().__init__(parent)
        self.base_url, self.model, self.api_key = base_url, model, api_key

    def run(self):
        caps = None
        try:
            status, _, body = http.post(
                self.base_url + ai_chat.OLLAMA_SHOW_PATH, ai_chat.show_request(self.model),
                ai_chat.request_headers(self.api_key))
            if status == 200:
                caps = ai_chat.parse_capabilities(body)
                self.context_ready.emit(self.base_url, self.model,
                                        ai_chat.parse_context_length(body))
        except Exception:
            caps = None
        self.capabilities_ready.emit(self.base_url, self.model, caps)


class ChatWorker(QThread):
    """Streams one reply. stop() closes the connection mid-reply."""
    token     = pyqtSignal(str)
    reasoning = pyqtSignal(str)               # the model's thinking, as it streams
    failed   = pyqtSignal(str)
    done     = pyqtSignal(str)                # the full reply

    def __init__(self, base_url: str, model: str, messages: list[dict],
                 api_key: str | None = None, parent=None, thinking: str = "default",
                 ollama: bool = False, num_ctx: int | None = None):
        """ollama=True: use Ollama's native /api/chat, which (unlike its
        OpenAI-compatible endpoint) accepts num_ctx."""
        super().__init__(parent)
        self.ollama, self.num_ctx = ollama, num_ctx
        self.url = base_url + (ai_chat.OLLAMA_CHAT_PATH if ollama else ai_chat.CHAT_PATH)
        self.model, self.messages, self.api_key = model, list(messages), api_key
        self.thinking = thinking
        self._resp = None
        self._stopped = False

    def stop(self):
        self._stopped = True
        try:
            if self._resp is not None:
                self._resp.close()
        except Exception:
            pass

    def run(self):
        reply = []
        try:
            if self.ollama:
                body = ai_chat.ollama_request_body(self.model, self.messages, self.thinking,
                                                   self.num_ctx)
                parse = ai_chat.parse_ollama_line
            else:
                body = ai_chat.request_body(self.model, self.messages, self.thinking)
                parse = ai_chat.parse_stream_line
            self._resp = http.post_stream(self.url, body, ai_chat.request_headers(self.api_key))
            for raw in self._resp:
                if self._stopped:
                    break
                chunk = parse(raw.decode("utf-8", errors="replace"))
                if chunk is None:
                    continue
                if chunk.error:
                    self.failed.emit(chunk.error)
                    return
                if chunk.reasoning:
                    self.reasoning.emit(chunk.reasoning)
                if chunk.content:
                    reply.append(chunk.content)
                    self.token.emit(chunk.content)
                if chunk.done:
                    break
        except urllib.error.HTTPError as e:
            msg = ai_chat.error_message(e.code, e.read())
            if e.code not in (401, 403):
                msg += ai_chat.thinking_hint(self.thinking)
            self.failed.emit(msg)
            return
        except Exception as e:
            if not self._stopped:
                self.failed.emit(f"Connection error: {e}")
                return
        finally:
            try:
                if self._resp is not None:
                    self._resp.close()
            except Exception:
                pass
        self.done.emit("".join(reply))
