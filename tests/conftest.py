"""
Test isolation.

1. LANSCANMAN_CONFIG_DIR is pointed at a throwaway directory *before* any
   lanscanman module is imported, so no test can touch ~/.config/LanScanMan.
2. The desktop keyring is disconnected: code that asks for the default
   SecretStore gets "no keyring" (file fallback). Tests that exercise the
   keyring path pass an in-memory fake explicitly.
3. Every test runs with the network tools and sockets booby-trapped: running
   nmap / sudo / ping / ssh / rsync or opening a real connection fails the
   test instead of reaching the network.
"""

import os
import socket
import subprocess
import tempfile

_CONFIG = tempfile.mkdtemp(prefix="lanscanman-test-")
os.environ["LANSCANMAN_CONFIG_DIR"] = _CONFIG

import pytest  # noqa: E402

FORBIDDEN = {"nmap", "sudo", "ping", "ssh", "rsync", "ssh-copy-id", "ssh-keygen", "notify-send",
             "pkexec", "pkttyagent"}


def _guard(real):
    def wrapper(args, *a, **kw):
        argv0 = os.path.basename(args[0] if isinstance(args, (list, tuple)) else str(args).split()[0])
        if argv0 in FORBIDDEN:
            raise AssertionError(f"test tried to run {argv0!r} — tests must not touch the network")
        return real(args, *a, **kw)
    return wrapper


class _NoNetworkSocket(socket.socket):
    def connect(self, address):
        raise AssertionError(f"test tried to connect to {address!r}")

    def sendto(self, *args):
        raise AssertionError("test tried to send a datagram")


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", _guard(subprocess.Popen))
    monkeypatch.setattr(subprocess, "run", _guard(subprocess.run))
    monkeypatch.setattr(socket, "socket", _NoNetworkSocket)

    real_getaddrinfo = socket.getaddrinfo

    def no_dns(host, *args, **kwargs):
        # Literal IP addresses still "resolve"; names never reach DNS
        import ipaddress
        try:
            ipaddress.ip_address(str(host).strip("[]"))
        except ValueError:
            raise socket.gaierror(f"DNS lookup of {host!r} blocked in tests") from None
        return real_getaddrinfo(host, *args, **kwargs)
    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    from lanscanman.services import secret_store
    monkeypatch.setattr(secret_store, "_secure_backend", lambda: None)


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    """Every test gets its own config dir and a fresh file-backed vault."""
    from lanscanman import paths
    from lanscanman.services import vault
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    for name, filename in [("HOSTS_FILE", "hosts.json"), ("KNOWN_HOSTS", "known_hosts"),
                           ("HMAC_KEY", "hmac.key"), ("SCHEDULES_FILE", "schedules.json"),
                           ("SCHEDULES_HMAC", "schedules.hmac"), ("SMART_LOG_DIR", "smart_log"),
                           ("TRANSFER_HISTORY", "transfer_history.json"),
                           ("CHATS_DIR", "chats"), ("DEVICES_FILE", "devices.json"),
                           ("SECURITY_FILE", "security.json")]:
        monkeypatch.setattr(paths, name, cfg / filename)
    monkeypatch.setattr(paths, "CONFIG_DIR", cfg)
    from lanscanman.core import sshkey
    monkeypatch.setattr(sshkey, "DEFAULT_KEY", tmp_path / "ssh" / "id_ed25519")
    from lanscanman.services import ssh
    monkeypatch.setattr(ssh, "SYSTEM_KNOWN_HOSTS", [tmp_path / "ssh" / "known_hosts"])
    vault.set_vault(vault.Vault(key_file=cfg / "hmac.key"))
    yield cfg
    try:
        from lanscanman.workers import ai
        ai.wait_for_all()       # no thread may outlive the test that started it
        ai._running.clear()     # (fakes never report "finished")
    except ImportError:
        pass
    vault.set_vault(None)
    try:
        import paramiko
    except ImportError:
        return

    def _no_ssh(self, hostname, *a, **kw):
        raise AssertionError(f"test tried to SSH to {hostname!r}")
    monkeypatch.setattr(paramiko.SSHClient, "connect", _no_ssh)


@pytest.fixture
def config_dir(tmp_path):
    return tmp_path


class FakeKeyring:
    """In-memory stand-in for a Secret Service backend."""
    name = "fake"

    def __init__(self, locked=False):
        self.items: dict[tuple[str, str], str] = {}
        self.locked = locked

    def _check(self):
        if self.locked:
            raise RuntimeError("collection is locked (prompt dismissed)")

    def get_password(self, service, name):
        self._check()
        return self.items.get((service, name))

    def set_password(self, service, name, value):
        self._check()
        self.items[(service, name)] = value

    def delete_password(self, service, name):
        self._check()
        del self.items[(service, name)]


@pytest.fixture
def fake_keyring():
    return FakeKeyring()


@pytest.fixture
def qapp():
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


class FakeChatWorker:
    """Stands in for ChatWorker: records the request; tests emit the reply."""
    last = None

    class _Sig:
        def __init__(self):
            self.slots = []

        def connect(self, fn):
            self.slots.append(fn)

        def emit(self, *a):
            for fn in self.slots:
                fn(*a)

    def __init__(self, base_url, model, messages, api_key=None, parent=None, thinking="default",
                 ollama=False, num_ctx=None):
        self.base_url, self.model, self.messages, self.api_key = base_url, model, list(messages), api_key
        self.thinking, self.ollama, self.num_ctx = thinking, ollama, num_ctx
        self.token, self.reasoning, self.failed, self.done, self.finished = (
            self._Sig() for _ in range(5))
        FakeChatWorker.last = self

    def start(self):
        pass

    def stop(self):
        pass

    def wait(self, *_):
        return True


@pytest.fixture
def fake_chat(monkeypatch):
    from lanscanman.ui.dialogs import chat_window
    monkeypatch.setattr(chat_window, "ChatWorker", FakeChatWorker)
    return FakeChatWorker
