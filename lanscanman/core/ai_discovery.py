"""
Recognising local AI servers from read-only HTTP requests.

Each candidate host:port is identified by asking AI-specific endpoints
(never by port number alone), so a router's admin page on :8080 is not
mistaken for an AI server. Pure module: callers supply `fetch`, a function
(url, headers) -> (status, content_type, body_bytes) that raises OSError on
connection failure.

What the tab does with a result:
    has_ui  -> "Open Web UI" in the browser (covers image generators)
    else    -> LanScanMan's own chat window (OpenAI-compatible API)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable

Fetch = Callable[[str, dict], tuple[int, str, bytes]]

# Default ports of common local AI software. Order = probing order per host.
AI_PORTS: dict[int, str] = {
    11434: "Ollama",
    8080:  "llama.cpp / llama-swap / LocalAI / Open WebUI",
    1234:  "LM Studio",
    8000:  "vLLM",
    5000:  "text-generation-webui / TabbyAPI",
    5001:  "KoboldCpp",
    1337:  "Jan",
    3000:  "Open WebUI",
    7860:  "AUTOMATIC1111 / Forge / SD.Next",
    7865:  "Fooocus",
    8188:  "ComfyUI",
    9090:  "InvokeAI",
}

CHAT = "chat"
IMAGE = "image"
FRONTEND = "chat UI"        # a web front end for other servers (Open WebUI)


@dataclass
class AIService:
    host: str
    port: int
    software: str                     # "Ollama", "ComfyUI", "OpenAI-compatible", …
    kind: str                         # CHAT | IMAGE | FRONTEND
    models: list[str] = field(default_factory=list)
    has_ui: bool = False
    needs_key: bool = False           # /v1/models itself demanded a key
    ui_path: str = "/"
    scheme: str = "http"              # "https" for servers added as https://…

    @property
    def base_url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}"

    @property
    def encrypted(self) -> bool:
        return self.scheme == "https"

    @property
    def ui_url(self) -> str:
        return self.base_url + self.ui_path

    @property
    def chat_capable(self) -> bool:
        return self.kind == CHAT


def _json(body: bytes):
    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except ValueError:
        return None


def _get(fetch: Fetch, url: str, headers: dict | None = None):
    """(status, content_type, body) or None if the connection failed."""
    try:
        return fetch(url, headers or {})
    except OSError:
        return None


def _serves_html(fetch: Fetch, base: str, path: str = "/") -> bool:
    r = _get(fetch, base + path)
    return bool(r and r[0] == 200 and "html" in (r[1] or "").lower())


def _openai_models(data) -> list[str] | None:
    """Model ids from an OpenAI-style /v1/models body, or None if it isn't one."""
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        return [m.get("id", "") for m in data["data"] if isinstance(m, dict) and m.get("id")]
    return None


def identify(host: str, port: int, fetch: Fetch, scheme: str = "http") -> AIService | None:
    """What AI software (if any) answers on host:port."""
    base = AIService(host, port, "", "", scheme=scheme).base_url

    def svc(software, kind, **kw):
        return AIService(host, port, software, kind, scheme=scheme, **kw)

    # ComfyUI
    r = _get(fetch, base + "/system_stats")
    if r and r[0] == 200 and isinstance(_json(r[2]), dict) and "system" in _json(r[2]):
        return svc("ComfyUI", IMAGE, has_ui=True)

    # AUTOMATIC1111 / Forge / SD.Next
    r = _get(fetch, base + "/sdapi/v1/sd-models")
    if r and r[0] == 200 and isinstance(_json(r[2]), list):
        models = [m.get("model_name") or m.get("title", "") for m in _json(r[2]) if isinstance(m, dict)]
        return svc("Stable Diffusion WebUI", IMAGE,
                   models=[m for m in models if m], has_ui=True)

    # InvokeAI
    r = _get(fetch, base + "/api/v1/app/version")
    if r and r[0] == 200 and isinstance(_json(r[2]), dict) and "version" in _json(r[2]):
        return svc("InvokeAI", IMAGE, has_ui=True)

    # Open WebUI (a chat front end — hand off to it)
    r = _get(fetch, base + "/api/config")
    data = _json(r[2]) if r and r[0] == 200 else None
    if isinstance(data, dict) and "open webui" in str(data.get("name", "")).lower():
        return svc("Open WebUI", FRONTEND, has_ui=True)

    # Ollama (native API; also speaks OpenAI-compatible /v1 for chat)
    r = _get(fetch, base + "/api/tags")
    data = _json(r[2]) if r and r[0] == 200 else None
    if isinstance(data, dict) and isinstance(data.get("models"), list):
        models = [m.get("name", "") for m in data["models"] if isinstance(m, dict)]
        return svc("Ollama", CHAT, models=[m for m in models if m],
                   has_ui=_serves_html(fetch, base))

    # Any OpenAI-compatible server: llama.cpp, llama-swap, LM Studio, vLLM, …
    r = _get(fetch, base + "/v1/models")
    if r:
        data = _json(r[2])
        models = _openai_models(data)
        if r[0] == 200 and models is not None:
            return svc("OpenAI-compatible", CHAT, models=models,
                       has_ui=_serves_html(fetch, base))
        if r[0] in (401, 403) and isinstance(data, dict) and "error" in data:
            return svc("OpenAI-compatible", CHAT, needs_key=True,
                       has_ui=_serves_html(fetch, base))
    return None


def list_models(service: AIService, fetch: Fetch, api_key: str | None = None) -> list[str]:
    """Refresh a chat server's model list (e.g. once a key is supplied)."""
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    r = _get(fetch, service.base_url + "/v1/models", headers)
    if r and r[0] == 200:
        return _openai_models(_json(r[2])) or []
    return []


def primary_action(service: AIService) -> str:
    """'open_ui' when the server has a web page of its own, else 'chat'."""
    if service.has_ui or not service.chat_capable:
        return "open_ui"
    return "chat"


# Beyond RFC 1918 & co: the carrier-grade NAT range that Tailscale and
# similar VPNs use for devices on your own network
_EXTRA_LAN = ("100.64.0.0/10",)


def is_lan_address(address: str) -> bool:
    """On your own network: private, loopback, link-local or VPN (100.64/10).
    Anything else is the internet."""
    import ipaddress
    try:
        ip = ipaddress.ip_address(address.strip("[]").split("%")[0])
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or any(ip in ipaddress.ip_network(n) for n in _EXTRA_LAN if ip.version == 4))


def is_local(host: str) -> bool:
    """This machine (loopback) — traffic never leaves it."""
    import ipaddress
    if host in ("localhost", "localhost.localdomain"):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def sends_key_in_clear(service: AIService, api_key: str | None) -> bool:
    """An API key would cross the network unencrypted."""
    return bool(api_key) and not service.encrypted and not is_local(service.host)


def parse_server_address(text: str) -> tuple[str, str, int]:
    """'192.168.1.5:8080', 'http://h:8080' or 'https://h[:port]' ->
    (scheme, host, port). Raises ValueError."""
    from urllib.parse import urlsplit
    text = text.strip()
    if "://" not in text:
        text = "http://" + text
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("expected host:port, http://host:port or https://host:port")
    port = parts.port or (443 if parts.scheme == "https" else None)
    if port is None:
        raise ValueError("a port is needed for http:// servers")
    return parts.scheme, parts.hostname, port


def keyring_name(service: AIService) -> str:
    """Keyring item for this server's API key."""
    return f"api-key {service.base_url}"
