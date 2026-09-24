"""
The chat protocol for LanScanMan's own chat window: OpenAI-compatible
/v1/chat/completions with streaming, which Ollama, llama.cpp, llama-swap,
LM Studio, vLLM, LocalAI and friends all speak. Pure — no HTTP here.

Streaming replies arrive as server-sent events:

    data: {"choices":[{"delta":{"content":"Hel"}}]}
    data: {"choices":[{"delta":{"content":"lo"}}]}
    data: [DONE]

Reasoning models may also stream `delta.reasoning_content` (their thinking)
before the answer; that is reported separately so the UI can show or hide it.
Thinking is never sent back to the model.

Every request carries the whole conversation — the API is stateless — but
servers cache the processed prompt (llama.cpp prompt cache, Ollama's KV
cache, vLLM prefix caching), so only the new part costs anything *as long as
earlier messages are re-sent byte-for-byte identical*. Nothing here rewrites
past messages; images are encoded once when attached.

Ollama servers are the exception: they get the native /api/chat (NDJSON
stream), the only way to set the context size — see "Context size" below.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

CHAT_PATH = "/v1/chat/completions"


# Thinking level -> OpenAI `reasoning_effort`. "default" sends nothing, which
# every server accepts; the others are ignored or rejected by servers that
# don't support them (some finetunes silently ignore them).
REASONING_EFFORT = {"default": None, "off": "none", "low": "low",
                    "medium": "medium", "high": "high"}


def request_body(model: str, messages: list[dict], thinking: str = "default") -> bytes:
    body = {"model": model, "messages": messages, "stream": True}
    effort = REASONING_EFFORT.get(thinking)
    if effort is not None:
        body["reasoning_effort"] = effort
    return json.dumps(body).encode()


def thinking_hint(thinking: str) -> str:
    """Appended to request errors when a thinking level was set."""
    if REASONING_EFFORT.get(thinking) is None:
        return ""
    return ("\nThis server or model may not support thinking levels — "
            "set Thinking to Default and try again.")


def request_headers(api_key: str | None) -> dict:
    headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


@dataclass
class Chunk:
    content: str = ""
    reasoning: str = ""
    done: bool = False
    error: str = ""


def parse_stream_line(line: str) -> Chunk | None:
    """One line of the event stream -> Chunk, or None for blank/comment lines."""
    line = line.strip()
    if not line or line.startswith(":"):
        return None
    if not line.startswith("data:"):
        return None
    payload = line[5:].strip()
    if payload == "[DONE]":
        return Chunk(done=True)
    try:
        data = json.loads(payload)
    except ValueError:
        return None
    if isinstance(data, dict) and "error" in data:
        err = data["error"]
        return Chunk(error=err.get("message", str(err)) if isinstance(err, dict) else str(err))
    try:
        choice = data["choices"][0]
    except (KeyError, IndexError, TypeError):
        return None
    delta = choice.get("delta") or choice.get("message") or {}
    chunk = Chunk(content=delta.get("content") or "",
                  reasoning=delta.get("reasoning_content") or delta.get("reasoning") or "")
    if choice.get("finish_reason"):
        chunk.done = True
    return chunk


def error_message(status: int, body: bytes) -> str:
    """A readable error for a non-200 chat response."""
    detail = ""
    try:
        data = json.loads(body)
        err = data.get("error", data) if isinstance(data, dict) else data
        detail = err.get("message", "") if isinstance(err, dict) else str(err)
    except ValueError:
        detail = body.decode("utf-8", errors="replace").strip()[:300]
    if status in (401, 403):
        return "The server needs an API key (or the key was rejected)." + (f"\n{detail}" if detail else "")
    return f"HTTP {status}" + (f": {detail}" if detail else "")


def user_content(text: str, image_urls: list[str] | None = None):
    """Plain string for text-only messages; the OpenAI multi-part form
    (text + image_url parts) when images are attached."""
    if not image_urls:
        return text
    parts: list[dict] = [{"type": "text", "text": text}] if text else []
    parts += [{"type": "image_url", "image_url": {"url": url}} for url in image_urls]
    return parts


# ── Model capabilities (Ollama only; other servers don't report them) ────────

OLLAMA_SHOW_PATH = "/api/show"


def show_request(model: str) -> bytes:
    return json.dumps({"model": model}).encode()


def parse_capabilities(body: bytes) -> set[str] | None:
    """Ollama /api/show -> {"completion", "vision", "thinking", …}, or None
    when the server does not say (older Ollama, other software)."""
    try:
        data = json.loads(body)
    except ValueError:
        return None
    caps = data.get("capabilities") if isinstance(data, dict) else None
    return set(caps) if isinstance(caps, list) else None


# ── Context size ─────────────────────────────────────────────────────────────
# Ollama's context window defaults to a few thousand tokens, and its
# OpenAI-compatible endpoint can't change it: anything longer is silently
# cut from the *start* — the instructions and the beginning of a report
# vanish and the model improvises. For Ollama, LanScanMan therefore talks
# to the native /api/chat, which takes options.num_ctx.

REPLY_BUDGET = 4096               # tokens kept free for the answer (and thinking)
OLLAMA_DEFAULT_CONTEXT = 4096     # what Ollama uses unless configured otherwise
SHORT_PROMPT = OLLAMA_DEFAULT_CONTEXT - 1024   # fits the default with room to answer
_IMAGE_TOKENS = 1000              # rough allowance per attached picture


def estimate_tokens(messages: list[dict]) -> int:
    """A deliberately generous estimate (about 3 characters per token)."""
    chars, images = 0, 0
    for m in messages:
        content = m.get("content")
        if isinstance(content, str):
            chars += len(content)
        elif isinstance(content, list):
            for part in content:
                if part.get("type") == "text":
                    chars += len(part.get("text", ""))
                elif part.get("type") == "image_url":
                    images += 1
    return chars // 3 + images * _IMAGE_TOKENS + 8 * len(messages)


def ollama_context(prompt: int, model_max: int | None, previous: int | None = None) -> int | None:
    """num_ctx to request for a prompt of about `prompt` tokens: None while it
    fits Ollama's default with room for a short reply (nothing changes);
    otherwise the next of 8k/16k/32k/… that holds the prompt plus REPLY_BUDGET,
    never smaller than what this chat already used (each change makes Ollama
    reload the model), capped at the model's maximum."""
    if prompt <= SHORT_PROMPT and not previous:
        return None
    needed = prompt + REPLY_BUDGET
    size = 8192
    while size < needed:
        size *= 2
    if previous:
        size = max(size, previous)
    if model_max:
        size = min(size, model_max)
    return size


def parse_context_length(body: bytes) -> int | None:
    """The model's maximum context from Ollama /api/show (model_info
    "<architecture>.context_length")."""
    try:
        info = json.loads(body).get("model_info") or {}
    except (ValueError, AttributeError):
        return None
    for key, value in info.items():
        if key.endswith(".context_length") and isinstance(value, int):
            return value
    return None


# ── Ollama's native chat API ─────────────────────────────────────────────────

OLLAMA_CHAT_PATH = "/api/chat"


def _ollama_message(m: dict) -> dict:
    """OpenAI-style message -> Ollama: text in `content`, pictures as bare
    base64 in `images`."""
    content = m.get("content")
    if isinstance(content, str):
        return {"role": m["role"], "content": content}
    text, images = [], []
    for part in content or []:
        if part.get("type") == "text":
            text.append(part.get("text", ""))
        elif part.get("type") == "image_url":
            url = part.get("image_url", {}).get("url", "")
            images.append(url.split(",", 1)[1] if url.startswith("data:") else url)
    out = {"role": m["role"], "content": "\n".join(text)}
    if images:
        out["images"] = images
    return out


def ollama_request_body(model: str, messages: list[dict], thinking: str = "default",
                        num_ctx: int | None = None) -> bytes:
    body: dict = {"model": model, "messages": [_ollama_message(m) for m in messages],
                  "stream": True}
    if num_ctx:
        body["options"] = {"num_ctx": num_ctx}
    if thinking == "off":
        body["think"] = False
    elif thinking in ("low", "medium", "high"):
        # Levels are understood by gpt-oss; other thinking models take on/off
        body["think"] = thinking if "gpt-oss" in model else True
    return json.dumps(body).encode()


def parse_ollama_line(line: str) -> Chunk | None:
    """One NDJSON line of Ollama's streamed /api/chat reply."""
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    if "error" in data:
        return Chunk(error=str(data["error"]))
    msg = data.get("message") or {}
    return Chunk(content=msg.get("content") or "", reasoning=msg.get("thinking") or "",
                 done=bool(data.get("done")))
