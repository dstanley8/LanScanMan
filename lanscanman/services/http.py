"""
Minimal HTTP for talking to AI servers on the LAN (standard library only).

- Proxy settings from the environment are ignored: these requests are for
  your own network and should never be sent via a proxy.
- Redirects are followed only within the same host and port.
- Discovery responses are capped at 1 MB.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

MAX_BODY = 1_000_000


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        if (old.scheme, old.netloc) != (new.scheme, new.netloc):
            return None          # stop here; caller sees the 3xx
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _SameHostRedirects())


def fetch(url: str, headers: dict | None = None, timeout: float = 3.0) -> tuple[int, str, bytes]:
    """GET -> (status, content_type, body). HTTP errors are returned, not
    raised; connection failures raise OSError."""
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with _opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers.get("Content-Type", ""), resp.read(MAX_BODY)
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", "") if e.headers else "", e.read(MAX_BODY)


def post_stream(url: str, body: bytes, headers: dict, timeout: float = 300.0):
    """POST and return the open response (iterate it for lines; close() to
    cancel). Raises urllib.error.HTTPError for non-2xx and OSError when the
    server can't be reached."""
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    return _opener.open(req, timeout=timeout)


def post(url: str, body: bytes, headers: dict | None = None,
         timeout: float = 5.0) -> tuple[int, str, bytes]:
    """POST -> (status, content_type, body); same error handling as fetch()."""
    req = urllib.request.Request(url, data=body, headers=headers or {}, method="POST")
    try:
        with _opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers.get("Content-Type", ""), resp.read(MAX_BODY)
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", "") if e.headers else "", e.read(MAX_BODY)
