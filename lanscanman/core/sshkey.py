"""
Inspecting the user's SSH private key without ever decrypting it.

LanScanMan used to create ~/.ssh/id_ed25519 with an empty passphrase, which
made it a plain file that logs in to every host you set up. It now only
creates keys interactively (ssh-keygen in a terminal, so the app never sees
the passphrase) and warns about existing unencrypted keys.
"""

from __future__ import annotations

import base64
import shlex
import struct
from pathlib import Path

DEFAULT_KEY = Path.home() / ".ssh" / "id_ed25519"

_OPENSSH_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----"
_OPENSSH_END = "-----END OPENSSH PRIVATE KEY-----"
_MAGIC = b"openssh-key-v1\x00"


def is_encrypted(private_key_text: str) -> bool | None:
    """
    True / False for keys we can read the header of, None if the format is
    unrecognised. Reads only the cipher name — nothing is decrypted.
    """
    text = private_key_text.strip()
    if text.startswith(_OPENSSH_BEGIN):
        body = text[len(_OPENSSH_BEGIN):].split(_OPENSSH_END)[0]
        try:
            blob = base64.b64decode("".join(body.split()))
        except ValueError:
            return None
        if not blob.startswith(_MAGIC) or len(blob) < len(_MAGIC) + 4:
            return None
        (length,) = struct.unpack(">I", blob[len(_MAGIC):len(_MAGIC) + 4])
        cipher = blob[len(_MAGIC) + 4:len(_MAGIC) + 4 + length]
        return cipher != b"none"
    if text.startswith("-----BEGIN") and "PRIVATE KEY-----" in text.splitlines()[0]:
        # Legacy PEM: encrypted keys carry a Proc-Type header or are PKCS#8 "ENCRYPTED"
        return "ENCRYPTED" in text.splitlines()[0] or "Proc-Type: 4,ENCRYPTED" in text
    return None


def key_status(path: Path | None = None) -> str:
    """'missing' | 'encrypted' | 'unencrypted' | 'unknown'"""
    path = path or DEFAULT_KEY
    try:
        text = path.read_text()
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unknown"
    enc = is_encrypted(text)
    if enc is None:
        return "unknown"
    return "encrypted" if enc else "unencrypted"


def keygen_command(path: Path | None = None) -> str:
    """Interactive key creation — ssh-keygen asks for the passphrase itself."""
    return f"ssh-keygen -t ed25519 -f {shlex.quote(str(path or DEFAULT_KEY))}"


def add_passphrase_command(path: Path | None = None) -> str:
    """Interactive passphrase change (-p) on an existing key."""
    return f"ssh-keygen -p -f {shlex.quote(str(path or DEFAULT_KEY))}"


def ssh_add_command(path: Path | None = None) -> str:
    """Load the key into the running agent (asks for the passphrase once)."""
    return f"ssh-add {shlex.quote(str(path or DEFAULT_KEY))}"
