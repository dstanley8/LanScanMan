"""
Encryption for saved chats: AES-256-GCM with a key derived (HKDF) from the
vault's integrity key, which lives in the desktop keyring. Deriving means no
second keyring item and no second prompt; the derived key is separate from
the signing key, so one can't be used as the other.

File format: b"LSMC1" + 12-byte nonce + ciphertext+tag.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from lanscanman import paths
from lanscanman.core.chat_store import ChatStore
from lanscanman.services.vault import get_vault

MAGIC = b"LSMC1"


def _chat_key(master: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"LanScanMan saved chats v1").derive(master)


def seal(data: bytes, master: bytes) -> bytes:
    nonce = os.urandom(12)
    return MAGIC + nonce + AESGCM(_chat_key(master)).encrypt(nonce, data, MAGIC)


def unseal(blob: bytes, master: bytes) -> bytes:
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 12 + 16:
        raise ValueError("not a LanScanMan chat file")
    nonce, ct = blob[len(MAGIC):len(MAGIC) + 12], blob[len(MAGIC) + 12:]
    try:
        return AESGCM(_chat_key(master)).decrypt(nonce, ct, MAGIC)
    except InvalidTag as e:
        raise ValueError("chat file could not be decrypted (wrong key or damaged)") from e


def chat_store() -> ChatStore:
    """The saved-chats store. Each read/write asks the vault for the key, so a
    locked keyring raises KeyUnavailable at that moment (and prompts again
    on the next action)."""
    vault = get_vault()
    return ChatStore(paths.CHATS_DIR,
                     seal=lambda d: seal(d, vault.key()),
                     unseal=lambda b: unseal(b, vault.key()))
