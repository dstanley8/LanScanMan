"""
Preparing pictures for vision models (Qt image handling, so it lives in ui/).

Each attached image is decoded and re-encoded once:
- scaled down so the longest side is at most MAX_SIDE px (keeps requests fast)
- re-encoded from the pixels only, which drops EXIF metadata such as GPS
  location, camera serial numbers and timestamps
- PNG when it has transparency or is small (screenshots stay crisp), JPEG
  otherwise
The resulting data: URL is stored with the message and re-sent unchanged on
later turns, so the server's prompt cache keeps matching.
"""

from __future__ import annotations

import base64

from PyQt6.QtCore import QBuffer, QByteArray, QIODevice, Qt
from PyQt6.QtGui import QImage

MAX_SIDE = 1536
PNG_LIMIT = 1_000_000          # bytes; larger PNGs are re-encoded as JPEG
JPEG_QUALITY = 85
THUMB_SIDE = 96


class ImageError(ValueError):
    pass


def _encode(img: QImage, fmt: str, quality: int = -1) -> bytes:
    data = QByteArray()
    buf = QBuffer(data)
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    img.save(buf, fmt, quality)
    buf.close()
    return bytes(data)


def load(source) -> QImage:
    """QImage from a QImage, raw bytes or a file path."""
    if isinstance(source, QImage):
        img = source
    elif isinstance(source, (bytes, bytearray)):
        img = QImage.fromData(bytes(source))
    else:
        img = QImage(str(source))
    if img.isNull():
        raise ImageError("That file isn't an image LanScanMan can read.")
    return img


def prepare(source) -> tuple[str, QImage]:
    """(data URL to send, thumbnail to show)."""
    img = load(source)
    if max(img.width(), img.height()) > MAX_SIDE:
        img = img.scaled(MAX_SIDE, MAX_SIDE, Qt.AspectRatioMode.KeepAspectRatio,
                         Qt.TransformationMode.SmoothTransformation)
    # A fresh image from the pixels alone: no metadata survives
    img = img.convertToFormat(QImage.Format.Format_ARGB32 if img.hasAlphaChannel()
                              else QImage.Format.Format_RGB32)
    data, mime = _encode(img, "PNG"), "image/png"
    if not img.hasAlphaChannel() and len(data) > PNG_LIMIT:
        data, mime = _encode(img, "JPEG", JPEG_QUALITY), "image/jpeg"
    url = f"data:{mime};base64,{base64.b64encode(data).decode()}"
    thumb = img.scaled(THUMB_SIDE, THUMB_SIDE, Qt.AspectRatioMode.KeepAspectRatio,
                       Qt.TransformationMode.SmoothTransformation)
    return url, thumb


def is_image_file(path: str) -> bool:
    return path.lower().rsplit(".", 1)[-1] in {"png", "jpg", "jpeg", "gif", "bmp", "webp", "tif", "tiff"}


def thumbnail_from_data_url(url: str) -> QImage:
    """Thumbnail for a picture already stored in a message (data: URL)."""
    try:
        header, b64 = url.split(",", 1)
        if not header.startswith("data:image/"):
            raise ValueError
        img = load(base64.b64decode(b64))
    except (ValueError, ImageError) as e:
        raise ImageError("unreadable picture") from e
    return img.scaled(THUMB_SIDE, THUMB_SIDE, Qt.AspectRatioMode.KeepAspectRatio,
                      Qt.TransformationMode.SmoothTransformation)
