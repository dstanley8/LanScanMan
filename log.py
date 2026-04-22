"""
log.py
──────
Centralised logger for LanScanMan.

Writes to both console (stderr) and a rolling log file at
  ~/.config/LanScanMan/lanscanman.log

Usage from any module:
    from log import log
    log.debug("Short message")
    log.info("Noteworthy event")
    log.warning("Something unexpected but recoverable")
    log.error("A failure the user should know about")
    log.exception("A caught exception — includes traceback")

Callers should prefer log.exception(msg) over log.error(msg) inside
except blocks; it automatically includes the traceback.
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


_LOG_DIR  = Path.home() / ".config" / "LanScanMan"
_LOG_FILE = _LOG_DIR / "lanscanman.log"


def _make_logger() -> logging.Logger:
    _LOG_DIR.mkdir(parents=True, exist_ok=True)

    lgr = logging.getLogger("lanscanman")
    lgr.setLevel(logging.DEBUG)
    # Guard against reconfiguration on reimport
    if lgr.handlers:
        return lgr

    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")

    # Console (stderr)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    lgr.addHandler(ch)

    # Rolling file — 5 files × 512 KB each = 2.5 MB max on disk
    try:
        fh = RotatingFileHandler(
            _LOG_FILE, maxBytes=512_000, backupCount=5, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        lgr.addHandler(fh)
    except Exception:
        # If we can't write to the log file (read-only FS, etc.) just
        # fall back to console-only. Do not crash the app over logging.
        pass

    lgr.propagate = False
    return lgr


log = _make_logger()