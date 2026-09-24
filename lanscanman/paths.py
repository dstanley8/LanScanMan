"""
Every file LanScanMan reads or writes lives under one config directory,
~/.config/LanScanMan by default. Set LANSCANMAN_CONFIG_DIR to point the
whole app somewhere else (the test suite does this).
"""

import os
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("LANSCANMAN_CONFIG_DIR")
                  or Path.home() / ".config" / "LanScanMan")

HOSTS_FILE       = CONFIG_DIR / "hosts.json"
KNOWN_HOSTS      = CONFIG_DIR / "known_hosts"
TRANSFER_HISTORY = CONFIG_DIR / "transfer_history.json"
SCHEDULES_FILE   = CONFIG_DIR / "schedules.json"
SCHEDULES_HMAC   = CONFIG_DIR / "schedules.hmac"
HMAC_KEY         = CONFIG_DIR / "hmac.key"
SMART_LOG_DIR    = CONFIG_DIR / "smart_log"
CHATS_DIR        = CONFIG_DIR / "chats"
DEVICES_FILE     = CONFIG_DIR / "devices.json"
SECURITY_FILE    = CONFIG_DIR / "security.json"
LOG_FILE         = CONFIG_DIR / "lanscanman.log"
