"""
Every device ever seen on the network, so new ones can be flagged.

- Devices are keyed by MAC address. Unprivileged scans have no MACs, so
  those hosts are keyed "ip:<address>" until a privileged scan identifies
  them (the IP entry is then folded into the MAC entry, not re-alerted).
- The first scan is the baseline: everything in it counts as known.
- A new device stays flagged, scan after scan, until you mark it known.
  Devices you have a profile for are known automatically.
- Phones and laptops often use randomised ("private") Wi-Fi MACs that change
  now and then; those are recognisable (locally-administered bit) and are
  labelled so a re-alert can be judged.

The file is signed (it decides what does *not* raise an alert), so it is
passed in as a SignedFile-like object. Pure logic otherwise.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field


def device_key(ip: str, mac: str) -> str:
    mac = (mac or "").strip().lower()
    return mac if mac and mac != "—" and ":" in mac else f"ip:{ip}"


def is_randomised_mac(mac: str) -> bool:
    """Locally-administered unicast MAC (bit 1 of the first octet) — what
    phones and laptops use for private Wi-Fi addresses."""
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first & 0b10) and not (first & 0b1)


@dataclass
class ScanReport:
    new: list[dict] = field(default_factory=list)       # flagged devices seen in this scan
    baseline: int = 0                                   # >0: this scan set the baseline


class DeviceRegistry:
    def __init__(self, signed_file, clock=time.time):
        self._file = signed_file
        self._clock = clock
        self.devices: dict[str, dict] = {}
        self.baseline_done = False
        self._loaded = False

    # ── persistence ──────────────────────────────────────────────────────────

    def load(self) -> None:
        """Verified read. Raises KeyUnavailable / TamperedError."""
        raw = self._file.read()
        data = json.loads(raw) if raw else {}
        self.devices = data.get("devices", {}) if isinstance(data, dict) else {}
        self.baseline_done = bool(data.get("baseline_done")) if isinstance(data, dict) else False
        self._loaded = True

    def save(self) -> None:
        self._file.write(json.dumps({"baseline_done": self.baseline_done,
                                     "devices": self.devices}, indent=2).encode())

    # ── observing a scan ─────────────────────────────────────────────────────

    def _find_by_ip(self, ip: str) -> str | None:
        for key, d in self.devices.items():
            if d.get("ip") == ip:
                return key
        return None

    def observe(self, results: list[dict], known_macs=(), known_ips=()) -> ScanReport:
        """Record a scan. known_macs / known_ips (e.g. from profiles) count as
        known. Returns the flagged devices seen in this scan."""
        if not self._loaded:
            self.load()
        now = self._clock()
        known_macs = {m.lower() for m in known_macs}
        known_ips = set(known_ips)
        report = ScanReport()
        seen: list[str] = []

        for host in results:
            ip, mac = host.get("ip", ""), host.get("mac", "")
            key = device_key(ip, mac)
            if key.startswith("ip:") and key not in self.devices:
                # No MAC this time: an IP a known MAC device had counts as that device
                key = self._find_by_ip(ip) or key
            entry = self.devices.get(key)
            if entry is None:
                ip_entry = self.devices.pop(f"ip:{ip}", None) if not key.startswith("ip:") else None
                entry = ip_entry or {"first_seen": now, "acknowledged": False}
                self.devices[key] = entry
            entry.update(ip=ip, last_seen=now,
                         hostname=host.get("hostname") or entry.get("hostname", ""),
                         vendor=host.get("vendor") if host.get("vendor") not in (None, "", "unknown")
                         else entry.get("vendor", ""))
            history = entry.setdefault("ips", [])
            if ip and ip not in history:
                history.append(ip)              # every IP this device has used
            if key in known_macs or ip in known_ips:
                entry["acknowledged"] = True
            seen.append(key)

        if not self.baseline_done:
            for key in seen:
                self.devices[key]["acknowledged"] = True
            self.baseline_done = True
            report.baseline = len(seen)
        else:
            for key in dict.fromkeys(seen):
                d = self.devices[key]
                if not d.get("acknowledged"):
                    report.new.append(self.describe(key))
        self.save()
        return report

    # ── acknowledging ────────────────────────────────────────────────────────

    def acknowledge(self, keys) -> None:
        for key in keys:
            if key in self.devices:
                self.devices[key]["acknowledged"] = True
        self.save()

    def acknowledge_all(self) -> int:
        pending = [k for k, d in self.devices.items() if not d.get("acknowledged")]
        self.acknowledge(pending)
        return len(pending)

    def flagged_ips(self) -> dict[str, str]:
        """{ip: key} for devices not yet marked known."""
        return {d.get("ip", ""): k for k, d in self.devices.items() if not d.get("acknowledged")}

    def describe(self, key: str) -> dict:
        d = self.devices[key]
        mac = "" if key.startswith("ip:") else key
        return {"key": key, "ip": d.get("ip", ""), "mac": mac,
                "hostname": d.get("hostname", ""), "vendor": d.get("vendor", ""),
                "first_seen": d.get("first_seen"), "randomised_mac": bool(mac) and is_randomised_mac(mac),
                "no_mac": not mac}


def ip_owners(devices: dict[str, dict], ip: str) -> list[str]:
    """MAC addresses that have ever used this IP: the device that has it now
    first, then the others, most recently seen first."""
    owners = [k for k, d in devices.items()
              if not k.startswith("ip:") and (d.get("ip") == ip or ip in d.get("ips", []))]
    return sorted(owners, key=lambda k: (devices[k].get("ip") == ip,
                                         devices[k].get("last_seen") or 0.0), reverse=True)


def key_change_context(devices: dict[str, dict], ip: str) -> tuple[str, str]:
    """
    Help judge a changed host key from what the scanner has seen:

      ("moved", text)   more than one device has used this IP — a different
                        machine now answers here, so a different key is expected
      ("same", text)    only one device has had this IP — the same machine is
                        presenting a new key (reinstall… or interception)
      ("unknown", text) no MAC history for this IP

    MACs can be spoofed, so this informs the decision; it doesn't make it.
    """
    owners = ip_owners(devices, ip)
    if len(owners) > 1:
        return "moved", (f"This IP address has been used by more than one device. It now "
                         f"belongs to {owners[0]} (previously {owners[1]}), so a "
                         f"different host key is expected.")
    if len(owners) == 1:
        return "same", (f"The same device ({owners[0]}) has always had this IP address, "
                        f"and its key is now different. That's normal after reinstalling its "
                        f"operating system; if you haven't, someone may be intercepting the "
                        f"connection.")
    return "unknown", ("LanScanMan has no record of which device owns this IP (run a "
                       "privileged scan to find out).")
