# LanScanMan

A local-network administration utility for Linux. Scan your subnet, monitor host health, manage file transfers, inspect open ports, and check disk SMART status — all from one dark-themed desktop app.

Built with Python and PyQt6. No server component, no browser, no subscription, no agents installed on remote hosts.

---

## Features

- **Network Scanner** — SYN scan (privileged) or TCP connect scan (no sudo) via nmap. Discovers hosts, open ports, MAC addresses, vendor names, and SSH status. Background ping latency for every host. Add hosts manually for devices that don't respond to nmap.
- **Host Inspector** — deep port scan of a single host across Quick (top 1000), Full (all 65535), or Custom port ranges. Version detection via nmap `-sV`. Connect to any discovered port directly from results.
- **File Transfers** — rsync-based transfers between any combination of local and remote hosts, with live progress bars and per-file output. SFTP remote file browser included. Supports dry-run, recursive, checksum, delete, and compression flags.
  - **Scheduled Transfers** — named lists of rsync jobs with Manual, Interval (minutes/hours/days/months), or Day+Time triggers. Confirm-before-run option, missed-run handling (skip/run/warn), per-list failure behaviour (continue/abort). Schedule config is HMAC-SHA256 protected against external tampering.
- **Host Monitor** — per-host live view of CPU model/usage/temperature, RAM usage, GPU model/usage/VRAM/temperature (NVIDIA, AMD, Intel). Reads entirely from `/proc` and `/sys` — nothing installed on remote hosts.
- **Disk Health** — SMART data for all physical drives via `smartctl` (full metrics) with automatic fallback to `udisksctl` (basic health, no root needed). Shows capacity, filesystem usage, temperature, power-on hours, TBW, bad sectors, and wear level.
  - **SMART History** — logs degradation attributes (reallocated sectors, pending sectors, uncorrectable sectors, wear, TBW) to per-host JSON files. Draws degradation charts with a custom QPainter widget. Fires desktop notifications when attributes worsen.
- **SSH key management** — generate and push `ed25519` keys to remote hosts with one click.
- **tmux integration** — detect existing sessions, attach to them, or create new named sessions when connecting.
- **Wake-on-LAN** — send magic packets to offline devices from the context menu.
- **Profile system** — save aliases and usernames per device, keyed by MAC address so profiles survive DHCP IP changes.
- **WiFi signal strength** — live dBm indicator in the status bar, reads `/proc/net/wireless` locally.
- **Centralised logging** — rotating log file at `~/.config/LanScanMan/lanscanman.log` (5 × 512 KB).

---

## Screenshots

> Add screenshots here before publishing.

---

## Requirements

### Local machine

| Package | Purpose | Install |
|---|---|---|
| `nmap` | Network scanning | `sudo apt install nmap` |
| `rsync` | File transfers | `sudo apt install rsync` |
| `openssh-client` | Terminal connections and key management | Usually pre-installed |
| `PyQt6` | GUI framework | `pip install PyQt6` |
| `paramiko` | SSH/SFTP library | `pip install paramiko` |
| `python-nmap` | Nmap Python bindings | `pip install python-nmap` |

One-liner:
```bash
sudo apt install nmap rsync openssh-client && pip install PyQt6 paramiko python-nmap
```

### Remote hosts (optional but recommended)

| Package | Purpose | Install |
|---|---|---|
| `smartmontools` | Full SMART disk health data | `sudo apt install smartmontools` |
| `tmux` | Persistent terminal sessions | `sudo apt install tmux` |
| `rsync` | Receiving file transfers | `sudo apt install rsync` |
| `openssh-server` | SSH access | `sudo apt install openssh-server` |

---

## Installation

```bash
git clone https://github.com/dstanley8/LanScanMan.git
cd LanScanMan
pip install -r requirements.txt
python3 main.py
```

A virtual environment is recommended:
```bash
git clone https://github.com/dstanley8/LanScanMan.git
cd LanScanMan
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

---

## First Run

1. **Scan your network** — enter your subnet (auto-detected on launch) and click **Scan Network**. You'll be prompted for your sudo password for the privileged SYN scan. Use **Scan (No Sudo)** to scan without root access (fewer details, no MACs).

2. **Set up a profile** — right-click any discovered host → **Edit Profile**. Set a nickname and your SSH username for that machine.

3. **Push your SSH key** — right-click → **Setup SSH Key**, enter the remote password once. All future connections use key auth.

4. **Double-click to connect** — opens a tmux session dialog if tmux is installed on the remote host, then launches your local terminal emulator.

5. **Monitor and health tabs** — once profiles are set up, the **Host Monitor** and **Disk Health** tabs populate automatically. Click **Refresh All** to probe all configured hosts.

6. **Schedule a transfer** — go to the **File Transfers** tab, click **Schedules**, then **New Schedule List**. Add transfers via the Queue tab (right-click any transfer → **Add to schedule list…**).

---

## Full SMART Data (optional)

By default, disk health uses `udisksctl` (no root needed), which provides basic SMART status, temperature, and power-on hours.

For full metrics (TBW, wear percentage, bad sector breakdown), grant passwordless sudo for `smartctl` on each remote host:

```bash
echo 'yourusername ALL=(root) NOPASSWD: /usr/sbin/smartctl' | sudo tee /etc/sudoers.d/smartctl
```

---

## Keyboard Shortcuts

| Shortcut | Tab | Action |
|---|---|---|
| `Ctrl+Tab` | Any | Cycle to next tab |
| `Ctrl+Shift+Tab` | Any | Cycle to previous tab |
| `Ctrl+R` | Network Scanner | Privileged SYN scan |
| `Ctrl+Shift+R` | Network Scanner | Unprivileged TCP scan |
| `Escape` | Network Scanner / Host Inspector | Cancel running scan |
| `Enter` | Network Scanner | Connect to selected host |
| `Delete` | Network Scanner | Delete profile for selected host |
| `F5` | Host Inspector | Start scan |
| `Enter` | Host Inspector | Connect on selected port |
| `Ctrl+N` | File Transfers | Open Add Transfer dialog |
| `F5` | Host Monitor / Disk Health | Refresh all hosts |

---

## Security Notes

- The sudo password (for nmap) is held in memory only if you tick "Remember for this session". It is never written to disk.
- SSH agent forwarding (`-A`) is only used for remote-to-remote rsync transfers. A warning is shown in the UI before any such transfer is created.
- LanScanMan maintains its own `~/.config/LanScanMan/known_hosts` file, separate from your system `~/.ssh/known_hosts`. Any host key change triggers a visible warning dialog.
- All remote commands run by the Monitor and Disk Health tabs are read-only. Nothing is installed or modified on remote hosts (except SSH keys, which you explicitly trigger).
- Scheduled transfer lists are protected with HMAC-SHA256 using a per-install salt key. If the schedule file is modified outside LanScanMan, the app will refuse to run scheduled transfers and warn you on startup.
- All subprocess calls use list form (`shell=False`). User-supplied paths and rsync arguments are validated against a forbidden character set before use.
- No telemetry, no update checks, no network traffic beyond your local subnet.

See the **About & Security** tab inside the app for a full breakdown of every command sent to remote hosts.

---

## Data Stored Locally

All data is stored under `~/.config/LanScanMan/`:

| File | Contents |
|---|---|
| `profiles.json` | Host aliases, usernames, MAC→IP mappings |
| `transfer_history.json` | Completed transfer records |
| `schedules.json` | Scheduled rsync lists |
| `schedules.hmac` | HMAC integrity signature for schedules.json |
| `hmac.key` | Per-install HMAC salt (600 permissions) |
| `smart_log/<profile>.json` | Per-host SMART attribute history |
| `lanscanman.log` | Rotating application log |
| `known_hosts` | SSH host keys (separate from system known_hosts) |

---

## Project Structure

```
LanScanMan/
├── main.py                    # Application entry point and main window
├── manager.py                 # NetworkManager: profiles, SSH, WoL, ping
├── scanner.py                 # ScannerThread: nmap subnet scan wrapper
├── wifi_widget.py             # Local WiFi signal strength status bar widget
├── log.py                     # Centralised logger (console + rotating file)
├── schedule_manager.py        # Schedule data model, HMAC integrity, path validation
├── requirements.txt
└── tabs/
    ├── dialogs.py             # Shared dialogs: CustomPortConnectDialog
    ├── scanner_tab.py         # Network Scanner tab
    ├── host_inspector_tab.py  # Host Inspector tab
    ├── transfer_tab.py        # File Transfers tab (Queue + Schedules)
    ├── schedule_ui.py         # Schedules UI, ScheduledRunner, run detail dialog
    ├── monitor_tab.py         # Host Monitor tab (CPU/GPU/RAM)
    ├── smart_tab.py           # Disk Health tab (SMART)
    ├── smart_log.py           # SMART history logger and chart dialog
    └── about_tab.py           # About and Security documentation tab
```

---

## Tested On

- Ubuntu 24.04
- Python 3.10+
- PyQt6 6.4+

---

## License

MIT — do what you like with it, no warranty implied.
