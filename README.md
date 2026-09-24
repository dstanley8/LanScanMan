# LanScanMan

[![Tests](https://github.com/dstanley8/lanscanman/actions/workflows/tests.yml/badge.svg)](https://github.com/dstanley8/lanscanman/actions/workflows/tests.yml)

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
- **AI** — finds local AI servers on your network after a scan (Ollama, llama.cpp / llama-swap, LM Studio, vLLM, Open WebUI, ComfyUI, AUTOMATIC1111 and more). Servers with a web UI open in your browser (including image generators); the rest get a simple built-in chat window with a model picker, optional API key (can be remembered in your keyring), a thinking level (Default/Off/Low/Medium/High) and *Show thinking* toggle, picture attachments for vision models (shrunk and stripped of metadata), branching (regenerate a reply, edit an earlier message, switch between alternatives), and switching server/model mid-conversation. Chats save automatically, encrypted with a key from your keyring.
- **Ask a local AI about your disks** — from Disk Health, per disk, per host or as a fleet report: LanScanMan builds a report (current SMART readings, trends and rates it calculates from its history log, its own rule-based view) and opens a chat with it in the message box for you to review before sending. AI servers are limited to your own network.
- **New-device alerts** — after your first scan, any device not seen before is highlighted and triggers a desktop notification until you mark it as known. The device list is signed so it can't be quietly edited.
- **Host health** — the Host Monitor also reports failed systemd services, stopped/unhealthy Docker containers, pending apt updates (security counted separately) and reboot-required, all read-only.
- **Wake-on-LAN** — send magic packets to offline devices from the context menu.
- **Profile system** — save aliases and usernames per device, keyed by MAC address so profiles survive DHCP IP changes.
- **WiFi signal strength** — live dBm indicator in the status bar, reads `/proc/net/wireless` locally.
- **Centralised logging** — rotating log file at `~/.config/LanScanMan/lanscanman.log` (5 × 512 KB).

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
| `keyring` | Desktop keyring access (GNOME Keyring / KDE Wallet) | `pip install keyring` |

One-liner:
```bash
sudo apt install nmap rsync openssh-client && pip install PyQt6 paramiko python-nmap keyring
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

1. **Scan your network** — enter your subnet (auto-detected on launch) and click **Scan Network**. Your desktop will ask for your password for the privileged SYN scan (LanScanMan never sees it). Use **Scan (unprivileged)** to scan without root access (fewer details, no MACs).

2. **Set up a profile** — right-click any discovered host → **Edit Profile**. Set a nickname and your SSH username for that machine.

3. **Push your SSH key** — right-click → **Setup SSH Key**, enter the remote password once. All future connections use key auth.

4. **Double-click to connect** — opens a tmux session dialog if tmux is installed on the remote host, then launches your local terminal emulator.

5. **Monitor and health tabs** — once profiles are set up, the **Host Monitor** and **Disk Health** tabs populate automatically. Click **Refresh All** to probe all configured hosts.

6. **Schedule a transfer** — go to the **File Transfers** tab, click **Schedules**, then **New Schedule List**. Add transfers via the Queue tab (right-click any transfer → **Add to schedule list…**).

---

## Full SMART Data (optional)

By default, disk health uses `udisksctl` (no root needed), which provides basic SMART status, temperature, and power-on hours.

For full metrics (TBW, wear percentage, bad sector breakdown), grant passwordless sudo for `smartctl` on each remote host:

verify with which smartctl first — the path must be exact or the sudoers rule won't match. 

```bash
which smartctl
echo 'yourusername ALL=(root) NOPASSWD: /usr/sbin/smartctl' | sudo tee /etc/sudoers.d/smartctl
sudo chown root:root /etc/sudoers.d/smartctl
sudo chmod 0440 /etc/sudoers.d/smartctl
sudo visudo -c   # validate — should print "parsed OK"
```
If visudo -c reports an error, fix the file before logging out — a broken sudoers file can prevent all future sudo access.
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

- **Privileged scans — your choice of how to ask** (⚙ → *Ask for scan permission with*). **System prompt** (default): your desktop's polkit dialog (or polkit's terminal agent / `sudo -A` askpass if there's no agent), asked every scan; LanScanMan never sees the password. **sudo**: remembered by sudo itself for about 15 minutes, so repeat scans don't ask; it uses a graphical askpass if installed, otherwise LanScanMan's password box, whose password goes straight to sudo once and isn't kept. **sudo, remembered until LanScanMan closes (insecure)**: asked once in LanScanMan's password box and kept in memory (never on disk) until the app quits — only for machines you trust. ⚙ → *Forget remembered permission* clears any of this, and the app does so on exit. Nothing is installed; scan options are checked before asking.
- SSH agent forwarding (`-A`) is only used for remote-to-remote rsync transfers. A warning is shown in the UI before any such transfer is created. While the transfer runs, anyone with root on the sender can use your agent to log in to any machine your key opens. If a sender might be compromised at root level, transfer remote → local, then local → remote instead.
- **Man-in-the-middle defences.** The first connection to a host is checked against your own `~/.ssh/known_hosts`: if you've SSH'd there before and the key differs, LanScanMan refuses it instead of trusting it. Optional strict mode (⚙ → *Confirm new SSH host keys*) shows the fingerprint of any never-seen host and waits for your confirmation. A changed key later shows the old and new fingerprints and whether the scanner saw a different device take that IP, with *Keep blocked* as the default. In the AI tab, an API key for a plain-HTTP server on another machine triggers a warning and a one-time confirmation; `https://` servers can be added and are marked 🔒.
- LanScanMan maintains its own `~/.config/LanScanMan/known_hosts`, separate from your system `~/.ssh/known_hosts`. Only LanScanMan writes it: the `ssh` and `rsync` commands it launches use `StrictHostKeyChecking=yes`, after LanScanMan has pinned the host's key itself. A changed host key shows a warning and needs your confirmation.
- All remote commands run by the Monitor and Disk Health tabs are read-only. Nothing is installed or modified on remote hosts (except SSH keys, which you explicitly trigger).
- **Signed configuration.** `hosts.json`, `known_hosts` and `schedules.json` decide where LanScanMan connects and what it trusts, so each is HMAC-SHA256 signed. The signing key is kept in your desktop keyring (GNOME Keyring or KDE Wallet), encrypted with your login password. If there is no keyring it falls back to `hmac.key`. Existing files are signed the first time the key is unlocked after upgrading. A file changed outside LanScanMan blocks all connections until you review it.
- **If you decline the keyring at startup**, LanScanMan still opens and shows your saved hosts. Anything that connects, transfers or edits a profile asks for the keyring again first. Scheduled transfers stay off for that session.
- **SSH keys get a passphrase.** LanScanMan never creates a key without one. It runs `ssh-keygen` in a terminal so it never sees the passphrase, and it warns at startup if `~/.ssh/id_ed25519` is unencrypted. GNOME asks for the passphrase the first time the key is used and can remember it in your login keyring.
- The keyring protects the key *at rest*: a stolen disk, a leaked backup of `~/.config`, or a bug that exposes your files won't reveal it. It does not stop malware already running as your user while the keyring is unlocked, because Linux keyrings don't restrict which of your programs can read an item.
- All subprocess calls use list form (`shell=False`). User-supplied paths and rsync arguments are validated against a forbidden character set before use.
- No telemetry, no update checks, no network traffic beyond your local subnet.

See the **About & Security** tab inside the app for a full breakdown of every command sent to remote hosts.

---

## Data Stored Locally

All data is stored under `~/.config/LanScanMan/`:

| File | Contents |
|---|---|
| `hosts.json` | Host aliases, usernames, MAC→IP mappings |
| `transfer_history.json` | Completed transfer records |
| `schedules.json` | Scheduled rsync lists |
| `schedules.hmac` | HMAC signature for schedules.json |
| `hosts.json.sig`, `known_hosts.sig` | HMAC signatures for hosts.json and known_hosts |
| `hmac.key` | Signing key — **only when no keyring is available**; otherwise it's in the keyring as *LanScanMan / integrity-key* |
| `smart_log/<profile>.json` | Per-host SMART attribute history |
| `devices.json` (+ `.sig`) | Every device seen on the network, for new-device alerts (signed) |
| `security.json` (+ `.sig`) | Security preferences — strict mode, password-box fallback (signed; tampering assumes the strict choice) |
| `chats/` | Saved AI chats — encrypted (AES-256-GCM, key derived from your keyring) |
| `lanscanman.log` | Rotating application log |
| `known_hosts` | SSH host keys (separate from system known_hosts) |

---

## Project Structure

```
LanScanMan/
├── main.py              # entry point: python3 main.py
├── lanscanman/
│   ├── app.py           # main window, tab wiring, schedule timer
│   ├── paths.py         # every file under ~/.config/LanScanMan
│   ├── core/            # pure logic — parsers, command builders, data model (no Qt)
│   ├── services/        # SSH (paramiko), NetworkManager, subprocess side effects
│   ├── workers/         # QThreads: scans, probes, rsync, scheduled runs
│   └── ui/              # tabs/, dialogs/, widgets/, theme.py, resources/about.html
├── tests/               # pytest suite — never touches the network
└── docs/ARCHITECTURE.md # layers, data flow, conventions, known issues
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the layers fit together.

---

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
QT_QPA_PLATFORM=offscreen pytest        # ~220 tests, about a second
python -m pyflakes lanscanman           # lint
isort lanscanman tests                  # import order
```

The test suite blocks nmap, ping, ssh, rsync, sudo and outgoing sockets. A
test that tries to use them fails, so the suite is safe to run on any network.
It also uses a throwaway config directory, so your real profiles and schedules
are never touched. You can point the app itself at a different config directory
with `LANSCANMAN_CONFIG_DIR=/some/dir python3 main.py`.

### Continuous integration and releases

- Every push and pull request runs lint and the full test suite on Python 3.10 and 3.12 (`.github/workflows/tests.yml`).
- Pushing a tag such as `v0.3.0` runs the tests, builds the AppImage, smoke-tests it and attaches it (with a SHA-256 checksum) to a new GitHub release (`.github/workflows/release.yml`):

```bash
git tag v0.3.0 && git push origin v0.3.0
```

---

## Tested On

- Ubuntu 24.04
- Python 3.10+
- PyQt6 6.4+

---

## License

MIT — do what you like with it, no warranty implied.
