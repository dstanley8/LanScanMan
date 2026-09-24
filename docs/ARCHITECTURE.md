# LanScanMan architecture

LanScanMan is a single-process PyQt6 desktop app. The code is split into
four layers, each only allowed to import from the layers below it:

```
 ui/        Qt widgets: tabs, dialogs, theme           (PyQt6)
   │
 workers/   QThreads: run one blocking job, emit signals  (PyQt6)
   │
 services/  side effects: SSH, subprocess, sockets      (paramiko)
   │
 core/      pure logic: commands, parsers, models, rules  (stdlib only)
```

`core/` imports neither Qt nor paramiko, so all of it can be unit-tested
without a display, a network, or root. The UI classes still hold UI state
(tables, dialogs, timers), but they no longer parse text or build shell
commands themselves; they call into `core`.

## Package map

```
main.py                          entry point: python3 main.py
lanscanman/
├── app.py                       main window, tab wiring, schedule timer
├── paths.py                     every file under ~/.config/LanScanMan
├── log.py                       rotating logger
├── core/
│   ├── formatting.py            fmt_bytes / fmt_eta / … and colour thresholds
│   ├── nmap_scan.py             nmap argv builders + result shaping
│   ├── probe.py                 Host Monitor probe script + parser, CPU/GPU brand
│   ├── smart.py                 Disk Health probe script + smartctl/udisks/lsblk/df parsers
│   ├── smart_history.py         SmartLogger: per-host SMART history + worsening alerts
│   ├── rsync.py                 rsync argv builder (3 topologies) + progress parser
│   ├── schedules.py             Schedule/Transfer/Trigger model, due-time rules, HMAC store
│   ├── schedule_runner.py       run_schedule(): sequencing/abort rules for a list
│   ├── profiles.py              ProfileStore: hosts.json CRUD, MAC re-keying
│   ├── ai_discovery.py          recognise AI servers from HTTP responses; open-UI vs chat
│   ├── ai_chat.py               streaming chat: OpenAI (SSE) and Ollama native (NDJSON), context sizing
│   ├── chat_tree.py             branching conversations (regenerate / edit / switch)
│   ├── chat_store.py            saved chats + index; encryption passed in
│   ├── connect.py               ssh / tmux / ssh-copy-id commands, terminal detection
│   ├── privilege.py             scan privilege methods, nmap argument check, outcomes
│   ├── devices.py               DeviceRegistry: every device seen; new-device flags
│   ├── integrity.py             signing key (keyring/file), SignedFile, tamper errors
│   ├── sshkey.py                is the private key encrypted? keygen / ssh-add commands
│   ├── net.py                   Wake-on-LAN packet, ping output, MAC validation
│   ├── wifi.py                  /proc/net/wireless parser + signal labels
│   └── notify.py                notify-send wrapper
├── services/
│   ├── ssh.py                   signed known_hosts, paramiko client, prepare_cli_ssh()
│   ├── secret_store.py          desktop keyring (Secret Service / KWallet) wrapper
│   ├── http.py                  stdlib HTTP for LAN AI servers (no proxy, same-host redirects)
│   ├── chat_crypto.py           AES-256-GCM for saved chats, key via HKDF from the vault key
│   ├── vault.py                 the session's key: prompt-once, adoption, trust checks
│   ├── privilege.py             detect pkexec/pkttyagent/askpass; build commands
│   ├── security_settings.py     signed security.json (strict mode, password fallback)
│   └── network_manager.py       NetworkManager facade shared by all tabs
├── workers/
│   ├── scanner.py               ScannerThread (subnet), HostScanThread (one host)
│   ├── probes.py                ProbeWorker (monitor), SmartProbeWorker (disks)
│   ├── ai.py                    AIDiscoveryWorker, ModelListWorker, ChatWorker
│   ├── rsync.py                 RsyncWorker: runs one transfer, streams progress
│   └── scheduled_runner.py      ScheduledRunner: runs a schedule list sequentially
└── ui/
    ├── theme.py                 palette + application stylesheet
    ├── trust.py                 tamper / keyring / host-key-changed dialogs
    ├── ssh_key.py               create key with passphrase, add passphrase, ssh-add
    ├── resources/about.html     About & Security page (plain HTML)
    ├── widgets/                 WifiStrengthWidget, shared bars/badges/labels
    ├── tabs/                    one module per tab, plus the Schedules panel
    └── dialogs/                 every QDialog, grouped by the tab that opens it
tests/                           pytest suite (see below)
```

## How a feature flows through the layers

**Network scan.** `ScannerTab` → `workers.scanner.ScannerThread` →
`core.nmap_scan.subnet_scan_command()` builds the argv → the thread runs nmap
and feeds it the sudo password on stdin → python-nmap parses the XML →
`core.nmap_scan.parse_subnet_scan()` shapes rows → `results_ready` signal →
the tab fills its table.

**Host Monitor / Disk Health.** The tab starts a `ProbeWorker` /
`SmartProbeWorker` per host. The worker calls `services.ssh.run_remote()` with
a read-only script from `core.probe.PROBE_CMD` / `core.smart.SMART_PROBE_CMD`.
The script prints `###TAG###` sentinel lines between sections, and
`core.probe.split_sections()` splits the output apart before the
parsers turn it into dicts. Disk results also go to
`core.smart_history.SmartLogger`, which de-duplicates them and raises a
desktop notification when a degradation counter goes up.

**Transfers.** `AddTransferDialog` produces a dict (the same shape as
`core.schedules.Transfer`). `RsyncWorker` checks that the source exists, then runs
`core.rsync.build_command()` and streams stdout through
`core.rsync.split_output()` and `parse_progress()`.
- local ↔ remote: local rsync with `--rsh` pointing at our known_hosts
- remote → remote: `ssh -A sender 'bash -lc "rsync …"'`, so the sender
  authenticates to the receiver through your forwarded agent

**Schedules.** `app.py` ticks once a minute and asks
`ScheduleManager.due_now()`. For each due list, `ScheduledRunner` calls
`core.schedule_runner.run_schedule()`, which runs each transfer through an
`RsyncWorker`. Before running it re-validates every transfer and applies the
list's `on_transfer_failure` setting. `schedules.json` is HMAC-signed with a
per-install key, and a file that fails verification is not loaded.
**AI tab.** `ScannerTab.hosts_changed` marks `AITab` stale; showing the tab
then runs `AIDiscoveryWorker` over this machine plus
`ScannerTab.current_hosts()` × `core.ai_discovery.AI_PORTS`. A TCP connect filters
closed ports, and `identify()` recognises the software from AI-specific
endpoints only. `primary_action()` picks **Open Web UI** (browser) when the
server serves a page and **Chat** otherwise. `ChatWindow` streams replies via
`ChatWorker` and `core.ai_chat`. Thinking (`reasoning` signal) is kept per
turn and shown or hidden by re-rendering. Pictures go through `ui/images.py`
(downscale + re-encode, which strips metadata) once, and the same data URL is
re-sent each turn so server prompt caches keep matching. `CapabilityWorker`
asks Ollama's `/api/show` whether a model has `vision` and its maximum
context (`context_ready`). Ollama silently truncates prompts beyond its small
default context from the start, and its OpenAI endpoint can't change that,
so for Ollama servers `ChatWorker(ollama=True)` uses the native `/api/chat`
(NDJSON) with `options.num_ctx` from `ai_chat.ollama_context()` (bucketed,
never shrinking within a chat — kept in `tree.settings["num_ctx"]` — capped
at the model maximum). `ChatWindow._fits()` warns before a send that won't
fit (Ollama) or is large on a server whose limit is unknown (once).
Conversations are `core.chat_tree.ChatTree`s: the transcript is the path to
`current`; regenerate adds a sibling reply, edit adds a sibling user message,
and `lsm:` anchor links in the transcript drive both (model text is still
inserted as plain text). Each reply is autosaved through
`services.chat_crypto.chat_store()`. Its key is derived with HKDF from the
vault's integrity key, so a locked keyring means "not saved" and asks again
on the next reply. Thinking levels map to `reasoning_effort` (`core.ai_chat`). API keys are stored only when the user asks,
as keyring item `api-key <base_url>` in the same `SecretStore` the vault uses.

**Drive reports.** `core.drive_report` turns `core.smart` readings and
`SmartLogger.all_disks()` history into text. Trends, rates, projections and a
rule-based view are computed in code, because small local models are bad at
arithmetic. `disk_request` / `host_request` / `fleet_request` are opened via
`AITab.open_drive_chat()`. That puts `SYSTEM_PROMPT` in
`ChatTree.settings["system"]`, which is sent first and shown in the
transcript, and places the report in the message box unsent. `AITab`'s *Add
server…* only accepts addresses where `is_lan_address()` is true for every
resolved address.

## Trust model

Three files decide where LanScanMan connects and what it trusts, and each is
HMAC-signed with one per-install key:

| file | signature | what tampering would do |
|---|---|---|
| `hosts.json` | `hosts.json.sig` | point a host at another IP/user (and your forwarded agent) |
| `devices.json` | `devices.json.sig` | mark an intruder's device as "known" to silence the alert |
| `known_hosts` | `known_hosts.sig` | swap a host key, so a MITM goes unnoticed |
| `schedules.json` | `schedules.hmac` | rsync your data somewhere else, on a timer |

- **The key** comes from `core.integrity.load_key()`: it's kept in the
  desktop keyring (`services.secret_store`) and falls back to `hmac.key` only
  when there is no keyring. `core` never imports the keyring; it receives a
  `key_provider`.
- **`services.vault.Vault`** holds the key for the session. The first use
  prompts. After a refusal, further requests fail immediately for 5 seconds
  (so one click causes one prompt), and the next action asks again.
  The first unlock after upgrading signs files that pre-date signing. That
  one-time adoption is recorded next to the key, so deleting a `.sig` later
  does not get a file re-trusted.
- **The gate**: `vault.ensure_trusted()` unlocks the key and verifies
  `known_hosts` and `hosts.json`. `services.ssh.make_ssh_client()` and
  `prepare_cli_ssh()` call it, so nothing connects on unverified data.
- **First contact** (paramiko policy and `prepare_cli_ssh`) is cross-checked
  with `ssh.system_host_keys()`, which reads `~/.ssh/known_hosts` and
  `/etc/ssh/ssh_known_hosts` line by line, including hashed entries. A
  contradiction raises `SystemKeyMismatch`, a `BadHostKeyException`
  subclass, so every existing handler treats it as a key change with
  `source=SYSTEM`.
- **Strict mode** (`services.security_settings`, a signed `security.json`
  that falls back to strict if tampered): a first contact with nothing to
  compare against raises `UnconfirmedHostKey` (source `NEW`), and the same
  dialog asks you to confirm the fingerprint.
- **Key changes**: `HostKeyMismatchError` carries both keys.
  `ui.trust.confirm_host_key_change()` is the only dialog for this. It shows
  fingerprints and `core.devices.key_change_context()` (from each device's IP
  history: "moved" vs "same device"), defaults to *Keep blocked*, and on
  consent calls `ssh.accept_new_key()`.
- **AI over HTTP**: `AIService.scheme` / `Server.scheme` are `"http"` or
  `"https"`. `sends_key_in_clear()` drives the chat window's warning and
  its once-per-server confirmation.
- **The OpenSSH CLI never writes known_hosts.** It runs with
  `StrictHostKeyChecking=yes`. `prepare_cli_ssh(ip, port)` fetches the host
  key with a key exchange only (no login) and pins it (TOFU). It raises
  `HostKeyMismatchError` on a change. The UI calls it via
  `ui.trust.pin_host_or_warn()`, and `RsyncWorker` calls it for the remote end.
- **Failures**: `KeyUnavailable` (keyring declined) and `TamperedError`
  subclass `IntegrityError`. In the UI thread, `app._excepthook` turns any that
  escape into the dialogs in `ui/trust.py` instead of crashing. Workers catch
  them and show them as the row's error text.
- **SSH private key**: `core.sshkey.is_encrypted()` reads only the
  cipher name in the key header. Keys are created and re-encrypted only by
  `ssh-keygen` running in a terminal (`ui/ssh_key.py`).

## Privileged scans

The mode is a signed security setting (`security_settings.privilege_method`),
and tampering falls back to `polkit`.

- **polkit mode** (default): `pkexec` (desktop agent), then `pkexec` plus
  `pkttyagent --process <pid>` in a terminal, then `sudo -A` with an askpass.
  It asks on every scan.
- **sudo mode**: `sudo -n` first. Without a tty, sudo keys its timestamp to
  the parent process (LanScanMan), so this succeeds for about 15 minutes after
  authenticating. Then `sudo -A` if an askpass exists; otherwise the UI's
  password box feeds `sudo -S` once and drops the password. After a sudo
  method is used, `privilege.forget_if_used()` runs `sudo -k` at exit.
- **sudo_session mode** (insecure, opt-in with a confirmation): the password
  box's password is held in `services.privilege._session_password`. It is
  never written or logged, and is re-supplied via `sudo -S` whenever `sudo -n`
  fails. It is dropped on forget, mode change, a DENIED outcome, and exit.

Nothing is installed: pkexec/sudo run the system's own nmap. Before asking,
`core.privilege.validate_scan_args()` checks the arguments against the shapes
LanScanMan generates, so a custom port list can't smuggle in `--script`,
output files or extra targets. (A root-owned helper that enforced this at the
root boundary was built and deliberately removed: LanScanMan doesn't install
components onto the system.)

## Remote command output

The probes ask for JSON where the tool supports it, and keep the text form
as a fallback for older hosts. The parsers accept either:

- `smartctl -j -iAH`: the script checks once with `smartctl -j --version`.
  `core.smart._apply_smartctl_json()`; the TB-written figure is rounded to 3
  significant digits, as smartctl's text shows it, so switching format
  doesn't change the SMART history.
- `lsblk -J -b -d`: `parse_lsblk_json()`; `LSBLK` text is kept alongside.
- `systemctl list-units --failed --output=json` (systemd 246+) and
  `docker ps --format '{{json .}}'`: `core.probe.parse_health()`.
- `apt list --upgradable`, `df` and the `lsblk -l` tree stay text: no JSON
  mode, or already plain columns.

Test fixtures in `tests/fixtures/smartctl/` are real captured outputs
(smartctl_exporter, Apache-2.0).

## CI

`.github/workflows/tests.yml` runs pyflakes, `isort --check` and pytest on
Python 3.10 and 3.12 (with `QT_QPA_PLATFORM=offscreen` and PyQt's system
libraries). `release.yml` runs on `v*` tags: tests, then
`PY=python packaging/build-appimage.sh` with `APPIMAGE_EXTRACT_AND_RUN=1`,
then a 10-second smoke run, then `gh release create` with the AppImage and
its SHA-256.

## Where state lives

All paths are defined in `lanscanman/paths.py`. Set `LANSCANMAN_CONFIG_DIR`
to move all of it (the tests do). The files themselves are listed in the
README under "Data Stored Locally".

## Tests

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
QT_QPA_PLATFORM=offscreen pytest
```

| file | covers |
|---|---|
| `test_formatting.py` | sizes, durations, ETA parsing, colour thresholds |
| `test_probe.py` | section splitting, CPU %, NVIDIA/AMD/lspci GPU paths, brand detection, health checks (real Ubuntu output), probe stays read-only |
| `test_smart.py` | SATA + NVMe smartctl, udisks fallback, lsblk/df aggregation, health summary |
| `test_smart_history.py` | de-duplication, worsening alerts, persistence, corrupt files |
| `test_schedules.py` | path/arg validation, triggers, due-time maths, HMAC tamper detection, legacy format |
| `test_schedule_runner.py` | completed / partial / aborted, rejected transfers, stop requests |
| `test_rsync.py` | argv for all three topologies, hostile-input quoting, progress parsing |
| `test_nmap_scan.py` | scan argv, result shaping, IP sort order |
| `test_connect.py` | ssh/tmux commands incl. hostile session names, tmux ls parsing, protocol guessing |
| `test_profiles_and_net.py` | ProfileStore, Wake-on-LAN packet, ping parsing, WiFi parsing |
| `test_ui_smoke.py` | every module imports; the main window builds headlessly; Copy menu; tamper and host-key-changed dialogs |
| `test_integrity.py` | keyring key + migration, SignedFile, vault prompt-once and adoption, signed hosts.json / known_hosts / schedules, host-key pinning, private-key encryption detection |
| `test_ai.py` | server recognition (incl. routers ignored), chat stream parsing, workers with fake HTTP, AI tab + chat window, redirect/proxy rules |
| `test_chats.py` | chat tree branching + round-trip, AES-GCM tamper/wrong-key, encrypted store (nothing readable on disk, index rebuild, path safety), thinking levels, regenerate/edit/switch/autosave/server-switch in the window, saved-chats dialog |
| `test_devices.py` | baseline, new-device flags, no-MAC scans, randomised MACs, signing, scanner highlighting + menu |
| `test_mitm.py` | first contact vs ~/.ssh/known_hosts (plain, hashed, ports, malformed lines), paramiko path, fingerprints, IP-history context, dialog wording/default |
| `test_privilege.py` | argument check (allowed vs `--script`/`-oN`/`-iL`/…), method order, commands, fallback chain, one-shot password, UI prompts, nothing installed |
| `test_drive_report.py` | trends/rates/projections, rule view, report contents and caps, history-only disks, system prompt, Disk Health → chat (prefilled, unsent), fleet report |
| `test_safety_net.py` | proves the guards below actually block the network |

**The suite never touches the network.** `tests/conftest.py` points the config
dir at a temp directory before anything is imported. It also makes every test
fail if it runs `nmap`, `sudo`, `ping`, `ssh`, `rsync` or `notify-send`, opens
a socket connection, calls `paramiko.SSHClient.connect`, or looks up a hostname in DNS. The desktop
keyring is disconnected too; keyring tests use an in-memory fake. It is safe to
run on any network.

## Conventions

- New parsing or command-building code goes in `core/` with a test. If you
  want to import Qt or paramiko there, the code belongs in a worker or service.
- Shell strings are built only in `core/connect.py` and `core/rsync.py`,
  and every interpolated value goes through `shlex.quote`. Everything else
  uses argv lists (`shell=False`).
- All remote commands are read-only. The only remote write is installing an
  SSH key, which the user starts from the menu.
- Anything new that connects goes through `services.ssh` (paramiko) or
  calls `prepare_cli_ssh` / `pin_host_or_warn` before launching `ssh`. Any new
  file that affects where the app connects should be a `vault.signed_file()`.
- Lint: `python -m pyflakes lanscanman tests && isort --check-only lanscanman tests main.py` (CI enforces both).

## Known issues

- Two unused locals that pyflakes reports (`host_inspector_tab.py` `proto`,
  `schedule_dialogs.py` `s`) predate the refactor.

## Fixed during the refactor

- **Local command injection through tmux session names.** Session names
  (which can come from a remote host's `tmux ls`) were quoted twice in a way
  that cancelled out, so a session named `x;cmd` ran `cmd` on your machine
  when you attached. `core.connect.tmux_command` now quotes the whole
  remote command as a single word. The regression test is in `test_connect.py`.
- **Filesystem usage for SD/eMMC and LVM/LUKS disks.** The Disk Health probe
  now also reads `lsblk -n -l -p -o NAME,PKNAME`, and `disk_for_device()`
  follows each df device up that tree to its physical disk. `mmcblk0p1` → `mmcblk0`
  also works without the tree.
- **xfce4-terminal, mate-terminal and lxterminal never ran the command.** Their
  `-e` takes one string, so `terminal_argv()` now quotes the script into it.
  Checked by launching each one for real (plus gnome-terminal).
- **SSH key comments containing `'`** broke the remote authorized_keys
  command. The key is now shell-quoted (`core.connect.authorized_keys_commands`).
