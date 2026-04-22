from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QTextBrowser, QLabel
from PyQt6.QtCore import Qt


# ─────────────────────────────────────────────────────────────────────────────
# HTML content — written once, rendered by QTextBrowser
# ─────────────────────────────────────────────────────────────────────────────

_STYLE = """
<style>
    body {
        background-color: #121417;
        color: #E6E6E6;
        font-family: 'Segoe UI', 'Liberation Sans', Arial, sans-serif;
        font-size: 13px;
        line-height: 1.65;
        margin: 0;
        padding: 0;
    }

    h1 {
        color: #3498db;
        font-size: 20px;
        font-weight: bold;
        margin-top: 0;
        margin-bottom: 4px;
        padding-bottom: 6px;
        border-bottom: 2px solid #3498db;
    }

    h2 {
        color: #3498db;
        font-size: 14px;
        font-weight: bold;
        margin-top: 22px;
        margin-bottom: 6px;
        padding-bottom: 4px;
        border-bottom: 1px solid #2A313B;
        letter-spacing: 0.5px;
    }

    h3 {
        color: #9AA4AF;
        font-size: 12px;
        font-weight: bold;
        margin-top: 14px;
        margin-bottom: 4px;
        letter-spacing: 0.8px;
    }

    p  { margin: 6px 0; color: #E6E6E6; }
    li { margin: 4px 0; color: #E6E6E6; }
    ul { padding-left: 20px; margin: 6px 0; }

    code {
        background-color: #1B1F24;
        color: #3498db;
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 12px;
        padding: 1px 5px;
        border-radius: 3px;
        border: 1px solid #2A313B;
    }

    .warn-box {
        background-color: #1e1505;
        border: 1px solid #7a5500;
        border-left: 3px solid #f39c12;
        border-radius: 4px;
        padding: 10px 14px;
        margin: 10px 0;
        color: #f0c060;
    }

    .danger-box {
        background-color: #1e0808;
        border: 1px solid #7a1a1a;
        border-left: 3px solid #c0392b;
        border-radius: 4px;
        padding: 10px 14px;
        margin: 10px 0;
        color: #e07070;
    }

    .good-box {
        background-color: #081a0e;
        border: 1px solid #1a5c2a;
        border-left: 3px solid #27ae60;
        border-radius: 4px;
        padding: 10px 14px;
        margin: 10px 0;
        color: #70c888;
    }

    .info-box {
        background-color: #071728;
        border: 1px solid #1060bb;
        border-left: 3px solid #3498db;
        border-radius: 4px;
        padding: 10px 14px;
        margin: 10px 0;
        color: #80b8e8;
    }

    .cmd-block {
        background-color: #0d1117;
        border: 1px solid #2A313B;
        border-left: 3px solid #3498db;
        border-radius: 4px;
        padding: 8px 12px;
        margin: 6px 0;
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 11.5px;
        color: #9AA4AF;
    }

    .tag-good  { color: #27ae60; font-weight: bold; }
    .tag-warn  { color: #f39c12; font-weight: bold; }
    .tag-bad   { color: #c0392b; font-weight: bold; }
    .tag-muted { color: #9AA4AF; }
    .tag-accent{ color: #3498db; }

    hr {
        border: none;
        border-top: 1px solid #2A313B;
        margin: 18px 0;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        margin: 8px 0;
        font-size: 12px;
    }

    th {
        background-color: #20262E;
        color: #3498db;
        text-align: left;
        padding: 6px 10px;
        border-bottom: 1px solid #3498db;
        font-weight: bold;
        text-transform: uppercase;
        font-size: 11px;
        letter-spacing: 0.5px;
    }

    td {
        padding: 6px 10px;
        border-bottom: 1px solid #1A1F26;
        vertical-align: top;
    }

    tr:last-child td { border-bottom: none; }
</style>
"""

_CONTENT = """
<h1>LanScanMan</h1>
<p class="tag-muted">
    A local-network administration utility for scanning, monitoring, and
    transferring files between Linux hosts over SSH.
    This tab documents every operation the application performs —
    including all remote commands, how profiles are stored, what external
    programs are required and why — so you always know exactly what it is
    doing on your behalf.
</p>

<hr>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<h2>Required &amp; Optional Programs</h2>

<p>
    LanScanMan is built entirely on standard Linux tools. None of them phone
    home or require accounts. The table below lists what is needed, why, and
    how to install it.
</p>

<table>
    <tr><th>Program</th><th>Used for</th><th>Required?</th><th>Install (Debian/Ubuntu)</th></tr>
    <tr>
        <td><code>nmap</code></td>
        <td>Network scanning — discovers hosts and checks which ports are open</td>
        <td><span class="tag-bad">Required</span></td>
        <td><code>sudo apt install nmap</code></td>
    </tr>
    <tr>
        <td><code>python3-nmap</code></td>
        <td>Python bindings that parse nmap's XML output into usable data structures</td>
        <td><span class="tag-bad">Required</span></td>
        <td><code>pip install python-nmap</code></td>
    </tr>
    <tr>
        <td><code>paramiko</code></td>
        <td>Pure-Python SSH library — all SSH connections, SFTP browsing, and key management go through this</td>
        <td><span class="tag-bad">Required</span></td>
        <td><code>pip install paramiko</code></td>
    </tr>
    <tr>
        <td><code>PyQt6</code></td>
        <td>The GUI framework — every window, table, button, and dialog</td>
        <td><span class="tag-bad">Required</span></td>
        <td><code>pip install PyQt6</code></td>
    </tr>
    <tr>
        <td><code>rsync</code></td>
        <td>File transfers — the File Transfers tab builds rsync commands and streams their progress output</td>
        <td><span class="tag-warn">Needed for transfers</span></td>
        <td><code>sudo apt install rsync</code></td>
    </tr>
    <tr>
        <td><code>openssh-client</code></td>
        <td>The <code>ssh</code> binary that terminal connections are handed off to; also <code>ssh-keygen</code> for key generation</td>
        <td><span class="tag-warn">Needed for terminal connect</span></td>
        <td>Usually pre-installed. <code>sudo apt install openssh-client</code></td>
    </tr>
    <tr>
        <td><code>smartmontools</code></td>
        <td>Provides <code>smartctl</code> on remote hosts — reads drive health attributes directly from firmware</td>
        <td><span class="tag-warn">Optional (Disk Health tab)</span></td>
        <td>On the <em>remote</em> host: <code>sudo apt install smartmontools</code></td>
    </tr>
    <tr>
        <td><code>udisks2</code></td>
        <td>Provides <code>udisksctl</code> on remote hosts — fallback SMART source when smartctl lacks root; usually pre-installed</td>
        <td><span class="tag-muted">Auto-fallback</span></td>
        <td>On the <em>remote</em> host: <code>sudo apt install udisks2</code></td>
    </tr>
    <tr>
        <td><code>tmux</code></td>
        <td>Terminal multiplexer — optional on remote hosts; enables session persistence (see tmux section below)</td>
        <td><span class="tag-muted">Optional (remote hosts)</span></td>
        <td>On the <em>remote</em> host: <code>sudo apt install tmux</code></td>
    </tr>
    <tr>
        <td>A terminal emulator</td>
        <td>SSH terminal connections are launched in your local terminal. Tried in order: gnome-terminal, konsole, xfce4-terminal, mate-terminal, lxterminal, xterm</td>
        <td><span class="tag-warn">Needed for terminal connect</span></td>
        <td>Usually pre-installed with your desktop environment</td>
    </tr>
</table>

<div class="info-box">
    <strong>Quick install — everything at once (local machine):</strong><br>
    <code>sudo apt install nmap rsync openssh-client &amp;&amp; pip install PyQt6 paramiko python-nmap</code><br><br>
    <strong>Quick install — remote host full features:</strong><br>
    <code>sudo apt install smartmontools tmux rsync openssh-server</code>
</div>

<hr>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<h2>How Profiles Work</h2>

<p>
    A <strong>profile</strong> is a small record LanScanMan keeps about a
    device so it can remember its alias, SSH username, and hostname between
    scans. Profiles are stored in a single JSON file at
    <code>~/.config/LanScanMan/hosts.json</code>.
</p>

<h3>Profile keys — MAC vs IP</h3>
<p>
    Each profile is stored under a <strong>key</strong> that uniquely
    identifies the device. The preferred key is the device's MAC address
    (e.g. <code>AA:BB:CC:DD:EE:FF</code>) because MAC addresses are stable
    even when a device's IP changes due to DHCP reassignment. When a MAC is
    not available — for example after a no-sudo scan that couldn't run ARP
    discovery — the IP address is used as the key instead.
</p>
<p>
    An IP-keyed profile is automatically <strong>upgraded to a MAC-keyed
    profile</strong> the first time you successfully double-click and SSH
    into that device. During the SSH probe, LanScanMan asks the remote host
    for its own MAC address via:
</p>
<div class="cmd-block">
    iface=$(ip route | awk '/^default/{print $5; exit}')<br>
    cat /sys/class/net/$iface/address
</div>
<p>
    If that returns a valid MAC, the profile is silently re-keyed from
    <code>"10.0.0.72"</code> to <code>"aa:bb:cc:dd:ee:ff"</code> in the
    JSON file. The old IP key is removed. From that point on, the profile
    survives IP changes.
</p>

<h3>What is stored in a profile</h3>
<table>
    <tr><th>Field</th><th>Meaning</th><th>Set by</th></tr>
    <tr>
        <td><code>alias</code></td>
        <td>Human-readable nickname shown in blue in the scanner table (e.g. "farm1", "snow")</td>
        <td>You, via Edit Profile</td>
    </tr>
    <tr>
        <td><code>username</code></td>
        <td>SSH login username for this host — used for all SSH operations including monitoring and disk health</td>
        <td>You, via Edit Profile</td>
    </tr>
    <tr>
        <td><code>last_ip</code></td>
        <td>The most recently seen IP address; used to pre-fill connection dialogs and as a fallback key</td>
        <td>Updated automatically on each scan</td>
    </tr>
    <tr>
        <td><code>hostname</code></td>
        <td>The hostname reported by the remote machine during the last nmap scan</td>
        <td>Updated automatically on each scan</td>
    </tr>
</table>

<h3>Which tabs use profiles</h3>
<ul>
    <li><strong>Network Scanner</strong> — reads profiles to enrich the table with aliases and usernames; writes profiles when you use Edit Profile</li>
    <li><strong>File Transfers</strong> — reads profiles to populate the sender/receiver dropdowns (only hosts with a username appear)</li>
    <li><strong>Host Monitor</strong> — reads profiles to know which hosts to probe and which username to SSH with</li>
    <li><strong>Disk Health</strong> — same as Host Monitor</li>
</ul>

<h3>No-sudo scan and profile matching</h3>
<p>
    The unprivileged scan (<em>Scan No Sudo</em>) uses TCP connect instead
    of ARP, so nmap cannot determine MAC addresses. When populating the
    scanner table after a no-sudo scan, LanScanMan builds a reverse lookup
    from stored <code>last_ip</code> values so that a scan result for
    <code>10.0.0.72</code> will still correctly match and display the profile
    for key <code>AA:BB:CC:DD:EE:FF</code> — as long as that device's IP
    hasn't changed since the last privileged scan. Additionally, if a
    previously-offline history row returns a successful ping during the
    background ping phase, its row colour is restored from grey to white even
    if nmap didn't find it, so you can see it's reachable.
</p>

<hr>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<h2>Network Scanner Tab</h2>

<h3>What it does</h3>
<p>
    Discovers all reachable hosts on a given subnet by running a privileged
    <strong>Nmap SYN scan</strong> on your local machine. Results are enriched
    with MAC address vendor lookups (from Nmap's built-in database) and
    presented in a table alongside hostnames, open ports, and SSH status.
    Ping latency is then measured independently for every discovered host.
</p>

<h3>Commands executed — locally, as root via sudo</h3>
<div class="cmd-block">
    sudo nmap -sS -p 22,80,443,3389,5900,8080 -PR -T4 --host-timeout 15s -oX - &lt;subnet&gt;
</div>
<p>
    Flags explained:
</p>
<ul>
    <li><code>-sS</code> — SYN ("half-open") scan. Sends a TCP SYN packet and
        reads the response without completing the handshake. Faster and less
        logged than a full connect scan, but <strong>requires root</strong>.</li>
    <li><code>-p</code> — Only the six ports listed above are checked (SSH, HTTP,
        HTTPS, RDP, VNC, HTTP-Alt). No full port sweep is performed.</li>
    <li><code>-PR</code> — ARP ping for host discovery. Only sends ARP requests
        within your local subnet; no packets leave your network.</li>
    <li><code>-T4</code> — Aggressive timing (T3 in Thorough mode). Reduces scan
        time; may miss hosts on very congested networks.</li>
    <li><code>-oX -</code> — XML output to stdout, parsed entirely in memory.
        Nothing is written to disk.</li>
</ul>

<h3>Ping latency</h3>
<div class="cmd-block">ping -c 1 -W 1 &lt;ip&gt;</div>
<p>
    Run once per discovered host in a thread pool (up to 10 concurrent pings)
    after the scan completes. Uses the system <code>ping</code> binary —
    no elevated privileges required.
</p>

<h3>Wake-on-LAN</h3>
<p>
    When triggered from the right-click context menu, sends a standard
    <strong>802.3 Magic Packet</strong> as a UDP broadcast on port 9.
    This is a local broadcast only — it does not leave your subnet.
    No remote commands are involved.
</p>

<div class="info-box">
    <strong>Data stored locally:</strong> Alias, username, hostname, and last-seen
    IP are saved to <code>~/.config/LanScanMan/hosts.json</code> on your
    machine when you edit a profile. Nothing is sent anywhere.
</div>

<hr>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<h2>SSH Connections &amp; Key Management</h2>

<h3>Host key verification</h3>
<p>
    LanScanMan maintains its own known-hosts file at
    <code>~/.config/LanScanMan/known_hosts</code>, separate from your
    system's <code>~/.ssh/known_hosts</code>. On first connection to a new
    host the server's public key is saved automatically. On subsequent
    connections, Paramiko verifies the key matches — a mismatch triggers a
    visible warning dialog before any further action is taken.
</p>

<h3>SSH key setup</h3>
<p>
    "Setup SSH Key" generates an <code>ed25519</code> key pair at
    <code>~/.ssh/id_ed25519</code> if one does not already exist, then
    connects with the password you provide and runs the following on the
    remote host:
</p>
<div class="cmd-block">
    mkdir -p ~/.ssh &amp;&amp; chmod 700 ~/.ssh<br>
    touch ~/.ssh/authorized_keys &amp;&amp; chmod 600 ~/.ssh/authorized_keys<br>
    grep -qxF '&lt;pubkey&gt;' ~/.ssh/authorized_keys || echo '&lt;pubkey&gt;' &gt;&gt; ~/.ssh/authorized_keys
</div>
<p>
    The password is used only for this single session and is never stored.
    The <code>grep</code> check prevents duplicate key entries.
</p>

<h3>Terminal launch — tmux detection</h3>
<p>
    When you double-click a host, LanScanMan connects via SSH key auth and
    runs the following on the remote machine to discover tmux sessions:
</p>
<div class="cmd-block">tmux ls 2>/dev/null; echo EXIT:$?</div>
<p>
    Based on your choice in the dialog, one of these final commands is
    assembled and handed off to your local terminal emulator:
</p>
<div class="cmd-block">
    # Standard SSH<br>
    ssh -t -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=~/.config/LanScanMan/known_hosts &lt;user&gt;@&lt;ip&gt;<br><br>
    # New named tmux session<br>
    ssh -t ... &lt;user&gt;@&lt;ip&gt; 'tmux new -s &lt;name&gt; || tmux a'<br><br>
    # Attach to existing session<br>
    ssh -t ... &lt;user&gt;@&lt;ip&gt; 'tmux a -t &lt;name&gt;'
</div>
<p>
    The terminal process is launched with <code>subprocess.Popen</code> and
    is entirely independent of LanScanMan from that point on. The app does
    not monitor, log, or interact with your terminal session in any way.
</p>

<hr>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<h2>tmux — What It Is and How LanScanMan Uses It</h2>

<h3>What tmux is</h3>
<p>
    <strong>tmux</strong> (terminal multiplexer) is a program that runs on
    the remote host and lets you keep terminal sessions alive after you
    disconnect. When you SSH into a machine normally, closing the terminal or
    losing your network connection kills every process running in that session.
    With tmux, those processes keep running inside a tmux session on the
    server — you can reconnect later and pick up exactly where you left off.
</p>
<p>
    It is especially useful for long-running tasks: a file copy, a build, a
    training run, a server process. You start it inside tmux, detach, and
    come back hours later to see the output.
</p>

<h3>How LanScanMan integrates tmux</h3>
<p>
    When you double-click a host in the scanner, LanScanMan first checks
    whether tmux is installed on that machine by running:
</p>
<div class="cmd-block">tmux ls 2>/dev/null; echo EXIT:$?</div>
<p>
    The exit code tells us three things:
</p>
<ul>
    <li><strong>Exit 0</strong> — tmux is installed and at least one session is running. The session list is parsed and presented to you.</li>
    <li><strong>Exit 1</strong> — tmux is installed but no sessions exist yet. You can create a new named session.</li>
    <li><strong>Exit 127</strong> — tmux is not installed (command not found). LanScanMan skips the dialog and opens a plain SSH connection instead.</li>
</ul>
<p>
    Based on your choice in the connection dialog, one of three commands is
    assembled and handed to your local terminal emulator:
</p>
<div class="cmd-block">
    <span class="tag-muted"># Attach to an existing session by name</span><br>
    ssh -t [opts] user@host 'tmux a -t &lt;session-name&gt;'<br><br>
    <span class="tag-muted"># Create a new named session (falls back to attach if name already exists)</span><br>
    ssh -t [opts] user@host 'tmux new -s &lt;session-name&gt; || tmux a'<br><br>
    <span class="tag-muted"># Plain SSH, no tmux</span><br>
    ssh [opts] user@host
</div>
<p>
    The <code>-t</code> flag allocates a pseudo-terminal, which is required
    for interactive programs like tmux. Once the terminal launches, LanScanMan
    has no further involvement — it does not monitor, log, or interact with
    your session.
</p>

<div class="info-box">
    <strong>Installing tmux on a remote host:</strong>
    <code>sudo apt install tmux</code><br><br>
    <strong>Quick tmux reference:</strong> <code>Ctrl+B D</code> detaches
    (leaves session running). <code>Ctrl+B $</code> renames the current
    session. <code>tmux ls</code> lists sessions. <code>tmux a -t name</code>
    attaches to one.
</div>

<hr>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<h2>Privileged vs Unprivileged Scan</h2>

<p>
    LanScanMan offers two scan modes. Both use nmap on your local machine and
    produce the same output format — the difference is in how nmap discovers
    hosts and checks ports.
</p>

<table>
    <tr><th></th><th>Scan Network (sudo)</th><th>Scan (No Sudo)</th></tr>
    <tr>
        <td>Nmap scan type</td>
        <td>SYN scan (<code>-sS</code>) — sends a raw TCP SYN, reads the response, never completes the handshake</td>
        <td>Connect scan (<code>-sT</code>) — completes the full TCP handshake on each port</td>
    </tr>
    <tr>
        <td>Host discovery</td>
        <td>ARP ping (<code>-PR</code>) — sends ARP broadcasts; finds every device on the subnet regardless of firewall rules</td>
        <td>ICMP echo + TCP ping — only finds hosts that respond to ping or have at least one of the 6 scanned ports open</td>
    </tr>
    <tr>
        <td>MAC addresses</td>
        <td>Available — nmap reads them from ARP replies</td>
        <td>Not available — ARP requires root; MAC column shows "—"</td>
    </tr>
    <tr>
        <td>Vendor lookup</td>
        <td>Available — nmap matches MACs against its OUI database</td>
        <td>Not available</td>
    </tr>
    <tr>
        <td>Visibility on network</td>
        <td>ARP is normal LAN traffic; SYN packets are less logged than full connects</td>
        <td>Full TCP handshakes are more visible to firewalls and IDS systems</td>
    </tr>
    <tr>
        <td>Sudo password</td>
        <td>Required (can be remembered for the session)</td>
        <td>Not required</td>
    </tr>
</table>

<p>
    Both modes scan the same six ports: <code>22</code> (SSH),
    <code>80</code> (HTTP), <code>443</code> (HTTPS), <code>3389</code> (RDP),
    <code>5900</code> (VNC), <code>8080</code> (HTTP-Alt).
</p>

<hr>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<h2>File Transfers Tab</h2>

<h3>What it does</h3>
<p>
    Orchestrates <strong>rsync</strong> file transfers between any combination
    of local machine and remote hosts. Progress is parsed from rsync's
    <code>--info=progress2</code> output and displayed live in the table.
    Transfer history is saved to
    <code>~/.config/LanScanMan/transfer_history.json</code>.
</p>

<h3>Local → Remote / Remote → Local</h3>
<div class="cmd-block">
    rsync --info=progress2 [-r] [-a] [-z] &lt;source&gt; &lt;user&gt;@&lt;ip&gt;:&lt;dest&gt;
</div>

<h3>Remote → Remote (both hosts are non-local)</h3>
<div class="cmd-block">
    ssh -A -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=... &lt;user&gt;@&lt;sender_ip&gt; &#92;<br>
    &nbsp;&nbsp;"bash -lc 'rsync --info=progress2 [args] &lt;src&gt; &lt;user&gt;@&lt;dest_ip&gt;:&lt;dst&gt;'"
</div>

<div class="warn-box">
    <strong>⚠ SSH Agent Forwarding (-A):</strong> Remote-to-remote transfers
    use SSH agent forwarding so the sender host can authenticate to the
    receiver without a password. While the transfer is active, the sender
    machine has access to your SSH agent. This means any process running
    as your user on that sender could use your agent to authenticate
    elsewhere. LanScanMan displays a warning in the UI when this mode is
    active. Only use remote-to-remote transfers with machines you trust.
</div>

<h3>Remote file browser (SFTP)</h3>
<p>
    The "Browse…" button for remote paths opens an SFTP session using
    Paramiko's SFTP subsystem. It calls <code>sftp.listdir_attr(path)</code>
    to list directories — read-only, no files are transferred or modified
    during browsing.
</p>

<hr>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<h2>Host Monitor Tab</h2>

<h3>What it does</h3>
<p>
    Connects to each configured host via SSH key auth and runs a single
    batched command that collects system metrics. The connection is opened,
    the command runs, and the connection is closed — one round trip per
    refresh. No persistent agent or daemon is installed on the remote host.
</p>

<h3>Remote command (runs as your SSH user, no sudo)</h3>
<div class="cmd-block">
    cat /etc/os-release &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="tag-muted"># distro name</span><br>
    grep "model name" /proc/cpuinfo &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="tag-muted"># CPU model</span><br>
    grep -c "^processor" /proc/cpuinfo &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="tag-muted"># CPU core count</span><br>
    cat /proc/stat &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="tag-muted"># CPU usage snapshot 1</span><br>
    sleep 1 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="tag-muted"># 1-second delta for CPU %</span><br>
    cat /proc/stat &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="tag-muted"># CPU usage snapshot 2</span><br>
    grep MemTotal/MemAvailable /proc/meminfo &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="tag-muted"># RAM</span><br>
    cat /proc/uptime &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="tag-muted"># uptime</span><br>
    /sys/class/hwmon/hwmon*/temp1_input &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="tag-muted"># CPU temp (hwmon)</span><br>
    /sys/class/drm/card0/device/gpu_busy_percent &nbsp;&nbsp;<span class="tag-muted"># AMD GPU usage</span><br>
    /sys/class/drm/card0/device/mem_info_vram_* &nbsp;&nbsp;&nbsp;<span class="tag-muted"># AMD GPU VRAM</span><br>
    /sys/class/drm/card0/device/hwmon/*/temp1_input<span class="tag-muted"># AMD GPU temp</span><br>
    nvidia-smi --query-gpu=... &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="tag-muted"># NVIDIA GPU (if present)</span><br>
    lspci | grep -iE "VGA|3D|Display" &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="tag-muted"># GPU name fallback</span>
</div>
<p>
    All reads are from <code>/proc</code>, <code>/sys</code>, and standard
    binaries. Nothing is written. No files are created or modified on the
    remote host.
</p>

<hr>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<h2>Disk Health Tab</h2>

<h3>What it does</h3>
<p>
    Connects via SSH key auth and runs a single batched command to gather
    disk layout, filesystem usage, and SMART health data. Uses a two-tier
    approach depending on available permissions.
</p>

<h3>Remote command — disk discovery (no sudo needed)</h3>
<div class="cmd-block">
    lsblk -d -n -b -o NAME,SIZE,TYPE,MODEL &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="tag-muted"># physical disks</span><br>
    df -B1 | grep "^/dev/" &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="tag-muted"># filesystem usage</span><br>
    udisksctl dump &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="tag-muted"># SMART via UDisks daemon</span>
</div>

<h3>Remote command — SMART data (tries sudo first, falls back to udisksctl)</h3>
<div class="cmd-block">
    sudo -n smartctl -iAH /dev/&lt;disk&gt; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="tag-muted"># tier 1: passwordless sudo</span><br>
    smartctl -iAH /dev/&lt;disk&gt; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="tag-muted"># tier 2: direct (if setuid)</span><br>
    <span class="tag-muted"># tier 3: read cached values from the udisksctl dump above</span>
</div>

<h3>SMART data tiers explained</h3>
<table>
    <tr>
        <th>Tier</th><th>Method</th><th>Data available</th><th>Requires</th>
    </tr>
    <tr>
        <td><span class="tag-good">Full</span></td>
        <td>smartctl with sudo</td>
        <td>All attributes: PASSED/FAILED, temp, TBW, bad sectors, wear, power-on hours</td>
        <td>NOPASSWD sudoers entry for <code>/usr/sbin/smartctl</code></td>
    </tr>
    <tr>
        <td><span class="tag-warn">Partial</span></td>
        <td>udisksctl dump</td>
        <td>PASSED/FAILED, temperature, power-on hours, bad sector count</td>
        <td>Nothing — works for any logged-in user</td>
    </tr>
    <tr>
        <td><span class="tag-bad">None</span></td>
        <td>—</td>
        <td>Only disk name and capacity from lsblk</td>
        <td>Drive not known to UDisks daemon (e.g. USB, eSATA hot-plug)</td>
    </tr>
</table>

<div class="warn-box">
    <strong>⚠ Regarding sudoers and smartctl:</strong> Granting passwordless
    sudo for <code>smartctl</code> allows your SSH user to read raw hardware
    data from all drives without a password prompt. This is lower risk than a
    general NOPASSWD sudo rule since smartctl is a read-only diagnostic tool,
    but it does mean any process running as your user on that host could invoke
    it. Restrict the sudoers entry to the exact binary path as shown.
</div>

<hr>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<h2>Security Warnings &amp; Liabilities</h2>

<div class="danger-box">
    <strong>⛔ LanScanMan is designed for use on networks you own and
    administer.</strong> Running network scans, SSH operations, or SMART
    probes against systems without explicit authorisation may violate computer
    misuse laws in your jurisdiction. The authors accept no liability for
    misuse.
</div>

<h3>Known security considerations</h3>

<table>
    <tr><th>Area</th><th>Risk</th><th>Mitigation in this app</th></tr>
    <tr>
        <td>Sudo password</td>
        <td>Required for Nmap SYN scan; held in memory for session duration if "Remember" is checked</td>
        <td>Never written to disk. Cleared if the scan fails with an auth error. Not transmitted anywhere.</td>
    </tr>
    <tr>
        <td>SSH agent forwarding</td>
        <td>Remote-to-remote rsync requires <code>-A</code>; sender can use your agent</td>
        <td>Explicit warning shown in the Transfer dialog before the task is added. Only active during the transfer.</td>
    </tr>
    <tr>
        <td>Host key trust</td>
        <td>First connection to a new host auto-trusts its key (TOFU model)</td>
        <td>Key saved to a dedicated known_hosts file. Any subsequent key change triggers a warning dialog and requires explicit user confirmation before proceeding.</td>
    </tr>
    <tr>
        <td>Path injection in rsync</td>
        <td>Malicious path strings could alter rsync behaviour</td>
        <td>All paths are passed through <code>shlex.quote()</code>. A regex check blocks shell metacharacters (<code>;&amp;|`$&lt;&gt;\"'</code>) in SFTP-browsed paths.</td>
    </tr>
    <tr>
        <td>Remote command execution</td>
        <td>The app runs commands on remote hosts via SSH</td>
        <td>All remote commands are hardcoded read-only operations (no writes, no installs). The exact command sent is documented in this tab.</td>
    </tr>
    <tr>
        <td>Profile data at rest</td>
        <td>Aliases, usernames, and IPs stored in JSON</td>
        <td>No passwords or private keys are ever written to disk by this application. Files are stored in <code>~/.config/LanScanMan/</code> with standard user permissions.</td>
    </tr>
    <tr>
        <td>Nmap SYN scan</td>
        <td>May be flagged by IDS on monitored networks</td>
        <td>Scan is limited to 6 ports and your local subnet only. The target is always the subnet you enter manually — there is no automatic subnet discovery.</td>
    </tr>
</table>

<h3>What this app does NOT do</h3>
<ul>
    <li>Does not store or transmit passwords (sudo or SSH)</li>
    <li>Does not modify any files on remote hosts (all remote operations are read-only, except SSH key installation which you explicitly trigger)</li>
    <li>Does not phone home, check for updates, or send any telemetry</li>
    <li>Does not scan ports beyond the six explicitly listed</li>
    <li>Does not install software, daemons, or cron jobs on remote hosts</li>
    <li>Does not persist SSH sessions between operations — each probe opens and closes its own connection</li>
</ul>

<div class="good-box">
    <strong>✔ Principle of least privilege:</strong> Every operation in this
    app requests only the access it needs. SSH key auth is used instead of
    passwords wherever possible. Remote commands use the minimum privilege
    level available — udisksctl before sudo, read-only /proc and /sys before
    any elevated tool. Sudo is only invoked for Nmap (required for SYN scan)
    and smartctl (optional, with explicit user setup).
</div>

<hr>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<h2>Data Stored on Your Machine</h2>

<table>
    <tr><th>File</th><th>Contents</th><th>When written</th></tr>
    <tr>
        <td><code>~/.config/LanScanMan/hosts.json</code></td>
        <td>
            Device profiles — alias, username, hostname, last seen IP.
            Keyed by MAC address where available, IP address otherwise.
            IP keys are automatically upgraded to MAC keys on first SSH connect.
        </td>
        <td>When you save or edit a profile; when a profile is MAC-upgraded on SSH connect</td>
    </tr>
    <tr>
        <td><code>~/.config/LanScanMan/known_hosts</code></td>
        <td>
            SSH host public keys for every remote host LanScanMan has connected to.
            Separate from <code>~/.ssh/known_hosts</code> so it does not interfere
            with your system SSH config. Standard OpenSSH format.
        </td>
        <td>On first successful SSH connection to a new host</td>
    </tr>
    <tr>
        <td><code>~/.config/LanScanMan/transfer_history.json</code></td>
        <td>
            Rsync job history — source path, destination path, status, size.
            No file content is stored, only metadata about the transfer.
            Restored on next launch so completed and in-progress jobs persist.
        </td>
        <td>When a transfer is added, updated, or cleared</td>
    </tr>
    <tr>
        <td><code>~/.ssh/id_ed25519[.pub]</code></td>
        <td>
            Your SSH key pair. Only generated if you click "Setup SSH Key" and
            no <code>id_ed25519</code> key already exists. The private key never
            leaves your machine — only the public key is copied to remote hosts.
        </td>
        <td>Only if you click "Setup SSH Key" and no key exists yet</td>
    </tr>
    <tr>
        <td><code>~/.config/LanScanMan/smart_log/&lt;host-key&gt;.json</code></td>
        <td>
            SMART attribute history for each host — one file per host, keyed by
            MAC address (or IP if MAC is unavailable). Stores reallocated sectors,
            pending sectors, uncorrectable errors, wear percentage, TBW, and
            power-on hours. Uses first-seen / last-seen deduplication so stable
            periods are represented by exactly two timestamps. Temperature is
            intentionally excluded — it is session-only data.
        </td>
        <td>Automatically on every successful Disk Health probe</td>
    </tr>
    <tr>
        <td><code>~/.config/LanScanMan/lanscanman.log</code></td>
        <td>
            Rotating diagnostic log — up to 5 files of 512 KB each
            (2.5 MB maximum). Records caught exceptions and unexpected
            conditions to help diagnose problems. Contains no credentials
            and no file contents — only event messages and stack traces.
        </td>
        <td>Continuously during app use when events are logged</td>
    </tr>
</table>

<hr>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<h2>SMART History Logging</h2>

<h3>What is logged</h3>
<p>
    Every time the Disk Health tab successfully probes a host, LanScanMan
    silently records a snapshot of the attributes that indicate physical
    degradation. These are the only values that matter for long-term trending:
</p>
<table>
    <tr><th>Attribute</th><th>Why it matters</th></tr>
    <tr>
        <td>Reallocated Sectors</td>
        <td>Sectors the drive has moved to spare area because they started failing.
        Any increase is a serious warning sign.</td>
    </tr>
    <tr>
        <td>Pending Sectors</td>
        <td>Sectors flagged as unstable and waiting to be reallocated.
        Should always be zero on a healthy drive.</td>
    </tr>
    <tr>
        <td>Uncorrectable Errors</td>
        <td>Read errors that could not be recovered. Should always be zero.</td>
    </tr>
    <tr>
        <td>Wear Percentage</td>
        <td>For SSDs — percentage of rated write endurance consumed. Increases
        slowly over the drive's life.</td>
    </tr>
    <tr>
        <td>TBW</td>
        <td>Total terabytes written. Useful context alongside wear percentage.</td>
    </tr>
    <tr>
        <td>Power-On Hours</td>
        <td>Recorded for context alongside each entry — tells you how much
        the drive had been used when the snapshot was taken. Does not by
        itself trigger new log entries.</td>
    </tr>
</table>
<p>
    Temperature is deliberately <strong>not</strong> logged — it fluctuates
    constantly with workload and ambient conditions. Knowing a drive ran at
    31°C fourteen months ago provides no useful information.
</p>

<h3>Deduplication — first seen / last seen</h3>
<p>
    Rather than logging every probe (which would create thousands of
    redundant entries), LanScanMan uses a <strong>first-seen / last-seen</strong>
    strategy:
</p>
<ul>
    <li>When a probe result matches the previous entry's attribute values,
    only the <code>last_seen</code> timestamp is updated in-place.</li>
    <li>When attributes change, the previous entry is finalised and a new
    entry begins.</li>
    <li>Any stable period is therefore represented by exactly two timestamps:
    when the state was first recorded, and when it last matched.</li>
</ul>
<p>
    Example — a drive stable for two years then showing its first bad sector:
</p>
<div class="cmd-block">
    2024-01-15  reallocated=0  pending=0  (first seen)<br>
    2026-04-17  reallocated=0  pending=0  (last seen before change)<br>
    2026-04-17  reallocated=1  pending=0  (change detected — new entry)<br>
    2026-04-18  reallocated=1  pending=0  (current)
</div>

<h3>Degradation alerts</h3>
<p>
    When a probe detects that any tracked attribute has worsened — for
    example reallocated sectors increasing — a desktop notification is
    sent immediately via <code>notify-send</code> with the specific change:
    <em>"Reallocated sectors: 0 → 3 on /dev/sda at farm1"</em>. The
    notification priority is set to critical so it is not silently discarded.
</p>

<h3>Viewing history</h3>
<p>
    In the Disk Health tab, double-click a host row to open its disk list.
    Then double-click any disk row (or right-click → View SMART History) to
    open the history chart for that disk. The chart shows attribute values
    over time with dots at each recorded state, a line connecting stable
    periods, and dashed red connectors where values changed.
</p>

<hr>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<h2>Host Inspector Tab</h2>

<h3>What it does</h3>
<p>
    The Host Inspector performs a deep port scan of a single host — going
    well beyond the six ports checked by the Network Scanner. It detects
    service versions, lets you filter results, and lets you connect to
    any open port directly from the results table.
</p>
<p>
    Use the Network Scanner to discover what's on your network. Use the
    Host Inspector when you want to dig deeper into a specific host — for
    example to see what's running on non-standard ports, or to find a
    service you didn't know was exposed.
</p>

<h3>Scan modes</h3>
<table>
    <tr><th>Mode</th><th>Ports scanned</th><th>Typical duration</th><th>When to use</th></tr>
    <tr>
        <td><strong>Quick</strong></td>
        <td>Top 1,000 most common ports</td>
        <td>5–15 seconds</td>
        <td>First investigation — covers nearly all real-world services</td>
    </tr>
    <tr>
        <td><strong>Full</strong></td>
        <td>All 65,535 ports</td>
        <td>1–5 minutes depending on host</td>
        <td>Thorough audit — finds services on non-standard ports</td>
    </tr>
    <tr>
        <td><strong>Custom</strong></td>
        <td>Ports you specify (e.g. <code>22,8080,9000</code> or <code>1-1024</code>)</td>
        <td>Seconds</td>
        <td>Quick check of specific ports you already suspect</td>
    </tr>
</table>

<h3>Commands executed — locally, as root via sudo (when sudo is enabled)</h3>
<div class="cmd-block">
    sudo nmap -sS -sV --version-intensity 5 [port-arg] -T4 -oX - &lt;host-ip&gt;
</div>
<p>
    Without sudo, falls back to <code>-sT</code> (TCP connect scan).
    Version detection (<code>-sV</code>) works in both modes but is more
    accurate with a SYN scan.
</p>

<h3>Connecting from results</h3>
<p>
    Double-click any row, or right-click for options. The connection dialog
    pre-fills the protocol (guessed from the service name or port number)
    and port, and uses the SSH username from your profile. All fields are
    editable before connecting. Supported protocols:
</p>
<ul>
    <li><strong>SSH</strong> — opens a terminal on the specified port. Username required.</li>
    <li><strong>VNC</strong> — opens a VNC URL in your default viewer.</li>
    <li><strong>RDP</strong> — opens an RDP URL.</li>
    <li><strong>HTTP / HTTPS</strong> — opens in your default web browser.</li>
</ul>

<h3>Connect on custom port from Network Scanner</h3>
<p>
    You don't need to run a Host Inspector scan to connect on a non-standard
    port. In the <strong>Network Scanner</strong>, right-click any online host
    and choose <em>Connect on custom port…</em> to open the same connection
    dialog and specify any protocol and port directly.
</p>

<hr>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<h2>Status Bar — WiFi Signal Indicator</h2>

<p>
    The bottom-right corner of the window shows your <strong>local</strong>
    machine's WiFi signal strength in dBm (decibels relative to one milliwatt).
    This reads <code>/proc/net/wireless</code> directly — no tools are needed
    and nothing is sent over the network. The indicator hides automatically
    on wired-only machines. It refreshes every 10 seconds.
</p>

<table>
    <tr><th>Signal range</th><th>Quality</th></tr>
    <tr><td><span class="tag-good">-50 dBm or better</span></td><td>Excellent — full bars, strong connection</td></tr>
    <tr><td><span class="tag-good">-51 to -65 dBm</span></td><td>Good — reliable for most tasks</td></tr>
    <tr><td><span class="tag-warn">-66 to -75 dBm</span></td><td>Fair — usable but may see latency</td></tr>
    <tr><td><span class="tag-warn">-76 to -85 dBm</span></td><td>Weak — connection may drop</td></tr>
    <tr><td><span class="tag-bad">Below -85 dBm</span></td><td>Very weak — expect disconnections</td></tr>
</table>

<hr>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<h2>Keyboard Shortcuts</h2>

<p>
    All shortcuts are active when the relevant tab is in focus.
    No modifier conflicts with standard desktop shortcuts.
</p>

<h3>Network Scanner</h3>
<table>
    <tr><th>Shortcut</th><th>Action</th></tr>
    <tr>
        <td><code>Ctrl + R</code></td>
        <td>Start a privileged SYN scan. Prompts for sudo password if not cached.</td>
    </tr>
    <tr>
        <td><code>Ctrl + Shift + R</code></td>
        <td>Start an unprivileged TCP connect scan. No password required.</td>
    </tr>
    <tr>
        <td><code>Escape</code></td>
        <td>Cancel the currently running scan.</td>
    </tr>
    <tr>
        <td><code>Enter / Return</code></td>
        <td>Connect to the selected row — identical to double-clicking. Runs the full SSH probe and tmux detection flow for the primary user.</td>
    </tr>
    <tr>
        <td><code>Delete</code></td>
        <td>Delete the saved profile for the selected row. Shows the same confirmation dialog as right-click → Delete Profile.</td>
    </tr>
</table>

<h3>File Transfers</h3>
<table>
    <tr><th>Shortcut</th><th>Action</th></tr>
    <tr>
        <td><code>Ctrl + N</code></td>
        <td>Open the Add Transfer dialog.</td>
    </tr>
</table>

<h3>Host Monitor &amp; Disk Health</h3>
<table>
    <tr><th>Shortcut</th><th>Action</th></tr>
    <tr>
        <td><code>F5</code></td>
        <td>Refresh all hosts. Works on whichever of the two tabs is currently active.</td>
    </tr>
</table>

<h3>Host Inspector</h3>
<table>
    <tr><th>Shortcut</th><th>Action</th></tr>
    <tr>
        <td><code>F5</code></td>
        <td>Start a scan of the currently selected host.</td>
    </tr>
    <tr>
        <td><code>Escape</code></td>
        <td>Cancel the running scan.</td>
    </tr>
    <tr>
        <td><code>Enter / Return</code></td>
        <td>Open the connection dialog for the selected result row.</td>
    </tr>
</table>
"""

_HTML = f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8">{_STYLE}</head>
<body>
<div style="max-width: 860px; margin: 0 auto; padding: 20px 24px 40px 24px;">
{_CONTENT}
</div>
</body>
</html>
"""


# ─────────────────────────────────────────────────────────────────────────────
# AboutTab widget
# ─────────────────────────────────────────────────────────────────────────────

class AboutTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        browser = QTextBrowser()
        browser.setHtml(_HTML)
        browser.setOpenExternalLinks(True)
        browser.setReadOnly(True)

        # Match the app's panel background so there's no white flash
        browser.setStyleSheet("""
            QTextBrowser {
                background-color: #121417;
                border: none;
                padding: 0px;
            }
            QScrollBar:vertical {
                background: #1B1F24;
                width: 10px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical {
                background: #3A4452;
                border-radius: 5px;
                min-height: 30px;
            }
            QScrollBar::handle:vertical:hover {
                background: #3498db;
            }
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)

        root.addWidget(browser)