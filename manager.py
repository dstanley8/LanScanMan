import json
from pathlib import Path
import subprocess
import paramiko
import socket


KNOWN_HOSTS = Path.home() / ".config" / "LanScanMan" / "known_hosts"


class HostKeyMismatchError(Exception):
    """Raised when a host's key has changed — may be benign (reinstall) or malicious (MITM)."""
    def __init__(self, hostname):
        self.hostname = hostname
        super().__init__(f"Host key mismatch for {hostname}")


def remove_host_from_known_hosts(hostname):
    if not KNOWN_HOSTS.exists():
        return
    lines = KNOWN_HOSTS.read_text().splitlines()
    filtered = [l for l in lines if not l.startswith(hostname + " ")]
    KNOWN_HOSTS.write_text("\n".join(filtered) + "\n")


class LanScanManHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Auto-trusts new hosts (saves to known_hosts). Paramiko rejects mismatches automatically."""
    def missing_host_key(self, client, hostname, key):
        KNOWN_HOSTS.parent.mkdir(parents=True, exist_ok=True)
        with open(KNOWN_HOSTS, "a") as f:
            f.write(f"{hostname} {key.get_name()} {key.get_base64()}\n")
        client._host_keys.add(hostname, key.get_name(), key)


def _make_ssh_client():
    ssh = paramiko.SSHClient()
    if KNOWN_HOSTS.exists():
        ssh.load_host_keys(str(KNOWN_HOSTS))
    ssh.set_missing_host_key_policy(LanScanManHostKeyPolicy())
    return ssh


class NetworkManager:
    def __init__(self):
        self.config_dir  = Path.home() / ".config" / "LanScanMan"
        self.config_file = self.config_dir / "hosts.json"
        self.profiles    = self.load_profiles()

    # ── Persistence ───────────────────────────────────────────────────────────

    def load_profiles(self):
        if not self.config_file.exists():
            return {}
        try:
            with open(self.config_file, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def _write_profiles(self):
        self.config_dir.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, "w") as f:
            json.dump(self.profiles, f, indent=4)

    # ── Profile CRUD ──────────────────────────────────────────────────────────

    def save_profile(self, mac, ip, hostname, alias, username):
        key = mac if mac else ip
        # Preserve extra_users when updating an existing profile
        existing    = self.profiles.get(key, {})
        extra_users = existing.get("extra_users", [])
        self.profiles[key] = {
            "alias":       alias,
            "username":    username,
            "last_ip":     ip,
            "hostname":    hostname,
            "extra_users": extra_users,
        }
        self._write_profiles()

    def get_profile(self, mac, ip):
        key = mac if mac else ip
        return self.profiles.get(key, {})

    def _profile_key(self, mac: str, ip: str) -> str | None:
        key = mac if (mac and ":" in mac) else ip
        return key if key in self.profiles else None

    # ── Extra user management ─────────────────────────────────────────────────

    def add_extra_user(self, mac: str, ip: str, username: str) -> bool:
        """Add a secondary username. Returns False if already present."""
        key = self._profile_key(mac, ip)
        if key is None:
            return False
        profile = self.profiles[key]
        if username == profile.get("username") or \
           username in profile.get("extra_users", []):
            return False
        profile.setdefault("extra_users", []).append(username)
        self._write_profiles()
        return True

    def remove_extra_user(self, mac: str, ip: str, username: str):
        key = self._profile_key(mac, ip)
        if key is None:
            return
        extras = self.profiles[key].get("extra_users", [])
        if username in extras:
            extras.remove(username)
            self.profiles[key]["extra_users"] = extras
            self._write_profiles()

    def set_primary_user(self, mac: str, ip: str, username: str):
        """Promote a secondary user to primary, demoting the current primary."""
        key = self._profile_key(mac, ip)
        if key is None:
            return
        profile         = self.profiles[key]
        current_primary = profile.get("username", "")
        extras          = profile.get("extra_users", [])
        if username not in extras:
            return
        extras.remove(username)
        if current_primary and current_primary not in extras:
            extras.append(current_primary)
        profile["username"]    = username
        profile["extra_users"] = extras
        self._write_profiles()

    def get_all_users(self, mac: str, ip: str) -> list[str]:
        """Return [primary, *extra_users] or [] if no profile / no username."""
        profile = self.get_profile(mac, ip)
        primary = profile.get("username", "").strip()
        if not primary or primary == "—":
            return []
        return [primary] + profile.get("extra_users", [])

    # ── SSH operations ────────────────────────────────────────────────────────

    def get_remote_tmux_sessions(self, user, ip):
        try:
            ssh = _make_ssh_client()
            ssh.connect(ip, username=user, timeout=3,
                        look_for_keys=True, allow_agent=True)
            _, stdout, _ = ssh.exec_command("tmux ls 2>/dev/null; echo EXIT:$?")
            output    = stdout.read().decode().strip()
            ssh.close()

            lines      = output.splitlines()
            exit_line  = next((l for l in lines if l.startswith("EXIT:")), "EXIT:0")
            exit_code  = int(exit_line.split(":")[1])
            tmux_lines = [l for l in lines if not l.startswith("EXIT:")]

            if exit_code == 127:
                return True, None
            sessions = [l.split(":")[0] for l in tmux_lines if ":" in l]
            return True, sessions

        except paramiko.BadHostKeyException:
            raise HostKeyMismatchError(ip)
        except Exception:
            return False, []

    def enrich_profile_with_mac(self, user: str, ip: str) -> str | None:
        """SSH in, read remote MAC, re-key profile from IP to MAC if needed."""
        try:
            ssh = _make_ssh_client()
            ssh.connect(ip, username=user, timeout=5,
                        look_for_keys=True, allow_agent=True)
            cmd = (
                "iface=$(ip route 2>/dev/null | awk '/^default/{print $5; exit}'); "
                "if [ -n \"$iface\" ]; then "
                "  cat /sys/class/net/$iface/address 2>/dev/null; "
                "else "
                "  ip link 2>/dev/null | awk '/ether/{print $2; exit}'; "
                "fi"
            )
            _, stdout, _ = ssh.exec_command(cmd, timeout=5)
            mac = stdout.read().decode().strip().lower()
            ssh.close()

            if not mac or len(mac) != 17 or mac.count(":") != 5:
                return None

            ip_key = None
            for key, data in self.profiles.items():
                if data.get("last_ip") == ip and ":" not in key:
                    ip_key = key
                    break

            if ip_key and mac not in self.profiles:
                profile            = self.profiles.pop(ip_key)
                self.profiles[mac] = profile
                self._write_profiles()

            return mac

        except Exception:
            return None

    def ensure_ssh_key(self) -> tuple[bool, str]:
        """
        Generate an ed25519 key pair if one doesn't exist.
        Returns (True, public_key_text) or (False, error_message).
        """
        key_path     = Path.home() / ".ssh" / "id_ed25519"
        pub_key_path = Path.home() / ".ssh" / "id_ed25519.pub"

        if not key_path.exists():
            result = subprocess.run(
                ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path)],
                capture_output=True,
            )
            if result.returncode != 0:
                return False, "Failed to generate SSH key pair"

        try:
            return True, pub_key_path.read_text().strip()
        except Exception as e:
            return False, f"Could not read public key: {e}"

    def push_ssh_key_silent(self, user: str, ip: str) -> tuple[bool, str]:
        """
        Install our public key on a remote host using existing key auth — no password.

        Returns (True, "") on success.
        Returns (False, "auth_failed") if key auth isn't set up yet — the caller
        should fall back to launching ssh-copy-id in a terminal.
        Returns (False, error) for any other failure.
        Never handles raw passwords.
        """
        ok, result = self.ensure_ssh_key()
        if not ok:
            return False, result
        pub_key = result

        try:
            ssh = _make_ssh_client()
            ssh.connect(ip, username=user, timeout=8,
                        look_for_keys=True, allow_agent=True)
            commands = [
                "mkdir -p ~/.ssh",
                "chmod 700 ~/.ssh",
                "touch ~/.ssh/authorized_keys",
                "chmod 600 ~/.ssh/authorized_keys",
                f"grep -qxF '{pub_key}' ~/.ssh/authorized_keys "
                f"|| echo '{pub_key}' >> ~/.ssh/authorized_keys",
            ]
            for cmd in commands:
                _, stdout, stderr = ssh.exec_command(cmd)
                if stdout.channel.recv_exit_status() != 0:
                    err = stderr.read().decode().strip()
                    ssh.close()
                    return False, f"Command failed: {cmd}\n{err}"
            ssh.close()
            return True, ""

        except paramiko.BadHostKeyException:
            raise HostKeyMismatchError(ip)
        except paramiko.AuthenticationException:
            # Key auth not set up yet — signal caller to use ssh-copy-id
            return False, "auth_failed"
        except paramiko.SSHException as e:
            return False, f"SSH error: {e}"
        except Exception as e:
            return False, str(e)

    def get_ping_latency(self, ip):
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True, text=True, timeout=1.5,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "time=" in line:
                        latency_str = line.split("time=")[1].split(" ")[0]
                        return f"{float(latency_str):.1f}ms"
            return "Timeout"
        except Exception:
            return "Error"

    def wake_device(self, mac_address):
        if not mac_address or ":" not in mac_address:
            return False, "Invalid MAC address"
        try:
            clean_mac = mac_address.replace(":", "").replace("-", "")
            data = bytes.fromhex("FFFFFFFFFFFF" + clean_mac * 16)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.sendto(data, ("<broadcast>", 9))
            return True, None
        except Exception as e:
            return False, str(e)