"""
NetworkManager — the one object the UI tabs share. A facade over the
profile store (core/profiles.py) plus the side-effecting operations:
SSH probes, key setup, ping and Wake-on-LAN.
"""

import socket
import subprocess

import paramiko

from lanscanman import paths
from lanscanman.core import sshkey
from lanscanman.core.connect import authorized_keys_commands, parse_tmux_ls
from lanscanman.core.devices import DeviceRegistry
from lanscanman.core.integrity import IntegrityError
from lanscanman.core.net import magic_packet, parse_ping_latency
from lanscanman.core.profiles import ProfileStore
from lanscanman.services.ssh import connect, mismatch_from
from lanscanman.services.vault import get_vault

# Reads the MAC of the remote host's default-route interface
_REMOTE_MAC_CMD = (
    "iface=$(ip route 2>/dev/null | awk '/^default/{print $5; exit}'); "
    "if [ -n \"$iface\" ]; then "
    "  cat /sys/class/net/$iface/address 2>/dev/null; "
    "else "
    "  ip link 2>/dev/null | awk '/ether/{print $2; exit}'; "
    "fi"
)


class NetworkManager:
    def __init__(self, store: ProfileStore | None = None):
        vault = get_vault()
        self.store = store or ProfileStore(signed_file=vault.signed_file(paths.HOSTS_FILE))
        # Connecting anywhere requires hosts.json to verify
        vault.add_trust_check(self.store.require_verified)
        # Every device ever seen, for new-device alerts (signed: it decides
        # what does *not* raise an alert)
        self.devices = DeviceRegistry(vault.signed_file(paths.DEVICES_FILE))

    # ── Profiles (delegated) ──────────────────────────────────────────────────

    @property
    def profiles(self) -> dict:
        return self.store.profiles

    def save_profile(self, mac, ip, hostname, alias, username):
        self.store.put(mac, ip, hostname, alias, username)

    def get_profile(self, mac, ip):
        return self.store.get(mac, ip)

    def delete_profile(self, mac: str, ip: str) -> bool:
        return self.store.delete(mac, ip)

    def clear_profiles(self) -> None:
        self.store.clear()

    def add_extra_user(self, mac: str, ip: str, username: str) -> bool:
        return self.store.add_extra_user(mac, ip, username)

    def remove_extra_user(self, mac: str, ip: str, username: str):
        self.store.remove_extra_user(mac, ip, username)

    def set_primary_user(self, mac: str, ip: str, username: str):
        self.store.set_primary_user(mac, ip, username)

    def get_all_users(self, mac: str, ip: str) -> list[str]:
        return self.store.all_users(mac, ip)

    # ── SSH operations ────────────────────────────────────────────────────────

    def get_remote_tmux_sessions(self, user, ip):
        """
        (True, [sessions]) — connected; tmux present
        (True, None)       — connected; tmux not installed
        (False, [])        — could not connect / authenticate
        Raises HostKeyMismatchError if the host key changed.
        """
        try:
            ssh = connect(ip, user, timeout=3)
            _, stdout, _ = ssh.exec_command("tmux ls 2>/dev/null; echo EXIT:$?")
            output = stdout.read().decode()
            ssh.close()
            return parse_tmux_ls(output)
        except paramiko.BadHostKeyException as e:
            raise mismatch_from(e) from None
        except IntegrityError:
            raise
        except Exception:
            return False, []

    def enrich_profile_with_mac(self, user: str, ip: str) -> str | None:
        """SSH in, read the remote MAC, and re-key an IP-keyed profile to it."""
        try:
            ssh = connect(ip, user, timeout=5)
            _, stdout, _ = ssh.exec_command(_REMOTE_MAC_CMD, timeout=5)
            mac = stdout.read().decode().strip().lower()
            ssh.close()
        except IntegrityError:
            raise
        except Exception:
            return None
        if not mac or len(mac) != 17 or mac.count(":") != 5:
            return None
        self.store.rekey_ip_to_mac(ip, mac)
        return mac

    def ensure_ssh_key(self) -> tuple[bool, str]:
        """
        (True, public_key_text) if ~/.ssh/id_ed25519 exists, else
        (False, "no_key"). Keys are never generated here: an unencrypted
        key would be a plain file that logs in to every host. The UI creates
        one interactively instead (ui/ssh_key.py).
        """
        key_path = sshkey.DEFAULT_KEY
        pub_key_path = key_path.with_name(key_path.name + ".pub")
        if not key_path.exists():
            return False, "no_key"
        try:
            return True, pub_key_path.read_text().strip()
        except Exception as e:
            return False, f"Could not read public key: {e}"

    def push_ssh_key_silent(self, user: str, ip: str) -> tuple[bool, str]:
        """
        Install our public key using existing key auth — never handles passwords.

        (True, "")             success
        (False, "auth_failed") key auth isn't set up yet; caller should fall
                               back to ssh-copy-id in a terminal
        (False, error)         anything else
        """
        ok, result = self.ensure_ssh_key()
        if not ok:
            return False, result
        pub_key = result

        try:
            ssh = connect(ip, user, timeout=8)
            commands = authorized_keys_commands(pub_key)
            for cmd in commands:
                _, stdout, stderr = ssh.exec_command(cmd)
                if stdout.channel.recv_exit_status() != 0:
                    err = stderr.read().decode().strip()
                    ssh.close()
                    return False, f"Command failed: {cmd}\n{err}"
            ssh.close()
            return True, ""
        except paramiko.BadHostKeyException as e:
            raise mismatch_from(e) from None
        except paramiko.AuthenticationException:
            return False, "auth_failed"
        except paramiko.SSHException as e:
            return False, f"SSH error: {e}"
        except IntegrityError:
            raise
        except Exception as e:
            return False, str(e)

    # ── Local network operations ──────────────────────────────────────────────

    def get_ping_latency(self, ip):
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True, text=True, timeout=1.5,
            )
            if result.returncode == 0:
                return parse_ping_latency(result.stdout) or "Timeout"
            return "Timeout"
        except Exception:
            return "Error"

    def wake_device(self, mac_address):
        if not mac_address or ":" not in mac_address:
            return False, "Invalid MAC address"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.sendto(magic_packet(mac_address), ("<broadcast>", 9))
            return True, None
        except Exception as e:
            return False, str(e)
