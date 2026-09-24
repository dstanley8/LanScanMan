"""Keyring-backed integrity: the key, signed files, the vault, and each signed store."""

import base64
import json

import paramiko
import pytest
from conftest import FakeKeyring
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from lanscanman import paths
from lanscanman.core import sshkey
from lanscanman.core.integrity import (
    KEYRING_ITEM,
    KeyUnavailable,
    SignedFile,
    TamperedError,
    load_key,
    sign,
)
from lanscanman.core.profiles import ProfileStore
from lanscanman.core.schedules import (
    Schedule,
    ScheduleIntegrityError,
    ScheduleKeyUnavailable,
    ScheduleManager,
)
from lanscanman.services import ssh
from lanscanman.services.network_manager import NetworkManager
from lanscanman.services.secret_store import SERVICE, SecretStore, SecretStoreError
from lanscanman.services.vault import ADOPTED_ITEM, DECLINE_COOLDOWN, Vault, set_vault

MAC = "aa:bb:cc:dd:ee:ff"


class CountingKeyring(FakeKeyring):
    """Counts reads, i.e. how often a real keyring would have prompted."""
    def __init__(self, locked=False):
        super().__init__(locked)
        self.reads = 0

    def get_password(self, service, name):
        self.reads += 1
        return super().get_password(service, name)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def keyring_vault(isolated_config):
    kr, clock = CountingKeyring(), Clock()
    v = Vault(SecretStore(kr), key_file=isolated_config / "hmac.key", clock=clock)
    set_vault(v)
    return v, kr, clock


# ── SecretStore ─────────────────────────────────────────────────────────────

def test_secret_store_roundtrip(fake_keyring):
    store = SecretStore(fake_keyring)
    assert store.available and store.get("x") is None
    store.set("x", "secret")
    assert fake_keyring.items[(SERVICE, "x")] == "secret"
    store.delete("x")
    assert store.get("x") is None


def test_secret_store_locked_raises():
    with pytest.raises(SecretStoreError):
        SecretStore(FakeKeyring(locked=True)).get("x")


def test_default_store_is_disconnected_in_tests():
    assert not SecretStore.default().available


# ── load_key ────────────────────────────────────────────────────────────────

def test_no_keyring_uses_file(tmp_path):
    key, where = load_key(tmp_path / "hmac.key", SecretStore(None))
    assert where == "file" and len(key) == 32
    assert (tmp_path / "hmac.key").read_bytes() == key
    assert (tmp_path / "hmac.key").stat().st_mode & 0o777 == 0o600


def test_fresh_install_keeps_key_only_in_keyring(tmp_path, fake_keyring):
    key, where = load_key(tmp_path / "hmac.key", SecretStore(fake_keyring))
    assert where == "keyring"
    assert base64.b64decode(fake_keyring.items[(SERVICE, KEYRING_ITEM)]) == key
    assert not (tmp_path / "hmac.key").exists()


def test_file_key_is_migrated_then_deleted(tmp_path, fake_keyring):
    (tmp_path / "hmac.key").write_bytes(b"k" * 32)
    assert load_key(tmp_path / "hmac.key", SecretStore(fake_keyring)) == (b"k" * 32, "keyring")
    assert not (tmp_path / "hmac.key").exists()
    assert load_key(tmp_path / "hmac.key", SecretStore(fake_keyring)) == (b"k" * 32, "keyring")


def test_locked_keyring_touches_nothing(tmp_path):
    (tmp_path / "hmac.key").write_bytes(b"k" * 32)
    with pytest.raises(KeyUnavailable):
        load_key(tmp_path / "hmac.key", SecretStore(FakeKeyring(locked=True)))
    assert (tmp_path / "hmac.key").read_bytes() == b"k" * 32


# ── SignedFile ──────────────────────────────────────────────────────────────

def test_signed_file_roundtrip_and_tamper(tmp_path):
    f = SignedFile(tmp_path / "data", lambda: b"k" * 32)
    assert f.read() is None
    f.write(b"hello")
    assert f.read() == b"hello"
    assert (tmp_path / "data").stat().st_mode & 0o777 == 0o600
    (tmp_path / "data").write_bytes(b"evil")
    with pytest.raises(TamperedError):
        f.read()
    f.resign()
    assert f.read() == b"evil"


def test_signed_file_missing_signature_is_tampered(tmp_path):
    (tmp_path / "data").write_bytes(b"x")
    with pytest.raises(TamperedError):
        SignedFile(tmp_path / "data", lambda: b"k" * 32).read()


def test_signed_file_write_with_locked_key_changes_nothing(tmp_path):
    good = SignedFile(tmp_path / "data", lambda: b"k" * 32)
    good.write(b"original")

    def locked():
        raise KeyUnavailable("locked")
    with pytest.raises(KeyUnavailable):
        SignedFile(tmp_path / "data", locked).write(b"changed")
    assert good.read() == b"original"


# ── Vault ───────────────────────────────────────────────────────────────────

def test_vault_caches_key(keyring_vault):
    v, kr, _ = keyring_vault
    v.key()
    reads = kr.reads
    for _ in range(5):
        v.key()
    assert kr.reads == reads


def test_declined_unlock_asks_once_per_action_then_again_later(keyring_vault):
    v, kr, clock = keyring_vault
    kr.locked = True
    with pytest.raises(KeyUnavailable):
        v.key()
    first = kr.reads
    for _ in range(10):                    # e.g. Refresh All over ten hosts
        with pytest.raises(KeyUnavailable):
            v.key()
    assert kr.reads == first               # no extra prompts
    clock.t += DECLINE_COOLDOWN + 1        # the user's next action
    kr.locked = False
    assert v.try_unlock()
    assert kr.reads > first


def test_adoption_signs_preexisting_files_once(keyring_vault, isolated_config):
    v, kr, _ = keyring_vault
    (isolated_config / "hosts.json").write_text("{}")          # from before signing existed
    f = v.signed_file(isolated_config / "hosts.json")
    v.key()
    assert f.read() == b"{}"
    assert "hosts.json" in json.loads(kr.items[(SERVICE, ADOPTED_ITEM)])


def test_deleting_signature_later_is_not_re_trusted(keyring_vault, isolated_config):
    v, _, _ = keyring_vault
    f = v.signed_file(isolated_config / "hosts.json")
    f.write(b"{}")
    (isolated_config / "hosts.json").write_text('{"evil": {}}')
    f.sig_path.unlink()                                        # attacker removes the .sig
    fresh = Vault(v.store, key_file=v.key_file)                # next app start
    g = fresh.signed_file(isolated_config / "hosts.json")
    fresh.key()
    with pytest.raises(TamperedError):
        g.read()


def test_ensure_trusted_runs_checks(keyring_vault):
    v, _, _ = keyring_vault
    calls = []
    v.add_trust_check(lambda: calls.append(1))
    v.ensure_trusted()
    assert calls == [1]


# ── hosts.json ──────────────────────────────────────────────────────────────

def test_profiles_display_only_while_locked(keyring_vault, isolated_config):
    v, kr, clock = keyring_vault
    store = ProfileStore(signed_file=v.signed_file(isolated_config / "hosts.json"))
    store.put(MAC, "192.168.50.5", "nas", "NAS", "carol")

    set_vault(None)
    kr.locked = True
    locked_vault = Vault(SecretStore(kr), key_file=v.key_file, clock=clock)
    locked = ProfileStore(signed_file=locked_vault.signed_file(isolated_config / "hosts.json"))
    assert locked.get(MAC, "")["alias"] == "NAS"          # still shown
    assert not locked.verified and isinstance(locked.problem, KeyUnavailable)
    before = (isolated_config / "hosts.json").read_bytes()
    clock.t += DECLINE_COOLDOWN + 1
    with pytest.raises(KeyUnavailable):
        locked.put(MAC, "192.168.50.5", "nas", "Renamed", "carol")   # edits need the key
    assert (isolated_config / "hosts.json").read_bytes() == before

    kr.locked = False
    clock.t += DECLINE_COOLDOWN + 1
    locked.put(MAC, "192.168.50.5", "nas", "Renamed", "carol")
    assert locked.verified and locked.get(MAC, "")["alias"] == "Renamed"


def test_tampered_profiles_are_flagged_and_block_edits(keyring_vault, isolated_config):
    v, _, _ = keyring_vault
    path = isolated_config / "hosts.json"
    ProfileStore(signed_file=v.signed_file(path)).put(MAC, "192.168.50.5", "nas", "NAS", "carol")
    path.write_text(json.dumps({MAC: {"alias": "NAS", "username": "root", "last_ip": "6.6.6.6"}}))
    store = ProfileStore(signed_file=v.signed_file(path))
    assert isinstance(store.problem, TamperedError)
    with pytest.raises(TamperedError):
        store.add_extra_user(MAC, "", "x")
    store.trust_current_file()                              # user says "I made that edit"
    assert store.verified and store.get(MAC, "")["last_ip"] == "6.6.6.6"


def test_clear_works_even_when_tampered(keyring_vault, isolated_config):
    v, _, _ = keyring_vault
    path = isolated_config / "hosts.json"
    path.write_text("{}")
    v.key()
    path.write_text('{"evil": {}}')
    store = ProfileStore(signed_file=v.signed_file(path))
    store.clear()
    assert store.profiles == {} and not path.exists()


# ── schedules ───────────────────────────────────────────────────────────────

def test_schedules_upgrade_from_file_key(isolated_config, fake_keyring):
    old = ScheduleManager(isolated_config)                 # old version: hmac.key file
    old.schedules = [Schedule(name="Nightly")]
    old.save()
    v = Vault(SecretStore(fake_keyring), key_file=isolated_config / "hmac.key")
    new = ScheduleManager(isolated_config, key_provider=v.key)
    new.load()
    assert [s.name for s in new.schedules] == ["Nightly"]
    assert v.location == "keyring" and not (isolated_config / "hmac.key").exists()


def test_schedules_forged_with_planted_file_key_are_rejected(isolated_config, fake_keyring):
    v = Vault(SecretStore(fake_keyring), key_file=isolated_config / "hmac.key")
    m = ScheduleManager(isolated_config, key_provider=v.key)
    m.schedules = [Schedule(name="Nightly")]
    m.save()
    content = b'{"version": 1, "lists": [{"name": "Evil"}]}'
    (isolated_config / "schedules.json").write_bytes(content)
    (isolated_config / "hmac.key").write_bytes(b"a" * 32)
    (isolated_config / "schedules.hmac").write_text(sign(b"a" * 32, content))
    with pytest.raises(ScheduleIntegrityError):
        ScheduleManager(isolated_config, key_provider=Vault(
            SecretStore(fake_keyring), key_file=isolated_config / "hmac.key").key).load()


def test_schedules_locked_keyring(isolated_config, fake_keyring):
    v = Vault(SecretStore(fake_keyring), key_file=isolated_config / "hmac.key")
    m = ScheduleManager(isolated_config, key_provider=v.key)
    m.schedules = [Schedule(name="Nightly")]
    m.save()
    before = (isolated_config / "schedules.json").read_bytes()
    fake_keyring.locked = True
    locked = ScheduleManager(isolated_config, key_provider=Vault(
        SecretStore(fake_keyring), key_file=isolated_config / "hmac.key").key)
    with pytest.raises(ScheduleKeyUnavailable):
        locked.load()
    locked.schedules = [Schedule(name="Changed")]
    with pytest.raises(ScheduleKeyUnavailable):
        locked.save()
    assert (isolated_config / "schedules.json").read_bytes() == before


# ── known_hosts ─────────────────────────────────────────────────────────────

def _key():
    return paramiko.ECDSAKey.generate()


def test_known_hosts_add_remove_are_signed(isolated_config):
    k = _key()
    ssh.add_host_key("192.168.50.5", k)
    assert ssh.trusted_host_keys().lookup("192.168.50.5")[k.get_name()].asbytes() == k.asbytes()
    assert (isolated_config / "known_hosts.sig").exists()
    ssh.remove_host_from_known_hosts("192.168.50.5")
    assert ssh.trusted_host_keys().lookup("192.168.50.5") is None


def test_swapped_host_key_blocks_all_ssh(isolated_config):
    ssh.add_host_key("192.168.50.5", _key())
    evil = _key()
    (isolated_config / "known_hosts").write_text(
        f"192.168.50.5 {evil.get_name()} {evil.get_base64()}\n")
    with pytest.raises(TamperedError):
        ssh.make_ssh_client()
    with pytest.raises(TamperedError):
        ssh.prepare_cli_ssh("192.168.50.5", fetch=lambda *a, **k: evil)


def test_prepare_cli_ssh_pins_on_first_use_then_detects_change(isolated_config):
    first, other = _key(), _key()
    ssh.prepare_cli_ssh("192.168.50.5", fetch=lambda *a, **k: first)
    assert ssh.trusted_host_keys().lookup("192.168.50.5") is not None
    ssh.prepare_cli_ssh("192.168.50.5", fetch=lambda *a, **k: first)      # same key: fine
    with pytest.raises(ssh.HostKeyMismatchError):
        ssh.prepare_cli_ssh("192.168.50.5", fetch=lambda *a, **k: other)


def test_prepare_cli_ssh_asks_for_pinned_key_types_and_ports(isolated_config):
    k = _key()
    seen = {}

    def fetch(ip, port, key_types=None):
        seen.update(ip=ip, port=port, key_types=key_types)
        return k
    ssh.prepare_cli_ssh("192.168.50.5", 2222, fetch=fetch)
    assert ssh.trusted_host_keys().lookup("[192.168.50.5]:2222") is not None
    ssh.prepare_cli_ssh("192.168.50.5", 2222, fetch=fetch)
    assert seen == {"ip": "192.168.50.5", "port": 2222, "key_types": [k.get_name()]}


def test_connection_helpers_do_not_swallow_integrity_errors(isolated_config):
    nm = NetworkManager()
    ssh.add_host_key("192.168.50.5", _key())
    (isolated_config / "known_hosts").write_text("tampered\n")
    # Previously any exception meant "(False, [])" -> a misleading
    # "push your SSH key" dialog. Tampering must surface as tampering.
    with pytest.raises(TamperedError):
        nm.get_remote_tmux_sessions("carol", "192.168.50.5")


def test_network_manager_registers_hosts_json(isolated_config):
    NetworkManager().save_profile(MAC, "192.168.50.5", "nas", "NAS", "carol")
    (isolated_config / "hosts.json").write_text("{}")
    with pytest.raises(TamperedError):
        ssh.make_ssh_client()          # connecting checks hosts.json too


# ── SSH private key ─────────────────────────────────────────────────────────

def _openssh_key(passphrase: bytes | None) -> str:
    enc = (serialization.BestAvailableEncryption(passphrase) if passphrase
           else serialization.NoEncryption())
    return ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, enc).decode()


def test_is_encrypted_openssh():
    assert sshkey.is_encrypted(_openssh_key(None)) is False
    assert sshkey.is_encrypted(_openssh_key(b"hunter2")) is True


def test_is_encrypted_legacy_pem_and_garbage():
    assert sshkey.is_encrypted("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n...") is True
    assert sshkey.is_encrypted("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n") is False
    assert sshkey.is_encrypted("-----BEGIN ENCRYPTED PRIVATE KEY-----\n...") is True
    assert sshkey.is_encrypted("not a key") is None


def test_key_status(tmp_path):
    p = tmp_path / "id"
    assert sshkey.key_status(p) == "missing"
    p.write_text(_openssh_key(None))
    assert sshkey.key_status(p) == "unencrypted"
    p.write_text(_openssh_key(b"pw"))
    assert sshkey.key_status(p) == "encrypted"


def test_no_key_is_never_generated_silently(isolated_config):
    ok, reason = NetworkManager().ensure_ssh_key()
    assert (ok, reason) == (False, "no_key")
    assert not sshkey.DEFAULT_KEY.exists()


def test_interactive_commands_quote_paths(tmp_path):
    p = tmp_path / "my keys" / "id"
    assert sshkey.keygen_command(p) == f"ssh-keygen -t ed25519 -f '{p}'"
    assert sshkey.add_passphrase_command(p) == f"ssh-keygen -p -f '{p}'"
    assert sshkey.ssh_add_command(p) == f"ssh-add '{p}'"


def test_isolation_paths_point_at_tmp(isolated_config):
    assert paths.KNOWN_HOSTS.parent == isolated_config
