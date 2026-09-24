"""The conftest guards must actually block network tools — prove it."""
import socket
import subprocess

import pytest


@pytest.mark.parametrize("argv", [["nmap", "-sn", "192.168.50.0/24"], ["ping", "-c1", "192.168.50.1"],
                                  ["sudo", "-S", "nmap"], ["ssh", "host"], ["rsync", "a", "b"]])
def test_network_tools_are_blocked(argv):
    with pytest.raises(AssertionError):
        subprocess.run(argv)
    with pytest.raises(AssertionError):
        subprocess.Popen(argv)


def test_sockets_are_blocked():
    with pytest.raises(AssertionError):
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM).connect(("8.8.8.8", 80))


def test_ssh_is_blocked():
    paramiko = pytest.importorskip("paramiko")
    with pytest.raises(AssertionError):
        paramiko.SSHClient().connect("192.168.50.1")


def test_config_dir_is_isolated():
    from pathlib import Path

    from lanscanman import paths
    assert paths.CONFIG_DIR != Path.home() / ".config" / "LanScanMan"
