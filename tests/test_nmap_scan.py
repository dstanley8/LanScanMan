import pytest

from lanscanman.core.nmap_scan import (
    host_scan_args,
    nmap_error_message,
    parse_host_scan,
    parse_subnet_scan,
    subnet_scan_args,
)


def test_subnet_scan_args_privileged():
    args = subnet_scan_args("192.168.1.0/24", privileged=True)
    assert args[0] == "-sS" and "sudo" not in args and "nmap" not in args
    assert "-PR" in args and "-T4" in args
    i = args.index("-p")
    assert args[i + 1] == "22,80,443,3389,5900,8080"        # separate argument
    assert args[-3:] == ["-oX", "-", "192.168.1.0/24"]


def test_subnet_scan_args_unprivileged_thorough():
    args = subnet_scan_args("192.168.50.0/24", privileged=False, thorough=True)
    assert args[0] == "-sT"
    assert "-PR" not in args                                # ARP ping needs root
    assert "-T3" in args and "--max-retries" in args


@pytest.mark.parametrize("mode, expected", [
    ("quick", ["--top-ports", "1000"]),
    ("full", ["-p-"]),
])
def test_host_scan_modes(mode, expected):
    args = host_scan_args("192.168.50.5", mode, privileged=False)
    assert args[:2] == ["-sT", "-sV"]
    assert args[4:4 + len(expected)] == expected
    assert args[-1] == "192.168.50.5"


def test_host_scan_custom_ports():
    args = host_scan_args("192.168.50.5", "custom", privileged=True, custom_ports=" 22, 80-90 ")
    assert args[0] == "-sS"
    assert args[args.index("-p") + 1] == "22,80-90"
    with pytest.raises(ValueError):
        host_scan_args("192.168.50.5", "custom", privileged=False, custom_ports="  ")


def test_nmap_error_message():
    assert nmap_error_message("  Failed to resolve  \n") == "Nmap error: Failed to resolve"


# Shape of python-nmap's analyse_nmap_xml_scan()["scan"]
SUBNET = {
    "192.168.1.20": {
        "hostnames": [{"name": "nas.lan", "type": "PTR"}],
        "addresses": {"ipv4": "192.168.1.20", "mac": "AA:BB:CC:00:11:22"},
        "vendor": {"AA:BB:CC:00:11:22": "Synology"},
        "tcp": {22: {"state": "open"}, 80: {"state": "open"}, 443: {"state": "closed"}},
    },
    "192.168.1.3": {
        "hostnames": [{"name": "", "type": ""}],
        "addresses": {"ipv4": "192.168.1.3"},
        "vendor": {},
        "tcp": {22: {"state": "filtered"}},
    },
    "192.168.1.100": {"addresses": {}, "vendor": {}},
}


def test_parse_subnet_scan():
    rows = parse_subnet_scan(SUBNET)
    assert [r["ip"] for r in rows] == ["192.168.1.3", "192.168.1.20", "192.168.1.100"]  # numeric, not string order
    nas = rows[1]
    assert nas == {"ip": "192.168.1.20", "hostname": "nas.lan", "mac": "AA:BB:CC:00:11:22",
                   "vendor": "Synology", "ssh": "open", "services": "SSH, HTTP"}
    assert rows[0]["vendor"] == "unknown" and rows[0]["ssh"] == "filtered"
    assert rows[2]["ssh"] == "closed" and rows[2]["services"] == "None"


def test_parse_subnet_scan_sorts_ipv6_last():
    rows = parse_subnet_scan({"fe80::1": {}, "192.168.50.1": {}})
    assert [r["ip"] for r in rows] == ["192.168.50.1", "fe80::1"]


def test_parse_host_scan():
    scan = {"192.168.50.5": {
        "tcp": {443: {"state": "open", "name": "https", "product": "nginx", "version": "1.24"},
                22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "9.6p1",
                     "extrainfo": "Ubuntu"}},
        "udp": {53: {"state": "open|filtered", "name": "domain"}},
    }}
    rows = parse_host_scan(scan, "192.168.50.5")
    assert [(r["protocol"], r["port"]) for r in rows] == [("tcp", 22), ("tcp", 443), ("udp", 53)]
    assert rows[0]["version"] == "OpenSSH 9.6p1 Ubuntu"
    assert rows[2]["version"] == ""
    assert parse_host_scan(scan, "192.168.50.6") == []
