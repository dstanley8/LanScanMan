"""
nmap command construction and result shaping for the Network Scanner and
Host Inspector tabs. Pure — the workers run the command and hand the
`scan` dict from python-nmap's analyse_nmap_xml_scan() to these parsers.
"""

from __future__ import annotations

import ipaddress

# Ports the subnet scan checks, and the label shown for each
SERVICE_PORTS = {
    22:   "SSH",
    80:   "HTTP",
    443:  "HTTPS",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
}

HOST_SCAN_MODES = {
    "quick": ["--top-ports", "1000"],
    "full":  ["-p-"],
}


def subnet_scan_args(target: str, privileged: bool, thorough: bool = False) -> list[str]:
    """
    nmap arguments (without "nmap") for a subnet sweep.
    Privileged: SYN scan + ARP discovery (most accurate, needs root — run via
    services.privilege). Unprivileged: TCP connect scan; ARP ping needs root.
    """
    speed = "-T3" if thorough else "-T4"
    extra = (["--max-retries", "3", "--host-timeout", "30s"] if thorough
             else ["--host-timeout", "15s"])
    ports = ["-p", ",".join(map(str, SERVICE_PORTS))]
    if privileged:
        return ["-sS", *ports, "-PR", speed, *extra, "-oX", "-", target]
    return ["-sT", *ports, speed, *extra, "-oX", "-", target]


def host_scan_args(ip: str, mode: str, privileged: bool, custom_ports: str = "") -> list[str]:
    """Single-host port scan with version detection (-sV)."""
    if mode == "custom":
        custom_ports = custom_ports.strip().replace(" ", "")
        if not custom_ports:
            raise ValueError("No ports specified for custom scan.")
        port_args = ["-p", custom_ports]
    else:
        port_args = HOST_SCAN_MODES[mode]
    return ["-sS" if privileged else "-sT", "-sV", "--version-intensity", "5",
            *port_args, "-T4", "-oX", "-", ip]


def nmap_error_message(stderr: str) -> str:
    return f"Nmap error: {stderr.strip()}"


def _ip_sort_key(ip: str):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return (2, ip)
    return (0 if addr.version == 4 else 1, addr.packed)


def parse_subnet_scan(scan: dict) -> list[dict]:
    """
    Shape python-nmap's `scan` dict into table rows sorted by address:
    {ip, hostname, mac, vendor, ssh, services}.
    """
    results = []
    for host, info in scan.items():
        mac = info.get("addresses", {}).get("mac", "")
        tcp = info.get("tcp", {})
        hostnames = info.get("hostnames") or [{}]
        open_services = [svc for port, svc in SERVICE_PORTS.items()
                         if tcp.get(port, {}).get("state") == "open"]
        results.append({
            "ip":       host,
            "hostname": hostnames[0].get("name", ""),
            "mac":      mac,
            "vendor":   info.get("vendor", {}).get(mac, "unknown") if mac else "unknown",
            "ssh":      tcp.get(22, {}).get("state", "closed"),
            "services": ", ".join(open_services) if open_services else "None",
        })
    results.sort(key=lambda r: _ip_sort_key(r["ip"]))
    return results


def parse_host_scan(scan: dict, ip: str) -> list[dict]:
    """Rows of {port, protocol, state, service, version} for one host, TCP then UDP."""
    host = scan.get(ip)
    if not host:
        return []
    results = []
    for proto in ("tcp", "udp"):
        for port, data in sorted(host.get(proto, {}).items()):
            results.append({
                "port":     port,
                "protocol": proto,
                "state":    data.get("state", "unknown"),
                "service":  data.get("name", ""),
                "version":  " ".join(filter(None, [
                    data.get("product", ""),
                    data.get("version", ""),
                    data.get("extrainfo", ""),
                ])).strip(),
            })
    return results
