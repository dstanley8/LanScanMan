import subprocess
import socket
import nmap
from PyQt6.QtCore import QThread, pyqtSignal


class ScannerThread(QThread):
    results_ready = pyqtSignal(list)
    error_occurred = pyqtSignal(str)

    def __init__(self, target, password=None, thorough=False, use_sudo=True):
        super().__init__()
        self.target   = target
        self.password = password
        self.thorough = thorough
        self.use_sudo = use_sudo
        self.port_map = {
            22:   "SSH",
            80:   "HTTP",
            443:  "HTTPS",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP-Alt",
        }

    def run(self):
        nm    = nmap.PortScanner()
        speed = "-T3" if self.thorough else "-T4"
        extra = "--max-retries 3 --host-timeout 30s" if self.thorough else "--host-timeout 15s"
        ports = ",".join(map(str, self.port_map.keys()))

        if self.use_sudo:
            # Privileged SYN scan + ARP host discovery — most accurate, needs root.
            cmd = [
                "sudo", "-S", "nmap",
                "-sS",          # SYN scan (stealth, fast, requires root)
                f"-p {ports}",
                "-PR",          # ARP ping — reliable on local subnets
                speed, *extra.split(),
                "-oX", "-",
                self.target,
            ]
        else:
            # Unprivileged TCP connect scan — no root needed.
            # -sT completes the full TCP handshake so it is slightly slower
            # and more visible than SYN, but works fine without root.
            # -PR (ARP ping) requires root so we drop it; nmap falls back to
            # ICMP echo + TCP ping which still finds most hosts.
            cmd = [
                "nmap",
                "-sT",          # TCP connect scan (no root needed)
                f"-p {ports}",
                speed, *extra.split(),
                "-oX", "-",
                self.target,
            ]

        try:
            if self.use_sudo:
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True,
                )
                proc.stdin.write(self.password + "\n")
                proc.stdin.flush()
                proc.stdin.close()
            else:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )

            # Poll instead of blocking — check for cancellation every 250 ms
            while proc.poll() is None:
                if self.isInterruptionRequested():
                    proc.kill()
                    self.error_occurred.emit("Scan cancelled.")
                    return
                self.msleep(250)

            stdout = proc.stdout.read()
            stderr = proc.stderr.read()

            if proc.returncode != 0:
                if self.use_sudo and "incorrect password" in stderr.lower():
                    self.error_occurred.emit("Incorrect sudo password.")
                else:
                    self.error_occurred.emit(f"Nmap Error: {stderr}")
                return

            nm.analyse_nmap_xml_scan(stdout)
            results = []
            for host in nm.all_hosts():
                info         = nm[host]
                mac          = info["addresses"].get("mac", "")
                tcp_info     = info.get("tcp", {})
                open_services = [
                    svc for port, svc in self.port_map.items()
                    if tcp_info.get(port, {}).get("state") == "open"
                ]
                results.append({
                    "ip":       host,
                    "hostname": info.hostname(),
                    "mac":      mac,
                    "vendor":   info["vendor"].get(mac, "unknown") if mac else "unknown",
                    "ssh":      tcp_info.get(22, {}).get("state", "closed"),
                    "services": ", ".join(open_services) if open_services else "None",
                })

            results.sort(key=lambda x: (
                0, socket.inet_aton(x["ip"])
            ) if ":" not in x["ip"] else (
                1, socket.inet_pton(socket.AF_INET6, x["ip"])
            ))
            self.results_ready.emit(results)

        except Exception as e:
            self.error_occurred.emit(str(e))