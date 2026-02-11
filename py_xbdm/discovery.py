import socket
import subprocess
import platform
import re
import ipaddress
from typing import Optional

XBDM_PORT = 730
TIMEOUT = 0.25


def get_arp_ips():
    os_name = platform.system().lower()

    if os_name == "windows":
        cmd = "arp -a"
    elif os_name == "linux":
        cmd = "ip neigh"
    elif os_name == "darwin":
        cmd = "arp -a"
    else:
        return []

    try:
        output = subprocess.check_output(cmd, shell=True, text=True)
    except Exception:
        return []

    ips = set()
    for line in output.splitlines():
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        if match:
            ips.add(match.group(1))

    return list(ips)


def is_xbdm(ip, timeout=0.4):
    try:
        sock = socket.create_connection((ip, XBDM_PORT), timeout=timeout)
        banner = sock.recv(1024)
        sock.close()

        return b"201-" in banner or b"xbox" in banner.lower()
    except:
        return False
    
def discover_xbdm():
    results = []

    for ip in get_arp_ips():
        if is_xbdm(ip):
            results.append(ip)

    return results

def xbox_ip() -> Optional[str]:
    devices = discover_xbdm()
    return devices[0] if devices else None
