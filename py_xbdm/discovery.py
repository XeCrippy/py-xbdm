import socket
import ipaddress
from typing import Optional
from concurrent.futures import ThreadPoolExecutor

XBDM_PORT = 730
TIMEOUT = 0.25
MAX_WORKERS = 32


"""
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
"""
def get_local_ip() -> Optional[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()

def get_subnet_ips(local_ip: str) -> list[str]:
    try:
        network = ipaddress.IPv4Network(local_ip + "/24", strict=False)
        return [str(ip) for ip in network.hosts()]
    except Exception:
        return []
    
def is_xbdm(ip: str, timeout: float = TIMEOUT) -> bool:
    try:
        with socket.create_connection((ip, XBDM_PORT), timeout=timeout) as sock:
            banner = sock.recv(1024)
            return b"201-" in banner or b"xbox" in banner.lower()
    except Exception:
        return False
    
def discover_xbdm() -> list[str]:
    local_ip = get_local_ip()
    if not local_ip:
        return []

    subnet_ips = get_subnet_ips(local_ip)
    found_ips = []

    def check_ip(ip: str):
        if is_xbdm(ip):
            found_ips.append(ip)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        executor.map(check_ip, subnet_ips)

    return found_ips

def xbox_ip() -> Optional[str]:
    devices = discover_xbdm()
    return devices[0] if devices else None

