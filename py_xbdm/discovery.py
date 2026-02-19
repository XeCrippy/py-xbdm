import socket
import ipaddress
import struct
from typing import Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event

XBDM_PORT = 730
NAP_PORT = 731
TIMEOUT = 0.5
NAP_TIMEOUT = 0.5
MAX_WORKERS = 128

NAP_TYPE_LOOKUP   = 1
NAP_TYPE_REPLY    = 2
NAP_TYPE_WILDCARD = 3

"""
FROM XBOXDEVWIKI:

A NAP packet contains 3 fields, the last of which is variable-length. The minimum length of a NAP packet is 2 bytes and the maximum is 257. Invalid packets are silently dropped by XBDM.

Type
This unsigned 8-bit field may contain the values 1 (lookup), 2 (reply), or 3 (wildcard).
Name Length
This unsigned 8-bit field specifies the length of the Name field and should be a value from 0 to 255. For Type 3 packets, this field should always be 0. For Type 1 and Type 2 packets, this field should never be 0.
Name
This variable-length field contains the ASCII-encoded debug name for Type 1 and Type 2 packets. The number of bytes in this field is given by the Length field. It should not contain any NUL characters.
Forward Lookup
To resolve a debug name to an IP address, send a Type 1 NAP packet containing the debug name to be resolved to UDP address 255.255.255.255:731. The XDK with that name will respond with a Type 2 NAP packet and its IP address can be retrieved from the UDP header. There is no way to prevent multiple XDKs being assigned the same debug name, so it's possible that the client may receive replies from multiple IP addresses.

Reverse Lookup
To resolve an IP address to a debug name, send a Type 3 NAP packet with no name (length 0) to the IP address on UDP port 731. Assuming the target is actually an XDK, it will respond with a Type 2 NAP packet containing its name. This is very similar to the Console Discovery process (below), except that by sending the wildcard packet to a single IP address, only that XDK will respond.

Console Discovery
To discover all XDKs on the local network, send a Type 3 NAP packet with no name (length 0) to the UDP address 255.255.255.255:731. Each XDK will respond with a Type 2 NAP packet containing its name. As with a forward lookup, the client may receive multiple replies with the same name, but different IP addresses.
"""


"""COULD NOT GET THIS WORKING BUT MAY BE USEFUL. I DON'T HAVE AN ACTUAL XDK TO TEST IF IT'S XDK SPECIFIC"""
# ── NAP protocol helpers ──────────────────────
def _build_nap_packet(pkt_type: int, name: str = "") -> bytes:
    """Build a NAP packet: [type(1)] [name_len(0)] [name(variable)]"""
    name_bytes = name.encode("ascii") if name else b""
    return struct.pack("BB", pkt_type, len(name_bytes)) + name_bytes


def _parse_nap_reply(data: bytes) -> Optional[str]:
    """Parse a NAP Type 2 reply and return the console name, or None."""
    if len(data) < 2:
        return None
    pkt_type, name_len = struct.unpack("BB", data[:2])
    if pkt_type != NAP_TYPE_REPLY:
        return None
    if name_len == 0 or len(data) < 2 + name_len:
        return None
    return data[2:2 + name_len].decode("ascii", errors="replace")


def discover_nap(find_all: bool = True, timeout: float = NAP_TIMEOUT) -> list[Tuple[str, str]]:
    """
    Discover consoles via NAP broadcast.
    Returns a list of (ip, console_name) tuples.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 0))
    sock.settimeout(timeout)

    results = []
    seen_ips = set()

    try:
        packet = _build_nap_packet(NAP_TYPE_WILDCARD)
        print(f"NAP: Sending wildcard packet ({packet.hex()}) to 255.255.255.255:{NAP_PORT}")
        sock.sendto(packet, ("255.255.255.255", NAP_PORT))

        while True:
            try:
                data, addr = sock.recvfrom(512)
                ip = addr[0]
                if ip in seen_ips:
                    continue
                name = _parse_nap_reply(data)
                if name is not None:
                    seen_ips.add(ip)
                    results.append((ip, name))
                    print(f"NAP: Discovered \"{name}\" at {ip}")
                    if not find_all:
                        break
            except socket.timeout:
                break
    finally:
        sock.close()

    return results


def nap_lookup(name: str, timeout: float = NAP_TIMEOUT) -> Optional[str]:
    """Resolve a console debug name to an IP address via NAP forward lookup."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)

    try:
        packet = _build_nap_packet(NAP_TYPE_LOOKUP, name)
        sock.sendto(packet, ("255.255.255.255", NAP_PORT))

        data, addr = sock.recvfrom(512)
        reply_name = _parse_nap_reply(data)
        if reply_name is not None:
            return addr[0]
    except socket.timeout:
        pass
    finally:
        sock.close()

    return None


def nap_reverse_lookup(ip: str, timeout: float = NAP_TIMEOUT) -> Optional[str]:
    """Resolve an IP address to a console debug name via NAP reverse lookup."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        packet = _build_nap_packet(NAP_TYPE_WILDCARD)
        sock.sendto(packet, (ip, NAP_PORT))

        data, addr = sock.recvfrom(512)
        return _parse_nap_reply(data)
    except socket.timeout:
        pass
    finally:
        sock.close()

    return None

def discover_xbdm_with_names(find_all: bool = False) -> list[Tuple[str, str]]:
    """Discover consoles and return (ip, name) tuples. Uses NAP first, then TCP fallback."""
    # Try NAP broadcast first
    try:
        nap_results = discover_nap(find_all=find_all)
        if nap_results:
            return nap_results
    except Exception:
        pass

    # Fall back to TCP scan + NAP reverse lookup for names
    ips = discover_xbdm(find_all=find_all)
    results = []
    for ip in ips:
        name = nap_reverse_lookup(ip) or "jtag"
        results.append((ip, name))
    return results


# ── Network helpers ───────────────────────────
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
    except Exception as e:
        raise RuntimeError(f"Failed to get subnet IPs: {e}")
    
def is_xbdm(ip: str, timeout: float = TIMEOUT) -> bool:
    try:
        with socket.create_connection((ip, XBDM_PORT), timeout=timeout) as sock:
            banner = sock.recv(1024)
            return b"201-" in banner or b"connected" in banner.lower()
    except Exception as e:
        raise RuntimeError(f"Error checking IP {ip}: {e}")
    
def discover_xbdm(find_all: bool = False, use_nap: bool = False) -> list[str]:
    # Try NAP broadcast if requested 
    if use_nap:
        try:
            nap_results = discover_nap(find_all=find_all)
            if nap_results:
                return [ip for ip, _name in nap_results]
        except Exception:
            pass
        print("NAP discovery got no response, falling back to TCP scan...")

    # Fall back to TCP subnet scan
    try:
        local_ip = get_local_ip()
        if not local_ip:
            raise RuntimeError("Local IP address not found.")

        subnet_ips = get_subnet_ips(local_ip)
        if not subnet_ips:
            raise RuntimeError("Subnet IPs not found.")

        results = []
        stop_event = Event()

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(is_xbdm, ip): ip for ip in subnet_ips}

            for future in as_completed(futures):
                ip = futures[future]
                try:
                    if future.result():
                        results.append(ip)
                        if not find_all:
                            stop_event.set()
                            break
                except Exception:
                    continue

        return results
    except Exception as e:
        print(f"Error during discovery: {e}")
        raise RuntimeError(f"XBDM discovery failed:\n{e}")

def xbox_ip() -> Optional[str]:
    devices = discover_xbdm(find_all=False, use_nap=False)
    if devices:
        return devices[0]
    else:
        print("No XBDM devices found.")
        raise RuntimeError("No XBDM devices found.")

