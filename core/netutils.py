"""
CGS — Network utilities (scapy).

The entire network layer relies on scapy (https://scapy.net),
the reference Python library for:
  - Packet construction and parsing (Ethernet, ARP, IP, TCP, UDP, ICMP, DNS)
  - Send/receive on raw sockets
  - Network sniffing

Additional utility functions (subnet, entropy, OUI, OS guess).
"""

import logging
import math
import os
import socket
from collections import defaultdict

from scapy.all import conf as scapy_conf

logger = logging.getLogger("cgs.netutils")

# Reduce scapy verbosity
scapy_conf.verb = 0

# ── Simplified OUI (MAC prefixes → manufacturer) ──
OUI = {
    "00:50:56": "VMware", "00:0c:29": "VMware", "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM", "dc:a6:32": "Raspberry Pi", "b8:27:eb": "Raspberry Pi",
    "ac:de:48": "Apple", "3c:22:fb": "Apple", "f8:ff:c2": "Apple",
    "30:b5:c2": "TP-Link", "50:c7:bf": "TP-Link", "a4:cf:12": "Espressif",
    "24:0a:c4": "Espressif", "00:1a:2b": "Cisco", "00:26:cb": "Cisco",
    "f0:9f:c2": "Ubiquiti", "78:8a:20": "Ubiquiti",
    "00:0e:c6": "Dell", "e4:54:e8": "Intel", "a0:36:9f": "Intel",
    "18:b4:30": "Nest", "44:07:0b": "Google", "00:17:88": "Philips",
    "68:a3:78": "Samsung", "b0:be:76": "TP-Link",
}

# ── TTL → OS family ──
OS_TTL = [(32, "Windows 9x/ME"), (64, "Linux/Unix/macOS"), (128, "Windows"), (255, "Cisco/Solaris")]

# ── Known ports ──
WELL_KNOWN_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 27017: "mongodb",
}


def vendor_from_mac(mac: str) -> str:
    """Resolves manufacturer from MAC prefix (OUI)."""
    return OUI.get(mac[:8].lower(), "")


def guess_os_from_ttl(ttl: int) -> str:
    """Estimates OS from an ICMP/IP packet TTL value."""
    best, name = 999, "Unknown"
    for ref, os_name in OS_TTL:
        if abs(ref - ttl) < best:
            best, name = abs(ref - ttl), os_name
    return name


def shannon_entropy(s: str) -> float:
    """Computes Shannon entropy of a string (DGA/DNS tunnel detection)."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def get_default_iface() -> str:
    """Returns default network interface via /proc/net/route."""
    try:
        with open("/proc/net/route") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == "00000000":
                    return parts[0]
    except Exception as e:
        logger.debug("Failed to read default iface from /proc/net/route: %s", e)
    try:
        for iface in os.listdir("/sys/class/net"):
            if iface != "lo":
                return iface
    except Exception as e:
        logger.debug("Failed to list network interfaces: %s", e)
    return "eth0"


def get_iface_ip(iface: str) -> str:
    """Returns interface IP."""
    try:
        from scapy.all import get_if_addr
        return get_if_addr(iface)
    except Exception:
        return "0.0.0.0"  # nosec B104 — fallback when interface IP cannot be determined


def get_iface_mac(iface: str) -> str:
    """Returns interface MAC."""
    try:
        from scapy.all import get_if_hwaddr
        return get_if_hwaddr(iface)
    except Exception:
        path = f"/sys/class/net/{iface}/address"
        if os.path.exists(path):
            with open(path) as f:
                return f.read().strip()
        return "00:00:00:00:00:00"


def get_all_interfaces() -> dict:
    """Lists all interfaces with IP, MAC, status."""
    result = {}
    try:
        for iface in os.listdir("/sys/class/net"):
            info = {"mac": get_iface_mac(iface), "ip": get_iface_ip(iface), "up": False, "speed": 0}
            try:
                with open(f"/sys/class/net/{iface}/operstate") as f:
                    info["up"] = f.read().strip() == "up"
            except Exception as e:
                logger.debug("Failed to read operstate for %s: %s", iface, e)
            try:
                with open(f"/sys/class/net/{iface}/speed") as f:
                    info["speed"] = int(f.read().strip())
            except Exception as e:
                logger.debug("Failed to read speed for %s: %s", iface, e)
            result[iface] = info
    except Exception as e:
        logger.debug("Failed to enumerate network interfaces: %s", e)
    return result


def ip_in_subnet(ip: str, subnet: str) -> bool:
    """Checks if an IP belongs to a subnet CIDR."""
    import struct
    net_addr, prefix_len = subnet.split("/")
    prefix_len = int(prefix_len)
    ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
    net_int = struct.unpack("!I", socket.inet_aton(net_addr))[0]
    mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    return (ip_int & mask) == (net_int & mask)
