"""
CGS — Threat intelligence feeds + honeypot services.

Threat feeds:
  - Auto-downloads IOC lists from public sources (Abuse.ch, Feodo, URLhaus)
  - Bloom filter for O(1) lookup on millions of indicators
  - Hourly auto-refresh, no admin intervention
  - Feeds into the IocLive detector and the ConfidenceScorer

Honeypots:
  - Opens decoy ports (RDP, MSSQL, SMB, HTTP) on configurable IPs
  - Any connection = immediate high-confidence alert (zero false positive)
  - Logs full connection metadata (IP, port, timing, payload sample)
  - Lightweight: no real service, just TCP accept + log + close
"""

import hashlib
import json
import logging
import os
import socket
import struct
import threading
import time
from datetime import datetime

logger = logging.getLogger("cgs.threatfeeds")

# ══════════════════════════════════════════════════
# Bloom filter (compact, O(1) lookup)
# ══════════════════════════════════════════════════

class BloomFilter:
    """Simple bloom filter for fast IOC membership testing."""

    def __init__(self, capacity: int = 1_000_000, fp_rate: float = 0.001):
        import math
        self._size = int(-capacity * math.log(fp_rate) / (math.log(2) ** 2))
        self._hash_count = int(self._size / capacity * math.log(2))
        self._bits = bytearray(self._size // 8 + 1)
        self._count = 0
        self._lock = threading.Lock()

    def add(self, item: str):
        with self._lock:
            for i in range(self._hash_count):
                idx = self._hash(item, i) % self._size
                self._bits[idx // 8] |= (1 << (idx % 8))
            self._count += 1

    def __contains__(self, item: str) -> bool:
        with self._lock:
            for i in range(self._hash_count):
                idx = self._hash(item, i) % self._size
                if not (self._bits[idx // 8] & (1 << (idx % 8))):
                    return False
            return True

    @staticmethod
    def _hash(item: str, seed: int) -> int:
        return int(hashlib.md5(f"{seed}:{item}".encode(), usedforsecurity=False).hexdigest()[:8], 16)

    def __len__(self):
        return self._count

    def clear(self):
        with self._lock:
            self._bits = bytearray(len(self._bits))
            self._count = 0


# ══════════════════════════════════════════════════
# Threat feed manager
# ══════════════════════════════════════════════════

# Public, free, no-API-key feeds
FEED_SOURCES = [
    {
        "name": "abuse_ch_feodo",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "type": "ip",
        "comment_char": "#",
    },
    {
        "name": "abuse_ch_sslbl",
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "type": "ip",
        "comment_char": "#",
    },
    {
        "name": "abuse_ch_urlhaus",
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
        "type": "domain",
        "comment_char": "#",
    },
    {
        "name": "stamparm_ipsum_l3",
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        "type": "ip",
        "comment_char": "#",
    },
    {
        "name": "cinsscore",
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "type": "ip",
        "comment_char": "#",
    },
]


class ThreatFeedManager:
    """Downloads, parses, and serves IOC feeds via bloom filter."""

    def __init__(self, config):
        self.cfg = config
        self._bloom_ips = BloomFilter(capacity=500_000)
        self._bloom_domains = BloomFilter(capacity=200_000)
        self._lock = threading.Lock()
        self._stats = {"ips": 0, "domains": 0, "feeds_loaded": 0,
                       "last_refresh": "", "errors": []}

        # Data dir for cached feeds
        self._cache_dir = os.path.join(
            config.get("general.data_dir", "/var/lib/cgs/data"), "feeds")
        os.makedirs(self._cache_dir, exist_ok=True)

        # Also load local IOC file if it exists
        self._local_ioc_path = config.get("detectors.ioc_live.file_path",
                                          "/opt/cgs/data/ioc_list.json")

        # Initial load from cache
        self._load_cached()

        # Background refresh
        threading.Thread(target=self._refresh_loop, daemon=True,
                        name="threat-feeds").start()

    def check_ip(self, ip: str) -> bool:
        """O(1) check if IP is in any threat feed."""
        return ip in self._bloom_ips

    def check_domain(self, domain: str) -> bool:
        """O(1) check if domain (or parent domain) is in any threat feed."""
        if domain in self._bloom_domains:
            return True
        # Check parent domains
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self._bloom_domains:
                return True
        return False

    def _parse_feed_file(self, filepath: str, source: dict) -> int:
        """Parse a cached feed file and add indicators to bloom filters."""
        count = 0
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(source["comment_char"]):
                    continue
                indicator = line.split()[0] if " " in line else line
                if "://" in indicator:
                    indicator = indicator.split("://", 1)[1].split("/")[0]
                if source["type"] == "ip":
                    parts = indicator.split(".")
                    if len(parts) == 4:
                        self._bloom_ips.add(indicator)
                        count += 1
                elif source["type"] == "domain":
                    indicator = indicator.lower().rstrip(".")
                    if "." in indicator:
                        self._bloom_domains.add(indicator)
                        count += 1
        return count

    def _load_cached(self):
        """Load feeds from local cache files."""
        loaded = 0
        for source in FEED_SOURCES:
            cache_file = os.path.join(self._cache_dir, f"{source['name']}.txt")
            if os.path.exists(cache_file):
                try:
                    count = self._parse_feed_file(cache_file, source)
                    loaded += count
                except Exception as e:
                    logger.debug("Cache load %s: %s", source["name"], e)

        # Load local IOC file
        try:
            if os.path.exists(self._local_ioc_path):
                with open(self._local_ioc_path) as f:
                    data = json.load(f)
                for ip in data.get("ips", []):
                    self._bloom_ips.add(ip.strip())
                for domain in data.get("domains", []):
                    self._bloom_domains.add(domain.strip().lower())
                loaded += len(data.get("ips", [])) + len(data.get("domains", []))
        except Exception as e:
            logger.debug("Local IOC: %s", e)

        if loaded:
            logger.info("Threat feeds: %d indicators loaded from cache", loaded)

    def _refresh_loop(self):
        """Periodically download fresh feeds."""
        time.sleep(30)  # Wait for system startup
        while True:
            self._refresh_all()
            time.sleep(3600)  # Hourly

    def _refresh_all(self):
        """Download all feed sources."""
        total = 0
        errors = []

        # Rebuild bloom filters fresh
        new_ips = BloomFilter(capacity=500_000)
        new_domains = BloomFilter(capacity=200_000)

        for source in FEED_SOURCES:
            try:
                import requests
                r = requests.get(source["url"], timeout=30,
                                headers={"User-Agent": "CGS/1.0"})
                if r.status_code != 200:
                    errors.append(f"{source['name']}: HTTP {r.status_code}")
                    continue

                # Cache to disk
                cache_file = os.path.join(self._cache_dir, f"{source['name']}.txt")
                with open(cache_file, "w") as f:
                    f.write(r.text)

                count = 0
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith(source["comment_char"]):
                        continue
                    # Extract IP or domain
                    indicator = line.split()[0] if " " in line else line
                    # Remove URL prefix if present
                    if "://" in indicator:
                        indicator = indicator.split("://", 1)[1].split("/")[0]

                    if source["type"] == "ip":
                        # Validate IP format
                        parts = indicator.split(".")
                        if len(parts) == 4:
                            new_ips.add(indicator)
                            count += 1
                    elif source["type"] == "domain":
                        indicator = indicator.lower().rstrip(".")
                        if "." in indicator:
                            new_domains.add(indicator)
                            count += 1

                total += count
                logger.info("Feed %s: %d indicators", source["name"], count)

            except Exception as e:
                errors.append(f"{source['name']}: {e}")
                logger.debug("Feed %s error: %s", source["name"], e)

        # Load local IOC file into new filters
        try:
            if os.path.exists(self._local_ioc_path):
                with open(self._local_ioc_path) as f:
                    data = json.load(f)
                for ip in data.get("ips", []):
                    new_ips.add(ip.strip())
                for domain in data.get("domains", []):
                    new_domains.add(domain.strip().lower())
        except Exception as e:
            logger.debug("Failed to load local IOC file during refresh: %s", e)

        # Swap atomically
        if total > 0:
            with self._lock:
                self._bloom_ips = new_ips
                self._bloom_domains = new_domains
            self._stats = {
                "ips": len(new_ips),
                "domains": len(new_domains),
                "feeds_loaded": len(FEED_SOURCES),
                "last_refresh": datetime.now().isoformat(),
                "errors": errors,
            }
            logger.info("Threat feeds refreshed: %d IPs, %d domains, %d errors",
                        len(new_ips), len(new_domains), len(errors))
        elif errors:
            self._stats["errors"] = errors

    @property
    def stats(self) -> dict:
        return self._stats


# ══════════════════════════════════════════════════
# Honeypot services
# ══════════════════════════════════════════════════

# Default decoy ports (attractive to attackers)
DEFAULT_HONEYPOT_PORTS = [
    (3389, "rdp"),      # Remote Desktop
    (1433, "mssql"),    # Microsoft SQL Server
    (5900, "vnc"),      # VNC
    (8080, "http-alt"), # Alternative HTTP
    (2222, "ssh-alt"),  # Alternative SSH
    (9200, "elastic"),  # Elasticsearch
    (27017, "mongodb"), # MongoDB
]


class HoneypotService:
    """
    Lightweight TCP honeypot. Opens decoy ports that no legitimate
    service uses. Any connection = immediate alert with 100% confidence.
    """

    def __init__(self, config, alert_fn):
        self.cfg = config
        self._alert = alert_fn
        self._running = False
        self._threads: list[threading.Thread] = []
        self._connections: list[dict] = []
        self._conn_lock = threading.Lock()

        self.enabled = config.get("honeypot.enabled", False)
        self.ports = config.get("honeypot.ports", [])
        self.bind_ip = config.get("honeypot.bind_ip", "0.0.0.0")  # nosec B104 — honeypot must listen on all interfaces

        if not self.ports and self.enabled:
            self.ports = [p for p, _ in DEFAULT_HONEYPOT_PORTS]

    def start(self):
        """Start honeypot listeners."""
        if not self.enabled:
            logger.info("Honeypot disabled.")
            return

        self._running = True
        started = 0
        for port_cfg in self.ports:
            if isinstance(port_cfg, dict):
                port = port_cfg.get("port", 0)
                name = port_cfg.get("name", f"port-{port}")
            else:
                port = int(port_cfg)
                name = next((n for p, n in DEFAULT_HONEYPOT_PORTS if p == port),
                           f"port-{port}")

            t = threading.Thread(target=self._listen, args=(port, name),
                               daemon=True, name=f"honeypot-{port}")
            t.start()
            self._threads.append(t)
            started += 1

        if started:
            logger.info("Honeypot started: %d decoy ports", started)

    def stop(self):
        self._running = False

    def _listen(self, port: int, service_name: str):
        """Listen on a single decoy port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(2.0)
            sock.bind((self.bind_ip, port))
            sock.listen(5)
            logger.info("Honeypot listening on %s:%d (%s)", self.bind_ip, port, service_name)

            while self._running:
                try:
                    conn, addr = sock.accept()
                    threading.Thread(target=self._handle_connection,
                                   args=(conn, addr, port, service_name),
                                   daemon=True).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self._running:
                        logger.debug("Honeypot %d accept error: %s", port, e)
                    time.sleep(1)

        except OSError as e:
            logger.warning("Honeypot port %d: %s (port may be in use)", port, e)
        except Exception as e:
            logger.error("Honeypot %d fatal: %s", port, e)

    def _handle_connection(self, conn: socket.socket, addr: tuple,
                           port: int, service_name: str):
        """Handle a honeypot connection: log metadata, alert, close."""
        src_ip, src_port = addr
        payload_sample = b""

        try:
            conn.settimeout(5)
            try:
                payload_sample = conn.recv(1024)
            except socket.timeout:
                pass

            # Send a fake banner to keep attacker engaged briefly
            banners = {
                "rdp": b"\x03\x00\x00\x13",  # RDP negotiation
                "mssql": b"\x04\x01\x00",
                "ssh-alt": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n",
                "http-alt": b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n",
                "vnc": b"RFB 003.008\n",
            }
            banner = banners.get(service_name, b"")
            if banner:
                try:
                    conn.sendall(banner)
                except Exception as e:
                    logger.debug("Failed to send honeypot banner: %s", e)

        except Exception as e:
            logger.debug("Failed to handle honeypot connection: %s", e)
        finally:
            try:
                conn.close()
            except Exception as e:
                logger.debug("Failed to close honeypot connection: %s", e)

        # Record connection
        record = {
            "ts": datetime.now().isoformat(),
            "src_ip": src_ip,
            "src_port": src_port,
            "honeypot_port": port,
            "service": service_name,
            "payload_size": len(payload_sample),
            "payload_hex": payload_sample[:64].hex() if payload_sample else "",
        }

        with self._conn_lock:
            self._connections.append(record)
            if len(self._connections) > 1000:
                self._connections = self._connections[-1000:]

        # Alert with 100% confidence (zero false positive by design)
        logger.warning("HONEYPOT HIT: %s:%d → port %d (%s)",
                       src_ip, src_port, port, service_name)

        self._alert(
            severity=1, source="honeypot", category="honeypot_connection",
            title=f"Honeypot: {src_ip} connected to decoy {service_name}:{port}",
            detail=(f"Source: {src_ip}:{src_port}\n"
                    f"Decoy port: {port} ({service_name})\n"
                    f"Payload: {len(payload_sample)} bytes\n"
                    f"This is a decoy — no legitimate service runs here.\n"
                    f"Connection indicates active reconnaissance or attack."),
            src_ip=src_ip,
            ioc=src_ip,
        )

    @property
    def stats(self) -> dict:
        with self._conn_lock:
            return {
                "enabled": self.enabled,
                "ports": self.ports,
                "total_connections": len(self._connections),
                "recent": self._connections[-10:],
            }
