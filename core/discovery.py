"""
CGS — Network discovery.

Uses:
  - scapy     : ARP sweep, SYN scan, ICMP fingerprint
  - python-nmap: advanced service and OS detection (optional, if nmap installed)
"""

import logging
import re
import socket
import time
from datetime import datetime
from typing import Optional

from scapy.all import (
    ARP, Ether, IP, TCP, ICMP, RandShort,
    srp, sr, sr1, conf as scapy_conf,
)

from core.netutils import (
    vendor_from_mac, guess_os_from_ttl, get_default_iface,
    get_iface_ip, get_iface_mac, WELL_KNOWN_SERVICES,
)
from core.database import Host, Port, db

logger = logging.getLogger("cgs.discovery")

scapy_conf.verb = 0  # silence scapy

# ── Banner signatures (for TCP banner grabbing) ──
BANNER_SIGS = [
    (re.compile(rb"^SSH-", re.I), "ssh"),
    (re.compile(rb"^220.*ftp", re.I), "ftp"),
    (re.compile(rb"^220.*smtp|^EHLO", re.I), "smtp"),
    (re.compile(rb"HTTP/\d\.\d", re.I), "http"),
    (re.compile(rb"^\+OK.*POP", re.I), "pop3"),
    (re.compile(rb"^\* OK.*IMAP", re.I), "imap"),
    (re.compile(rb"mysql|MariaDB", re.I), "mysql"),
    (re.compile(rb"PostgreSQL", re.I), "postgresql"),
    (re.compile(rb"redis|\+PONG", re.I), "redis"),
    (re.compile(rb"MongoDB", re.I), "mongodb"),
]


class NetworkDiscovery:
    """Network discovery via scapy + python-nmap."""

    def __init__(self, config, alert_fn, mac_resolver=None, identity_engine=None):
        self.cfg = config
        self._alert = alert_fn
        self.mac_resolver = mac_resolver
        self.identity = identity_engine
        self.subnets = config.get("network.subnets", ["192.168.1.0/24"])
        self.exclude = set(config.get("network.exclude_ips", []))
        self.top_ports = config.get("discovery.top_ports")
        self.do_svc = config.get("discovery.service_detection", True)
        self.do_os = config.get("discovery.os_fingerprint", True)

        iface = config.get("network.interface", "auto")
        self.iface = iface if iface != "auto" else get_default_iface()
        self.my_ip = get_iface_ip(self.iface)
        self.my_mac = get_iface_mac(self.iface)

        # python-nmap: only if the admin chose to keep it
        self._nmap_available = False
        if config.get("discovery.use_nmap", True):
            try:
                import nmap
                self._nmap = nmap.PortScanner()
                self._nmap_available = True
                logger.info("python-nmap enabled — advanced service detection.")
            except (ImportError, Exception):
                logger.info("nmap not available — port scanning in scapy mode.")
        else:
            logger.info("Nmap disabled by administrator — scapy-only mode.")

        logger.info("Interface: %s  IP: %s  MAC: %s", self.iface, self.my_ip, self.my_mac)

    # ══════════════════════════════════════════════
    # ARP Sweep (Layer 2) — scapy
    # ══════════════════════════════════════════════
    def arp_sweep(self) -> list[dict]:
        """Discovers active hosts via ARP broadcast via scapy.srp()."""
        logger.info("ARP sweep on %s", self.subnets)
        t0 = time.time()
        all_hosts = []

        for subnet in self.subnets:
            try:
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
                answered, _ = srp(pkt, iface=self.iface, timeout=3, retry=1)

                for sent, rcv in answered:
                    ip = rcv[ARP].psrc
                    mac = rcv[ARP].hwsrc
                    if ip in self.exclude or ip == self.my_ip:
                        continue
                    all_hosts.append({
                        "ip": ip,
                        "mac": mac,
                        "vendor": vendor_from_mac(mac),
                    })

            except PermissionError:
                logger.error("Permission denied — run as root (sudo).")
                return []
            except Exception as e:
                logger.error("ARP sweep %s : %s", subnet, e)

        # OS fingerprint via ICMP TTL (scapy)
        if self.do_os:
            self._fingerprint_ttl(all_hosts)

        new_count = self._update_hosts(all_hosts)
        elapsed = time.time() - t0
        logger.info("ARP: %d hosts, %d new (%.1fs)", len(all_hosts), new_count, elapsed)
        return all_hosts

    def _fingerprint_ttl(self, hosts: list[dict]):
        """Sends ICMP echo via scapy and deduces OS from TTL."""
        for h in hosts:
            try:
                pkt = IP(dst=h["ip"]) / ICMP()
                reply = sr1(pkt, timeout=1)
                if reply and reply.haslayer(IP):
                    h["os_hint"] = guess_os_from_ttl(reply[IP].ttl)
                    h["ttl"] = reply[IP].ttl
            except Exception as e:
                logger.debug("Failed to fingerprint TTL for %s: %s", h["ip"], e)

    # ══════════════════════════════════════════════
    # Port Scan — scapy SYN ou python-nmap
    # ══════════════════════════════════════════════
    def port_scan(self, targets: list[str] = None) -> dict:
        """Scans ports of known hosts."""
        if targets is None:
            targets = [h.ip for h in Host.select().where(Host.status == "up")]
        if not targets:
            return {}

        # If nmap is available, use it for richer detection
        if self._nmap_available:
            return self._nmap_scan(targets)
        else:
            return self._scapy_syn_scan(targets)

    def _scapy_syn_scan(self, targets: list[str]) -> dict:
        """SYN scan via scapy.sr() — fast, no external dependency."""
        logger.info("SYN scan (scapy) : %d hosts × %d ports", len(targets), len(self.top_ports))
        t0 = time.time()
        results = {}

        for ip in targets:
            if ip in self.exclude:
                continue
            open_ports = []

            # Send all SYNs in batch via scapy.sr()
            pkt = IP(dst=ip) / TCP(sport=RandShort(), dport=self.top_ports, flags="S")
            answered, _ = sr(pkt, timeout=2, retry=0)

            for sent, rcv in answered:
                if rcv.haslayer(TCP) and rcv[TCP].flags == 0x12:  # SYN-ACK
                    port = rcv[TCP].sport
                    svc = WELL_KNOWN_SERVICES.get(port, "unknown")
                    banner = ""

                    # Banner grabbing (standard TCP socket)
                    if self.do_svc and port not in (443, 993, 995, 8443):
                        svc_detected, banner = self._grab_banner(ip, port)
                        if svc_detected != "unknown":
                            svc = svc_detected

                    open_ports.append({"port": port, "service": svc, "banner": banner})

                    # Send RST to close properly
                    sr1(IP(dst=ip) / TCP(sport=sent[TCP].sport, dport=port, flags="R"),
                        timeout=0.3)

            results[ip] = open_ports
            self._update_ports(ip, open_ports)

        total = sum(len(v) for v in results.values())
        logger.info("SYN scan completed: %d open ports (%.1fs)", total, time.time() - t0)
        return results

    def _nmap_scan(self, targets: list[str]) -> dict:
        """Scan via python-nmap — advanced service and OS detection."""
        logger.info("Nmap scan : %d hosts × top ports", len(targets))
        t0 = time.time()
        results = {}
        port_str = ",".join(str(p) for p in self.top_ports)
        exclude_str = ",".join(self.exclude) if self.exclude else None

        for ip in targets:
            if ip in self.exclude:
                continue
            try:
                args = f"-sS -sV -T4 --max-retries 2 -p {port_str}"
                if self.do_os:
                    args += " -O --osscan-guess"
                self._nmap.scan(hosts=ip, arguments=args)

                open_ports = []
                if ip in self._nmap.all_hosts():
                    host_data = self._nmap[ip]

                    # OS detection
                    if "osmatch" in host_data and host_data["osmatch"]:
                        os_guess = host_data["osmatch"][0].get("name", "")
                        try:
                            h = Host.get(Host.ip == ip)
                            h.os_hint = os_guess
                            h.save()
                        except Exception as e:
                            logger.debug("Failed to save OS hint for %s: %s", ip, e)

                    # Ports
                    for proto in host_data.all_protocols():
                        for port in host_data[proto]:
                            info = host_data[proto][port]
                            if info["state"] == "open":
                                open_ports.append({
                                    "port": port,
                                    "service": info.get("name", "unknown"),
                                    "banner": f"{info.get('product', '')} {info.get('version', '')}".strip(),
                                })

                results[ip] = open_ports
                self._update_ports(ip, open_ports)

            except Exception as e:
                logger.warning("Nmap scan %s : %s — fallback scapy", ip, e)
                # Scapy fallback for this host
                results[ip] = self._scapy_syn_scan([ip]).get(ip, [])

        total = sum(len(v) for v in results.values())
        logger.info("Nmap scan completed: %d open ports (%.1fs)", total, time.time() - t0)
        return results

    # ──────────────────────────────────────────────
    # Banner Grabbing (socket standard)
    # ──────────────────────────────────────────────
    @staticmethod
    def _grab_banner(ip: str, port: int, timeout: float = 2.0) -> tuple[str, str]:
        """Attempts to retrieve a TCP service banner."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            banner = b""
            try:
                banner = s.recv(1024)
            except socket.timeout:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n")
                try:
                    banner = s.recv(1024)
                except socket.timeout:
                    pass
            s.close()
            if banner:
                for regex, svc in BANNER_SIGS:
                    if regex.search(banner):
                        return svc, banner[:256].decode("utf-8", errors="replace")
            return (WELL_KNOWN_SERVICES.get(port, "unknown"),
                    banner[:256].decode("utf-8", errors="replace") if banner else "")
        except Exception:
            return WELL_KNOWN_SERVICES.get(port, "unknown"), ""

    # ──────────────────────────────────────────────
    # Database update
    # ──────────────────────────────────────────────
    def _update_hosts(self, hosts: list[dict]) -> int:
        new_count = 0
        now = datetime.now()
        seen = set()
        with db.atomic():
            for h in hosts:
                ip = h["ip"]
                mac = h.get("mac", "")
                seen.add(ip)

                # Update MAC ↔ IP table (handles DHCP changes)
                if self.mac_resolver and mac:
                    change = self.mac_resolver.update(
                        mac=mac, ip=ip,
                        hostname=h.get("hostname", ""),
                        vendor=h.get("vendor", ""),
                        os_hint=h.get("os_hint", ""),
                    )
                    if change.get("changed"):
                        # IP changed via DHCP — DB already updated by resolver
                        continue

                # Search first by MAC (more reliable than by IP in DHCP)
                obj = None
                if mac:
                    obj = Host.get_or_none(Host.mac == mac.lower())
                    if obj and obj.ip != ip:
                        # Known MAC but different IP → DHCP update
                        old_ip = obj.ip
                        obj.ip = ip
                        obj.last_seen = now
                        obj.status = "up"
                        for k in ("vendor", "os_hint"):
                            if h.get(k):
                                setattr(obj, k, h[k])
                        obj.save()
                        # Update ports
                        Port.update(host_ip=ip).where(Port.host_ip == old_ip).execute()
                        continue

                if not obj:
                    obj, created = Host.get_or_create(ip=ip, defaults={
                        "mac": mac, "vendor": h.get("vendor"),
                        "os_hint": h.get("os_hint"), "status": "up",
                        "first_seen": now, "last_seen": now,
                    })
                    if created:
                        new_count += 1
                        self._alert(severity=3, source="discovery", category="new_host",
                                    title=f"New host: {ip}",
                                    detail=f"MAC={mac} Vendor={h.get('vendor','')} "
                                           f"OS≈{h.get('os_hint','')}",
                                    src_ip=ip)
                    else:
                        # ARP spoofing detection (same IP, different MAC, not DHCP)
                        if mac and obj.mac and mac.lower() != obj.mac.lower():
                            self._alert(severity=1, source="discovery", category="arp_spoof",
                                        title=f"MAC changed on {ip} !",
                                        detail=f"Ancien={obj.mac} Nouveau={mac}",
                                        src_ip=ip)
                        obj.last_seen = now
                        obj.status = "up"
                        for k in ("mac", "vendor", "os_hint"):
                            if h.get(k):
                                setattr(obj, k, h[k])
                        obj.save()

            Host.update(status="down").where(Host.status == "up", Host.ip.not_in(seen)).execute()

        # Observe fingerprints (multi-factor identity)
        if self.identity:
            for h in hosts:
                if h.get("mac"):
                    result = self.identity.observe(
                        ip=h["ip"], mac=h["mac"],
                        hostname=h.get("hostname", ""),
                        os_hint=h.get("os_hint", ""),
                        ttl=h.get("ttl", 0),
                        vendor_oui=h["mac"][:8] if h.get("mac") else "",
                    )
                    # If spoofing detected, increase risk_score
                    if result.get("spoofing"):
                        try:
                            host = Host.get_or_none(Host.ip == h["ip"])
                            if host:
                                host.risk_score = min(100, host.risk_score + 60)
                                host.save()
                        except Exception as e:
                            logger.debug("Failed to update spoofing risk score for %s: %s", h["ip"], e)

        return new_count

    def _update_ports(self, ip: str, ports: list[dict]):
        now = datetime.now()
        current = set()
        with db.atomic():
            for p in ports:
                current.add(p["port"])
                obj, created = Port.get_or_create(
                    host_ip=ip, port=p["port"], proto="tcp",
                    defaults={"state": "open", "service": p.get("service"),
                              "banner": p.get("banner", "")[:512],
                              "first_seen": now, "last_seen": now})
                if created:
                    self._alert(severity=3, source="discovery", category="new_port",
                                title=f"New port {p['port']}/tcp on {ip}",
                                detail=f"Service={p.get('service','')}",
                                dst_ip=ip)
                else:
                    obj.last_seen = now
                    obj.service = p.get("service") or obj.service
                    if p.get("banner"):
                        obj.banner = p["banner"][:512]
                    obj.save()
            Port.update(state="closed").where(
                Port.host_ip == ip, Port.state == "open",
                Port.port.not_in(current) if current else True).execute()
            Host.update(open_ports_cache=",".join(str(p) for p in sorted(current))).where(
                Host.ip == ip).execute()

        # Enrich fingerprint with ports and banners
        if self.identity and ports:
            import hashlib
            mac = ""
            try:
                host = Host.get_or_none(Host.ip == ip)
                if host and host.mac:
                    mac = host.mac
            except Exception as e:
                logger.debug("Failed to resolve MAC for port enrichment on %s: %s", ip, e)
            if mac:
                banners = {}
                for p in ports:
                    if p.get("banner"):
                        banners[str(p["port"])] = hashlib.sha256(
                            p["banner"].encode()).hexdigest()[:8]
                self.identity.observe(
                    ip=ip, mac=mac,
                    open_ports=[p["port"] for p in ports],
                    banners=banners,
                )

    @staticmethod
    def get_inventory() -> list[dict]:
        out = []
        for h in Host.select().order_by(Host.last_seen.desc()):
            ports = list(Port.select().where(Port.host_ip == h.ip, Port.state == "open"))
            out.append({
                "ip": h.ip, "mac": h.mac, "hostname": h.hostname,
                "vendor": h.vendor, "os": h.os_hint, "status": h.status,
                "risk_score": h.risk_score,
                "first_seen": h.first_seen.isoformat(),
                "last_seen": h.last_seen.isoformat(),
                "ports": [{"port": p.port, "service": p.service,
                           "banner": (p.banner or "")[:100]} for p in ports],
            })
        return out
