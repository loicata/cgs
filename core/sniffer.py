"""
CyberGuard Sentinel — Real-time network capture (scapy.sniff).

Utilise scapy.sniff() pour capturer les paquets sur l'interface network,
les parse via les couches scapy (IP, TCP, UDP, ICMP, DNS, ARP),
and feeds normalized events to the analysis engine.
"""

import logging
import threading
import time
from collections import defaultdict
from datetime import datetime

from scapy.all import (
    sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, ARP,
    conf as scapy_conf,
)

from core.netutils import shannon_entropy, get_default_iface
from core.database import Flow, DnsLog, db

logger = logging.getLogger("cyberguard.sniffer")
scapy_conf.verb = 0


class PacketSniffer:
    """Capture L2/L3 via scapy.sniff() et dispatch vers l'analyseur."""

    def __init__(self, config, analyzer_callback, identity_engine=None):
        self.cfg = config
        self._analyze = analyzer_callback
        self.identity = identity_engine

        iface = config.get("network.interface", "auto")
        self.iface = iface if iface != "auto" else get_default_iface()
        self.promisc = config.get("sniffer.promiscuous", True)
        self.bpf = config.get("sniffer.bpf_filter", "")

        self._stop = threading.Event()
        self._thread = None
        self._flush_thread = None
        self._pkt_count = 0
        self._byte_count = 0
        self._start_ts = None

        # Flow aggregation (flushed to DB every 15s)
        self._flows: dict[tuple, dict] = {}
        self._flow_lock = threading.Lock()
        self._dns_buf: list[dict] = []

    # ──────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────
    def start(self):
        if not self.cfg.get("sniffer.enabled", True):
            logger.info("Sniffer disabled.")
            return
        self._stop.clear()
        self._start_ts = time.time()

        self._thread = threading.Thread(target=self._sniff_loop, daemon=True, name="sniffer")
        self._thread.start()

        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True, name="sniffer-flush")
        self._flush_thread.start()

        logger.info("Scapy sniffer started on %s (promisc=%s, filter=%s)",
                     self.iface, self.promisc, self.bpf or "aucun")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        if self._flush_thread:
            self._flush_thread.join(timeout=3)
        self._flush_to_db()
        logger.info("Sniffer stopped — %d packets captured.", self._pkt_count)

    # ──────────────────────────────────────────────
    # Capture via scapy
    # ──────────────────────────────────────────────
    def _sniff_loop(self):
        """Capture loop using scapy.sniff()."""
        try:
            sniff(
                iface=self.iface,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
                filter=self.bpf or None,
                promisc=self.promisc,
            )
        except PermissionError:
            logger.error("Sniffer: permission denied (sudo required).")
        except Exception as e:
            if not self._stop.is_set():
                logger.error("Sniffer : %s", e)

    def _on_packet(self, pkt):
        """Callback for each captured packet par scapy."""
        self._pkt_count += 1
        size = len(pkt)
        self._byte_count += size
        ts = time.time()

        # ── ARP ──
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP Reply
            self._analyze({
                "type": "arp_reply",
                "src_ip": pkt[ARP].psrc,
                "src_mac": pkt[ARP].hwsrc,
                "ts": ts,
            })
            return

        # ── IP requis pour la suite ──
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src, dst = ip.src, ip.dst
        proto = "OTHER"
        sport, dport = 0, 0
        flags = ""

        # ── TCP ──
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            proto = "TCP"
            sport, dport = tcp.sport, tcp.dport
            flags = str(tcp.flags)

            self._analyze({
                "type": "tcp", "src": src, "dst": dst,
                "sport": sport, "dport": dport,
                "flags": flags, "size": size, "ttl": ip.ttl, "ts": ts,
            })

            # Observe fingerprint (sampled — 1 SYN sur 100)
            if self.identity and self._pkt_count % 100 == 0:
                # SYN-ACK reveals the responder's TCP window
                mac = ""
                if pkt.haslayer(ARP):
                    mac = pkt[ARP].hwsrc
                elif hasattr(pkt, 'src'):
                    mac = pkt.src  # MAC Ethernet
                tcp_win = tcp.window if hasattr(tcp, 'window') else 0
                try:
                    from scapy.all import Ether
                    if pkt.haslayer(Ether):
                        mac = pkt[Ether].src
                except Exception:
                    pass
                if mac and mac != "ff:ff:ff:ff:ff:ff":
                    self.identity.observe(
                        ip=src, mac=mac, ttl=ip.ttl,
                        tcp_window=tcp_win, packet_size=size, dst_ip=dst,
                    )

        # ── UDP ──
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            proto = "UDP"
            sport, dport = udp.sport, udp.dport

            # DNS
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                dns = pkt[DNS]
                if dns.qr == 0:  # Query
                    self._process_dns(dns, src, ts)

            self._analyze({
                "type": "udp", "src": src, "dst": dst,
                "sport": sport, "dport": dport,
                "size": size, "ts": ts,
            })

        # ── ICMP ──
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            self._analyze({
                "type": "icmp", "src": src, "dst": dst,
                "icmp_type": pkt[ICMP].type,
                "size": size, "ts": ts,
            })

        # Flow aggregation
        key = (src, sport, dst, dport, proto)
        with self._flow_lock:
            if key not in self._flows:
                self._flows[key] = {"pkts": 0, "bytes": 0, "flags": set()}
            f = self._flows[key]
            f["pkts"] += 1
            f["bytes"] += size
            if flags:
                f["flags"].add(flags)

    # ──────────────────────────────────────────────
    # DNS
    # ──────────────────────────────────────────────
    def _process_dns(self, dns_pkt, src_ip: str, ts: float):
        """Parses a DNS query via la couche scapy DNS."""
        try:
            qname = dns_pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
            qtype = dns_pkt[DNSQR].qtype

            # Subdomain entropy le plus long
            parts = qname.split(".")
            subdomain = parts[0] if len(parts) > 2 else ""
            ent = round(shannon_entropy(subdomain), 3)

            self._dns_buf.append({
                "src_ip": src_ip, "query": qname,
                "qtype": qtype, "entropy": ent,
                "suspicious": ent >= self.cfg.get("analysis.dns_entropy_threshold", 3.5),
                "ts": datetime.fromtimestamp(ts),
            })

            self._analyze({
                "type": "dns_query",
                "src": src_ip, "query": qname,
                "entropy": ent, "ts": ts,
            })
        except Exception as e:
            logger.debug("DNS parse : %s", e)

    # ──────────────────────────────────────────────
    # Periodic flush → BDD
    # ──────────────────────────────────────────────
    def _flush_loop(self):
        while not self._stop.is_set():
            self._stop.wait(15)
            if not self._stop.is_set():
                self._flush_to_db()

    def _flush_to_db(self):
        # Flows
        with self._flow_lock:
            flows = dict(self._flows)
            self._flows.clear()
        if flows:
            try:
                with db.atomic():
                    for (src, sp, dst, dp, proto), d in flows.items():
                        Flow.create(
                            src_ip=src, src_port=sp, dst_ip=dst, dst_port=dp,
                            proto=proto, packets=d["pkts"], bytes_total=d["bytes"],
                            flags=",".join(d["flags"]) if d["flags"] else None,
                        )
            except Exception as e:
                logger.warning("Flush flows : %s", e)

        # DNS
        buf = list(self._dns_buf)
        self._dns_buf.clear()
        if buf:
            try:
                with db.atomic():
                    for d in buf:
                        DnsLog.create(**d)
            except Exception as e:
                logger.warning("Flush DNS : %s", e)

    # ──────────────────────────────────────────────
    # Stats
    # ──────────────────────────────────────────────
    @property
    def stats(self) -> dict:
        elapsed = max(time.time() - self._start_ts, 1) if self._start_ts else 1
        return {
            "running": self._thread is not None and self._thread.is_alive(),
            "packets": self._pkt_count,
            "bytes": self._byte_count,
            "pps": round(self._pkt_count / elapsed, 1),
            "mbps": round(self._byte_count * 8 / elapsed / 1_000_000, 2),
            "active_flows": len(self._flows),
            "uptime_s": round(elapsed),
        }
