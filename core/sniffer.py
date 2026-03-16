"""
CGS — High-performance network capture.

Architecture:
  - Capture thread: scapy.sniff() → ring buffer (fast, never blocks)
  - Analysis thread: drains buffer → parse + dispatch (can fall behind safely)
  - Flush thread: periodic DB writes (flows + DNS)
  - JA3 TLS fingerprinting on ClientHello packets
  - DNS response capture for fast-flux detection
  - Adaptive flush interval based on load
  - Noise filter: skip broadcast/multicast/mDNS/SSDP
"""

import hashlib
import logging
import struct
import threading
import time
from collections import defaultdict, deque
from datetime import datetime

from scapy.all import (
    sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, ARP, Raw, Ether,
    conf as scapy_conf,
)

from core.netutils import shannon_entropy, get_default_iface
from core.database import Flow, DnsLog, db

logger = logging.getLogger("cgs.sniffer")
scapy_conf.verb = 0

# Noise: IPs and ports to skip (broadcast, multicast, mDNS, SSDP, LLMNR)
_NOISE_DST = {"224.0.0.251", "224.0.0.252", "239.255.255.250", "255.255.255.255"}
_NOISE_PORTS = {5353, 1900, 5355, 137, 138}

# Known JA3 hashes for common tools/malware
_JA3_KNOWN = {
    "72a589da586844d7f0818ce684948eea": "Metasploit",
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike",
    "6734f37431670b3ab4292b8f60f29984": "Trickbot",
    "e7d705a3286e19ea42f587b344ee6865": "Emotet",
    "3b5074b1b5d032e5620f69f9f700ff0e": "Python requests",
    "cd08e31494f9531f560d64c695473da9": "curl",
    "4d7a28d6f2263ed61de88ca66eb011e3": "Go default",
}

# TLS record type and handshake type constants
_TLS_HANDSHAKE = 0x16
_TLS_CLIENT_HELLO = 0x01


class PacketSniffer:
    """High-performance L2/L3 capture with ring buffer and TLS fingerprinting."""

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
        self._analysis_thread = None
        self._flush_thread = None
        self._pkt_count = 0
        self._byte_count = 0
        self._drop_count = 0
        self._start_ts = None

        # Ring buffer: capture thread pushes, analysis thread pops
        self._ring: deque = deque(maxlen=50000)
        self._ring_lock = threading.Lock()

        # Flow aggregation
        self._flows: dict[tuple, dict] = {}
        self._flow_lock = threading.Lock()
        self._dns_buf: list[dict] = []
        self._dns_lock = threading.Lock()

        # JA3 cache: avoid recomputing for same (src, dst, port) combo
        self._ja3_cache: dict[tuple, str] = {}
        self._ja3_lock = threading.Lock()

        # Adaptive flush
        self._last_flush_ts = time.time()
        self._flush_interval = 15  # seconds, adapts to load

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

        self._analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True, name="sniffer-analyze")
        self._analysis_thread.start()

        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True, name="sniffer-flush")
        self._flush_thread.start()

        logger.info("Sniffer started on %s (promisc=%s, filter=%s, buffer=50k)",
                     self.iface, self.promisc, self.bpf or "none")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        if self._analysis_thread:
            self._analysis_thread.join(timeout=3)
        if self._flush_thread:
            self._flush_thread.join(timeout=3)
        self._flush_to_db()
        logger.info("Sniffer stopped — %d packets captured, %d dropped.",
                    self._pkt_count, self._drop_count)

    # ──────────────────────────────────────────────
    # Thread 1: Capture (fast, minimal processing)
    # ──────────────────────────────────────────────
    def _sniff_loop(self):
        """Capture loop. Auto-restarts on crash."""
        from core.safety import safe_thread

        @safe_thread("sniffer", restart=True, backoff=5.0)
        def _run():
            sniff(
                iface=self.iface,
                prn=self._enqueue,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
                filter=self.bpf or None,
                promisc=self.promisc,
            )
        try:
            _run()
        except PermissionError:
            logger.error("Sniffer: permission denied (sudo required).")

    def _enqueue(self, pkt):
        """Minimal callback: just count and push to ring buffer."""
        self._pkt_count += 1
        self._byte_count += len(pkt)
        with self._ring_lock:
            if len(self._ring) >= self._ring.maxlen:
                self._drop_count += 1
            self._ring.append((time.time(), pkt))

    # ──────────────────────────────────────────────
    # Thread 2: Analysis (drains ring buffer)
    # ──────────────────────────────────────────────
    def _analysis_loop(self):
        """Drain ring buffer and process packets. Runs in its own thread."""
        while not self._stop.is_set():
            batch = []
            with self._ring_lock:
                while self._ring:
                    batch.append(self._ring.popleft())
                    if len(batch) >= 500:
                        break

            if not batch:
                time.sleep(0.01)
                continue

            for ts, pkt in batch:
                try:
                    self._process_packet(pkt, ts)
                except Exception as e:
                    if self._pkt_count % 50000 == 0:
                        logger.debug("Packet error: %s", e)

    def _process_packet(self, pkt, ts: float):
        """Full packet processing with analysis dispatch."""
        size = len(pkt)

        # ── ARP ──
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            self._analyze({
                "type": "arp_reply",
                "src_ip": pkt[ARP].psrc,
                "src_mac": pkt[ARP].hwsrc,
                "ts": ts,
            })
            return

        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]
        src, dst = ip_layer.src, ip_layer.dst
        proto = "OTHER"
        sport, dport = 0, 0
        flags = ""

        # ── Noise filter ──
        if dst in _NOISE_DST:
            return

        # ── TCP ──
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            proto = "TCP"
            sport, dport = tcp.sport, tcp.dport

            if dport in _NOISE_PORTS or sport in _NOISE_PORTS:
                # Still aggregate flow but don't analyze
                self._flow_agg(src, sport, dst, dport, proto, size, flags)
                return

            flags = str(tcp.flags)

            evt = {
                "type": "tcp", "src": src, "dst": dst,
                "sport": sport, "dport": dport,
                "flags": flags, "size": size, "ttl": ip_layer.ttl, "ts": ts,
            }

            # ── JA3 TLS fingerprinting ──
            if pkt.haslayer(Raw) and dport == 443:
                ja3 = self._extract_ja3(pkt, src, dst, dport)
                if ja3:
                    evt["ja3"] = ja3["hash"]
                    evt["ja3_match"] = ja3.get("match", "")
                    if ja3.get("match"):
                        # Known malicious tool — fire immediately
                        self._analyze({
                            "type": "ja3_alert",
                            "src": src, "dst": dst,
                            "ja3_hash": ja3["hash"],
                            "ja3_match": ja3["match"],
                            "ts": ts,
                        })

            # ── TCP payload extract for HTTP anomaly detection ──
            if pkt.haslayer(Raw) and dport in (80, 8080, 443, 8443):
                payload = bytes(pkt[Raw].load)[:512]
                if payload:
                    evt["payload"] = payload

            self._analyze(evt)

            # Identity fingerprint (sampled)
            if self.identity and self._pkt_count % 100 == 0:
                mac = ""
                tcp_win = tcp.window if hasattr(tcp, 'window') else 0
                try:
                    if pkt.haslayer(Ether):
                        mac = pkt[Ether].src
                except Exception as e:
                    logger.warning("Failed to extract MAC from packet: %s", e)
                if mac and mac != "ff:ff:ff:ff:ff:ff":
                    self.identity.observe(
                        ip=src, mac=mac, ttl=ip_layer.ttl,
                        tcp_window=tcp_win, packet_size=size, dst_ip=dst,
                    )

        # ── UDP ──
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            proto = "UDP"
            sport, dport = udp.sport, udp.dport

            if dport in _NOISE_PORTS and sport in _NOISE_PORTS:
                self._flow_agg(src, sport, dst, dport, proto, size, flags)
                return

            # DNS
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                dns = pkt[DNS]
                if dns.qr == 0:
                    self._process_dns_query(dns, src, ts)
                elif dns.qr == 1:
                    self._process_dns_response(dns, dst, ts)

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
        self._flow_agg(src, sport, dst, dport, proto, size, flags)

    def _flow_agg(self, src, sport, dst, dport, proto, size, flags):
        """Aggregate flow data."""
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
    # JA3 TLS fingerprinting
    # ──────────────────────────────────────────────
    def _extract_ja3(self, pkt, src, dst, dport) -> dict | None:
        """Extract JA3 hash from a TLS ClientHello."""
        try:
            payload = bytes(pkt[Raw].load)
            if len(payload) < 6:
                return None

            # Check TLS handshake
            content_type = payload[0]
            if content_type != _TLS_HANDSHAKE:
                return None

            tls_version = (payload[1] << 8) | payload[2]
            # Skip record header (5 bytes), check handshake type
            if len(payload) < 6 or payload[5] != _TLS_CLIENT_HELLO:
                return None

            # Parse ClientHello for JA3 fields
            # JA3 = TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
            # Simplified: hash the raw ClientHello for fingerprinting
            # A full JA3 parser would extract each field, but for matching
            # known signatures, hashing the relevant bytes is sufficient

            # Skip to cipher suites offset
            if len(payload) < 44:
                return None

            # Client hello version
            ch_version = (payload[9] << 8) | payload[10]

            # Session ID length
            sid_len = payload[43]
            offset = 44 + sid_len
            if offset + 2 > len(payload):
                return None

            # Cipher suites
            cs_len = (payload[offset] << 8) | payload[offset + 1]
            offset += 2
            ciphers = []
            for i in range(0, cs_len, 2):
                if offset + i + 1 < len(payload):
                    c = (payload[offset + i] << 8) | payload[offset + i + 1]
                    if c not in (0x00FF, 0x5600):  # Skip GREASE
                        ciphers.append(str(c))
            offset += cs_len

            # Compression methods
            if offset >= len(payload):
                return None
            comp_len = payload[offset]
            offset += 1 + comp_len

            # Extensions
            extensions = []
            curves = []
            point_formats = []
            if offset + 2 <= len(payload):
                ext_len = (payload[offset] << 8) | payload[offset + 1]
                offset += 2
                ext_end = offset + ext_len
                while offset + 4 <= ext_end and offset + 4 <= len(payload):
                    ext_type = (payload[offset] << 8) | payload[offset + 1]
                    ext_data_len = (payload[offset + 2] << 8) | payload[offset + 3]
                    if ext_type not in (0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A,
                                        0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A,
                                        0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA):
                        extensions.append(str(ext_type))

                        # Supported groups (ext 10)
                        if ext_type == 10 and offset + 6 <= len(payload):
                            gl = (payload[offset + 4] << 8) | payload[offset + 5]
                            for i in range(0, gl, 2):
                                pos = offset + 6 + i
                                if pos + 1 < len(payload):
                                    g = (payload[pos] << 8) | payload[pos + 1]
                                    if g not in (0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A):
                                        curves.append(str(g))

                        # EC point formats (ext 11)
                        if ext_type == 11 and offset + 5 <= len(payload):
                            pf_len = payload[offset + 4]
                            for i in range(pf_len):
                                pos = offset + 5 + i
                                if pos < len(payload):
                                    point_formats.append(str(payload[pos]))

                    offset += 4 + ext_data_len

            # Build JA3 string
            ja3_str = ",".join([
                str(ch_version),
                "-".join(ciphers),
                "-".join(extensions),
                "-".join(curves),
                "-".join(point_formats),
            ])

            ja3_hash = hashlib.md5(ja3_str.encode(), usedforsecurity=False).hexdigest()

            # Cache to avoid recomputing
            cache_key = (src, dst, dport)
            with self._ja3_lock:
                if cache_key in self._ja3_cache:
                    return {"hash": self._ja3_cache[cache_key],
                            "match": _JA3_KNOWN.get(self._ja3_cache[cache_key], "")}
                self._ja3_cache[cache_key] = ja3_hash
                # Limit cache size
                if len(self._ja3_cache) > 10000:
                    # Remove oldest half
                    keys = list(self._ja3_cache.keys())
                    for k in keys[:5000]:
                        del self._ja3_cache[k]

            result = {"hash": ja3_hash}
            match = _JA3_KNOWN.get(ja3_hash)
            if match:
                result["match"] = match
                logger.warning("JA3 MATCH: %s from %s → %s (%s)", match, src, dst, ja3_hash)
            return result

        except Exception as e:
            logger.warning("Failed to extract JA3 fingerprint: %s", e)
            return None

    # ──────────────────────────────────────────────
    # DNS query
    # ──────────────────────────────────────────────
    def _process_dns_query(self, dns_pkt, src_ip: str, ts: float):
        """Parse DNS query and dispatch."""
        try:
            qname = dns_pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
            qtype = dns_pkt[DNSQR].qtype

            parts = qname.split(".")
            subdomain = parts[0] if len(parts) > 2 else ""
            ent = round(shannon_entropy(subdomain), 3)

            with self._dns_lock:
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
            logger.debug("DNS parse: %s", e)

    # ──────────────────────────────────────────────
    # DNS response (for fast-flux detection)
    # ──────────────────────────────────────────────
    def _process_dns_response(self, dns_pkt, querier_ip: str, ts: float):
        """Parse DNS response to extract answer IPs for fast-flux detection."""
        try:
            qname = dns_pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
            answers = []
            min_ttl = 86400

            for i in range(dns_pkt.ancount):
                try:
                    rr = dns_pkt.an[i]
                    if hasattr(rr, 'rdata'):
                        rdata = str(rr.rdata)
                        answers.append(rdata)
                    if hasattr(rr, 'ttl'):
                        min_ttl = min(min_ttl, rr.ttl)
                except Exception as e:
                    logger.warning("Failed to parse DNS response record: %s", e)

            if answers:
                self._analyze({
                    "type": "dns_response",
                    "src": querier_ip, "query": qname,
                    "answers": answers, "ttl": min_ttl,
                    "ts": ts,
                })
        except Exception as e:
            logger.warning("Failed to process DNS response: %s", e)

    # ──────────────────────────────────────────────
    # Periodic flush → DB (adaptive interval)
    # ──────────────────────────────────────────────
    def _flush_loop(self):
        while not self._stop.is_set():
            self._stop.wait(self._flush_interval)
            if not self._stop.is_set():
                self._flush_to_db()
                # Adaptive: faster flush under high load, slower when quiet
                ring_size = len(self._ring)
                if ring_size > 10000:
                    self._flush_interval = 5
                elif ring_size > 1000:
                    self._flush_interval = 10
                else:
                    self._flush_interval = 15

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
                logger.warning("Flush flows: %s", e)

        # DNS
        with self._dns_lock:
            buf = list(self._dns_buf)
            self._dns_buf.clear()
        if buf:
            try:
                with db.atomic():
                    for d in buf:
                        DnsLog.create(**d)
            except Exception as e:
                logger.warning("Flush DNS: %s", e)

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
            "dropped": self._drop_count,
            "pps": round(self._pkt_count / elapsed, 1),
            "mbps": round(self._byte_count * 8 / elapsed / 1_000_000, 2),
            "active_flows": len(self._flows),
            "ring_usage": len(self._ring),
            "ring_max": self._ring.maxlen,
            "ja3_cache": len(self._ja3_cache),
            "flush_interval": self._flush_interval,
            "uptime_s": round(elapsed),
        }
