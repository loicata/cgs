"""
CGS — All 8 advanced detectors in a single module.

Each detector is an isolated class extending BaseDetector:
  1. LateralMovement  — internal host scanning other internal hosts
  2. TemporalAnomaly  — activity outside normal hours
  3. DestinationAnomaly — host contacts unknown /16 prefix
  4. SlowExfil         — small periodic transfers to same external target
  5. DnsDeep           — DGA patterns, fast-flux, DoH bypass
  6. AttackGraph       — pivot detection (A→B then B→C = B compromised)
  7. IocLive           — real-time IOC file lookup
  8. HttpAnomaly       — suspicious user-agents and URL exploit patterns
"""

import ipaddress
import json
import logging
import math
import os
import re
import statistics
import threading
import time
from collections import defaultdict, deque

from analyzers.base import BaseDetector, Signal

log = logging.getLogger("cgs.detectors")


def _is_internal(ip, subnets):
    """Check if IP is in any of the monitored subnets."""
    try:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in net for net in subnets)
    except (ValueError, ipaddress.AddressValueError):
        return False


def _parse_subnets(config):
    nets = []
    for s in config.get("network.subnets", []):
        try:
            nets.append(ipaddress.IPv4Network(s, strict=False))
        except (ValueError, ipaddress.AddressValueError):
            pass
    return nets


# ══════════════════════════════════════════════════
# 1. Lateral movement
# ══════════════════════════════════════════════════

class LateralMovement(BaseDetector):
    """Detects internal host suddenly scanning other internal hosts."""
    name = "lateral_movement"

    def __init__(self, cfg):
        super().__init__(cfg)
        self._subnets = _parse_subnets(cfg)
        self._peers: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
        self._baseline: dict[str, set] = defaultdict(set)  # known peer sets
        self._window: dict[str, deque] = defaultdict(lambda: deque())
        self._threshold = cfg.get("detectors.lateral_movement.scan_threshold", 5)
        self._window_s = cfg.get("detectors.lateral_movement.window_seconds", 300)
        self._lock = threading.Lock()

    def _analyze(self, evt):
        if evt.get("type") != "tcp" or evt.get("flags", "") != "S":
            return []
        src, dst = evt.get("src", ""), evt.get("dst", "")
        if not src or not dst or src == dst:
            return []
        if not _is_internal(src, self._subnets) or not _is_internal(dst, self._subnets):
            return []

        now = time.time()
        with self._lock:
            self._peers[src][dst].add(evt.get("dport", 0))
            self._window[src].append((now, dst))
            # Trim window
            while self._window[src] and now - self._window[src][0][0] > self._window_s:
                self._window[src].popleft()
            # Count new peers in window (not in baseline)
            recent_peers = {d for _, d in self._window[src]}
            new_peers = recent_peers - self._baseline[src]
            if len(new_peers) >= self._threshold:
                # Update baseline to prevent re-alerting
                self._baseline[src].update(new_peers)
                conf = min(0.5 + len(new_peers) * 0.1, 0.95)
                return [Signal(
                    self.name, "lateral_movement",
                    f"Lateral movement: {src} scanning {len(new_peers)} new internal hosts",
                    f"New peers: {', '.join(list(new_peers)[:10])}",
                    severity=2, confidence=conf, src_ip=src,
                )]
            # Grow baseline slowly
            if len(self._peers[src]) > 0 and self._window[src]:
                self._baseline[src].update(recent_peers)
        return []

    def _estimate_size(self):
        return len(self._peers) * 500 + len(self._window) * 200

    def _evict(self):
        with self._lock:
            if len(self._peers) > 5000:
                oldest = list(self._peers.keys())[:len(self._peers) // 2]
                for k in oldest:
                    del self._peers[k]
                    self._window.pop(k, None)


# ══════════════════════════════════════════════════
# 2. Temporal anomaly
# ══════════════════════════════════════════════════

class TemporalAnomaly(BaseDetector):
    """Detects activity at unusual hours for each host."""
    name = "temporal_anomaly"

    def __init__(self, cfg):
        super().__init__(cfg)
        self._subnets = _parse_subnets(cfg)
        # {ip: [count_per_hour_0..23]}
        self._hist: dict[str, list] = defaultdict(lambda: [0] * 24)
        self._samples: dict[str, int] = defaultdict(int)
        self._min_samples = cfg.get("detectors.temporal_anomaly.learning_events", 500)
        self._pct = cfg.get("detectors.temporal_anomaly.percentile_threshold", 5)
        self._cooldown: dict[tuple, float] = {}
        self._lock = threading.Lock()

    def _analyze(self, evt):
        src = evt.get("src", "")
        if not src or not _is_internal(src, self._subnets):
            return []

        from datetime import datetime
        hour = datetime.now().hour

        with self._lock:
            self._hist[src][hour] += 1
            self._samples[src] += 1

            if self._samples[src] < self._min_samples:
                return []

            # Is this hour unusual?
            h = self._hist[src]
            total = sum(h)
            if total == 0:
                return []
            pct = h[hour] / total * 100

            # Bottom Nth percentile
            if pct > self._pct:
                return []

            # Cooldown: max 1 alert per host per hour
            ck = (src, hour)
            if ck in self._cooldown and time.time() - self._cooldown[ck] < 3600:
                return []
            self._cooldown[ck] = time.time()

        conf = min(0.5 + (self._pct - pct) * 0.1, 0.85)
        return [Signal(
            self.name, "temporal_anomaly",
            f"Unusual activity hour for {src}",
            f"Hour {hour}:00 represents only {pct:.1f}% of this host's traffic",
            severity=4, confidence=conf, src_ip=src,
        )]

    def _estimate_size(self):
        return len(self._hist) * 224

    def _evict(self):
        with self._lock:
            if len(self._hist) > 10000:
                to_del = list(self._hist.keys())[:len(self._hist) // 2]
                for k in to_del:
                    del self._hist[k]
                    self._samples.pop(k, None)


# ══════════════════════════════════════════════════
# 3. Destination anomaly
# ══════════════════════════════════════════════════

class DestinationAnomaly(BaseDetector):
    """Detects host contacting never-before-seen /16 prefix."""
    name = "destination_anomaly"

    def __init__(self, cfg):
        super().__init__(cfg)
        self._subnets = _parse_subnets(cfg)
        # {src_ip: set of /16 prefixes seen}
        self._known: dict[str, set] = defaultdict(set)
        self._first_seen: dict[str, float] = {}
        self._min_age = cfg.get("detectors.destination_anomaly.min_baseline_hours", 1) * 3600
        self._lock = threading.Lock()

    def _analyze(self, evt):
        if evt.get("type") not in ("tcp", "udp"):
            return []
        src, dst = evt.get("src", ""), evt.get("dst", "")
        if not src or not dst:
            return []
        if not _is_internal(src, self._subnets) or _is_internal(dst, self._subnets):
            return []

        # Get /16 prefix
        parts = dst.split(".")
        if len(parts) != 4:
            return []
        prefix = f"{parts[0]}.{parts[1]}"

        now = time.time()
        with self._lock:
            if src not in self._first_seen:
                self._first_seen[src] = now
                self._known[src].add(prefix)
                return []

            age = now - self._first_seen[src]
            if age < self._min_age:
                self._known[src].add(prefix)
                return []

            if prefix in self._known[src]:
                return []

            self._known[src].add(prefix)

        conf = min(0.4 + age / 86400 * 0.1, 0.8)  # Higher with longer baseline
        return [Signal(
            self.name, "destination_anomaly",
            f"{src} contacted new IP range {prefix}.0.0/16",
            f"Destination {dst} in never-before-seen /16 (baseline {age/3600:.0f}h)",
            severity=4, confidence=conf, src_ip=src, dst_ip=dst,
        )]

    def _estimate_size(self):
        return sum(len(v) * 20 for v in self._known.values())

    def _evict(self):
        with self._lock:
            if len(self._known) > 10000:
                to_del = list(self._known.keys())[:len(self._known) // 2]
                for k in to_del:
                    del self._known[k]
                    self._first_seen.pop(k, None)


# ══════════════════════════════════════════════════
# 4. Slow exfiltration
# ══════════════════════════════════════════════════

class SlowExfil(BaseDetector):
    """Detects slow, periodic data exfiltration."""
    name = "slow_exfil"

    def __init__(self, cfg):
        super().__init__(cfg)
        self._subnets = _parse_subnets(cfg)
        # {(src, dst): deque of (ts, bytes)}
        self._flows: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=5000))
        self._window = cfg.get("detectors.slow_exfil.window_hours", 24) * 3600
        self._min_count = cfg.get("detectors.slow_exfil.min_transfers", 10)
        self._max_single = cfg.get("detectors.slow_exfil.max_single_transfer_kb", 100) * 1024
        self._total_threshold = cfg.get("detectors.slow_exfil.total_threshold_mb", 10) * 1024 * 1024
        self._alerted: dict[tuple, float] = {}
        self._lock = threading.Lock()

    def _analyze(self, evt):
        if evt.get("type") not in ("tcp", "udp"):
            return []
        src, dst = evt.get("src", ""), evt.get("dst", "")
        size = evt.get("size", 0)
        if not src or not dst or size <= 0 or size > self._max_single:
            return []
        if not _is_internal(src, self._subnets) or _is_internal(dst, self._subnets):
            return []

        now = time.time()
        k = (src, dst)
        with self._lock:
            self._flows[k].append((now, size))
            # Trim window
            while self._flows[k] and now - self._flows[k][0][0] > self._window:
                self._flows[k].popleft()
            entries = list(self._flows[k])

        if len(entries) < self._min_count:
            return []
        total = sum(b for _, b in entries)
        if total < self._total_threshold:
            return []

        # Check periodicity (CV of intervals < 0.5)
        times = [t for t, _ in entries]
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        if not intervals or statistics.mean(intervals) == 0:
            return []
        cv = statistics.stdev(intervals) / statistics.mean(intervals) if len(intervals) > 1 else 1.0
        if cv > 0.5:
            return []

        # Cooldown: 1 alert per pair per hour
        with self._lock:
            if k in self._alerted and now - self._alerted[k] < 3600:
                return []
            self._alerted[k] = now

        return [Signal(
            self.name, "slow_exfiltration",
            f"Slow exfiltration: {src} → {dst}",
            f"{total/1e6:.1f}MB in {len(entries)} small transfers "
            f"(interval CV={cv:.2f}, periodic), window={self._window/3600:.0f}h",
            severity=2, confidence=0.8, src_ip=src, dst_ip=dst, ioc=dst,
        )]

    def _estimate_size(self):
        return sum(len(d) * 16 for d in self._flows.values())

    def _evict(self):
        with self._lock:
            if len(self._flows) > 50000:
                to_del = list(self._flows.keys())[:len(self._flows) // 2]
                for k in to_del:
                    del self._flows[k]


# ══════════════════════════════════════════════════
# 5. DNS deep analysis
# ══════════════════════════════════════════════════

# Known DoH resolver IPs
_DOH_IPS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
            "149.112.112.112", "208.67.222.222", "208.67.220.220"}


class DnsDeep(BaseDetector):
    """DGA detection, fast-flux, and DoH bypass detection."""
    name = "dns_deep"

    def __init__(self, cfg):
        super().__init__(cfg)
        self._consonant_ratio = cfg.get("detectors.dns_deep.dga_consonant_ratio", 0.7)
        # {src: {domain: count}} for DGA tracking
        self._dga_track: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        # {domain: set of answer IPs} for fast-flux
        self._dns_answers: dict[str, set] = defaultdict(set)
        self._dns_ttls: dict[str, list] = defaultdict(list)
        # {src: bytes to DoH resolvers}
        self._doh_bytes: dict[str, int] = defaultdict(int)
        self._alerted: dict[str, float] = {}
        self._lock = threading.Lock()
        self._vowels = set("aeiou")

    def _analyze(self, evt):
        etype = evt.get("type", "")
        sigs = []

        if etype == "dns_query":
            sigs.extend(self._check_dga(evt))
        elif etype == "dns_response":
            sigs.extend(self._check_fastflux(evt))
        elif etype == "tcp" and evt.get("dport") == 443:
            sigs.extend(self._check_doh(evt))

        return sigs

    def _check_dga(self, evt):
        src = evt.get("src", "")
        query = evt.get("query", "")
        entropy = evt.get("entropy", 0)
        if not query or entropy < 3.0:
            return []

        # Extract subdomain
        parts = query.split(".")
        if len(parts) < 3:
            return []
        sub = parts[0]
        if len(sub) < 8:
            return []

        # Consonant ratio
        consonants = sum(1 for c in sub.lower() if c.isalpha() and c not in self._vowels)
        total_alpha = sum(1 for c in sub.lower() if c.isalpha())
        if total_alpha == 0:
            return []
        ratio = consonants / total_alpha

        if ratio < self._consonant_ratio or entropy < 3.5:
            return []

        with self._lock:
            self._dga_track[src][query] += 1
            dga_count = sum(1 for c in self._dga_track[src].values() if c >= 1)

        if dga_count < 5:
            return []

        ck = f"dga:{src}"
        with self._lock:
            if ck in self._alerted and time.time() - self._alerted[ck] < 1800:
                return []
            self._alerted[ck] = time.time()

        return [Signal(
            self.name, "dga_detected",
            f"DGA pattern from {src}: {dga_count} suspicious domains",
            f"Sample: {query} (entropy={entropy:.2f}, consonant_ratio={ratio:.2f})",
            severity=2, confidence=min(0.6 + dga_count * 0.05, 0.95),
            src_ip=src, ioc=query,
        )]

    def _check_fastflux(self, evt):
        query = evt.get("query", "")
        answers = evt.get("answers", [])
        ttl = evt.get("ttl", 3600)
        if not query or not answers or ttl > 300:
            return []

        with self._lock:
            self._dns_answers[query].update(answers)
            self._dns_ttls[query].append(ttl)
            unique_ips = len(self._dns_answers[query])

        if unique_ips < 5:
            return []

        ck = f"ff:{query}"
        with self._lock:
            if ck in self._alerted and time.time() - self._alerted[ck] < 3600:
                return []
            self._alerted[ck] = time.time()

        return [Signal(
            self.name, "fast_flux",
            f"Fast-flux domain: {query}",
            f"{unique_ips} unique IPs, TTL={ttl}",
            severity=3, confidence=0.75, src_ip=evt.get("src", ""), ioc=query,
        )]

    def _check_doh(self, evt):
        dst = evt.get("dst", "")
        src = evt.get("src", "")
        if dst not in _DOH_IPS:
            return []

        with self._lock:
            self._doh_bytes[src] += evt.get("size", 0)
            total = self._doh_bytes[src]

        if total < 100000:  # 100KB threshold
            return []

        ck = f"doh:{src}"
        with self._lock:
            if ck in self._alerted and time.time() - self._alerted[ck] < 3600:
                return []
            self._alerted[ck] = time.time()

        return [Signal(
            self.name, "doh_bypass",
            f"DNS-over-HTTPS bypass from {src}",
            f"{total/1024:.0f}KB HTTPS traffic to DoH resolver {dst}",
            severity=4, confidence=0.6, src_ip=src, dst_ip=dst,
        )]

    def _estimate_size(self):
        return (len(self._dga_track) * 200 + len(self._dns_answers) * 100
                + len(self._doh_bytes) * 50)

    def _evict(self):
        with self._lock:
            for d in (self._dga_track, self._dns_answers, self._dns_ttls, self._doh_bytes):
                if len(d) > 10000:
                    keys = list(d.keys())[:len(d) // 2]
                    for k in keys:
                        del d[k]


# ══════════════════════════════════════════════════
# 6. Attack graph (pivot detection)
# ══════════════════════════════════════════════════

class AttackGraph(BaseDetector):
    """Detects pivoting: A attacks B, then B attacks C → B is compromised."""
    name = "attack_graph"

    def __init__(self, cfg):
        super().__init__(cfg)
        self._subnets = _parse_subnets(cfg)
        # {target_ip: [(ts, attacker_ip, category)]}
        self._attacked: dict[str, list] = defaultdict(list)
        self._compromised: set = set()
        self._window = cfg.get("detectors.attack_graph.pivot_window_seconds", 1800)
        self._lock = threading.Lock()

    def feed_signal(self, sig: Signal):
        """Receive signals from other detectors to build attack knowledge."""
        if not sig.src_ip or not sig.dst_ip:
            return
        if sig.severity > 3:  # Only track significant attacks
            return
        with self._lock:
            self._attacked[sig.dst_ip].append(
                (time.time(), sig.src_ip, sig.category))
            # Trim
            now = time.time()
            self._attacked[sig.dst_ip] = [
                (t, a, c) for t, a, c in self._attacked[sig.dst_ip]
                if now - t < self._window * 2
            ]

    def _analyze(self, evt):
        if evt.get("type") != "tcp" or evt.get("flags", "") != "S":
            return []
        src = evt.get("src", "")
        dst = evt.get("dst", "")
        if not src or not dst:
            return []
        if not _is_internal(src, self._subnets):
            return []

        now = time.time()
        with self._lock:
            # Was src recently attacked by an external entity?
            attacks_on_src = self._attacked.get(src, [])
            recent_attacks = [(t, a, c) for t, a, c in attacks_on_src
                             if now - t < self._window and not _is_internal(a, self._subnets)]

            if not recent_attacks:
                return []
            if src in self._compromised:
                return []  # Already flagged

            # src was attacked AND is now scanning internally → pivot
            if _is_internal(dst, self._subnets) and dst != src:
                self._compromised.add(src)
                attacker = recent_attacks[-1][1]
                return [Signal(
                    self.name, "pivot_detected",
                    f"Pivot: {src} possibly compromised, now attacking {dst}",
                    f"External attacker {attacker} → {src} → {dst}",
                    severity=1, confidence=0.85,
                    src_ip=src, dst_ip=dst, ioc=attacker,
                )]
        return []

    def _estimate_size(self):
        return sum(len(v) * 60 for v in self._attacked.values())

    def _evict(self):
        now = time.time()
        with self._lock:
            for ip in list(self._attacked.keys()):
                self._attacked[ip] = [
                    (t, a, c) for t, a, c in self._attacked[ip]
                    if now - t < self._window * 2
                ]
                if not self._attacked[ip]:
                    del self._attacked[ip]


# ══════════════════════════════════════════════════
# 7. IOC live check
# ══════════════════════════════════════════════════

class IocLive(BaseDetector):
    """Real-time IOC lookup from a local JSON file."""
    name = "ioc_live"

    def __init__(self, cfg):
        super().__init__(cfg)
        self._subnets = _parse_subnets(cfg)
        self._path = cfg.get("detectors.ioc_live.file_path",
                             "/opt/cgs/data/ioc_list.json")
        self._ips: set = set()
        self._domains: set = set()
        self._cache: dict[str, float] = {}  # checked items with TTL
        self._ttl = cfg.get("detectors.ioc_live.cache_ttl_seconds", 3600)
        self._lock = threading.Lock()
        self._load_iocs()
        # Periodic reload
        threading.Thread(target=self._reload_loop, daemon=True,
                        name="ioc-reload").start()

    def _load_iocs(self):
        try:
            if os.path.exists(self._path):
                with open(self._path) as f:
                    data = json.load(f)
                self._ips = set(data.get("ips", []))
                self._domains = set(d.lower() for d in data.get("domains", []))
                log.info("IOC loaded: %d IPs, %d domains", len(self._ips), len(self._domains))
        except Exception as e:
            log.debug("IOC load: %s", e)

    def _reload_loop(self):
        while True:
            time.sleep(300)
            self._load_iocs()

    def _analyze(self, evt):
        sigs = []
        now = time.time()

        # Check destination IP
        dst = evt.get("dst", "")
        if dst and not _is_internal(dst, self._subnets):
            with self._lock:
                if dst not in self._cache or now - self._cache.get(dst, 0) > self._ttl:
                    self._cache[dst] = now
                    if dst in self._ips:
                        sigs.append(Signal(
                            self.name, "ioc_ip_match",
                            f"IOC match: {dst}",
                            f"Destination IP matches local IOC list",
                            severity=2, confidence=0.9,
                            src_ip=evt.get("src", ""), dst_ip=dst, ioc=dst,
                        ))

        # Check DNS queries
        if evt.get("type") == "dns_query":
            query = evt.get("query", "").lower()
            if query:
                with self._lock:
                    if query not in self._cache or now - self._cache.get(query, 0) > self._ttl:
                        self._cache[query] = now
                        # Check domain and parent domains
                        parts = query.split(".")
                        for i in range(len(parts) - 1):
                            domain = ".".join(parts[i:])
                            if domain in self._domains:
                                sigs.append(Signal(
                                    self.name, "ioc_domain_match",
                                    f"IOC match: {query}",
                                    f"DNS query matches IOC domain {domain}",
                                    severity=2, confidence=0.9,
                                    src_ip=evt.get("src", ""), ioc=domain,
                                ))
                                break
        return sigs

    def _estimate_size(self):
        return len(self._cache) * 50 + len(self._ips) * 20 + len(self._domains) * 30

    def _evict(self):
        now = time.time()
        with self._lock:
            self._cache = {k: v for k, v in self._cache.items() if now - v < self._ttl}


# ══════════════════════════════════════════════════
# 8. HTTP anomaly detection
# ══════════════════════════════════════════════════

# Suspicious user-agent patterns
_TOOL_UAS = re.compile(
    rb"nikto|sqlmap|dirbuster|gobuster|masscan|nmap|zgrab|nuclei|"
    rb"wpscan|burpsuite|hydra|metasploit|cobalt|havoc",
    re.I,
)

# URL exploit patterns
_EXPLOIT_PATTERNS = [
    re.compile(rb"\.\./\.\./", re.I),                    # path traversal
    re.compile(rb"(?:UNION\s+SELECT|OR\s+1\s*=\s*1|'--|;\s*DROP)", re.I),  # SQLi
    re.compile(rb"\$\{jndi:", re.I),                     # Log4j
    re.compile(rb"php://|data://|expect://", re.I),      # PHP wrappers
    re.compile(rb"(?:cmd|powershell|/bin/(?:sh|bash))", re.I),  # command injection
    re.compile(rb"<script|javascript:|onerror=", re.I),  # XSS
    re.compile(rb"(?:c99|r57|b374k|webshell|wso)\.", re.I),  # webshells
]


class HttpAnomaly(BaseDetector):
    """Detects suspicious HTTP user-agents and URL exploitation patterns."""
    name = "http_anomaly"

    def __init__(self, cfg):
        super().__init__(cfg)
        self._http_ports = {80, 8080, 443, 8443}
        self._alerted: dict[str, float] = {}
        self._lock = threading.Lock()

    def _analyze(self, evt):
        if evt.get("type") != "tcp":
            return []
        dport = evt.get("dport", 0)
        if dport not in self._http_ports:
            return []

        src = evt.get("src", "")
        payload = evt.get("payload", b"")
        if not payload or not isinstance(payload, (bytes, bytearray)):
            return []

        sigs = []
        now = time.time()

        # Check user-agent
        if _TOOL_UAS.search(payload):
            match = _TOOL_UAS.search(payload).group().decode("utf-8", errors="replace")
            ck = f"ua:{src}:{match}"
            with self._lock:
                if ck not in self._alerted or now - self._alerted[ck] > 300:
                    self._alerted[ck] = now
                    sigs.append(Signal(
                        self.name, "suspicious_user_agent",
                        f"Attack tool detected from {src}: {match}",
                        f"User-Agent contains known attack tool signature",
                        severity=3, confidence=0.8, src_ip=src,
                        dst_ip=evt.get("dst", ""), ioc=match,
                    ))

        # Check exploit patterns
        matched = []
        for pattern in _EXPLOIT_PATTERNS:
            if pattern.search(payload):
                matched.append(pattern.pattern[:30].decode("utf-8", errors="replace"))

        if matched:
            ck = f"exp:{src}"
            with self._lock:
                if ck not in self._alerted or now - self._alerted[ck] > 300:
                    self._alerted[ck] = now
                    conf = min(0.5 + len(matched) * 0.15, 0.95)
                    sigs.append(Signal(
                        self.name, "http_exploit_attempt",
                        f"HTTP exploit attempt from {src}",
                        f"{len(matched)} patterns: {', '.join(matched[:5])}",
                        severity=2, confidence=conf, src_ip=src,
                        dst_ip=evt.get("dst", ""),
                    ))

        return sigs

    def _estimate_size(self):
        return len(self._alerted) * 50

    def _evict(self):
        now = time.time()
        with self._lock:
            self._alerted = {k: v for k, v in self._alerted.items() if now - v < 3600}


# ══════════════════════════════════════════════════
# Registry: all detectors
# ══════════════════════════════════════════════════

ALL_DETECTORS = [
    LateralMovement,
    TemporalAnomaly,
    DestinationAnomaly,
    SlowExfil,
    DnsDeep,
    AttackGraph,
    IocLive,
    HttpAnomaly,
]
