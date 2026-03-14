"""
Moteur d'analyse des menaces — le « cerveau » du SIEM.

Detections:
  1. Scan de ports vertical / horizontal
  2. Brute-force SSH et services
  3. DNS tunnel (high entropy)
  4. C2 beaconing (regular intervals)
  5. Exfiltration (volumes anormaux)
  6. ARP spoofing (changement MAC)
  7. Ports suspects (meterpreter, IRC…)
  8. Anomalie trafic vs baseline

Dynamic risk score 0-100 per host.
"""

import logging, math, statistics, threading, time
from collections import defaultdict
from datetime import datetime, timedelta

from core.database import Alert, Host, BaselineStat, DnsLog, Flow, db

logger = logging.getLogger("cyberguard.analyzer")

SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337,
                    12345, 4443, 6667, 6697}

SEV = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW", 5: "INFO"}


class ThreatEngine:

    def __init__(self, config, alert_fn):
        self.cfg = config
        self._alert = alert_fn

        self.ps_th = config.get("analysis.portscan_threshold", 15)
        self.bf_th = config.get("analysis.bruteforce_threshold", 10)
        self.bf_win = config.get("analysis.bruteforce_window", 60)
        self.bcn_tol = config.get("analysis.beacon_tolerance", 0.15)
        self.dns_th = config.get("analysis.dns_entropy_threshold", 3.5)
        self.exfil = config.get("analysis.exfil_mb", 100) * 1024 * 1024

        self._lock = threading.Lock()

        # Real-time trackers
        self._scan_tr: dict[str, dict] = defaultdict(
            lambda: {"ports": set(), "hosts": set(), "first": None, "last": None, "alerted": False})
        self._bf_tr: dict[tuple, list] = defaultdict(list)
        self._bcn_tr: dict[tuple, list] = defaultdict(list)
        self._bcn_last: dict[tuple, float] = {}
        self._vol_tr: dict[str, int] = defaultdict(int)
        self._dns_tr: dict[str, list] = defaultdict(list)
        self._arp_tbl: dict[str, str] = {}
        self._risk_d: dict[str, int] = defaultdict(int)

        threading.Thread(target=self._cleanup_loop, daemon=True, name="analyzer-gc").start()

    # ══════════════════════════════════════════════
    # Entry point: sniffer event
    # ══════════════════════════════════════════════
    def on_event(self, evt: dict):
        t = evt.get("type")
        with self._lock:
            if t == "tcp":       self._tcp(evt)
            elif t == "udp":     self._udp(evt)
            elif t == "icmp":    self._icmp(evt)
            elif t == "dns_query": self._dns(evt)
            elif t == "arp_reply": self._arp(evt)

    # ──────────────────────────────────────────────
    def _tcp(self, e):
        src, dst, dp, flags = e["src"], e["dst"], e["dport"], e.get("flags", "")

        # ── Scan ──
        if "SYN" in flags and "ACK" not in flags:
            tr = self._scan_tr[src]
            tr["ports"].add(dp); tr["hosts"].add(dst)
            if tr["first"] is None: tr["first"] = e["ts"]
            tr["last"] = e["ts"]

            if len(tr["ports"]) >= self.ps_th and not tr["alerted"]:
                tr["alerted"] = True; self._risk_d[src] += 25
                self._alert(severity=2, source="analyzer", category="portscan",
                            title=f"Scan de ports depuis {src}",
                            detail=f"{len(tr['ports'])} ports, {len(tr['hosts'])} hosts",
                            src_ip=src, dst_ip=dst)

            if len(tr["hosts"]) >= self.ps_th and not tr.get("ha"):
                tr["ha"] = True; self._risk_d[src] += 20
                self._alert(severity=2, source="analyzer", category="hostscan",
                            title=f"Network sweep from {src}",
                            detail=f"{len(tr['hosts'])} hosts", src_ip=src)

        # ── Brute-force ──
        if "SYN" in flags and dp in (22, 23, 3389, 5900, 3306, 1433, 445, 21):
            key = (src, dst, dp)
            now = time.time()
            self._bf_tr[key] = [t for t in self._bf_tr[key] if t > now - self.bf_win]
            self._bf_tr[key].append(now)
            if len(self._bf_tr[key]) >= self.bf_th:
                self._risk_d[src] += 30
                self._alert(severity=1, source="analyzer", category="bruteforce",
                            title=f"Brute-force {src} → {dst}:{dp}",
                            detail=f"{len(self._bf_tr[key])} tentatives en {self.bf_win}s",
                            src_ip=src, dst_ip=dst)
                self._bf_tr[key].clear()

        # ── Port suspect ──
        if dp in SUSPICIOUS_PORTS:
            self._risk_d[src] += 10
            self._alert(severity=2, source="analyzer", category="suspicious_port",
                        title=f"Login port suspect {dp}",
                        detail=f"{src} → {dst}:{dp}", src_ip=src, dst_ip=dst)

        # ── Beaconing ──
        pair = (src, dst)
        now = time.time()
        if pair in self._bcn_last:
            iv = now - self._bcn_last[pair]
            if 1 < iv < 7200:
                self._bcn_tr[pair].append(iv)
                if len(self._bcn_tr[pair]) >= 20:
                    self._check_beacon(pair, src, dst)
        self._bcn_last[pair] = now

        self._vol_tr[src] += e.get("size", 0)

    def _udp(self, e):
        dp = e.get("dport", 0)
        if dp in SUSPICIOUS_PORTS:
            self._alert(severity=3, source="analyzer", category="suspicious_port",
                        title=f"UDP port suspect {dp}",
                        detail=f"{e['src']} → {e['dst']}:{dp}",
                        src_ip=e["src"], dst_ip=e["dst"])
        self._vol_tr[e["src"]] += e.get("size", 0)

    def _icmp(self, e):
        if e.get("icmp_type") == 8:
            tr = self._scan_tr[e["src"]]
            tr["hosts"].add(e["dst"])
            if len(tr["hosts"]) >= self.ps_th and not tr.get("icmp_a"):
                tr["icmp_a"] = True
                self._alert(severity=3, source="analyzer", category="ping_sweep",
                            title=f"Ping sweep depuis {e['src']}",
                            detail=f"{len(tr['hosts'])} hosts", src_ip=e["src"])

    def _dns(self, e):
        src, query, entropy = e["src"], e.get("query", ""), e.get("entropy", 0)
        self._dns_tr[src].append(entropy)

        if entropy >= self.dns_th and len(query) > 30:
            self._risk_d[src] += 15
            self._alert(severity=2, source="analyzer", category="dns_tunnel",
                        title=f"Possible tunnel DNS depuis {src}",
                        detail=f"Query: {query[:80]} (entropie={entropy:.2f})",
                        src_ip=src, ioc=query)

        for p in (".onion.", ".tor2web.", ".i2p."):
            if p in query:
                self._risk_d[src] += 20
                self._alert(severity=1, source="analyzer", category="tor_domain",
                            title=f"Network anonyme depuis {src}",
                            detail=f"DNS: {query}", src_ip=src, ioc=query)
                break

    def _arp(self, e):
        ip, mac = e["src_ip"], e["src_mac"]
        if ip in self._arp_tbl and self._arp_tbl[ip] != mac:
            self._risk_d[ip] += 40
            self._alert(severity=1, source="analyzer", category="arp_spoof",
                        title=f"ARP spoofing sur {ip}",
                        detail=f"Expected={self._arp_tbl[ip]} Received={mac}",
                        src_ip=ip)
        self._arp_tbl[ip] = mac

    # ──────────────────────────────────────────────
    def _check_beacon(self, pair, src, dst):
        ivs = self._bcn_tr[pair][-30:]
        if len(ivs) < 10:
            return
        mean = statistics.mean(ivs)
        if mean < 2:
            return
        sd = statistics.stdev(ivs) if len(ivs) > 1 else 0
        cv = sd / mean if mean else 1
        if cv < self.bcn_tol:
            self._risk_d[src] += 35
            self._alert(severity=1, source="analyzer", category="beaconing",
                        title=f"C2 beaconing : {src} → {dst}",
                        detail=f"Intervalle={mean:.1f}s σ={sd:.1f}s CV={cv:.3f} ({len(ivs)} samples)",
                        src_ip=src, dst_ip=dst)
            self._bcn_tr[pair].clear()

    # ══════════════════════════════════════════════
    # Baseline & anomalies (called periodically)
    # ══════════════════════════════════════════════
    def update_baseline(self):
        try:
            h_ago = datetime.now() - timedelta(hours=1)
            flows = Flow.select().where(Flow.ts >= h_ago).count()
            self._ustat("flow_rate_h", flows)
            from peewee import fn
            vol = Flow.select(fn.SUM(Flow.bytes_total)).where(Flow.ts >= h_ago).scalar() or 0
            self._ustat("bytes_h", vol)
            dns_c = DnsLog.select().where(DnsLog.ts >= h_ago).count()
            self._ustat("dns_h", dns_c)
        except Exception as e:
            logger.warning("Baseline : %s", e)

    def check_anomalies(self):
        self._check_volumes()
        self._update_risk()
        try:
            h_ago = datetime.now() - timedelta(hours=1)
            checks = {
                "flow_rate_h": Flow.select().where(Flow.ts >= h_ago).count(),
                "dns_h": DnsLog.select().where(DnsLog.ts >= h_ago).count(),
            }
            for key, current in checks.items():
                stat = BaselineStat.get_or_none(BaselineStat.key == key)
                if not stat or stat.samples < 12 or stat.std_dev <= 0:
                    continue
                z = (current - stat.value) / stat.std_dev
                if abs(z) > 3:
                    self._alert(severity=3, source="analyzer", category="anomaly",
                                title=f"Anomalie : {key}",
                                detail=f"Actuel={current} Baseline={stat.value:.0f}±{stat.std_dev:.0f} Z={z:.1f}")
        except Exception as e:
            logger.warning("Anomalies : %s", e)

    def _check_volumes(self):
        for ip, total in list(self._vol_tr.items()):
            if total >= self.exfil:
                mb = total / (1024 * 1024)
                self._risk_d[ip] += 25
                self._alert(severity=2, source="analyzer", category="exfiltration",
                            title=f"Volume anormal depuis {ip}",
                            detail=f"{mb:.1f} Mo transmis", src_ip=ip)

    @staticmethod
    def _ustat(key, value):
        st, created = BaselineStat.get_or_create(key=key, defaults={
            "value": value, "std_dev": 0, "samples": 1})
        if not created:
            n = st.samples + 1
            a = 2 / (min(n, 168) + 1)
            om = st.value
            nm = om + a * (value - om)
            nv = (1 - a) * (st.std_dev ** 2 + a * (value - om) ** 2)
            st.value, st.std_dev = nm, math.sqrt(max(nv, 0))
            st.samples, st.updated = n, datetime.now()
            st.save()

    def _update_risk(self):
        if not self._risk_d:
            return
        try:
            with db.atomic():
                for ip, delta in self._risk_d.items():
                    h = Host.get_or_none(Host.ip == ip)
                    if h:
                        h.risk_score = min(100, max(0, int(h.risk_score * 0.9) + delta))
                        h.save()
            self._risk_d.clear()
        except Exception:
            pass

    # ──────────────────────────────────────────────
    def _cleanup_loop(self):
        while True:
            time.sleep(300)
            with self._lock:
                now = time.time()
                for ip in list(self._scan_tr):
                    t = self._scan_tr[ip]
                    if t["last"] and now - t["last"] > 600:
                        del self._scan_tr[ip]
                for p in list(self._bcn_tr):
                    if len(self._bcn_tr[p]) > 50:
                        self._bcn_tr[p] = self._bcn_tr[p][-30:]
                for ip in list(self._dns_tr):
                    if len(self._dns_tr[ip]) > 200:
                        self._dns_tr[ip] = self._dns_tr[ip][-100:]
                self._vol_tr.clear()

    # ──────────────────────────────────────────────
    def get_threat_summary(self) -> dict:
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        return {
            "active_scanners": len(self._scan_tr),
            "bf_tracked": len(self._bf_tr),
            "beacon_pairs": len(self._bcn_tr),
            "alerts_today": Alert.select().where(Alert.ts >= today).count(),
            "alerts_critical": Alert.select().where(Alert.severity == 1, Alert.ts >= today).count(),
            "alerts_high": Alert.select().where(Alert.severity == 2, Alert.ts >= today).count(),
            "top_risk_hosts": [
                {"ip": h.ip, "score": h.risk_score, "os": h.os_hint}
                for h in Host.select().where(Host.risk_score > 0).order_by(Host.risk_score.desc()).limit(10)
            ],
        }
