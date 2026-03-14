"""
CyberGuard Sentinel — Multi-factor host identity.

Une A single MAC is not reliable (MAC spoofing, WiFi randomization,
VMs, conteneurs). Ce module identifie chaque machine par une
fingerprint combining multiple signals :

  1. MAC address (weight 25%)        — modireliable but costly to spoof perfectly
  2. Hostname / DHCP name (15%)     — souvent unique, parfois vide
  3. OS fingerprint TTL+TCP (15%)   — difficult to simulate exactly
  4. Typical open ports (15%)  — characteristic service profile
  5. Service banners (10%)    — unique software versions
  6. MAC Vendor OUI (10%)     — manufacturer consistency
  7. Patterns de trafic (10%)       — horaires, volumes, destinations habituelles

Identity confidence score : 0-100
  - ≥ 80 : identity confirmed (same machine)
  - 50-79 : probable but some signals changed
  - < 50  : different machine or spoofing

Detection de MAC spoofing :
  Une Known MAC appears on a machine with a different profile →
  critical alert + optional block.
"""

import hashlib
import json
import logging
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from core.database import Host, Port, Flow, db

logger = logging.getLogger("cyberguard.identity")


@dataclass
class HostFingerprint:
    """Multi-factor host fingerprint."""
    mac: str = ""
    hostname: str = ""
    os_ttl: int = 0                    # Observed TTL (ICMP/IP)
    os_hint: str = ""                  # Linux, Windows, macOS…
    tcp_window: int = 0                # TCP window size (SYN-ACK)
    open_ports: list = field(default_factory=list)   # ex: [22, 80, 443]
    banners: dict = field(default_factory=dict)      # port → banner hash
    vendor_oui: str = ""               # OUI prefix (first 3 MAC bytes)
    dhcp_hostname: str = ""            # Nom sent en DHCP option 12
    avg_packet_size: int = 0           # Taille moyenne des paquets
    active_hours: list = field(default_factory=list) # typical activity hours [9,10,11…]
    common_destinations: list = field(default_factory=list)  # top 5 contacted IPs
    first_seen: str = ""
    last_seen: str = ""
    samples: int = 0                   # nombre d'observations

    def to_dict(self) -> dict:
        return {
            "mac": self.mac, "hostname": self.hostname,
            "os_ttl": self.os_ttl, "os_hint": self.os_hint,
            "tcp_window": self.tcp_window,
            "open_ports": self.open_ports,
            "banners": self.banners, "vendor_oui": self.vendor_oui,
            "dhcp_hostname": self.dhcp_hostname,
            "avg_packet_size": self.avg_packet_size,
            "active_hours": self.active_hours,
            "common_destinations": self.common_destinations,
            "samples": self.samples,
        }

    @property
    def fingerprint_hash(self) -> str:
        """Hash court de l'empreinte pour comparaison rapide."""
        data = f"{self.os_ttl}:{self.tcp_window}:{sorted(self.open_ports)}:{self.vendor_oui}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]


# Weight of each factor dans le confidence score
WEIGHTS = {
    "mac": 0.25,
    "hostname": 0.15,
    "os_fingerprint": 0.15,
    "open_ports": 0.15,
    "banners": 0.10,
    "vendor_oui": 0.10,
    "traffic_pattern": 0.10,
}


class HostIdentityEngine:
    """Manages multi-factor identity de chaque host du network."""

    def __init__(self, config, alert_fn):
        self.cfg = config
        self._alert = alert_fn
        self.spoof_threshold = config.get("identity.spoof_threshold", 50)
        self.learning_period_hours = config.get("identity.learning_hours", 48)

        # Empreintes connues : MAC → HostFingerprint
        self._fingerprints: dict[str, HostFingerprint] = {}
        # IP history for each MAC
        self._mac_ip_history: dict[str, list] = defaultdict(list)
        self._lock = __import__("threading").Lock()

        # Load fingerprints from persistent file
        self._fp_file = os.path.join(
            config.get("general.data_dir", "/var/lib/cyberguard/data"),
            "fingerprints.json"
        )
        self._load()

    # ══════════════════════════════════════════════
    # Observation: fed by discovery + sniffer
    # ══════════════════════════════════════════════

    def observe(self, ip: str, mac: str = "", hostname: str = "",
                os_hint: str = "", ttl: int = 0, tcp_window: int = 0,
                open_ports: list = None, banners: dict = None,
                packet_size: int = 0, dst_ip: str = "", vendor_oui: str = "") -> dict:
        """
        Records an observation d'un host.
        Returns {"identity_score": int, "spoofing": bool, "details": str}
        """
        if not mac or mac == "00:00:00:00:00:00":
            return {"identity_score": 100, "spoofing": False, "details": ""}

        mac = mac.lower()
        vendor_oui = mac[:8]
        now = datetime.now()
        result = {"identity_score": 100, "spoofing": False, "details": ""}

        with self._lock:
            if mac in self._fingerprints:
                # Known MAC → check consistency
                known = self._fingerprints[mac]
                score, details = self._compare(known, mac, hostname, os_hint,
                                                ttl, tcp_window, open_ports,
                                                banners, vendor_oui, packet_size, dst_ip)
                result["identity_score"] = score
                result["details"] = details

                if score < self.spoof_threshold and known.samples >= 3:
                    result["spoofing"] = True
                    logger.warning(
                        "🚨 MAC SPOOFING suspected : %s (score=%d/100)\n  %s",
                        mac, score, details
                    )
                    self._alert(
                        severity=1, source="identity", category="mac_spoof",
                        title=f"Suspected MAC spoofing : {mac}",
                        detail=(
                            f"Confidence score : {score}/100 (threshold : {self.spoof_threshold})\n"
                            f"IP actuelle : {ip}\n"
                            f"Divergences : {details}\n"
                            f"Known fingerprint : {json.dumps(known.to_dict(), indent=2)[:500]}"
                        ),
                        src_ip=ip,
                    )

                # Update fingerprint (continuous learning)
                self._update_fingerprint(known, hostname, os_hint, ttl,
                                         tcp_window, open_ports, banners,
                                         packet_size, dst_ip)
            else:
                # New MAC → create fingerprint
                fp = HostFingerprint(
                    mac=mac, hostname=hostname, os_hint=os_hint,
                    os_ttl=ttl, tcp_window=tcp_window,
                    open_ports=sorted(open_ports or []),
                    banners=banners or {},
                    vendor_oui=vendor_oui,
                    dhcp_hostname=hostname,
                    avg_packet_size=packet_size,
                    first_seen=now.isoformat(),
                    last_seen=now.isoformat(),
                    samples=1,
                )
                if dst_ip:
                    fp.common_destinations = [dst_ip]
                fp.active_hours = [now.hour]
                self._fingerprints[mac] = fp

            # Historique IP
            history = self._mac_ip_history[mac]
            if not history or history[-1] != ip:
                history.append(ip)
                if len(history) > 50:
                    self._mac_ip_history[mac] = history[-50:]

        return result

    # ══════════════════════════════════════════════
    # Comparaison : empreinte connue vs observation
    # ══════════════════════════════════════════════

    def _compare(self, known: HostFingerprint, mac: str, hostname: str,
                 os_hint: str, ttl: int, tcp_window: int,
                 open_ports: list, banners: dict,
                 vendor_oui: str, packet_size: int, dst_ip: str) -> tuple[int, str]:
        """
        Compares observation with known fingerprint.
        Returns (score 0-100, divergence details).
        """
        scores = {}
        divergences = []

        # 1. MAC (always 100% since it's the lookup key)
        scores["mac"] = 100

        # 2. Hostname
        if hostname and known.hostname:
            if hostname.lower() == known.hostname.lower():
                scores["hostname"] = 100
            elif hostname.lower()[:5] == known.hostname.lower()[:5]:
                scores["hostname"] = 60  # common prefix
            else:
                scores["hostname"] = 0
                divergences.append(f"Hostname: '{known.hostname}' → '{hostname}'")
        else:
            scores["hostname"] = 80  # no hostname = neutral

        # 3. OS fingerprint (TTL + TCP window)
        if ttl > 0 and known.os_ttl > 0:
            ttl_diff = abs(ttl - known.os_ttl)
            if ttl_diff == 0:
                scores["os_fingerprint"] = 100
            elif ttl_diff <= 2:
                scores["os_fingerprint"] = 80  # normal network variation
            elif ttl_diff <= 10:
                scores["os_fingerprint"] = 50
                divergences.append(f"TTL: {known.os_ttl} → {ttl}")
            else:
                scores["os_fingerprint"] = 0
                divergences.append(f"Drastically different TTL: {known.os_ttl} → {ttl} (different OS?)")
        else:
            scores["os_fingerprint"] = 70

        if tcp_window > 0 and known.tcp_window > 0:
            if tcp_window == known.tcp_window:
                scores["os_fingerprint"] = min(scores.get("os_fingerprint", 100), 100)
            elif abs(tcp_window - known.tcp_window) < 1000:
                pass  # normal variation
            else:
                scores["os_fingerprint"] = max(scores.get("os_fingerprint", 0) - 30, 0)
                divergences.append(f"TCP Window: {known.tcp_window} → {tcp_window}")

        # 4. Open ports
        if open_ports and known.open_ports:
            known_set = set(known.open_ports)
            current_set = set(open_ports)
            if known_set == current_set:
                scores["open_ports"] = 100
            else:
                intersection = known_set & current_set
                union = known_set | current_set
                jaccard = len(intersection) / len(union) if union else 0
                scores["open_ports"] = int(jaccard * 100)
                if jaccard < 0.5:
                    divergences.append(
                        f"Ports: {sorted(known_set)} → {sorted(current_set)} "
                        f"(similarity {jaccard:.0%})")
        else:
            scores["open_ports"] = 70

        # 5. Service banners
        if banners and known.banners:
            matching = sum(1 for p, b in banners.items()
                         if p in known.banners and known.banners[p] == b)
            total = max(len(banners), len(known.banners))
            scores["banners"] = int((matching / total) * 100) if total else 80
            if scores["banners"] < 50:
                divergences.append(f"Different service banners ({matching}/{total})")
        else:
            scores["banners"] = 80

        # 6. Vendor OUI
        if vendor_oui and known.vendor_oui:
            if vendor_oui == known.vendor_oui:
                scores["vendor_oui"] = 100
            else:
                scores["vendor_oui"] = 0
                divergences.append(
                    f"MAC OUI changed: {known.vendor_oui} → {vendor_oui} "
                    "(different manufacturer = spoofing probable)")
        else:
            scores["vendor_oui"] = 80

        # 7. Traffic pattern (activity hours)
        current_hour = datetime.now().hour
        if known.active_hours:
            if current_hour in known.active_hours:
                scores["traffic_pattern"] = 100
            elif any(abs(current_hour - h) <= 2 for h in known.active_hours):
                scores["traffic_pattern"] = 70
            else:
                scores["traffic_pattern"] = 40
                # Don't flag as divergence (may be legitimate)
        else:
            scores["traffic_pattern"] = 80

        # Weighted final score
        total_score = sum(scores.get(k, 80) * w for k, w in WEIGHTS.items())
        total_score = max(0, min(100, int(total_score)))

        detail_str = "; ".join(divergences) if divergences else "Identity consistent"

        return total_score, detail_str

    # ══════════════════════════════════════════════
    # Continuous learning
    # ══════════════════════════════════════════════

    def _update_fingerprint(self, fp: HostFingerprint, hostname: str,
                            os_hint: str, ttl: int, tcp_window: int,
                            open_ports: list, banners: dict,
                            packet_size: int, dst_ip: str):
        """Updates the fingerprint avec la moving average des observations."""
        fp.samples += 1
        fp.last_seen = datetime.now().isoformat()
        n = fp.samples

        # Exponential moving average (decreasing alpha)
        alpha = 2 / (min(n, 100) + 1)

        if hostname and (not fp.hostname or n <= 5):
            fp.hostname = hostname

        if os_hint:
            fp.os_hint = os_hint

        if ttl > 0:
            if fp.os_ttl == 0:
                fp.os_ttl = ttl
            else:
                fp.os_ttl = int(fp.os_ttl * (1 - alpha) + ttl * alpha)

        if tcp_window > 0:
            if fp.tcp_window == 0:
                fp.tcp_window = tcp_window
            else:
                fp.tcp_window = int(fp.tcp_window * (1 - alpha) + tcp_window * alpha)

        if open_ports:
            # Union progressive des ports vus
            port_set = set(fp.open_ports) | set(open_ports)
            fp.open_ports = sorted(port_set)

        if banners:
            for port, banner in banners.items():
                fp.banners[str(port)] = banner

        if packet_size > 0:
            if fp.avg_packet_size == 0:
                fp.avg_packet_size = packet_size
            else:
                fp.avg_packet_size = int(fp.avg_packet_size * (1 - alpha) + packet_size * alpha)

        # Activity hours
        hour = datetime.now().hour
        if hour not in fp.active_hours:
            fp.active_hours.append(hour)
            if len(fp.active_hours) > 24:
                fp.active_hours = fp.active_hours[-24:]

        # Destinations
        if dst_ip and dst_ip not in fp.common_destinations:
            fp.common_destinations.append(dst_ip)
            if len(fp.common_destinations) > 20:
                fp.common_destinations = fp.common_destinations[-20:]

        # Save periodically
        if n % 10 == 0:
            self._save()

    # ══════════════════════════════════════════════
    # On-demand verification
    # ══════════════════════════════════════════════

    def verify_identity(self, ip: str, mac: str) -> dict:
        """Verifies a host's identity et retourne un detailed report."""
        mac = mac.lower() if mac else ""
        with self._lock:
            fp = self._fingerprints.get(mac)

        if not fp:
            return {
                "verified": False,
                "reason": "Unknown MAC — no fingerprint yet",
                "score": 0,
                "fingerprint": None,
            }

        # Retrieve current host data
        try:
            host = Host.get_or_none(Host.ip == ip)
            current_ports = [p.port for p in Port.select().where(
                Port.host_ip == ip, Port.state == "open")]
            current_banners = {
                str(p.port): hashlib.md5((p.banner or "").encode()).hexdigest()[:8]
                for p in Port.select().where(Port.host_ip == ip, Port.state == "open")
                if p.banner
            }
        except Exception:
            host = None
            current_ports = []
            current_banners = {}

        score, details = self._compare(
            fp, mac,
            hostname=host.hostname if host else "",
            os_hint=host.os_hint if host else "",
            ttl=0, tcp_window=0,
            open_ports=current_ports,
            banners=current_banners,
            vendor_oui=mac[:8],
            packet_size=0, dst_ip="",
        )

        return {
            "verified": score >= self.spoof_threshold,
            "score": score,
            "details": details,
            "fingerprint": fp.to_dict(),
            "ip_history": self._mac_ip_history.get(mac, []),
        }

    def get_fingerprint(self, mac: str) -> Optional[dict]:
        mac = mac.lower()
        with self._lock:
            fp = self._fingerprints.get(mac)
        return fp.to_dict() if fp else None

    # ══════════════════════════════════════════════
    # Persistence
    # ══════════════════════════════════════════════

    def _save(self):
        try:
            data = {}
            with self._lock:
                for mac, fp in self._fingerprints.items():
                    data[mac] = fp.to_dict()
            os.makedirs(os.path.dirname(self._fp_file), exist_ok=True)
            with open(self._fp_file, "w") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.warning("Sauvegarde fingerprints : %s", e)

    def _load(self):
        if not os.path.exists(self._fp_file):
            return
        try:
            with open(self._fp_file) as f:
                data = json.load(f)
            for mac, d in data.items():
                fp = HostFingerprint(
                    mac=d.get("mac", mac),
                    hostname=d.get("hostname", ""),
                    os_ttl=d.get("os_ttl", 0),
                    os_hint=d.get("os_hint", ""),
                    tcp_window=d.get("tcp_window", 0),
                    open_ports=d.get("open_ports", []),
                    banners=d.get("banners", {}),
                    vendor_oui=d.get("vendor_oui", ""),
                    dhcp_hostname=d.get("dhcp_hostname", ""),
                    avg_packet_size=d.get("avg_packet_size", 0),
                    active_hours=d.get("active_hours", []),
                    common_destinations=d.get("common_destinations", []),
                    first_seen=d.get("first_seen", ""),
                    last_seen=d.get("last_seen", ""),
                    samples=d.get("samples", 0),
                )
                self._fingerprints[mac.lower()] = fp
            logger.info("Fingerprints loaded : %d hosts", len(self._fingerprints))
        except Exception as e:
            logger.warning("Chargement fingerprints : %s", e)

    def save_all(self):
        """Forced save (called on shutdown)."""
        self._save()

    # ══════════════════════════════════════════════
    # Stats
    # ══════════════════════════════════════════════

    @property
    def stats(self) -> dict:
        with self._lock:
            total = len(self._fingerprints)
            mature = sum(1 for fp in self._fingerprints.values() if fp.samples >= 10)
        return {
            "total_fingerprints": total,
            "mature": mature,
            "learning": total - mature,
            "spoof_threshold": self.spoof_threshold,
        }
