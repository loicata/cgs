"""
CyberGuard Sentinel — Correlation engine.

Fusionne les alertes Suricata + l'analyse interne pour prendre
intelligent defense decisions.

Logique :
  - Critical Suricata alert → immediate block
  - Suricata alert + internal scan detected → block
  - Alerte Suricata + anomalie DNS → blocage + sinkhole
  - Accumulation d'alertes d'une IP → escalade progressive
  - Compromised internal host (beaconing + exfil) → quarantine
"""

import logging
import time
import threading
from collections import defaultdict
from datetime import datetime

from core.suricata_ingest import SuricataEvent
from core.database import Alert, Host, db

logger = logging.getLogger("cyberguard.correlator")


class Correlator:
    """Correlates multi-source events and triggers responses."""

    def __init__(self, config, alert_fn, defense_engine, threat_engine, incident_engine=None):
        self.cfg = config
        self._alert = alert_fn
        self.defense = defense_engine
        self.engine = threat_engine
        self.incident = incident_engine

        # Correlation counters
        self._ip_events: dict[str, dict] = defaultdict(
            lambda: {
                "suricata_alerts": 0,
                "suricata_critical": 0,
                "internal_alerts": 0,
                "categories": set(),
                "sids": set(),
                "first_seen": None,
                "last_seen": None,
            }
        )
        self._lock = threading.Lock()

        # Stats
        self._stats = {
            "events_processed": 0,
            "correlations_found": 0,
            "defenses_triggered": 0,
        }

    # ══════════════════════════════════════════════
    # Suricata input
    # ══════════════════════════════════════════════
    def on_suricata_event(self, evt: SuricataEvent):
        """Processes a Suricata event."""
        self._stats["events_processed"] += 1

        # Stocker les non-alertes pour enrichissement
        if evt.event_type == "dns" and evt.dns_query:
            self.engine.on_event({
                "type": "dns_query",
                "src": evt.src_ip,
                "query": evt.dns_query,
                "entropy": 0,  # will be calculated by the engine
                "ts": time.time(),
            })

        if evt.event_type == "http" and evt.http_hostname:
            # Record HTTP activity for context
            pass

        if not evt.is_alert:
            return

        # ── Traitement des alertes ──
        src = evt.src_ip
        sev = evt.sentinel_severity

        # Create alert in DB
        self._alert(
            severity=sev,
            source="suricata",
            category=evt.alert_category,
            title=f"[SID:{evt.alert_sid}] {evt.alert_signature}",
            detail=(
                f"Action: {evt.alert_action} | Proto: {evt.proto} | "
                f"App: {evt.app_proto}\n"
                f"{evt.src_ip}:{evt.src_port} → {evt.dst_ip}:{evt.dst_port}"
                f"{f' | HTTP: {evt.http_hostname}{evt.http_url[:100]}' if evt.http_hostname else ''}"
                f"{f' | TLS SNI: {evt.tls_sni}' if evt.tls_sni else ''}"
                f"{f' | DNS: {evt.dns_query}' if evt.dns_query else ''}"
            ),
            src_ip=evt.src_ip,
            dst_ip=evt.dst_ip,
            ioc=evt.http_hostname or evt.tls_sni or evt.dns_query or None,
        )

        # Accumulate data for correlation
        with self._lock:
            ip_data = self._ip_events[src]
            ip_data["suricata_alerts"] += 1
            if sev <= 1:
                ip_data["suricata_critical"] += 1
            ip_data["categories"].add(evt.alert_category)
            ip_data["sids"].add(evt.alert_sid)
            if ip_data["first_seen"] is None:
                ip_data["first_seen"] = time.time()
            ip_data["last_seen"] = time.time()

        # ── Defense decisions ──
        self._evaluate_response(evt, src, sev)

    # ══════════════════════════════════════════════
    # Decision logic
    # ══════════════════════════════════════════════
    def _evaluate_response(self, evt: SuricataEvent, src_ip: str, severity: int):
        """Decides the appropriate response."""
        ip_data = self._ip_events[src_ip]

        # ── Rule 1: Critical Suricata alert → immediate block + incident ──
        if severity <= 1 and evt.alert_action != "blocked":
            self._stats["defenses_triggered"] += 1
            # Create full incident with email
            if self.incident:
                self.incident.create_incident(
                    target_ip=evt.dst_ip,
                    attacker_ip=src_ip,
                    severity=severity,
                    threat_type=evt.alert_category or "Alerte critique",
                    threat_detail=f"[SID:{evt.alert_sid}] {evt.alert_signature}",
                    suricata_sids=[evt.alert_sid],
                    iocs=[x for x in (evt.http_hostname, evt.tls_sni, evt.dns_query) if x],
                )
            else:
                self.defense.evaluate_threat(
                    src_ip=src_ip, dst_ip=evt.dst_ip,
                    severity=severity, category=evt.alert_category,
                    signature=evt.alert_signature, sid=evt.alert_sid,
                    action_taken=evt.alert_action,
                )
            return

        # ── Rule 2: Multi-alert correlation ──
        if ip_data["suricata_alerts"] >= 3:
            # Check if IP is also seen by internal engine
            internal_risk = 0
            try:
                host = Host.get_or_none(Host.ip == src_ip)
                if host:
                    internal_risk = host.risk_score
            except Exception:
                pass

            # Suricata + high internal risk → incident + block
            if internal_risk >= 30:
                self._stats["correlations_found"] += 1
                if self.incident:
                    self.incident.create_incident(
                        target_ip=src_ip if internal_risk >= 50 else "",
                        attacker_ip=src_ip,
                        severity=1,
                        threat_type="Multi-source correlation",
                        threat_detail=(
                            f"Suricata: {ip_data['suricata_alerts']} alertes, "
                            f"Risk interne: {internal_risk}/100, "
                            f"Categorys: {', '.join(ip_data['categories'])}"
                        ),
                    )
                else:
                    self._alert(
                        severity=1, source="correlator", category="correlation",
                        title=f"Correlation: {src_ip} menace multi-source",
                        detail=(
                            f"Suricata: {ip_data['suricata_alerts']} alertes, "
                            f"Risk interne: {internal_risk}/100"
                        ),
                        src_ip=src_ip,
                    )
                    self.defense.block_ip(src_ip, reason="Multi-source correlation", auto=True)
                return

        # ── Rule 3: Trojan + suspicious DNS → block + sinkhole ──
        if "Trojan" in evt.alert_category or "trojan" in evt.alert_signature.lower():
            if evt.http_hostname:
                self.defense.dns_sinkhole(
                    evt.http_hostname,
                    reason=f"Suspected C2 : {evt.alert_signature}",
                )
            if evt.tls_sni:
                self.defense.dns_sinkhole(
                    evt.tls_sni,
                    reason=f"C2 TLS : {evt.alert_signature}",
                )
            self.defense.evaluate_threat(
                src_ip=src_ip, dst_ip=evt.dst_ip,
                severity=severity,
                category=evt.alert_category,
                signature=evt.alert_signature,
                sid=evt.alert_sid,
            )
            return

        # ── Rule 4: Exploitation → quarantine internal host ──
        if any(kw in evt.alert_category for kw in
               ("Privilege Gain", "Executable Code", "Exploit")):
            # If destination is an internal host → it may be compromised
            from core.netutils import ip_in_subnet
            for subnet in self.cfg.get("network.subnets", []):
                if ip_in_subnet(evt.dst_ip, subnet):
                    self.defense.quarantine_host(
                        evt.dst_ip,
                        reason=f"Exploitation detected : {evt.alert_signature}",
                        auto=True,
                    )
                    break
            self.defense.evaluate_threat(
                src_ip=src_ip, dst_ip=evt.dst_ip,
                severity=severity,
                category=evt.alert_category,
                signature=evt.alert_signature,
                sid=evt.alert_sid,
            )
            return

        # ── Rule 5: Otherwise → standard evaluation ──
        self.defense.evaluate_threat(
            src_ip=src_ip, dst_ip=evt.dst_ip,
            severity=severity,
            category=evt.alert_category,
            signature=evt.alert_signature,
            sid=evt.alert_sid,
            action_taken=evt.alert_action,
        )

    # ══════════════════════════════════════════════
    # Stats
    # ══════════════════════════════════════════════
    @property
    def stats(self) -> dict:
        return {
            **self._stats,
            "tracked_ips": len(self._ip_events),
            "top_offenders": sorted(
                [{"ip": ip, "alerts": d["suricata_alerts"], "cats": len(d["categories"])}
                 for ip, d in self._ip_events.items()],
                key=lambda x: x["alerts"], reverse=True
            )[:10],
        }
