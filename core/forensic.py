"""
CyberGuard Sentinel — Forensic evidence collection.

Generates a structured JSON file contenant ALL information
related to an incident pour future forensic analysis :

  - Complete timeline
  - Raw Suricata alerts
  - Attacker reconnaissance results
  - Target host state (ports, services, risque)
  - Associated network flows (depuis la BDD)
  - Querys DNS suspectes
  - Defense actions executeds
  - Complete audit trail
  - Sentinel metadata

Chaque fichier est timestamped and named par l'ID de l'incident.
"""

import json
import logging
import os
import platform
from datetime import datetime, timedelta
from typing import Optional

from core.database import Alert, Host, Port, Flow, DnsLog, db

logger = logging.getLogger("cyberguard.forensic")


class ForensicCollector:
    """Collecte et sauvegarde les preuves forensiques d'un incident."""

    def __init__(self, config):
        self.cfg = config
        self.output_dir = os.path.join(
            config.get("general.log_dir", "/var/log/cyberguard"),
            "forensics"
        )
        os.makedirs(self.output_dir, exist_ok=True)

    def collect_and_save(
        self,
        incident_id: str,
        incident_data: dict,
        attacker_ip: str,
        target_ip: str,
        recon_report: dict = None,
        defense_actions: list = None,
        suricata_raw_events: list = None,
        created_at: float = 0,
        identity_engine=None,
        mac_resolver=None,
    ) -> str:
        """
        Collecte toutes les preuves et les sauvegarde dans un fichier JSON.
        Returns the file path.
        """
        logger.info("📁 Forensic collection for %s…", incident_id)
        t0 = datetime.now()

        # Multi-factor identity fingerprints
        target_fingerprint = {}
        attacker_fingerprint = {}
        if identity_engine:
            try:
                target_mac = ""
                attacker_mac = ""
                if mac_resolver:
                    target_mac = mac_resolver.ip_to_mac(target_ip)
                    attacker_mac = mac_resolver.ip_to_mac(attacker_ip)
                if not target_mac:
                    try:
                        h = Host.get_or_none(Host.ip == target_ip)
                        if h: target_mac = h.mac or ""
                    except Exception:
                        pass
                if target_mac:
                    target_fingerprint = identity_engine.verify_identity(target_ip, target_mac)
                if attacker_mac:
                    attacker_fingerprint = identity_engine.verify_identity(attacker_ip, attacker_mac)
            except Exception as e:
                logger.debug("Fingerprint forensique : %s", e)

        evidence = {
            "_metadata": {
                "version": "2.0",
                "tool": "CyberGuard Sentinel",
                "generated_at": t0.isoformat(),
                "incident_id": incident_id,
                "hostname": platform.node(),
                "platform": platform.platform(),
                "python": platform.python_version(),
                "classification": "CONFIDENTIAL — FORENSIC EVIDENCE",
                "note": (
                    "Ce fichier contient des digital evidence related to a security "
                    "incident. It must be stored securely and can "
                    "be used in the context of an investigation or prosecution."
                ),
            },

            "incident": incident_data,

            "timeline": self._build_timeline(incident_data, created_at),

            "attacker": {
                "ip": attacker_ip,
                "reconnaissance": recon_report or {},
                "identity_fingerprint": attacker_fingerprint,
                "related_alerts": self._get_alerts_for_ip(attacker_ip, created_at),
                "related_flows": self._get_flows_for_ip(attacker_ip, created_at),
                "dns_queries": self._get_dns_for_ip(attacker_ip, created_at),
            },

            "target": {
                "ip": target_ip,
                "host_info": self._get_host_info(target_ip),
                "identity_fingerprint": target_fingerprint,
                "related_alerts": self._get_alerts_for_ip(target_ip, created_at),
                "related_flows": self._get_flows_for_ip(target_ip, created_at),
                "dns_queries": self._get_dns_for_ip(target_ip, created_at),
            },

            "suricata_events": suricata_raw_events or [],

            "defense": {
                "actions_proposed": incident_data.get("proposed_actions", []),
                "actions_executed": defense_actions or incident_data.get("actions_executed", []),
            },

            "network_context": {
                "all_alerts_24h": self._get_recent_alerts(created_at),
                "suspicious_dns_24h": self._get_suspicious_dns(created_at),
                "top_talkers_24h": self._get_top_talkers(created_at),
                "active_hosts": self._get_active_hosts(),
            },
        }

        # ── Sauvegarder ──
        filename = f"forensic_{incident_id}_{t0.strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(evidence, f, ensure_ascii=False, indent=2, default=str)

        size_kb = os.path.getsize(filepath) / 1024
        logger.warning("📁 Forensic evidence saved : %s (%.1f Ko)", filepath, size_kb)

        return filepath

    # ──────────────────────────────────────────────
    # Timeline
    # ──────────────────────────────────────────────
    @staticmethod
    def _build_timeline(incident_data: dict, created_at: float) -> list[dict]:
        """Construit la chronologie de l'incident."""
        events = []

        def _add(ts_key: str, label: str):
            ts = incident_data.get(ts_key)
            if ts:
                events.append({"timestamp": ts, "event": label})

        _add("created", "Incident detected")

        if incident_data.get("admin_alert_sent"):
            events.append({"timestamp": incident_data.get("created", ""), "event": "Email admin sent"})

        if incident_data.get("approved_at"):
            events.append({
                "timestamp": incident_data["approved_at"],
                "event": f"Approved by {incident_data.get('approved_by', '?')}"
            })

        if incident_data.get("user_alert_sent"):
            events.append({
                "timestamp": incident_data.get("approved_at", ""),
                "event": "User email sent (shutdown request)"
            })

        if incident_data.get("shutdown_detected_at"):
            events.append({
                "timestamp": incident_data["shutdown_detected_at"],
                "event": f"Host {incident_data.get('target_ip', '')} shutdown confirmed"
            })

        for action in incident_data.get("actions_executed", []):
            events.append({"timestamp": "", "event": f"Action : {action}"})

        if incident_data.get("resolved"):
            events.append({"timestamp": "", "event": f"Resolvedtion : {incident_data.get('resolution', '')}"})

        if incident_data.get("report_sent"):
            events.append({"timestamp": "", "event": "Rapport email sent"})

        return sorted(events, key=lambda e: e.get("timestamp", ""))

    # ──────────────────────────────────────────────
    # Querys BDD
    # ──────────────────────────────────────────────
    @staticmethod
    def _get_alerts_for_ip(ip: str, since_ts: float, limit: int = 200) -> list[dict]:
        since = datetime.fromtimestamp(since_ts) - timedelta(hours=24) if since_ts else datetime.now() - timedelta(hours=24)
        try:
            return [
                {
                    "ts": a.ts.isoformat(), "severity": a.severity,
                    "source": a.source, "category": a.category,
                    "title": a.title, "detail": a.detail,
                    "src_ip": a.src_ip, "dst_ip": a.dst_ip, "ioc": a.ioc,
                }
                for a in Alert.select()
                    .where(
                        (Alert.ts >= since) &
                        ((Alert.src_ip == ip) | (Alert.dst_ip == ip))
                    )
                    .order_by(Alert.ts.desc())
                    .limit(limit)
            ]
        except Exception:
            return []

    @staticmethod
    def _get_flows_for_ip(ip: str, since_ts: float, limit: int = 500) -> list[dict]:
        since = datetime.fromtimestamp(since_ts) - timedelta(hours=24) if since_ts else datetime.now() - timedelta(hours=24)
        try:
            return [
                {
                    "ts": f.ts.isoformat(), "src": f.src_ip, "src_port": f.src_port,
                    "dst": f.dst_ip, "dst_port": f.dst_port, "proto": f.proto,
                    "packets": f.packets, "bytes": f.bytes_total, "flags": f.flags,
                }
                for f in Flow.select()
                    .where(
                        (Flow.ts >= since) &
                        ((Flow.src_ip == ip) | (Flow.dst_ip == ip))
                    )
                    .order_by(Flow.ts.desc())
                    .limit(limit)
            ]
        except Exception:
            return []

    @staticmethod
    def _get_dns_for_ip(ip: str, since_ts: float, limit: int = 200) -> list[dict]:
        since = datetime.fromtimestamp(since_ts) - timedelta(hours=24) if since_ts else datetime.now() - timedelta(hours=24)
        try:
            return [
                {
                    "ts": d.ts.isoformat(), "src": d.src_ip,
                    "query": d.query, "qtype": d.qtype,
                    "entropy": d.entropy, "suspicious": d.suspicious,
                }
                for d in DnsLog.select()
                    .where((DnsLog.ts >= since) & (DnsLog.src_ip == ip))
                    .order_by(DnsLog.ts.desc())
                    .limit(limit)
            ]
        except Exception:
            return []

    @staticmethod
    def _get_host_info(ip: str) -> dict:
        try:
            h = Host.get_or_none(Host.ip == ip)
            if h:
                ports = list(Port.select().where(Port.host_ip == ip))
                return {
                    "ip": h.ip, "mac": h.mac, "hostname": h.hostname,
                    "vendor": h.vendor, "os": h.os_hint,
                    "risk_score": h.risk_score, "status": h.status,
                    "first_seen": h.first_seen.isoformat() if h.first_seen else None,
                    "last_seen": h.last_seen.isoformat() if h.last_seen else None,
                    "ports": [
                        {"port": p.port, "proto": p.proto, "state": p.state,
                         "service": p.service, "banner": p.banner}
                        for p in ports
                    ],
                }
        except Exception:
            pass
        return {}

    @staticmethod
    def _get_recent_alerts(since_ts: float, limit: int = 100) -> list[dict]:
        since = datetime.fromtimestamp(since_ts) - timedelta(hours=24) if since_ts else datetime.now() - timedelta(hours=24)
        try:
            return [
                {"ts": a.ts.isoformat(), "sev": a.severity, "src": a.source,
                 "title": a.title, "src_ip": a.src_ip, "dst_ip": a.dst_ip}
                for a in Alert.select().where(Alert.ts >= since)
                    .order_by(Alert.ts.desc()).limit(limit)
            ]
        except Exception:
            return []

    @staticmethod
    def _get_suspicious_dns(since_ts: float) -> list[dict]:
        since = datetime.fromtimestamp(since_ts) - timedelta(hours=24) if since_ts else datetime.now() - timedelta(hours=24)
        try:
            return [
                {"ts": d.ts.isoformat(), "src": d.src_ip, "query": d.query, "entropy": d.entropy}
                for d in DnsLog.select()
                    .where((DnsLog.ts >= since) & (DnsLog.suspicious == True))
                    .order_by(DnsLog.ts.desc()).limit(100)
            ]
        except Exception:
            return []

    @staticmethod
    def _get_top_talkers(since_ts: float) -> list[dict]:
        since = datetime.fromtimestamp(since_ts) - timedelta(hours=24) if since_ts else datetime.now() - timedelta(hours=24)
        try:
            from peewee import fn
            rows = (Flow.select(Flow.src_ip, fn.SUM(Flow.bytes_total).alias("total"),
                                fn.COUNT(Flow.id).alias("flows"))
                    .where(Flow.ts >= since)
                    .group_by(Flow.src_ip)
                    .order_by(fn.SUM(Flow.bytes_total).desc())
                    .limit(20))
            return [{"ip": r.src_ip, "bytes": r.total, "flows": r.flows} for r in rows]
        except Exception:
            return []

    @staticmethod
    def _get_active_hosts() -> list[dict]:
        try:
            return [
                {"ip": h.ip, "mac": h.mac, "hostname": h.hostname,
                 "os": h.os_hint, "risk": h.risk_score}
                for h in Host.select().where(Host.status == "up")
                    .order_by(Host.risk_score.desc())
            ]
        except Exception:
            return []
