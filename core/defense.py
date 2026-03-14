"""
CyberGuard Sentinel — Active defense engine.

Available actions :
  1. BLOCK_IP    : Blocks a source IP via iptables/nftables
  2. RATE_LIMIT  : Rate-limits an IP
  3. QUARANTINE  : Isolates an internal host (DROP tout trafic sortant sauf admin)
  4. RST_KILL    : Sends a RST to kill a connection TCP in progress
  5. DNS_SINKHOLE: Redirects a malicious domain vers 127.0.0.1
  6. ALERT_ONLY  : Alert only (observation mode)

Each action is reversible et a une time to live (TTL).
Le moteur tient un audit log de toutes les actions prises.
"""

import json
import logging
import os
import socket
import struct
import subprocess
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from core.database import db, Alert, Host
from scapy.all import IP as ScapyIP, TCP as ScapyTCP, send as scapy_send, conf as scapy_conf
from core.netutils import get_iface_ip

scapy_conf.verb = 0

logger = logging.getLogger("cyberguard.defense")

# ── Constants ──
CHAIN_NAME = "CYBERGUARD"
IPSET_BLOCKLIST = "cyberguard_block"
IPSET_RATELIMIT = "cyberguard_ratelimit"


@dataclass
class DefenseAction:
    """Defense action taken by Sentinel."""
    action_type: str             # BLOCK_IP, RATE_LIMIT, QUARANTINE, RST_KILL, DNS_SINKHOLE
    target_ip: str
    reason: str
    source_alert: str = ""       # signature or title of triggering alert
    severity: int = 2
    ttl_seconds: int = 3600      # default time to live: 1h
    created_at: float = 0
    expires_at: float = 0
    active: bool = True
    auto: bool = True            # True = automatique, False = manual

    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.time()
        if not self.expires_at:
            self.expires_at = self.created_at + self.ttl_seconds


class DefenseEngine:
    """Active defense engine — executes and manages countermeasures."""

    def __init__(self, config, alert_fn, mac_resolver=None):
        self.cfg = config
        self._alert = alert_fn
        self.mac_resolver = mac_resolver

        # Configuration
        self.enabled = config.get("defense.enabled", True)
        self.auto_block = config.get("defense.auto_block", True)
        self.block_ttl = config.get("defense.block_ttl_seconds", 3600)
        self.rate_limit_ttl = config.get("defense.rate_limit_ttl_seconds", 1800)
        self.quarantine_ttl = config.get("defense.quarantine_ttl_seconds", 7200)
        self.whitelist = set(config.get("defense.whitelist_ips", []))
        self.whitelist_macs = set(m.lower() for m in config.get("defense.whitelist_macs", []))
        self.internal_nets = config.get("network.subnets", ["192.168.1.0/24"])
        self.my_ip = get_iface_ip(
            config.get("network.interface", "auto")
            if config.get("network.interface", "auto") != "auto"
            else "eth0"
        )
        self.whitelist.add(self.my_ip)
        for ip in config.get("network.exclude_ips", []):
            self.whitelist.add(ip)

        self.auto_block_severity = config.get("defense.auto_block_severity", 1)
        self.alert_count_threshold = config.get("defense.alert_count_threshold", 5)
        self.alert_count_window = config.get("defense.alert_count_window", 300)

        # Status
        self._actions: dict[str, DefenseAction] = {}
        self._lock = threading.Lock()
        self._alert_counter: dict[str, list] = defaultdict(list)
        self._audit_log: list[dict] = []

        # Firewall local
        self._fw_backend = self._detect_firewall()

        # Firewall Netgate (pfSense / OPNsense) — optionnel
        self.netgate = None
        if config.get("netgate.enabled", False):
            try:
                from core.netgate import NetgateFirewall
                self.netgate = NetgateFirewall(config)
                if self.netgate.enabled:
                    logger.info("🔥 Netgate %s connected (%s)", self.netgate.fw_type, self.netgate.host)
                else:
                    self.netgate = None
            except Exception as e:
                logger.warning("Netgate non disponible : %s", e)
                self.netgate = None

        # Nettoyage
        threading.Thread(target=self._cleanup_loop, daemon=True, name="defense-gc").start()

        if self.enabled:
            self._init_firewall()

        # Callback DHCP : si une IP blockede change, re-bloquer la nouvelle
        if self.mac_resolver:
            self.mac_resolver.on_ip_change(self._on_ip_change)

    # ══════════════════════════════════════════════
    # Callback DHCP : IP change → re-bloquer
    # ══════════════════════════════════════════════
    def _on_ip_change(self, mac: str, old_ip: str, new_ip: str):
        """When a host changes IP (DHCP), re-apply rules."""
        with self._lock:
            # Chercher des actions actives sur l'ancienne IP
            for key, action in list(self._actions.items()):
                if not action.active or action.target_ip != old_ip:
                    continue

                logger.warning("🔄 DHCP : IP blockede %s → %s (MAC=%s) — re-applying rules",
                              old_ip, new_ip, mac)

                # Unblock old IP
                self._fw_unblock(old_ip)
                if self.netgate:
                    self.netgate.unblock_ip(old_ip)

                # Block new IP
                self._fw_block(new_ip)
                if self.netgate:
                    self.netgate.block_ip(new_ip, reason=f"DHCP re-block (was {old_ip})")

                # Update action
                action.target_ip = new_ip
                new_key = key.replace(old_ip, new_ip)
                del self._actions[key]
                self._actions[new_key] = action

                self._audit("DHCP_REBLOCK", new_ip,
                           f"IP changed {old_ip} → {new_ip} (MAC={mac})", True)
                self._alert(
                    severity=4, source="defense", category="dhcp_reblock",
                    title=f"Rule re-applied : {old_ip} → {new_ip}",
                    detail=f"MAC={mac}. Action={action.action_type}.",
                    src_ip=new_ip, notify=False,
                )

    def _is_whitelisted(self, ip: str) -> bool:
        """Checks whitelist by IP AND MAC."""
        if ip in self.whitelist:
            return True
        if self.mac_resolver and self.whitelist_macs:
            return self.mac_resolver.is_whitelisted(ip, self.whitelist, self.whitelist_macs)
        return False

    # ══════════════════════════════════════════════
    # Firewall backend detection
    # ══════════════════════════════════════════════
    @staticmethod
    def _detect_firewall() -> str:
        """Detects if using nftables or iptables."""
        try:
            r = subprocess.run(["nft", "list", "tables"], capture_output=True, timeout=5)
            if r.returncode == 0:
                return "nftables"
        except FileNotFoundError:
            pass
        try:
            r = subprocess.run(["iptables", "-L", "-n"], capture_output=True, timeout=5)
            if r.returncode == 0:
                return "iptables"
        except FileNotFoundError:
            pass
        return "none"

    def _init_firewall(self):
        """Creates CyberGuard chain in firewall."""
        if self._fw_backend == "iptables":
            self._run(f"iptables -N {CHAIN_NAME} 2>/dev/null || true")
            # Insert chain into INPUT and FORWARD if not already done
            self._run(f"iptables -C INPUT -j {CHAIN_NAME} 2>/dev/null || "
                      f"iptables -I INPUT 1 -j {CHAIN_NAME}")
            self._run(f"iptables -C FORWARD -j {CHAIN_NAME} 2>/dev/null || "
                      f"iptables -I FORWARD 1 -j {CHAIN_NAME}")
            logger.info("Firewall iptables : chain %s initialized.", CHAIN_NAME)

        elif self._fw_backend == "nftables":
            self._run(f"nft add table inet cyberguard 2>/dev/null || true")
            self._run(f"nft add chain inet cyberguard blocklist "
                      f"{{ type filter hook input priority -10 \\; policy accept \\; }} 2>/dev/null || true")
            logger.info("Firewall nftables : cyberguard table initialized.")
        else:
            logger.warning("None firewall detected (iptables/nftables). "
                           "Block actions will be simulated.")

    # ══════════════════════════════════════════════
    # Entry point: evaluate a threat
    # ══════════════════════════════════════════════
    def evaluate_threat(self, src_ip: str, dst_ip: str, severity: int,
                        category: str, signature: str, sid: int = 0,
                        action_taken: str = "", **kwargs):
        """
        Evaluates a threat and decides the response.
        Called by correlator for each Suricata + internal alert.
        """
        if not self.enabled:
            return

        target_ip = src_ip  # By default we act on the source

        # Ne jamais bloquer la whitelist
        if target_ip in self.whitelist:
            logger.debug("IP %s en whitelist, skippede.", target_ip)
            return

        # Compter les alertes pour cette IP
        now = time.time()
        self._alert_counter[target_ip].append(now)
        cutoff = now - self.alert_count_window
        self._alert_counter[target_ip] = [
            t for t in self._alert_counter[target_ip] if t > cutoff
        ]
        alert_count = len(self._alert_counter[target_ip])

        # ── Decision ──
        if not self.auto_block:
            return

        # Maximum criticality → immediate block
        if severity <= self.auto_block_severity:
            self.block_ip(target_ip,
                          reason=f"[SID:{sid}] {signature}",
                          ttl=self.block_ttl,
                          auto=True)
            return

        # Accumulation d'alertes → blocage
        if alert_count >= self.alert_count_threshold:
            self.block_ip(target_ip,
                          reason=f"{alert_count} alertes en {self.alert_count_window}s "
                                 f"(last: {signature})",
                          ttl=self.block_ttl,
                          auto=True)
            return

        # High severity + dangerous category → rate-limit
        if severity <= 2 and category in HIGH_CATEGORIES_DEFENSE:
            self.rate_limit_ip(target_ip,
                               reason=f"[SID:{sid}] {signature}",
                               auto=True)

    # ══════════════════════════════════════════════
    # Defense actions
    # ══════════════════════════════════════════════
    def block_ip(self, ip: str, reason: str = "", ttl: int = None,
                 auto: bool = True) -> bool:
        """Blocks an IP at the firewall level."""
        if self._is_whitelisted(ip):
            logger.warning("Attempted block of an IP/MAC whitelisted : %s", ip)
            return False

        key = f"BLOCK:{ip}"
        with self._lock:
            if key in self._actions and self._actions[key].active:
                # Prolonger le TTL
                self._actions[key].expires_at = time.time() + (ttl or self.block_ttl)
                return True

        ttl = ttl or self.block_ttl
        success = self._fw_block(ip)

        # Aussi bloquer sur le Netgate si configured
        netgate_ok = False
        if self.netgate:
            netgate_ok = self.netgate.block_ip(ip, reason=reason)

        if success or netgate_ok:
            where = []
            if success: where.append("local")
            if netgate_ok: where.append(f"Netgate({self.netgate.fw_type})")

            action = DefenseAction(
                action_type="BLOCK_IP", target_ip=ip,
                reason=reason, ttl_seconds=ttl, auto=auto,
            )
            with self._lock:
                self._actions[key] = action

            self._audit("BLOCK_IP", ip, f"{reason} [{'+'.join(where)}]", auto)
            self._alert(
                severity=1, source="defense", category="block",
                title=f"IP blockede : {ip} ({'+'.join(where)})",
                detail=f"Reason: {reason}\nDuration: {ttl}s\nFirewalls: {', '.join(where)}",
                src_ip=ip,
            )
            self._update_host_risk(ip, 50)
            logger.warning("🛡️  IP BLOCKED : %s [%s] (TTL=%ds) — %s", ip, '+'.join(where), ttl, reason)
            return True
        return False

    def unblock_ip(self, ip: str, reason: str = "Expiration or manual unblock") -> bool:
        """Unblocks an IP (local + Netgate)."""
        key = f"BLOCK:{ip}"
        success = self._fw_unblock(ip)
        if self.netgate:
            self.netgate.unblock_ip(ip)
        with self._lock:
            if key in self._actions:
                self._actions[key].active = False
        self._audit("UNBLOCK_IP", ip, reason, False)
        logger.info("🔓 IP unblocked : %s — %s", ip, reason)
        return success

    def rate_limit_ip(self, ip: str, reason: str = "", ttl: int = None,
                      auto: bool = True) -> bool:
        """Applies a rate-limit sur une IP."""
        if ip in self.whitelist:
            return False

        key = f"RATE:{ip}"
        with self._lock:
            if key in self._actions and self._actions[key].active:
                return True

        ttl = ttl or self.rate_limit_ttl
        success = self._fw_rate_limit(ip)
        if success:
            action = DefenseAction(
                action_type="RATE_LIMIT", target_ip=ip,
                reason=reason, ttl_seconds=ttl, auto=auto,
            )
            with self._lock:
                self._actions[key] = action
            self._audit("RATE_LIMIT", ip, reason, auto)
            self._alert(
                severity=2, source="defense", category="rate_limit",
                title=f"Rate-limit applied : {ip}",
                detail=f"Reason: {reason}\nDuration: {ttl}s",
                src_ip=ip,
            )
            logger.warning("⚡ Rate-limit : %s (TTL=%ds) — %s", ip, ttl, reason)
        return success

    def quarantine_host(self, ip: str, reason: str = "", ttl: int = None,
                        auto: bool = True) -> bool:
        """Isolates an internal host (bloque tout sauf SSH admin)."""
        if ip in self.whitelist:
            return False

        key = f"QUARANTINE:{ip}"
        ttl = ttl or self.quarantine_ttl
        success = self._fw_quarantine(ip)
        if success:
            action = DefenseAction(
                action_type="QUARANTINE", target_ip=ip,
                reason=reason, ttl_seconds=ttl, auto=auto,
            )
            with self._lock:
                self._actions[key] = action
            self._audit("QUARANTINE", ip, reason, auto)
            self._alert(
                severity=1, source="defense", category="quarantine",
                title=f"Host quarantined : {ip}",
                detail=f"Reason: {reason}\nTout trafic sortant blocked sauf admin.",
                src_ip=ip,
            )
            self._update_host_risk(ip, 80)
            logger.warning("🔒 QUARANTAINE : %s — %s", ip, reason)
        return success

    def rst_kill(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        """Sends a TCP RST via scapy pour kill a suspicious connection."""
        try:
            pkt = ScapyIP(dst=src_ip) / ScapyTCP(
                sport=dst_port, dport=src_port, flags="RA", seq=0)
            scapy_send(pkt)
            self._audit("RST_KILL", src_ip,
                        f"{src_ip}:{src_port} → {dst_ip}:{dst_port}", True)
            logger.info("💀 RST sent : %s:%d → %s:%d",
                        src_ip, src_port, dst_ip, dst_port)
        except Exception as e:
            logger.error("RST kill failed : %s", e)

    def dns_sinkhole(self, domain: str, reason: str = ""):
        """Ajoute un domaine au fichier hosts (sinkhole)."""
        try:
            hosts_line = f"127.0.0.1 {domain}  # CyberGuard sinkhole"
            with open("/etc/hosts", "r") as f:
                if domain in f.read():
                    return  # Already sinholed
            with open("/etc/hosts", "a") as f:
                f.write(f"\n{hosts_line}\n")
            self._audit("DNS_SINKHOLE", domain, reason, True)
            self._alert(
                severity=2, source="defense", category="sinkhole",
                title=f"Domain sinholed : {domain}",
                detail=reason, ioc=domain,
            )
            logger.warning("🕳️  DNS sinkhole : %s", domain)
        except PermissionError:
            logger.error("Cannot write to /etc/hosts")

    # ══════════════════════════════════════════════
    # Backend firewall
    # ══════════════════════════════════════════════
    def _fw_block(self, ip: str) -> bool:
        if self._fw_backend == "iptables":
            r = self._run(f"iptables -A {CHAIN_NAME} -s {ip} -j DROP")
            self._run(f"iptables -A {CHAIN_NAME} -d {ip} -j DROP")
            return r
        elif self._fw_backend == "nftables":
            return self._run(f"nft add rule inet cyberguard blocklist ip saddr {ip} drop")
        logger.warning("No firewall — simulated block for %s", ip)
        return True

    def _fw_unblock(self, ip: str) -> bool:
        if self._fw_backend == "iptables":
            self._run(f"iptables -D {CHAIN_NAME} -s {ip} -j DROP 2>/dev/null || true")
            self._run(f"iptables -D {CHAIN_NAME} -d {ip} -j DROP 2>/dev/null || true")
            return True
        elif self._fw_backend == "nftables":
            # nft handle lookup would be cleaner, flush and recreate
            return self._run(
                f"nft -a list chain inet cyberguard blocklist 2>/dev/null | "
                f"grep '{ip}' | grep -oP 'handle \\K\\d+' | "
                f"xargs -I{{}} nft delete rule inet cyberguard blocklist handle {{}}")
        return True

    def _fw_rate_limit(self, ip: str) -> bool:
        if self._fw_backend == "iptables":
            return self._run(
                f"iptables -A {CHAIN_NAME} -s {ip} -m limit "
                f"--limit 10/minute --limit-burst 20 -j ACCEPT && "
                f"iptables -A {CHAIN_NAME} -s {ip} -j DROP")
        return True  # Fallback

    def _fw_quarantine(self, ip: str) -> bool:
        """Bloque tout le trafic d'un host sauf SSH vers le serveur admin."""
        if self._fw_backend == "iptables":
            # Autoriser SSH vers le serveur Sentinel
            self._run(f"iptables -A {CHAIN_NAME} -s {ip} -d {self.my_ip} -p tcp --dport 22 -j ACCEPT")
            # Bloquer tout le reste
            self._run(f"iptables -A {CHAIN_NAME} -s {ip} -j DROP")
            self._run(f"iptables -A {CHAIN_NAME} -d {ip} -j DROP")
            return True
        return True

    @staticmethod
    def _run(cmd: str) -> bool:
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
            return r.returncode == 0
        except Exception as e:
            logger.error("Commande failede: %s — %s", cmd, e)
            return False

    # ══════════════════════════════════════════════
    # Cleanup: automatic unblock after TTL
    # ══════════════════════════════════════════════
    def _cleanup_loop(self):
        while True:
            time.sleep(30)
            now = time.time()
            with self._lock:
                expired = [k for k, a in self._actions.items()
                           if a.active and now >= a.expires_at]
            for key in expired:
                action = self._actions[key]
                if action.action_type == "BLOCK_IP":
                    self.unblock_ip(action.target_ip, "TTL expired")
                elif action.action_type == "RATE_LIMIT":
                    self._fw_unblock(action.target_ip)
                    self._audit("UNRATE_LIMIT", action.target_ip, "TTL expired", True)
                elif action.action_type == "QUARANTINE":
                    self._fw_unblock(action.target_ip)
                    self._audit("UNQUARANTINE", action.target_ip, "TTL expired", True)
                    self._alert(
                        severity=4, source="defense", category="quarantine_end",
                        title=f"Fin de quarantaine : {action.target_ip}",
                        src_ip=action.target_ip, notify=False,
                    )
                with self._lock:
                    self._actions[key].active = False

            # Purger les vieux compteurs
            cutoff = now - self.alert_count_window * 2
            for ip in list(self._alert_counter):
                self._alert_counter[ip] = [t for t in self._alert_counter[ip] if t > cutoff]
                if not self._alert_counter[ip]:
                    del self._alert_counter[ip]

    # ══════════════════════════════════════════════
    # Utilitaires
    # ══════════════════════════════════════════════
    def _audit(self, action: str, target: str, reason: str, auto: bool):
        entry = {
            "ts": datetime.now().isoformat(),
            "action": action,
            "target": target,
            "reason": reason,
            "auto": auto,
        }
        self._audit_log.append(entry)
        # Keep last 1000 entries in memory
        if len(self._audit_log) > 1000:
            self._audit_log = self._audit_log[-1000:]
        # Persister dans un fichier
        try:
            log_dir = self.cfg.get("general.log_dir", "/var/log/cyberguard")
            with open(os.path.join(log_dir, "defense_audit.jsonl"), "a") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass

    @staticmethod
    def _update_host_risk(ip: str, delta: int):
        try:
            h = Host.get_or_none(Host.ip == ip)
            if h:
                h.risk_score = min(100, h.risk_score + delta)
                h.save()
        except Exception:
            pass

    # ══════════════════════════════════════════════
    # API (pour le dashboard)
    # ══════════════════════════════════════════════
    def get_active_actions(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "type": a.action_type,
                    "target": a.target_ip,
                    "reason": a.reason,
                    "severity": a.severity,
                    "auto": a.auto,
                    "created": datetime.fromtimestamp(a.created_at).isoformat(),
                    "expires": datetime.fromtimestamp(a.expires_at).isoformat(),
                    "ttl_remaining": max(0, int(a.expires_at - time.time())),
                    "active": a.active,
                }
                for a in self._actions.values()
                if a.active
            ]

    def get_blocked_ips(self) -> list[str]:
        with self._lock:
            return [a.target_ip for a in self._actions.values()
                    if a.active and a.action_type == "BLOCK_IP"]

    def get_audit_log(self, limit: int = 100) -> list[dict]:
        return list(reversed(self._audit_log[-limit:]))

    def get_stats(self) -> dict:
        with self._lock:
            active = [a for a in self._actions.values() if a.active]
        return {
            "enabled": self.enabled,
            "auto_block": self.auto_block,
            "fw_backend": self._fw_backend,
            "total_actions": len(self._audit_log),
            "active_blocks": sum(1 for a in active if a.action_type == "BLOCK_IP"),
            "active_rate_limits": sum(1 for a in active if a.action_type == "RATE_LIMIT"),
            "active_quarantines": sum(1 for a in active if a.action_type == "QUARANTINE"),
            "tracked_ips": len(self._alert_counter),
        }


# Suricata categories triggering automatic rate-limit
HIGH_CATEGORIES_DEFENSE = {
    "Attempted Administrator Privilege Gain",
    "Attempted User Privilege Gain",
    "Web Application Attack",
    "Executable Code was Detected",
    "A Network Trojan was Detected",
    "Potentially Bad Traffic",
    "Attempted Denial of Service",
    "Misc Attack",
}
