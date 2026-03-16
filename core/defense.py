"""
CGS — Active defense engine.

Available actions :
  1. BLOCK_IP    : Blocks a source IP via iptables/nftables
  2. RATE_LIMIT  : Rate-limits an IP
  3. QUARANTINE  : Isolates an internal host (DROP all outgoing traffic except admin)
  4. RST_KILL    : Sends a RST to kill an ongoing TCP connection
  5. DNS_SINKHOLE: Redirects a malicious domain to 127.0.0.1
  6. ALERT_ONLY  : Alert only (observation mode)

Each action is reversible and has a time to live (TTL).
The engine maintains an audit log of all actions taken.
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
from core.security import InputValidator

scapy_conf.verb = 0

logger = logging.getLogger("cgs.defense")

# ── Constants ──
CHAIN_NAME = "CGS"
IPSET_BLOCKLIST = "cgs_block"
IPSET_RATELIMIT = "cgs_ratelimit"


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
    auto: bool = True            # True = automatic, False = manual

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

        # Local firewall
        self._fw_backend = self._detect_firewall()

        # Netgate firewall (pfSense / OPNsense) — optional
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
                logger.warning("Netgate not available: %s", e)
                self.netgate = None

        # Escalation ladder state: {ip: {"level": 0-4, "since": ts, "last_escalation": ts}}
        self._escalation: dict[str, dict] = {}
        self._escalation_lock = threading.Lock()

        # Post-action verification queue: [(ts, ip, action_type, expected)]
        self._verify_queue: list = []
        self._verify_lock = threading.Lock()

        # Cleanup + verification
        threading.Thread(target=self._cleanup_loop, daemon=True, name="defense-gc").start()
        threading.Thread(target=self._verify_loop, daemon=True, name="defense-verify").start()

        if self.enabled:
            self._init_firewall()

        # DHCP callback: if a blocked IP changes, re-block the new one
        if self.mac_resolver:
            self.mac_resolver.on_ip_change(self._on_ip_change)

    # ══════════════════════════════════════════════
    # DHCP callback: IP change → re-block
    # ══════════════════════════════════════════════
    def _on_ip_change(self, mac: str, old_ip: str, new_ip: str):
        """When a host changes IP (DHCP), re-apply rules."""
        with self._lock:
            # Look for active actions on the old IP
            for key, action in list(self._actions.items()):
                if not action.active or action.target_ip != old_ip:
                    continue

                logger.warning("🔄 DHCP: blocked IP %s → %s (MAC=%s) — re-applying rules",
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
            logger.debug("Failed to detect nftables: command not found")
        try:
            r = subprocess.run(["iptables", "-L", "-n"], capture_output=True, timeout=5)
            if r.returncode == 0:
                return "iptables"
        except FileNotFoundError:
            logger.debug("Failed to detect iptables: command not found")
        return "none"

    def _init_firewall(self):
        """Creates CGS chain in firewall."""
        if self._fw_backend == "iptables":
            self._run(f"iptables -N {CHAIN_NAME} 2>/dev/null || true")
            # Insert chain into INPUT and FORWARD if not already done
            self._run(f"iptables -C INPUT -j {CHAIN_NAME} 2>/dev/null || "
                      f"iptables -I INPUT 1 -j {CHAIN_NAME}")
            self._run(f"iptables -C FORWARD -j {CHAIN_NAME} 2>/dev/null || "
                      f"iptables -I FORWARD 1 -j {CHAIN_NAME}")
            logger.info("Firewall iptables: chain %s initialized.", CHAIN_NAME)

        elif self._fw_backend == "nftables":
            self._run(f"nft add table inet cgs 2>/dev/null || true")
            self._run(f"nft add chain inet cgs blocklist "
                      f"{{ type filter hook input priority -10 \\; policy accept \\; }} 2>/dev/null || true")
            logger.info("Firewall nftables: cgs table initialized.")
        else:
            logger.warning("No firewall detected (iptables/nftables). "
                           "Block actions will be simulated.")

    # ══════════════════════════════════════════════
    # Escalation levels
    # ══════════════════════════════════════════════
    # 0: MONITOR  — enhanced logging only
    # 1: THROTTLE — progressive rate-limit
    # 2: ISOLATE  — quarantine with limited access
    # 3: BLOCK    — full DROP
    # 4: NETWORK_ALERT — block + notify all agents

    ESCALATION_NAMES = ["MONITOR", "THROTTLE", "ISOLATE", "BLOCK", "NETWORK_ALERT"]

    # Context-based response: maps (category) → ideal starting escalation level
    CATEGORY_RESPONSE = {
        # Low confidence — start at monitoring
        "portscan": 0, "hostscan": 0, "ping_sweep": 0,
        "suspicious_port": 0, "destination_anomaly": 0,
        "temporal_anomaly": 0,
        # Medium confidence — start at throttle
        "dns_tunnel": 1, "exfiltration": 1, "slow_exfiltration": 1,
        "http_exploit_attempt": 1, "suspicious_user_agent": 1,
        "dga_detected": 1, "doh_bypass": 1,
        # High confidence — start at isolate or block
        "bruteforce": 2, "beaconing": 2, "lateral_movement": 2,
        "pivot_detected": 2, "ioc_ip_match": 2, "ioc_domain_match": 2,
        # Critical — immediate block
        "arp_spoof": 3, "tor_domain": 3, "multi_stage": 3,
        "intrusion": 3, "trojan": 3,
        # Kill chain complete — block + network-wide alert
        "kill_chain": 4,
    }

    # Time before auto-escalation at each level (seconds)
    ESCALATION_TIMERS = [120, 120, 180, 300, 0]  # 0 = no further escalation

    # ══════════════════════════════════════════════
    # Entry point: evaluate a threat
    # ══════════════════════════════════════════════
    def evaluate_threat(self, src_ip: str, dst_ip: str, severity: int,
                        category: str, signature: str, sid: int = 0,
                        action_taken: str = "", **kwargs):
        """
        Graduated threat response with escalation ladder.
        Called by correlator for each Suricata + internal alert.
        """
        if not self.enabled:
            return

        target_ip = src_ip

        # Never act on whitelisted IPs
        if self._is_whitelisted(target_ip):
            return

        # Count alerts for this IP
        now = time.time()
        self._alert_counter[target_ip].append(now)
        cutoff = now - self.alert_count_window
        self._alert_counter[target_ip] = [
            t for t in self._alert_counter[target_ip] if t > cutoff
        ]
        alert_count = len(self._alert_counter[target_ip])

        if not self.auto_block:
            return

        # ── Determine response level ──
        # Start from context-based level for this category
        context_level = self.CATEGORY_RESPONSE.get(category, 1)

        # Escalate based on severity
        if severity <= 1:
            context_level = max(context_level, 3)
        elif severity <= 2:
            context_level = max(context_level, 2)

        # Escalate based on alert accumulation
        if alert_count >= self.alert_count_threshold * 2:
            context_level = max(context_level, 3)
        elif alert_count >= self.alert_count_threshold:
            context_level = max(context_level, 2)

        # Get or create escalation state for this IP
        with self._escalation_lock:
            if target_ip not in self._escalation:
                self._escalation[target_ip] = {
                    "level": 0, "since": now, "last_escalation": now,
                    "category": category, "reason": signature,
                }
            state = self._escalation[target_ip]

            # Only escalate, never de-escalate from a new alert
            new_level = max(state["level"], context_level)

            # Auto-escalate if timer expired at current level
            timer = self.ESCALATION_TIMERS[state["level"]] if state["level"] < len(self.ESCALATION_TIMERS) else 0
            if timer > 0 and now - state["last_escalation"] > timer and alert_count > 1:
                new_level = max(new_level, state["level"] + 1)

            new_level = min(new_level, 4)

            if new_level > state["level"]:
                state["level"] = new_level
                state["last_escalation"] = now
                state["reason"] = signature

        # ── Execute action for current level ──
        reason = f"[SID:{sid}] {signature} (level={self.ESCALATION_NAMES[new_level]}, alerts={alert_count})"
        self._execute_level(target_ip, dst_ip, new_level, reason, category)

    def _execute_level(self, target_ip: str, dst_ip: str, level: int,
                       reason: str, category: str):
        """Execute the defense action for a given escalation level."""
        if level == 0:
            # MONITOR: just log and increase sampling
            logger.info("MONITOR: %s — %s", target_ip, reason)
            self._audit("MONITOR", target_ip, reason, True)

        elif level == 1:
            # THROTTLE: progressive rate-limit
            self.rate_limit_ip(target_ip, reason=reason, auto=True)

        elif level == 2:
            # ISOLATE: quarantine with limited access
            # For internal hosts → quarantine. For external → block.
            is_internal = any(
                target_ip.startswith(s.rsplit(".", 1)[0])
                for s in self.internal_nets
            )
            if is_internal:
                self.quarantine_host(target_ip, reason=reason, auto=True)
            else:
                self.block_ip(target_ip, reason=reason, ttl=self.block_ttl, auto=True)

            # Context: if beaconing/C2, also sinkhole the domain
            if category in ("beaconing", "dga_detected", "dns_tunnel"):
                # Extract domain from reason if possible
                pass  # Domain sinkhole handled by correlator

        elif level == 3:
            # BLOCK: full DROP
            self.block_ip(target_ip, reason=reason, ttl=self.block_ttl, auto=True)

        elif level == 4:
            # NETWORK_ALERT: block + notify all agents
            self.block_ip(target_ip, reason=reason, ttl=self.block_ttl * 2, auto=True)
            self._alert(
                severity=1, source="defense", category="network_alert",
                title=f"NETWORK ALERT: {target_ip} — full escalation",
                detail=reason, src_ip=target_ip, dst_ip=dst_ip,
            )

        # Queue post-action verification
        if level >= 1:
            with self._verify_lock:
                self._verify_queue.append({
                    "ts": time.time(),
                    "ip": target_ip,
                    "level": level,
                    "action": self.ESCALATION_NAMES[level],
                })

    # ══════════════════════════════════════════════
    # Auto-de-escalation (when attack stops)
    # ══════════════════════════════════════════════
    def _check_deescalation(self):
        """If no new alerts for an IP, gradually de-escalate."""
        now = time.time()
        with self._escalation_lock:
            for ip in list(self._escalation.keys()):
                state = self._escalation[ip]
                level = state["level"]
                since = state["last_escalation"]

                # De-escalate after 2x the escalation timer of silence
                timer = self.ESCALATION_TIMERS[level] if level < len(self.ESCALATION_TIMERS) else 300
                silence_required = max(timer * 2, 300)

                # Check if there are recent alerts for this IP
                recent = [t for t in self._alert_counter.get(ip, []) if now - t < silence_required]
                if recent:
                    continue  # Still active, no de-escalation

                if now - since < silence_required:
                    continue  # Not enough silence yet

                if level > 0:
                    new_level = level - 1
                    state["level"] = new_level
                    state["last_escalation"] = now
                    logger.info("DE-ESCALATE: %s %s → %s",
                               ip, self.ESCALATION_NAMES[level],
                               self.ESCALATION_NAMES[new_level])
                    self._audit("DE-ESCALATE", ip,
                               f"{self.ESCALATION_NAMES[level]} → {self.ESCALATION_NAMES[new_level]}",
                               True)

                    # If de-escalated to MONITOR, unblock
                    if new_level == 0:
                        key_block = f"BLOCK:{ip}"
                        key_rate = f"RATE:{ip}"
                        key_quar = f"QUARANTINE:{ip}"
                        with self._lock:
                            if key_block in self._actions and self._actions[key_block].active:
                                self.unblock_ip(ip, "Auto de-escalation: no more alerts")
                            if key_rate in self._actions and self._actions[key_rate].active:
                                self._fw_unblock(ip)
                                self._actions[key_rate].active = False
                                self._audit("UNRATE_LIMIT", ip, "Auto de-escalation", True)
                            if key_quar in self._actions and self._actions[key_quar].active:
                                self._fw_unblock(ip)
                                self._actions[key_quar].active = False
                                self._audit("UNQUARANTINE", ip, "Auto de-escalation", True)

                elif level == 0:
                    # Fully de-escalated, remove tracking
                    del self._escalation[ip]

    # ══════════════════════════════════════════════
    # Post-action verification (Layer C)
    # ══════════════════════════════════════════════
    def _verify_loop(self):
        """Verify that defense actions actually took effect."""
        while True:
            time.sleep(30)
            now = time.time()
            with self._verify_lock:
                # Process items that are 30+ seconds old
                ready = [v for v in self._verify_queue if now - v["ts"] > 30]
                self._verify_queue = [v for v in self._verify_queue if now - v["ts"] <= 30]

            for item in ready:
                try:
                    self._verify_action(item)
                except Exception as e:
                    logger.debug("Verification error: %s", e)

    def _verify_action(self, item: dict):
        """Verify a single defense action took effect."""
        ip = item["ip"]
        level = item["level"]

        if level >= 3:
            # BLOCK: verify iptables rule exists
            if self._fw_backend == "iptables":
                try:
                    r = subprocess.run(
                        ["iptables", "-C", CHAIN_NAME, "-s", ip, "-j", "DROP"],
                        capture_output=True, timeout=5)
                    if r.returncode != 0:
                        logger.warning("VERIFY FAILED: block rule for %s missing! Re-applying.", ip)
                        self._fw_block(ip)
                        self._alert(
                            severity=2, source="defense", category="verify_failed",
                            title=f"Block rule re-applied for {ip}",
                            detail="Post-action verification found missing rule",
                            src_ip=ip, notify=False,
                        )
                except Exception as e:
                    logger.warning("Failed to verify block rule for %s: %s", ip, e)

            # Verify traffic actually stopped (check recent flows)
            try:
                from core.database import Flow
                from datetime import datetime, timedelta
                recent_flows = Flow.select().where(
                    Flow.src_ip == ip,
                    Flow.ts >= datetime.now() - timedelta(seconds=60),
                ).count()
                if recent_flows > 10:
                    logger.warning("VERIFY: %s still sending traffic (%d flows) despite block!",
                                  ip, recent_flows)
                    # Re-apply + escalate
                    self._fw_block(ip)
                    with self._escalation_lock:
                        if ip in self._escalation:
                            self._escalation[ip]["level"] = min(
                                self._escalation[ip]["level"] + 1, 4)
            except Exception as e:
                logger.warning("Failed to verify traffic stop for %s: %s", ip, e)

        elif level == 2:
            # ISOLATE/QUARANTINE: verify host is isolated
            try:
                from core.database import Flow
                from datetime import datetime, timedelta
                # Quarantined host should only talk to admin IP
                non_admin_flows = Flow.select().where(
                    Flow.src_ip == ip,
                    Flow.dst_ip != self.my_ip,
                    Flow.ts >= datetime.now() - timedelta(seconds=60),
                ).count()
                if non_admin_flows > 5:
                    logger.warning("VERIFY: quarantined %s still communicating (%d flows)!",
                                  ip, non_admin_flows)
                    # Re-apply quarantine
                    self._fw_quarantine(ip)
            except Exception as e:
                logger.warning("Failed to verify quarantine for %s: %s", ip, e)

    # ══════════════════════════════════════════════
    # Defense actions
    # ══════════════════════════════════════════════
    def block_ip(self, ip: str, reason: str = "", ttl: int = None,
                 auto: bool = True) -> bool:
        """Blocks an IP at the firewall level."""
        if self._is_whitelisted(ip):
            logger.warning("Attempted block of a whitelisted IP/MAC: %s", ip)
            return False

        key = f"BLOCK:{ip}"
        with self._lock:
            if key in self._actions and self._actions[key].active:
                # Extend the TTL
                self._actions[key].expires_at = time.time() + (ttl or self.block_ttl)
                return True

        ttl = ttl or self.block_ttl
        success = self._fw_block(ip)

        # Also block on the Netgate if configured
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
                title=f"IP blocked: {ip} ({'+'.join(where)})",
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
        """Applies a rate-limit on an IP."""
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
        """Isolates an internal host (blocks everything except admin SSH)."""
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
                detail=f"Reason: {reason}\nAll outgoing traffic blocked except admin.",
                src_ip=ip,
            )
            self._update_host_risk(ip, 80)
            logger.warning("🔒 QUARANTAINE : %s — %s", ip, reason)
        return success

    def rst_kill(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        """Sends a TCP RST via scapy to kill a suspicious connection."""
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
        """Adds a domain to the hosts file (sinkhole)."""
        try:
            hosts_line = f"127.0.0.1 {domain}  # CGS sinkhole"
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
    @staticmethod
    def _validate_ip(ip: str) -> bool:
        """Validate IP before using in firewall commands."""
        return InputValidator.ip(ip)

    def _fw_block(self, ip: str) -> bool:
        if not self._validate_ip(ip):
            logger.error("Invalid IP rejected for block: %s", ip)
            return False
        if self._fw_backend == "iptables":
            r = self._run_cmd(["iptables", "-A", CHAIN_NAME, "-s", ip, "-j", "DROP"])
            self._run_cmd(["iptables", "-A", CHAIN_NAME, "-d", ip, "-j", "DROP"])
            return r
        elif self._fw_backend == "nftables":
            return self._run_cmd(["nft", "add", "rule", "inet", "cgs", "blocklist",
                                  "ip", "saddr", ip, "drop"])
        logger.warning("No firewall — simulated block for %s", ip)
        return True

    def _fw_unblock(self, ip: str) -> bool:
        if not self._validate_ip(ip):
            logger.error("Invalid IP rejected for unblock: %s", ip)
            return False
        if self._fw_backend == "iptables":
            self._run_cmd(["iptables", "-D", CHAIN_NAME, "-s", ip, "-j", "DROP"])
            self._run_cmd(["iptables", "-D", CHAIN_NAME, "-d", ip, "-j", "DROP"])
            return True
        elif self._fw_backend == "nftables":
            # Find and delete rules matching this IP
            try:
                r = subprocess.run(["nft", "-a", "list", "chain", "inet", "cgs", "blocklist"],
                                   capture_output=True, text=True, timeout=10)
                if r.returncode == 0:
                    import re
                    for line in r.stdout.splitlines():
                        if ip in line:
                            m = re.search(r'handle (\d+)', line)
                            if m:
                                self._run_cmd(["nft", "delete", "rule", "inet", "cgs",
                                               "blocklist", "handle", m.group(1)])
            except Exception as e:
                logger.error("nft unblock failed: %s", e)
            return True
        return True

    def _fw_rate_limit(self, ip: str) -> bool:
        if not self._validate_ip(ip):
            logger.error("Invalid IP rejected for rate-limit: %s", ip)
            return False
        if self._fw_backend == "iptables":
            r1 = self._run_cmd(["iptables", "-A", CHAIN_NAME, "-s", ip, "-m", "limit",
                                "--limit", "10/minute", "--limit-burst", "20", "-j", "ACCEPT"])
            r2 = self._run_cmd(["iptables", "-A", CHAIN_NAME, "-s", ip, "-j", "DROP"])
            return r1 and r2
        return True  # Fallback

    def _fw_quarantine(self, ip: str) -> bool:
        """Blocks all traffic from a host except SSH to the admin server."""
        if not self._validate_ip(ip):
            logger.error("Invalid IP rejected for quarantine: %s", ip)
            return False
        if self._fw_backend == "iptables":
            # Allow SSH to the Sentinel server
            self._run_cmd(["iptables", "-A", CHAIN_NAME, "-s", ip, "-d", self.my_ip,
                           "-p", "tcp", "--dport", "22", "-j", "ACCEPT"])
            # Block everything else
            self._run_cmd(["iptables", "-A", CHAIN_NAME, "-s", ip, "-j", "DROP"])
            self._run_cmd(["iptables", "-A", CHAIN_NAME, "-d", ip, "-j", "DROP"])
            return True
        return True

    @staticmethod
    def _run_cmd(args: list) -> bool:
        """Run a command safely without shell=True. Retries once on failure."""
        for attempt in range(2):
            try:
                r = subprocess.run(args, capture_output=True, timeout=10)
                if r.returncode == 0:
                    return True
                if attempt == 0:
                    logger.debug("Command retry: %s (rc=%d)", args[:3], r.returncode)
                    time.sleep(0.5)
            except subprocess.TimeoutExpired:
                logger.warning("Command timeout: %s", args[:3])
                return False
            except Exception as e:
                logger.error("Command failed: %s — %s", args[:3], e)
                return False
        return False

    @staticmethod
    def _run(cmd: str) -> bool:
        """Run a shell command (only for init with safe constants)."""
        try:
            r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, timeout=10)
            return r.returncode == 0
        except Exception as e:
            logger.error("Command failed: %s — %s", cmd, e)
            return False

    # ══════════════════════════════════════════════
    # Cleanup: automatic unblock after TTL
    # ══════════════════════════════════════════════
    def _cleanup_loop(self):
        while True:
            time.sleep(30)
            now = time.time()

            # Check auto-de-escalation
            try:
                self._check_deescalation()
            except Exception as e:
                logger.debug("De-escalation check error: %s", e)

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
                        title=f"End of quarantine: {action.target_ip}",
                        src_ip=action.target_ip, notify=False,
                    )
                with self._lock:
                    self._actions[key].active = False

            # Purge old counters
            cutoff = now - self.alert_count_window * 2
            for ip in list(self._alert_counter):
                self._alert_counter[ip] = [t for t in self._alert_counter[ip] if t > cutoff]
                if not self._alert_counter[ip]:
                    del self._alert_counter[ip]

    # ══════════════════════════════════════════════
    # Utilities
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
        # Persist to file
        try:
            log_dir = self.cfg.get("general.log_dir", "/var/log/cgs")
            with open(os.path.join(log_dir, "defense_audit.jsonl"), "a") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.warning("Failed to persist defense audit entry: %s", e)

    @staticmethod
    def _update_host_risk(ip: str, delta: int):
        try:
            h = Host.get_or_none(Host.ip == ip)
            if h:
                h.risk_score = min(100, h.risk_score + delta)
                h.save()
        except Exception as e:
            logger.warning("Failed to update host risk score for %s: %s", ip, e)

    # ══════════════════════════════════════════════
    # API (for the dashboard)
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
        with self._escalation_lock:
            esc_by_level = defaultdict(int)
            for state in self._escalation.values():
                esc_by_level[self.ESCALATION_NAMES[state["level"]]] += 1
        return {
            "enabled": self.enabled,
            "auto_block": self.auto_block,
            "fw_backend": self._fw_backend,
            "total_actions": len(self._audit_log),
            "active_blocks": sum(1 for a in active if a.action_type == "BLOCK_IP"),
            "active_rate_limits": sum(1 for a in active if a.action_type == "RATE_LIMIT"),
            "active_quarantines": sum(1 for a in active if a.action_type == "QUARANTINE"),
            "tracked_ips": len(self._alert_counter),
            "escalation": dict(esc_by_level),
            "pending_verifications": len(self._verify_queue),
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
