"""
CyberGuard Sentinel — Kill chain & sequence detector.

Detects multi-step attack patterns by correlating events
within time windows. A single port scan is noise; a port scan
followed by an exploit attempt followed by C2 beaconing is a kill chain.

Supported sequences:
  1. Recon → Exploit → C2        (classic intrusion)
  2. Recon → Brute force → Lateral movement
  3. Phishing → Download → Execution → Exfiltration
  4. ARP spoof → MITM → Data theft

Each stage has a time window. If all stages complete within
their windows, an incident is created automatically.
"""

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger("cyberguard.killchain")


@dataclass
class ChainStage:
    """One stage in a kill chain."""
    name: str
    categories: list[str]       # Alert categories that match this stage
    max_window: int = 300       # Max seconds since previous stage


@dataclass
class ChainDefinition:
    """A complete kill chain pattern."""
    name: str
    severity: int               # Incident severity if chain completes
    stages: list[ChainStage]
    description: str = ""


@dataclass
class ActiveChain:
    """A chain in progress for a specific IP."""
    definition: ChainDefinition
    source_ip: str
    current_stage: int = 0
    stage_times: list[float] = field(default_factory=list)
    stage_details: list[str] = field(default_factory=list)
    started_at: float = 0

    def __post_init__(self):
        if not self.started_at:
            self.started_at = time.time()


# ── Predefined kill chains ──

KILL_CHAINS = [
    ChainDefinition(
        name="Classic Intrusion",
        severity=1,
        description="Reconnaissance followed by exploitation and C2 establishment",
        stages=[
            ChainStage("Reconnaissance", ["port_scan", "sweep", "discovery", "nmap"], 600),
            ChainStage("Exploitation", ["exploit", "vulnerability", "overflow", "injection"], 300),
            ChainStage("Command & Control", ["c2", "beaconing", "callback", "reverse_shell"], 600),
        ],
    ),
    ChainDefinition(
        name="Brute Force Intrusion",
        severity=1,
        description="Scan followed by brute force and lateral movement",
        stages=[
            ChainStage("Reconnaissance", ["port_scan", "sweep", "discovery"], 600),
            ChainStage("Brute Force", ["brute_force", "login_failure", "auth_fail"], 900),
            ChainStage("Lateral Movement", ["lateral", "smb", "psexec", "wmi", "rdp"], 600),
        ],
    ),
    ChainDefinition(
        name="Data Exfiltration",
        severity=1,
        description="Initial access followed by data collection and exfiltration",
        stages=[
            ChainStage("Initial Access", ["exploit", "phishing", "download", "dropper"], 600),
            ChainStage("Collection", ["high_dns_entropy", "dns_tunnel", "large_upload"], 1200),
            ChainStage("Exfiltration", ["exfiltration", "data_theft", "upload_spike"], 1800),
        ],
    ),
    ChainDefinition(
        name="ARP MITM Attack",
        severity=2,
        description="ARP spoofing leading to man-in-the-middle",
        stages=[
            ChainStage("ARP Spoofing", ["arp_spoof", "arp_anomaly", "mac_changed"], 120),
            ChainStage("Traffic Interception", ["mitm", "ssl_strip", "dns_hijack"], 300),
        ],
    ),
    ChainDefinition(
        name="Ransomware Kill Chain",
        severity=1,
        description="Initial compromise followed by lateral movement and encryption",
        stages=[
            ChainStage("Initial Compromise", ["exploit", "phishing", "trojan", "dropper"], 600),
            ChainStage("Privilege Escalation", ["privesc", "mimikatz", "credential_dump"], 600),
            ChainStage("Lateral Movement", ["lateral", "smb", "psexec", "wmi"], 1200),
        ],
    ),
]


class KillChainDetector:
    """Detects multi-step attack sequences from alert streams."""

    def __init__(self, config, alert_callback: Callable = None,
                 incident_callback: Callable = None):
        self.cfg = config
        self._alert = alert_callback or (lambda **kw: None)
        self._create_incident = incident_callback
        self.chains = KILL_CHAINS

        # Active chains: source_ip → list of ActiveChain
        self._active: dict[str, list[ActiveChain]] = defaultdict(list)
        self._lock = threading.Lock()
        self._stats = {"chains_started": 0, "chains_completed": 0, "chains_expired": 0}

        # Cleanup thread
        threading.Thread(target=self._cleanup_loop, daemon=True,
                        name="killchain-gc").start()

        logger.info("Kill chain detector loaded: %d patterns", len(self.chains))

    def on_alert(self, src_ip: str, category: str, detail: str = "",
                 dst_ip: str = "", severity: int = 5):
        """
        Feed an alert into the kill chain detector.
        Called by the threat engine and correlator for each alert.
        """
        category_lower = category.lower()

        with self._lock:
            # Check existing active chains for this IP
            self._advance_chains(src_ip, category_lower, detail)

            # Start new chains if this alert matches a first stage
            for chain_def in self.chains:
                first_stage = chain_def.stages[0]
                if any(cat in category_lower for cat in first_stage.categories):
                    # Don't start duplicate chains
                    already = any(
                        c.definition.name == chain_def.name
                        for c in self._active.get(src_ip, [])
                        if c.current_stage == 0
                    )
                    if not already:
                        ac = ActiveChain(
                            definition=chain_def,
                            source_ip=src_ip,
                            current_stage=1,  # First stage completed
                            stage_times=[time.time()],
                            stage_details=[detail[:200]],
                        )
                        self._active[src_ip].append(ac)
                        self._stats["chains_started"] += 1
                        logger.debug("Kill chain started: %s for %s (stage 1/%d: %s)",
                                    chain_def.name, src_ip, len(chain_def.stages),
                                    first_stage.name)

    def _advance_chains(self, src_ip: str, category: str, detail: str):
        """Try to advance existing chains for this IP."""
        for chain in self._active.get(src_ip, []):
            defn = chain.definition
            if chain.current_stage >= len(defn.stages):
                continue

            next_stage = defn.stages[chain.current_stage]

            # Check if this alert matches the next stage
            if any(cat in category for cat in next_stage.categories):
                # Check time window
                elapsed = time.time() - chain.stage_times[-1]
                if elapsed <= next_stage.max_window:
                    chain.current_stage += 1
                    chain.stage_times.append(time.time())
                    chain.stage_details.append(detail[:200])

                    logger.info("Kill chain advanced: %s for %s (stage %d/%d: %s)",
                               defn.name, src_ip, chain.current_stage,
                               len(defn.stages), next_stage.name)

                    # Chain complete?
                    if chain.current_stage >= len(defn.stages):
                        self._chain_completed(chain)

    def _chain_completed(self, chain: ActiveChain):
        """A kill chain has fully completed — trigger incident."""
        self._stats["chains_completed"] += 1
        defn = chain.definition
        duration = int(chain.stage_times[-1] - chain.stage_times[0])

        stages_summary = " → ".join(
            f"{defn.stages[i].name} ({chain.stage_details[i][:50]})"
            for i in range(len(defn.stages))
        )

        logger.warning("⚠️ KILL CHAIN COMPLETE: %s from %s (%ds): %s",
                       defn.name, chain.source_ip, duration, stages_summary)

        self._alert(
            severity=defn.severity,
            source="killchain",
            category="kill_chain_complete",
            title=f"Kill chain detected: {defn.name}",
            detail=f"Source: {chain.source_ip} | Duration: {duration}s | {stages_summary}",
            src_ip=chain.source_ip,
        )

        # Create incident if callback available
        if self._create_incident:
            try:
                self._create_incident(
                    target_ip="",
                    attacker_ip=chain.source_ip,
                    severity=defn.severity,
                    threat_type=f"Kill chain: {defn.name}",
                    threat_detail=f"{defn.description}. Stages: {stages_summary}. Duration: {duration}s.",
                    iocs=[chain.source_ip],
                )
            except Exception as e:
                logger.error("Failed to create incident for kill chain: %s", e)

    def _cleanup_loop(self):
        """Remove expired chains."""
        while True:
            time.sleep(30)
            now = time.time()
            with self._lock:
                for ip in list(self._active.keys()):
                    active = []
                    for chain in self._active[ip]:
                        defn = chain.definition
                        if chain.current_stage >= len(defn.stages):
                            continue  # Already completed
                        # Check if next stage window expired
                        next_stage = defn.stages[chain.current_stage]
                        if now - chain.stage_times[-1] > next_stage.max_window * 2:
                            self._stats["chains_expired"] += 1
                        else:
                            active.append(chain)
                    self._active[ip] = active
                    if not self._active[ip]:
                        del self._active[ip]

    @property
    def stats(self) -> dict:
        with self._lock:
            active_count = sum(len(v) for v in self._active.values())
        return {**self._stats, "active_chains": active_count,
                "patterns_loaded": len(self.chains)}
