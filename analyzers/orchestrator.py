"""
CGS — Detector orchestrator.

Fan-out dispatcher + temporal correlation + health monitoring.
Wraps the existing ThreatEngine with the new plugin detectors.
The existing engine is untouched — new detectors only add.
"""

import logging
import threading
import time
from collections import defaultdict

from analyzers.scoring import Scorer
from analyzers.detectors import ALL_DETECTORS

log = logging.getLogger("cgs.orchestrator")


class DetectorOrchestrator:
    """Central dispatcher for all advanced detectors."""

    def __init__(self, config, alert_fn, threat_engine,
                 false_positives=None, threat_intel=None):
        self.cfg = config
        self._alert = alert_fn
        self.engine = threat_engine
        self.scorer = Scorer(config, false_positives, threat_intel)

        # Load detectors (each failing import is isolated)
        self.detectors = []
        for cls in ALL_DETECTORS:
            try:
                d = cls(config)
                self.detectors.append(d)
            except Exception as e:
                log.error("Failed to load %s: %s", cls.name, e)

        # Signal buffer for temporal correlation: {ip: [(ts, signal)]}
        self._buf = defaultdict(list)
        self._buf_lock = threading.Lock()

        # Reference to attack graph for signal feeding
        self._graph = next((d for d in self.detectors if d.name == "attack_graph"), None)

        # Background threads
        threading.Thread(target=self._eval_loop, daemon=True, name="orch-eval").start()
        threading.Thread(target=self._gc_loop, daemon=True, name="orch-gc").start()

        active = sum(1 for d in self.detectors if d.status == "active")
        observe = sum(1 for d in self.detectors if d.status == "observing")
        log.info("Orchestrator: %d detectors (%d active, %d observing)",
                len(self.detectors), active, observe)

    def on_event(self, evt: dict):
        """Sniffer callback. Fans out to ThreatEngine + all advanced detectors."""
        # 1. Existing engine (backward compatible)
        try:
            self.engine.on_event(evt)
        except Exception as e:
            log.debug("ThreatEngine: %s", e)

        # 2. Fan out to new detectors
        signals = []
        for d in self.detectors:
            sigs = d.on_event(evt)  # isolated try/except inside
            if sigs:
                signals.extend(sigs)

        if not signals:
            return

        # 3. Buffer for temporal correlation
        now = time.time()
        with self._buf_lock:
            for sig in signals:
                ip = sig.src_ip or "unknown"
                self._buf[ip].append((now, sig))
                # Feed attack graph
                if self._graph and sig.detector != "attack_graph":
                    try:
                        self._graph.feed_signal(sig)
                    except Exception as e:
                        log.debug("Failed to feed signal to attack graph: %s", e)

        # 4. High-confidence signals bypass buffer
        for sig in signals:
            if sig.confidence >= 0.9 and sig.severity <= 2:
                self._evaluate(sig.src_ip or "unknown")

    def _eval_loop(self):
        """Periodic evaluation of buffered signals."""
        while True:
            time.sleep(30)
            try:
                with self._buf_lock:
                    for ip in list(self._buf.keys()):
                        self._evaluate(ip)
            except Exception as e:
                log.debug("Eval loop: %s", e)

    def _evaluate(self, ip: str):
        """Score buffered signals for an IP and decide on alerting."""
        entries = self._buf.get(ip, [])
        if not entries:
            return

        now = time.time()
        recent = [(t, s) for t, s in entries if now - t < 300]
        if not recent:
            return

        # Mandatory temporal correlation (#2):
        # 1 detector = INFO max, 2 = HIGH, 3+ = CRITICAL
        detectors = set(s.detector for _, s in recent)
        if len(detectors) >= 3:
            max_sev = 1
        elif len(detectors) >= 2:
            max_sev = 2
        else:
            max_sev = 5

        seen = set()
        for _, sig in recent:
            if sig.observed:
                continue
            key = (sig.detector, sig.category, sig.src_ip, sig.dst_ip)
            if key in seen:
                continue

            final_sev, score, should = self.scorer.score(sig, max_sev)
            if should:
                seen.add(key)
                self._alert(
                    severity=final_sev,
                    source=f"advanced:{sig.detector}",
                    category=sig.category,
                    title=sig.title,
                    detail=f"{sig.detail} [conf={score:.2f}, sources={len(detectors)}]",
                    src_ip=sig.src_ip,
                    dst_ip=sig.dst_ip,
                    ioc=sig.ioc,
                )

        # Clean processed
        self._buf[ip] = [(t, s) for t, s in entries if now - t < 300]

    def _gc_loop(self):
        """Cleanup stale buffer entries."""
        while True:
            time.sleep(60)
            now = time.time()
            with self._buf_lock:
                for ip in list(self._buf.keys()):
                    self._buf[ip] = [(t, s) for t, s in self._buf[ip] if now - t < 600]
                    if not self._buf[ip]:
                        del self._buf[ip]

    def check_health(self):
        """Log detector health (called by daemon scheduler)."""
        for d in self.detectors:
            if d._open:
                log.warning("Detector %s: circuit breaker OPEN", d.name)

    @property
    def stats(self) -> dict:
        return {
            "detectors": [d.stats for d in self.detectors],
            "scorer": self.scorer.stats,
            "buffered_ips": len(self._buf),
        }

    def get_health(self) -> dict:
        return self.stats
