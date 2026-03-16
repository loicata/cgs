"""
CGS — Anti-false-positive scoring pipeline.

All 8 anti-FP mechanisms in a single module:
  1. Multi-factor confidence scoring
  2. Mandatory temporal correlation (enforced by orchestrator)
  3. Source IP reputation tiers (known_internal / new_internal / external)
  4. Cross-validation (cloud/CDN whitelist)
  5. Cloud/CDN CIDR whitelist (AWS, Azure, GCP, Cloudflare, Akamai)
  6. Per-host behavioral baseline (EMA with bounded thresholds)
  7. Exponential cooldown per (src, dst, category)
  8. False positive feedback integration
"""

import ipaddress
import logging
import math
import threading
import time
from collections import defaultdict

log = logging.getLogger("cgs.scoring")

# ── Static cloud CIDRs (fallback, refreshed live in background) ──
_CLOUD_CIDRS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "104.16.0.0/13",
    "172.64.0.0/13", "131.0.72.0/22",  # Cloudflare
    "8.8.8.0/24", "8.8.4.0/24", "34.0.0.0/8", "35.190.0.0/17",  # Google
    "52.0.0.0/8", "54.0.0.0/8", "13.0.0.0/8", "3.0.0.0/8",  # AWS
    "20.0.0.0/8", "40.0.0.0/8",  # Azure
    "23.0.0.0/12", "104.64.0.0/10",  # Akamai
    "151.101.0.0/16", "199.232.0.0/16",  # Fastly
    "140.82.112.0/20", "185.199.108.0/22",  # GitHub
]


class Scorer:
    """Scores detection signals through anti-FP filters."""

    def __init__(self, config, fp_mgr=None, threat_intel=None):
        self.cfg = config
        self.fp_mgr = fp_mgr
        self.ti = threat_intel
        self.threshold = config.get("detectors.confidence_threshold", 0.6)

        # Anti-FP #3: Reputation tiers
        self._subnets = []
        for s in config.get("network.subnets", []):
            try:
                self._subnets.append(ipaddress.IPv4Network(s, strict=False))
            except (ValueError, ipaddress.AddressValueError):
                pass
        self._learning_h = config.get("identity.learning_hours", 48)

        # Anti-FP #5: Cloud whitelist
        self._cloud_nets = []
        for c in _CLOUD_CIDRS + config.get("detectors.cloud_whitelist.custom", []):
            try:
                self._cloud_nets.append(ipaddress.IPv4Network(c, strict=False))
            except (ValueError, ipaddress.AddressValueError):
                pass
        self._cloud_refresh()

        # Anti-FP #6: Baselines {(ip, cat): {mean, var, n, ts}}
        self._bl: dict[tuple, dict] = {}
        self._bl_lock = threading.Lock()
        self._bl_min_n = config.get("detectors.baseline.min_samples", 100)
        self._bl_alpha = 0.01

        # Anti-FP #7: Cooldown {(src,dst,cat): {count, last_ts}}
        self._cd: dict[tuple, dict] = {}
        self._cd_lock = threading.Lock()
        self._cd_base = config.get("detectors.cooldown.base_factor", 0.5)
        self._cd_floor = config.get("detectors.cooldown.min_factor", 0.05)
        self._cd_reset = config.get("detectors.cooldown.reset_after_seconds", 3600)

        self._stats = {"evaluated": 0, "suppressed": 0, "alerted": 0}

        # Background cleanup
        threading.Thread(target=self._gc, daemon=True, name="scorer-gc").start()

    def score(self, sig, max_sev: int) -> tuple[int, float, bool]:
        """Returns (final_severity, score, should_alert)."""
        self._stats["evaluated"] += 1
        s = sig.confidence

        # #3 Reputation
        if sig.src_ip:
            tier = self._tier(sig.src_ip)
            if tier == "known_internal":
                s *= 0.7
            elif tier == "new_internal":
                s *= 0.85

        # #5 Cloud whitelist
        if sig.dst_ip and self._is_cloud(sig.dst_ip):
            s *= 0.3

        # #6 Baseline
        if sig.src_ip:
            dev = self._bl_deviation(sig.src_ip, sig.category)
            if dev is not None and dev < 1.5:
                s *= 0.5

        # #7 Cooldown
        if sig.src_ip:
            s *= self._cd_factor(sig.src_ip, sig.dst_ip or "", sig.category)

        # #8 FP feedback
        if self.fp_mgr and sig.src_ip:
            try:
                s /= max(self.fp_mgr.get_threshold_multiplier(
                    sig.src_ip, sig.category), 1.0)
            except Exception as e:
                log.debug("Failed to get FP threshold multiplier: %s", e)

        # #2 Temporal correlation (max_sev enforced by orchestrator)
        final_sev = max(sig.severity, max_sev)

        should = s >= self.threshold and not sig.observed
        if should:
            self._cd_record(sig.src_ip, sig.dst_ip or "", sig.category)
            self._bl_observe(sig.src_ip, sig.category, 1.0)
            self._stats["alerted"] += 1
        else:
            self._stats["suppressed"] += 1

        return final_sev, s, should

    # ── Reputation tiers ──
    def _tier(self, ip: str) -> str:
        try:
            addr = ipaddress.IPv4Address(ip)
            if not any(addr in net for net in self._subnets):
                return "external"
        except (ValueError, ipaddress.AddressValueError):
            return "external"
        try:
            from core.database import Host
            from datetime import datetime, timedelta
            h = Host.get_or_none(Host.ip == ip)
            if h and h.first_seen and (datetime.now() - h.first_seen).total_seconds() > self._learning_h * 3600:
                return "known_internal"
        except Exception as e:
            log.debug("Failed to determine reputation tier for %s: %s", ip, e)
        return "new_internal"

    # ── Cloud whitelist ──
    def _is_cloud(self, ip: str) -> bool:
        try:
            addr = ipaddress.IPv4Address(ip)
            return any(addr in n for n in self._cloud_nets)
        except (ValueError, ipaddress.AddressValueError):
            return False

    def _cloud_refresh(self):
        def _do():
            time.sleep(120)
            while True:
                try:
                    import requests
                    r = requests.get("https://www.cloudflare.com/ips-v4", timeout=10)
                    if r.status_code == 200:
                        for line in r.text.strip().splitlines():
                            try:
                                net = ipaddress.IPv4Network(line.strip(), strict=False)
                                if net not in self._cloud_nets:
                                    self._cloud_nets.append(net)
                            except ValueError:
                                pass
                except Exception as e:
                    log.debug("Failed to refresh cloud CIDR whitelist: %s", e)
                time.sleep(86400)
        threading.Thread(target=_do, daemon=True, name="cloud-refresh").start()

    # ── Baseline ──
    def _bl_observe(self, ip, cat, val):
        k = (ip, cat)
        with self._bl_lock:
            if k not in self._bl:
                self._bl[k] = {"m": val, "v": 0.0, "n": 1, "ts": time.time()}
                return
            b = self._bl[k]
            b["n"] += 1
            b["ts"] = time.time()
            old = b["m"]
            b["m"] = (1 - self._bl_alpha) * old + self._bl_alpha * val
            b["v"] = (1 - self._bl_alpha) * b["v"] + self._bl_alpha * (val - old) * (val - b["m"])

    def _bl_deviation(self, ip, cat) -> float | None:
        k = (ip, cat)
        with self._bl_lock:
            b = self._bl.get(k)
            if not b or b["n"] < self._bl_min_n:
                return None
            std = math.sqrt(max(b["v"], 1e-10))
            return abs(b["m"]) / max(std, 1e-10)

    # ── Cooldown ──
    def _cd_factor(self, src, dst, cat) -> float:
        k = (src, dst, cat)
        with self._cd_lock:
            e = self._cd.get(k)
            if not e:
                return 1.0
            if time.time() - e["ts"] > self._cd_reset:
                del self._cd[k]
                return 1.0
            return max(self._cd_floor, self._cd_base ** e["c"])

    def _cd_record(self, src, dst, cat):
        k = (src, dst, cat)
        with self._cd_lock:
            if k not in self._cd:
                self._cd[k] = {"c": 1, "ts": time.time()}
            else:
                self._cd[k]["c"] += 1
                self._cd[k]["ts"] = time.time()

    # ── Cleanup ──
    def _gc(self):
        while True:
            time.sleep(300)
            now = time.time()
            with self._bl_lock:
                stale = [k for k, v in self._bl.items() if now - v["ts"] > 7 * 86400]
                for k in stale:
                    del self._bl[k]
            with self._cd_lock:
                stale = [k for k, v in self._cd.items() if now - v["ts"] > self._cd_reset * 2]
                for k in stale:
                    del self._cd[k]

    @property
    def stats(self) -> dict:
        return {**self._stats, "threshold": self.threshold,
                "cloud_ranges": len(self._cloud_nets),
                "baselines": len(self._bl), "cooldowns": len(self._cd)}
