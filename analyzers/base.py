"""
CGS — Detector framework: base class, signal dataclass, circuit breaker.

Every advanced detector inherits BaseDetector which provides:
  - try/except isolation (never crashes the pipeline)
  - Circuit breaker (3 crashes in 10min = auto-disable, auto-recovery)
  - Observation mode (log only, severity capped at INFO)
  - Memory guard with LRU eviction
"""

import logging
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field

log = logging.getLogger("cgs.detector")


@dataclass
class Signal:
    """A detection finding before scoring."""
    detector: str
    category: str
    title: str
    detail: str
    severity: int           # 1-5 suggested (modulated by scorer)
    confidence: float       # 0.0-1.0
    src_ip: str = ""
    dst_ip: str = ""
    ioc: str = ""
    observed: bool = False


class BaseDetector(ABC):
    name: str = "unnamed"

    def __init__(self, config):
        self.cfg = config
        p = f"detectors.{self.name}"
        self.enabled = config.get(f"{p}.enabled", True)
        self.observe = config.get(f"{p}.observe", False)
        self._max_mem = config.get(f"{p}.max_memory_mb", 50) * 1024 * 1024
        # Auto-disable observation after date
        until = config.get(f"{p}.observe_until", "")
        if until:
            try:
                from datetime import datetime
                if datetime.now() > datetime.fromisoformat(until):
                    self.observe = False
            except (ValueError, TypeError):
                pass
        # Circuit breaker
        self._crashes: deque = deque()
        self._open = False
        self._open_until = 0.0
        self._n = 0  # events processed

    def on_event(self, evt: dict) -> list[Signal]:
        if not self.enabled:
            return []
        if self._open:
            if time.time() < self._open_until:
                return []
            self._open = False
        try:
            if self._estimate_size() > self._max_mem:
                self._evict()
            sigs = self._analyze(evt)
            self._n += 1
            if self.observe:
                for s in sigs:
                    s.severity = max(s.severity, 5)
                    s.observed = True
            return sigs
        except Exception as e:
            self._crash(e)
            return []

    @abstractmethod
    def _analyze(self, evt: dict) -> list[Signal]: ...

    def _estimate_size(self) -> int:
        return 0

    def _evict(self):
        pass

    def _crash(self, exc):
        now = time.time()
        self._crashes.append(now)
        while self._crashes and now - self._crashes[0] > 600:
            self._crashes.popleft()
        if len(self._crashes) >= 3:
            self._open = True
            self._open_until = now + 300
            log.error("CIRCUIT OPEN %s: %s", self.name, exc)
        else:
            log.warning("Detector %s crash (%d/3): %s",
                       self.name, len(self._crashes), exc)

    @property
    def status(self) -> str:
        if not self.enabled: return "disabled"
        if self._open: return "circuit_open"
        if self.observe: return "observing"
        return "active"

    @property
    def stats(self) -> dict:
        return {"name": self.name, "status": self.status,
                "events": self._n, "crashes": len(self._crashes),
                "mem_pct": round(self._estimate_size() / max(self._max_mem, 1) * 100, 1)}
