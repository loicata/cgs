"""Tests for analyzers/base.py — BaseDetector and Signal dataclass."""
import os
import sys
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.base import BaseDetector, Signal


# ── Helpers ──────────────────────────────────────────────

class _DummyConfig:
    """Minimal config stub that supports dotted-key get()."""
    def __init__(self, overrides=None):
        self._d = overrides or {}

    def get(self, dotted, default=None):
        return self._d.get(dotted, default)


class ConcreteDetector(BaseDetector):
    """Minimal concrete implementation for testing the base class."""
    name = "test_detector"

    def __init__(self, cfg, analyze_fn=None, size_fn=None, evict_fn=None):
        super().__init__(cfg)
        self._analyze_fn = analyze_fn or (lambda evt: [])
        self._size_fn = size_fn or (lambda: 0)
        self._evict_fn = evict_fn or (lambda: None)

    def _analyze(self, evt):
        return self._analyze_fn(evt)

    def _estimate_size(self):
        return self._size_fn()

    def _evict(self):
        self._evict_fn()


def _make_cfg(**kw):
    return _DummyConfig(kw)


# ── Signal dataclass ─────────────────────────────────────

class TestSignalDataclass:
    def test_signal_default_fields(self):
        s = Signal("det", "cat", "title", "detail", severity=3, confidence=0.8)
        assert s.detector == "det"
        assert s.category == "cat"
        assert s.title == "title"
        assert s.detail == "detail"
        assert s.severity == 3
        assert s.confidence == 0.8
        assert s.src_ip == ""
        assert s.dst_ip == ""
        assert s.ioc == ""
        assert s.observed is False

    def test_signal_with_optional_fields(self):
        s = Signal("d", "c", "t", "d", severity=1, confidence=0.9,
                   src_ip="10.0.0.1", dst_ip="10.0.0.2", ioc="evil.com",
                   observed=True)
        assert s.src_ip == "10.0.0.1"
        assert s.dst_ip == "10.0.0.2"
        assert s.ioc == "evil.com"
        assert s.observed is True


# ── BaseDetector basics ──────────────────────────────────

class TestBaseDetectorInit:
    def test_default_enabled_active(self):
        d = ConcreteDetector(_make_cfg())
        assert d.enabled is True
        assert d.observe is False
        assert d.status == "active"

    def test_disabled_via_config(self):
        d = ConcreteDetector(_make_cfg(**{"detectors.test_detector.enabled": False}))
        assert d.enabled is False
        assert d.status == "disabled"

    def test_observe_mode_via_config(self):
        d = ConcreteDetector(_make_cfg(**{"detectors.test_detector.observe": True}))
        assert d.observe is True
        assert d.status == "observing"

    def test_observe_until_past_date_disables_observe(self):
        d = ConcreteDetector(_make_cfg(**{
            "detectors.test_detector.observe": True,
            "detectors.test_detector.observe_until": "2020-01-01",
        }))
        assert d.observe is False

    def test_observe_until_future_date_keeps_observe(self):
        d = ConcreteDetector(_make_cfg(**{
            "detectors.test_detector.observe": True,
            "detectors.test_detector.observe_until": "2099-12-31",
        }))
        assert d.observe is True

    def test_observe_until_invalid_date_ignored(self):
        d = ConcreteDetector(_make_cfg(**{
            "detectors.test_detector.observe": True,
            "detectors.test_detector.observe_until": "not-a-date",
        }))
        assert d.observe is True

    def test_max_memory_config(self):
        d = ConcreteDetector(_make_cfg(**{"detectors.test_detector.max_memory_mb": 100}))
        assert d._max_mem == 100 * 1024 * 1024


# ── on_event dispatch ────────────────────────────────────

class TestOnEvent:
    def test_returns_empty_when_disabled(self):
        d = ConcreteDetector(_make_cfg(**{"detectors.test_detector.enabled": False}))
        result = d.on_event({"type": "tcp"})
        assert result == []

    def test_dispatches_to_analyze(self):
        sig = Signal("test_detector", "cat", "t", "d", severity=3, confidence=0.7)
        d = ConcreteDetector(_make_cfg(), analyze_fn=lambda e: [sig])
        result = d.on_event({"type": "tcp"})
        assert len(result) == 1
        assert result[0] is sig

    def test_increments_event_counter(self):
        d = ConcreteDetector(_make_cfg())
        assert d._n == 0
        d.on_event({})
        d.on_event({})
        assert d._n == 2

    def test_observe_mode_caps_severity_and_marks_observed(self):
        sig = Signal("test_detector", "cat", "t", "d", severity=2, confidence=0.9)
        d = ConcreteDetector(
            _make_cfg(**{"detectors.test_detector.observe": True}),
            analyze_fn=lambda e: [sig],
        )
        result = d.on_event({})
        assert result[0].severity == 5
        assert result[0].observed is True

    def test_memory_guard_triggers_evict(self):
        evicted = []
        d = ConcreteDetector(
            _make_cfg(**{"detectors.test_detector.max_memory_mb": 1}),
            size_fn=lambda: 2 * 1024 * 1024,  # 2 MB > 1 MB limit
            evict_fn=lambda: evicted.append(True),
        )
        d.on_event({})
        assert len(evicted) == 1

    def test_no_evict_when_under_limit(self):
        evicted = []
        d = ConcreteDetector(
            _make_cfg(**{"detectors.test_detector.max_memory_mb": 50}),
            size_fn=lambda: 100,  # well under limit
            evict_fn=lambda: evicted.append(True),
        )
        d.on_event({})
        assert len(evicted) == 0


# ── Circuit breaker ──────────────────────────────────────

class TestCircuitBreaker:
    def test_single_crash_does_not_open(self):
        def bad_analyze(evt):
            raise ValueError("boom")
        d = ConcreteDetector(_make_cfg(), analyze_fn=bad_analyze)
        d.on_event({})
        assert d._open is False
        assert d.status == "active"
        assert len(d._crashes) == 1

    def test_three_crashes_opens_circuit(self):
        def bad_analyze(evt):
            raise ValueError("boom")
        d = ConcreteDetector(_make_cfg(), analyze_fn=bad_analyze)
        d.on_event({})
        d.on_event({})
        d.on_event({})
        assert d._open is True
        assert d.status == "circuit_open"

    def test_circuit_open_blocks_events(self):
        call_count = [0]
        def counting_analyze(evt):
            call_count[0] += 1
            raise ValueError("boom")
        d = ConcreteDetector(_make_cfg(), analyze_fn=counting_analyze)
        # Open circuit
        for _ in range(3):
            d.on_event({})
        assert d._open is True
        count_after_open = call_count[0]
        # Should be blocked
        d.on_event({})
        assert call_count[0] == count_after_open

    def test_circuit_recovers_after_timeout(self):
        def bad_analyze(evt):
            raise ValueError("boom")
        d = ConcreteDetector(_make_cfg(), analyze_fn=bad_analyze)
        for _ in range(3):
            d.on_event({})
        assert d._open is True
        # Simulate timeout expiry
        d._open_until = time.time() - 1
        # Next call should reset _open and try _analyze again
        d._analyze_fn = lambda e: []
        d.on_event({})
        assert d._open is False

    def test_old_crashes_expire_from_window(self):
        def bad_analyze(evt):
            raise ValueError("boom")
        d = ConcreteDetector(_make_cfg(), analyze_fn=bad_analyze)
        d.on_event({})
        d.on_event({})
        assert len(d._crashes) == 2
        # Simulate old timestamps
        d._crashes[0] = time.time() - 700  # > 600s window
        d._crashes[1] = time.time() - 700
        d.on_event({})
        # The old crashes should have been evicted; only 1 recent remains
        assert len(d._crashes) == 1
        assert d._open is False


# ── Stats property ───────────────────────────────────────

class TestStats:
    def test_stats_structure(self):
        d = ConcreteDetector(_make_cfg())
        d.on_event({})
        s = d.stats
        assert s["name"] == "test_detector"
        assert s["status"] == "active"
        assert s["events"] == 1
        assert s["crashes"] == 0
        assert "mem_pct" in s

    def test_stats_reflects_crash(self):
        d = ConcreteDetector(_make_cfg(), analyze_fn=lambda e: (_ for _ in ()).throw(ValueError("x")))
        d.on_event({})
        assert d.stats["crashes"] == 1
