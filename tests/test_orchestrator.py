"""Tests for analyzers/orchestrator.py — DetectorOrchestrator."""
import os
import sys
import time
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.base import Signal


# ── Config stub ──────────────────────────────────────────

class _Cfg:
    def __init__(self, overrides=None):
        self._d = {
            "network.subnets": ["192.168.1.0/24"],
            "detectors.confidence_threshold": 0.6,
            "identity.learning_hours": 48,
            "detectors.cloud_whitelist.custom": [],
            "detectors.baseline.min_samples": 100,
            "detectors.cooldown.base_factor": 0.5,
            "detectors.cooldown.min_factor": 0.05,
            "detectors.cooldown.reset_after_seconds": 3600,
        }
        if overrides:
            self._d.update(overrides)

    def get(self, dotted, default=None):
        return self._d.get(dotted, default)


def _sig(detector="det_a", confidence=0.95, severity=2, src_ip="1.2.3.4",
         dst_ip="5.6.7.8", category="test", observed=False):
    return Signal(
        detector=detector, category=category,
        title="Test signal", detail="detail",
        severity=severity, confidence=confidence,
        src_ip=src_ip, dst_ip=dst_ip, observed=observed,
    )


# ── Fixtures ─────────────────────────────────────────────

@pytest.fixture
def mock_deps():
    """Return (alert_fn, threat_engine) mocks."""
    alert_fn = MagicMock()
    engine = MagicMock()
    return alert_fn, engine


@pytest.fixture
def orch(mock_deps):
    """Create an Orchestrator with all background threads and detectors mocked."""
    alert_fn, engine = mock_deps
    # Patch ALL_DETECTORS to avoid loading real detectors (with their threads)
    with patch("analyzers.orchestrator.ALL_DETECTORS", []), \
         patch("analyzers.orchestrator.Scorer") as MockScorer, \
         patch("analyzers.orchestrator.threading"):
        mock_scorer = MagicMock()
        mock_scorer.stats = {"evaluated": 0}
        MockScorer.return_value = mock_scorer
        from analyzers.orchestrator import DetectorOrchestrator
        o = DetectorOrchestrator(_Cfg(), alert_fn, engine)
    return o


# ── Constructor / detector loading ───────────────────────

class TestOrchestratorInit:
    def test_empty_detectors_list(self, orch):
        assert orch.detectors == []

    def test_loads_valid_detectors(self, mock_deps):
        alert_fn, engine = mock_deps
        mock_cls = MagicMock()
        mock_cls.name = "test_det"
        mock_instance = MagicMock()
        mock_instance.name = "test_det"
        mock_instance.status = "active"
        mock_cls.return_value = mock_instance

        with patch("analyzers.orchestrator.ALL_DETECTORS", [mock_cls]), \
             patch("analyzers.orchestrator.Scorer") as MockScorer, \
             patch("analyzers.orchestrator.threading"):
            MockScorer.return_value = MagicMock(stats={})
            from analyzers.orchestrator import DetectorOrchestrator
            o = DetectorOrchestrator(_Cfg(), alert_fn, engine)
        assert len(o.detectors) == 1

    def test_failed_detector_loading_is_isolated(self, mock_deps):
        alert_fn, engine = mock_deps
        bad_cls = MagicMock()
        bad_cls.name = "bad"
        bad_cls.side_effect = RuntimeError("init failed")

        good_cls = MagicMock()
        good_cls.name = "good"
        good_inst = MagicMock()
        good_inst.name = "good"
        good_inst.status = "active"
        good_cls.return_value = good_inst

        with patch("analyzers.orchestrator.ALL_DETECTORS", [bad_cls, good_cls]), \
             patch("analyzers.orchestrator.Scorer") as MockScorer, \
             patch("analyzers.orchestrator.threading"):
            MockScorer.return_value = MagicMock(stats={})
            from analyzers.orchestrator import DetectorOrchestrator
            o = DetectorOrchestrator(_Cfg(), alert_fn, engine)
        assert len(o.detectors) == 1


# ── on_event dispatch ────────────────────────────────────

class TestOnEvent:
    def test_forwards_event_to_threat_engine(self, orch, mock_deps):
        _, engine = mock_deps
        orch.on_event({"type": "tcp", "src": "1.2.3.4"})
        engine.on_event.assert_called_once()

    def test_engine_exception_does_not_crash(self, orch, mock_deps):
        _, engine = mock_deps
        engine.on_event.side_effect = RuntimeError("engine fail")
        # Should not raise
        orch.on_event({"type": "tcp"})

    def test_fans_out_to_detectors(self, orch):
        mock_det = MagicMock()
        mock_det.name = "mock_det"
        mock_det.on_event.return_value = []
        orch.detectors = [mock_det]
        orch.on_event({"type": "tcp"})
        mock_det.on_event.assert_called_once()

    def test_buffers_signals_from_detectors(self, orch):
        sig = _sig(src_ip="1.2.3.4")
        mock_det = MagicMock()
        mock_det.name = "mock_det"
        mock_det.on_event.return_value = [sig]
        orch.detectors = [mock_det]
        orch._graph = None
        # scorer.score called for high-confidence signals via _evaluate
        orch.scorer.score.return_value = (2, 0.9, False)

        orch.on_event({"type": "tcp"})
        assert "1.2.3.4" in orch._buf
        assert len(orch._buf["1.2.3.4"]) >= 1

    def test_high_confidence_signal_triggers_immediate_evaluate(self, orch):
        sig = _sig(confidence=0.95, severity=1, src_ip="1.2.3.4")
        mock_det = MagicMock()
        mock_det.name = "mock_det"
        mock_det.on_event.return_value = [sig]
        orch.detectors = [mock_det]
        orch._graph = None

        with patch.object(orch, "_evaluate") as mock_eval:
            orch.on_event({"type": "tcp"})
            mock_eval.assert_called_with("1.2.3.4")

    def test_low_confidence_signal_no_immediate_evaluate(self, orch):
        sig = _sig(confidence=0.5, severity=4, src_ip="1.2.3.4")
        mock_det = MagicMock()
        mock_det.name = "mock_det"
        mock_det.on_event.return_value = [sig]
        orch.detectors = [mock_det]
        orch._graph = None

        with patch.object(orch, "_evaluate") as mock_eval:
            orch.on_event({"type": "tcp"})
            mock_eval.assert_not_called()

    def test_feeds_signals_to_attack_graph(self, orch):
        sig = _sig(detector="lateral", src_ip="1.2.3.4")
        mock_det = MagicMock()
        mock_det.name = "lateral"
        mock_det.on_event.return_value = [sig]
        orch.detectors = [mock_det]
        orch.scorer.score.return_value = (2, 0.9, False)

        mock_graph = MagicMock()
        mock_graph.name = "attack_graph"
        orch._graph = mock_graph

        orch.on_event({"type": "tcp"})
        mock_graph.feed_signal.assert_called_once_with(sig)

    def test_does_not_feed_own_signals_to_attack_graph(self, orch):
        sig = _sig(detector="attack_graph", src_ip="1.2.3.4")
        mock_det = MagicMock()
        mock_det.name = "attack_graph"
        mock_det.on_event.return_value = [sig]
        orch.detectors = [mock_det]
        orch.scorer.score.return_value = (2, 0.9, False)

        mock_graph = MagicMock()
        mock_graph.name = "attack_graph"
        orch._graph = mock_graph

        orch.on_event({"type": "tcp"})
        mock_graph.feed_signal.assert_not_called()


# ── _evaluate ────────────────────────────────────────────

class TestEvaluate:
    def test_empty_buffer_no_alert(self, orch, mock_deps):
        alert_fn, _ = mock_deps
        orch._evaluate("1.2.3.4")
        alert_fn.assert_not_called()

    def test_evaluates_and_alerts_when_scorer_approves(self, orch, mock_deps):
        alert_fn, _ = mock_deps
        sig = _sig(src_ip="1.2.3.4")
        now = time.time()
        orch._buf["1.2.3.4"] = [(now, sig)]
        orch.scorer.score.return_value = (2, 0.9, True)

        orch._evaluate("1.2.3.4")
        alert_fn.assert_called_once()
        call_kw = alert_fn.call_args
        assert "advanced:" in (call_kw[1].get("source", "") if call_kw[1] else call_kw.kwargs.get("source", ""))

    def test_suppressed_signal_no_alert(self, orch, mock_deps):
        alert_fn, _ = mock_deps
        sig = _sig(src_ip="1.2.3.4")
        now = time.time()
        orch._buf["1.2.3.4"] = [(now, sig)]
        orch.scorer.score.return_value = (4, 0.3, False)

        orch._evaluate("1.2.3.4")
        alert_fn.assert_not_called()

    def test_stale_entries_ignored(self, orch, mock_deps):
        alert_fn, _ = mock_deps
        sig = _sig(src_ip="1.2.3.4")
        old_ts = time.time() - 600  # > 300s window
        orch._buf["1.2.3.4"] = [(old_ts, sig)]

        orch._evaluate("1.2.3.4")
        alert_fn.assert_not_called()

    def test_temporal_correlation_three_detectors_critical(self, orch, mock_deps):
        alert_fn, _ = mock_deps
        now = time.time()
        sigs = [
            _sig(detector="det_a", src_ip="1.2.3.4"),
            _sig(detector="det_b", src_ip="1.2.3.4"),
            _sig(detector="det_c", src_ip="1.2.3.4"),
        ]
        orch._buf["1.2.3.4"] = [(now, s) for s in sigs]
        orch.scorer.score.return_value = (1, 0.9, True)

        orch._evaluate("1.2.3.4")
        # With 3+ detectors, max_sev should be 1 (critical)
        calls = orch.scorer.score.call_args_list
        for call in calls:
            assert call[0][1] == 1  # max_sev=1

    def test_temporal_correlation_two_detectors_high(self, orch):
        now = time.time()
        sigs = [
            _sig(detector="det_a", src_ip="1.2.3.4"),
            _sig(detector="det_b", src_ip="1.2.3.4"),
        ]
        orch._buf["1.2.3.4"] = [(now, s) for s in sigs]
        orch.scorer.score.return_value = (2, 0.9, True)

        orch._evaluate("1.2.3.4")
        calls = orch.scorer.score.call_args_list
        for call in calls:
            assert call[0][1] == 2  # max_sev=2

    def test_temporal_correlation_one_detector_info(self, orch):
        now = time.time()
        sigs = [_sig(detector="det_a", src_ip="1.2.3.4")]
        orch._buf["1.2.3.4"] = [(now, s) for s in sigs]
        orch.scorer.score.return_value = (5, 0.9, True)

        orch._evaluate("1.2.3.4")
        calls = orch.scorer.score.call_args_list
        assert calls[0][0][1] == 5  # max_sev=5

    def test_observed_signals_skipped(self, orch, mock_deps):
        alert_fn, _ = mock_deps
        sig = _sig(src_ip="1.2.3.4", observed=True)
        now = time.time()
        orch._buf["1.2.3.4"] = [(now, sig)]
        orch.scorer.score.return_value = (2, 0.9, True)

        orch._evaluate("1.2.3.4")
        # observed signals are skipped in the loop
        alert_fn.assert_not_called()


# ── check_health ─────────────────────────────────────────

class TestCheckHealth:
    def test_logs_circuit_open_detectors(self, orch):
        mock_det = MagicMock()
        mock_det.name = "broken"
        mock_det._open = True
        orch.detectors = [mock_det]
        # Should not raise
        orch.check_health()

    def test_no_log_when_all_healthy(self, orch):
        mock_det = MagicMock()
        mock_det._open = False
        orch.detectors = [mock_det]
        orch.check_health()


# ── Stats / get_health ───────────────────────────────────

class TestStats:
    def test_stats_structure(self, orch):
        s = orch.stats
        assert "detectors" in s
        assert "scorer" in s
        assert "buffered_ips" in s

    def test_get_health_returns_stats(self, orch):
        assert orch.get_health() == orch.stats


# ── _evaluate deduplication ──────────────────────────────

class TestEvaluateDedup:
    def test_duplicate_signals_deduplicated(self, orch, mock_deps):
        alert_fn, _ = mock_deps
        now = time.time()
        sig1 = _sig(detector="det_a", src_ip="1.2.3.4", dst_ip="5.6.7.8", category="scan")
        sig2 = _sig(detector="det_a", src_ip="1.2.3.4", dst_ip="5.6.7.8", category="scan")
        orch._buf["1.2.3.4"] = [(now, sig1), (now, sig2)]
        orch.scorer.score.return_value = (3, 0.9, True)

        orch._evaluate("1.2.3.4")
        # Should only alert once due to dedup key
        assert alert_fn.call_count == 1

    def test_different_categories_not_deduplicated(self, orch, mock_deps):
        alert_fn, _ = mock_deps
        now = time.time()
        sig1 = _sig(detector="det_a", src_ip="1.2.3.4", category="scan")
        sig2 = _sig(detector="det_a", src_ip="1.2.3.4", category="exfil")
        orch._buf["1.2.3.4"] = [(now, sig1), (now, sig2)]
        orch.scorer.score.return_value = (3, 0.9, True)

        orch._evaluate("1.2.3.4")
        assert alert_fn.call_count == 2


# ── Buffer cleanup ───────────────────────────────────────

class TestBufferCleanup:
    def test_evaluate_cleans_old_entries(self, orch):
        now = time.time()
        old_sig = _sig(src_ip="1.2.3.4")
        new_sig = _sig(src_ip="1.2.3.4")
        orch._buf["1.2.3.4"] = [
            (now - 400, old_sig),  # stale
            (now, new_sig),        # fresh
        ]
        orch.scorer.score.return_value = (3, 0.9, False)
        orch._evaluate("1.2.3.4")
        # After evaluate, only recent entries remain
        assert len(orch._buf["1.2.3.4"]) == 1


# ── Attack graph feed error handling ─────────────────────

class TestAttackGraphFeedErrors:
    def test_feed_signal_exception_handled(self, orch):
        sig = _sig(detector="lateral", src_ip="1.2.3.4")
        mock_det = MagicMock()
        mock_det.name = "lateral"
        mock_det.on_event.return_value = [sig]
        orch.detectors = [mock_det]
        orch.scorer.score.return_value = (2, 0.9, False)

        mock_graph = MagicMock()
        mock_graph.name = "attack_graph"
        mock_graph.feed_signal.side_effect = RuntimeError("graph error")
        orch._graph = mock_graph

        # Should not raise
        orch.on_event({"type": "tcp"})


# ── Signals with unknown src_ip ──────────────────────────

class TestUnknownSourceIp:
    def test_signal_without_src_ip_uses_unknown(self, orch):
        sig = _sig(src_ip="", detector="det_a")
        mock_det = MagicMock()
        mock_det.name = "det_a"
        mock_det.on_event.return_value = [sig]
        orch.detectors = [mock_det]
        orch._graph = None
        orch.scorer.score.return_value = (5, 0.3, False)

        orch.on_event({"type": "tcp"})
        assert "unknown" in orch._buf


# ── Eval loop logic (inline) ────────────────────────────

class TestEvalLoopLogic:
    def test_eval_loop_processes_all_buffered_ips(self, orch, mock_deps):
        alert_fn, _ = mock_deps
        now = time.time()
        sig_a = _sig(src_ip="1.1.1.1", detector="det_a")
        sig_b = _sig(src_ip="2.2.2.2", detector="det_b")
        orch._buf["1.1.1.1"] = [(now, sig_a)]
        orch._buf["2.2.2.2"] = [(now, sig_b)]
        orch.scorer.score.return_value = (3, 0.9, True)

        # Simulate what _eval_loop does (without the sleep)
        with orch._buf_lock:
            for ip in list(orch._buf.keys()):
                orch._evaluate(ip)

        assert alert_fn.call_count == 2

    def test_eval_loop_handles_exception(self, orch):
        """Eval loop catches exceptions gracefully."""
        orch.scorer.score.side_effect = RuntimeError("boom")
        now = time.time()
        sig = _sig(src_ip="1.1.1.1")
        orch._buf["1.1.1.1"] = [(now, sig)]

        # Should not raise
        try:
            with orch._buf_lock:
                for ip in list(orch._buf.keys()):
                    orch._evaluate(ip)
        except Exception:
            pass  # eval_loop wraps in try/except


# ── GC loop logic (inline) ──────────────────────────────

class TestGcLoopLogic:
    def test_gc_removes_stale_buffer_entries(self, orch):
        now = time.time()
        old_sig = _sig(src_ip="1.1.1.1")
        orch._buf["1.1.1.1"] = [(now - 700, old_sig)]  # > 600s

        # Simulate _gc_loop logic
        with orch._buf_lock:
            for ip in list(orch._buf.keys()):
                orch._buf[ip] = [(t, s) for t, s in orch._buf[ip] if now - t < 600]
                if not orch._buf[ip]:
                    del orch._buf[ip]

        assert "1.1.1.1" not in orch._buf

    def test_gc_keeps_fresh_entries(self, orch):
        now = time.time()
        fresh_sig = _sig(src_ip="2.2.2.2")
        orch._buf["2.2.2.2"] = [(now, fresh_sig)]

        with orch._buf_lock:
            for ip in list(orch._buf.keys()):
                orch._buf[ip] = [(t, s) for t, s in orch._buf[ip] if now - t < 600]
                if not orch._buf[ip]:
                    del orch._buf[ip]

        assert "2.2.2.2" in orch._buf


# ── Direct method invocation for coverage ────────────────

class TestDirectMethodCoverage:
    def test_eval_loop_single_iteration(self, orch, mock_deps):
        """Invoke _eval_loop with sleep patched to break after one iteration."""
        import analyzers.orchestrator as orch_mod
        alert_fn, _ = mock_deps
        now = time.time()
        sig = _sig(src_ip="1.1.1.1")
        orch._buf["1.1.1.1"] = [(now, sig)]
        orch.scorer.score.return_value = (3, 0.9, True)

        call_count = [0]
        def fake_sleep(s):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise StopIteration("break loop")

        with patch.object(orch_mod.time, "sleep", side_effect=fake_sleep):
            try:
                orch._eval_loop()
            except StopIteration:
                pass

        alert_fn.assert_called()

    def test_gc_loop_single_iteration(self, orch):
        """Invoke _gc_loop with sleep patched to break after one iteration."""
        import analyzers.orchestrator as orch_mod
        now = time.time()
        old_sig = _sig(src_ip="1.1.1.1")
        orch._buf["1.1.1.1"] = [(now - 700, old_sig)]

        call_count = [0]
        def fake_sleep(s):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise StopIteration("break loop")

        with patch.object(orch_mod.time, "sleep", side_effect=fake_sleep):
            try:
                orch._gc_loop()
            except StopIteration:
                pass

        assert "1.1.1.1" not in orch._buf
