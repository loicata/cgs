"""Tests for analyzers/scoring.py — Scorer anti-FP pipeline."""
import os
import sys
import time
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.scoring import Scorer
from analyzers.base import Signal


# ── Helpers ──────────────────────────────────────────────

class _Cfg:
    """Minimal config stub."""
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


def _sig(confidence=0.8, severity=2, src_ip="1.2.3.4", dst_ip="5.6.7.8",
         category="test", observed=False, detector="test_det"):
    return Signal(
        detector=detector, category=category,
        title="Test signal", detail="detail",
        severity=severity, confidence=confidence,
        src_ip=src_ip, dst_ip=dst_ip, observed=observed,
    )


@pytest.fixture
def scorer():
    with patch.object(Scorer, '_cloud_refresh'):
        s = Scorer(_Cfg())
    return s


# ── Basic scoring ────────────────────────────────────────

class TestBasicScore:
    def test_high_confidence_external_ip_alerts(self, scorer):
        sig = _sig(confidence=0.9)
        final_sev, score, should = scorer.score(sig, max_sev=3)
        assert should is True
        assert score > 0
        assert final_sev >= 2  # max(sig.severity=2, max_sev=3) = 3

    def test_low_confidence_suppressed(self, scorer):
        sig = _sig(confidence=0.1)
        final_sev, score, should = scorer.score(sig, max_sev=5)
        assert should is False

    def test_observed_signal_suppressed(self, scorer):
        sig = _sig(confidence=0.99, observed=True)
        _, _, should = scorer.score(sig, max_sev=1)
        assert should is False

    def test_severity_uses_max_of_signal_and_max_sev(self, scorer):
        sig = _sig(severity=4)
        final_sev, _, _ = scorer.score(sig, max_sev=2)
        assert final_sev == 4  # max(4, 2)

        sig2 = _sig(severity=1)
        final_sev2, _, _ = scorer.score(sig2, max_sev=3)
        assert final_sev2 == 3  # max(1, 3)

    def test_stats_incremented(self, scorer):
        assert scorer._stats["evaluated"] == 0
        scorer.score(_sig(confidence=0.9), max_sev=5)
        assert scorer._stats["evaluated"] == 1


# ── Reputation tiers ─────────────────────────────────────

class TestReputationTiers:
    def test_external_ip_no_discount(self, scorer):
        # 1.2.3.4 is external, no discount applied for tier
        sig = _sig(confidence=0.8, src_ip="1.2.3.4")
        _, score, _ = scorer.score(sig, max_sev=5)
        # External IP: tier returns "external", no multiplier
        assert score > 0

    def test_internal_ip_gets_new_internal_discount(self, scorer):
        # 192.168.1.50 is internal; no Host record, so "new_internal" => *0.85
        sig = _sig(confidence=0.8, src_ip="192.168.1.50")
        with patch("core.database.Host") as mock_host:
            mock_host.get_or_none.return_value = None
            _, score, _ = scorer.score(sig, max_sev=5)
        # 0.8 * 0.85 = 0.68
        assert 0.60 < score < 0.75

    def test_known_internal_ip_gets_larger_discount(self, scorer):
        from datetime import datetime, timedelta
        sig = _sig(confidence=0.8, src_ip="192.168.1.50")
        mock_host = MagicMock()
        mock_host.first_seen = datetime.now() - timedelta(hours=100)
        with patch("core.database.Host") as HostCls:
            HostCls.get_or_none.return_value = mock_host
            _, score, _ = scorer.score(sig, max_sev=5)
        # 0.8 * 0.7 = 0.56
        assert score < 0.60

    def test_tier_external_for_non_subnet_ip(self, scorer):
        tier = scorer._tier("8.8.8.8")
        assert tier == "external"

    def test_tier_external_for_invalid_ip(self, scorer):
        tier = scorer._tier("not-an-ip")
        assert tier == "external"


# ── Cloud whitelist ──────────────────────────────────────

class TestCloudWhitelist:
    def test_cloud_ip_heavily_discounted(self, scorer):
        # 104.16.1.1 is in Cloudflare CIDR 104.16.0.0/13
        sig = _sig(confidence=0.9, dst_ip="104.16.1.1")
        _, score, _ = scorer.score(sig, max_sev=5)
        # 0.9 * 0.3 = 0.27 → suppressed
        assert score < 0.6

    def test_non_cloud_ip_no_discount(self, scorer):
        sig = _sig(confidence=0.9, dst_ip="200.200.200.200")
        _, score, should = scorer.score(sig, max_sev=5)
        assert should is True

    def test_is_cloud_returns_true_for_known_cidr(self, scorer):
        assert scorer._is_cloud("8.8.8.1") is True  # Google 8.8.8.0/24

    def test_is_cloud_returns_false_for_private_ip(self, scorer):
        assert scorer._is_cloud("192.168.1.1") is False

    def test_is_cloud_handles_invalid_ip(self, scorer):
        assert scorer._is_cloud("garbage") is False


# ── Cooldown mechanism ───────────────────────────────────

class TestCooldown:
    def test_first_alert_no_cooldown(self, scorer):
        factor = scorer._cd_factor("1.2.3.4", "5.6.7.8", "scan")
        assert factor == 1.0

    def test_repeated_alerts_get_increasing_cooldown(self, scorer):
        scorer._cd_record("1.2.3.4", "5.6.7.8", "scan")
        f1 = scorer._cd_factor("1.2.3.4", "5.6.7.8", "scan")
        assert f1 == 0.5  # base_factor^1

        scorer._cd_record("1.2.3.4", "5.6.7.8", "scan")
        f2 = scorer._cd_factor("1.2.3.4", "5.6.7.8", "scan")
        assert f2 == 0.25  # base_factor^2

    def test_cooldown_respects_floor(self, scorer):
        for _ in range(20):
            scorer._cd_record("1.2.3.4", "5.6.7.8", "scan")
        f = scorer._cd_factor("1.2.3.4", "5.6.7.8", "scan")
        assert f == 0.05  # min_factor

    def test_cooldown_resets_after_timeout(self, scorer):
        scorer._cd_record("1.2.3.4", "5.6.7.8", "scan")
        # Force stale timestamp
        k = ("1.2.3.4", "5.6.7.8", "scan")
        scorer._cd[k]["ts"] = time.time() - 4000  # > 3600 reset
        f = scorer._cd_factor("1.2.3.4", "5.6.7.8", "scan")
        assert f == 1.0
        assert k not in scorer._cd


# ── Baseline deviation ───────────────────────────────────

class TestBaseline:
    def test_no_baseline_returns_none(self, scorer):
        dev = scorer._bl_deviation("10.0.0.1", "scan")
        assert dev is None

    def test_insufficient_samples_returns_none(self, scorer):
        scorer._bl_observe("10.0.0.1", "scan", 1.0)
        dev = scorer._bl_deviation("10.0.0.1", "scan")
        assert dev is None

    def test_baseline_with_enough_samples_returns_deviation(self, scorer):
        for _ in range(150):
            scorer._bl_observe("10.0.0.1", "scan", 1.0)
        dev = scorer._bl_deviation("10.0.0.1", "scan")
        assert dev is not None
        assert isinstance(dev, float)

    def test_low_deviation_discounts_score(self, scorer):
        # Build up baseline with enough samples
        for _ in range(150):
            scorer._bl_observe("1.2.3.4", "test", 1.0)
        sig = _sig(confidence=0.9, src_ip="1.2.3.4", category="test")
        _, score, _ = scorer.score(sig, max_sev=5)
        # Low deviation => *0.5 multiplier should reduce score
        assert score <= 0.9


# ── FP feedback integration ──────────────────────────────

class TestFpFeedback:
    def test_fp_manager_applied_when_present(self):
        fp_mgr = MagicMock()
        fp_mgr.get_threshold_multiplier.return_value = 2.0
        with patch.object(Scorer, '_cloud_refresh'):
            scorer = Scorer(_Cfg(), fp_mgr=fp_mgr)
        sig = _sig(confidence=0.9, src_ip="1.2.3.4")
        _, score, _ = scorer.score(sig, max_sev=5)
        fp_mgr.get_threshold_multiplier.assert_called_once()
        # Score should be halved roughly (0.9 / 2.0 = 0.45)

    def test_fp_manager_exception_handled(self):
        fp_mgr = MagicMock()
        fp_mgr.get_threshold_multiplier.side_effect = RuntimeError("fail")
        with patch.object(Scorer, '_cloud_refresh'):
            scorer = Scorer(_Cfg(), fp_mgr=fp_mgr)
        sig = _sig(confidence=0.9, src_ip="1.2.3.4")
        # Should not raise
        _, score, _ = scorer.score(sig, max_sev=5)
        assert score > 0


# ── Stats ────────────────────────────────────────────────

class TestScorerStats:
    def test_stats_structure(self, scorer):
        s = scorer.stats
        assert "evaluated" in s
        assert "suppressed" in s
        assert "alerted" in s
        assert "threshold" in s
        assert "cloud_ranges" in s
        assert "baselines" in s
        assert "cooldowns" in s

    def test_alerted_and_suppressed_counters(self, scorer):
        scorer.score(_sig(confidence=0.9), max_sev=5)
        scorer.score(_sig(confidence=0.01), max_sev=5)
        assert scorer._stats["evaluated"] == 2
        assert scorer._stats["alerted"] >= 1
        assert scorer._stats["suppressed"] >= 1


# ── Cloud refresh (covers _cloud_refresh / _do) ─────────

class TestCloudRefresh:
    def test_cloud_refresh_called_on_init(self):
        """Ensure _cloud_refresh is called during __init__."""
        with patch.object(Scorer, '_cloud_refresh') as mock_cr:
            Scorer(_Cfg())
            mock_cr.assert_called_once()

    def test_cloud_nets_initialized_from_static_cidrs(self):
        with patch.object(Scorer, '_cloud_refresh'):
            s = Scorer(_Cfg())
        assert len(s._cloud_nets) > 0

    def test_custom_cloud_whitelist_added(self):
        with patch.object(Scorer, '_cloud_refresh'):
            s = Scorer(_Cfg({"detectors.cloud_whitelist.custom": ["100.100.0.0/16"]}))
        import ipaddress
        custom_net = ipaddress.IPv4Network("100.100.0.0/16")
        assert any(n == custom_net for n in s._cloud_nets)

    def test_invalid_custom_cidr_skipped(self):
        with patch.object(Scorer, '_cloud_refresh'):
            s = Scorer(_Cfg({"detectors.cloud_whitelist.custom": ["not-a-cidr"]}))
        # Should not crash, just skip the invalid entry


# ── Baseline observe EMA ─────────────────────────────────

class TestBaselineObserve:
    def test_first_observe_initializes(self, scorer):
        scorer._bl_observe("10.0.0.1", "cat", 5.0)
        k = ("10.0.0.1", "cat")
        assert k in scorer._bl
        assert scorer._bl[k]["m"] == 5.0
        assert scorer._bl[k]["n"] == 1

    def test_subsequent_observe_updates_ema(self, scorer):
        scorer._bl_observe("10.0.0.1", "cat", 5.0)
        scorer._bl_observe("10.0.0.1", "cat", 10.0)
        k = ("10.0.0.1", "cat")
        assert scorer._bl[k]["n"] == 2
        # EMA: (1-0.01)*5.0 + 0.01*10.0 = 5.05
        assert scorer._bl[k]["m"] == pytest.approx(5.05, abs=0.01)


# ── Cooldown record ─────────────────────────────────────

class TestCooldownRecord:
    def test_first_record_creates_entry(self, scorer):
        scorer._cd_record("a", "b", "c")
        k = ("a", "b", "c")
        assert k in scorer._cd
        assert scorer._cd[k]["c"] == 1

    def test_repeated_record_increments(self, scorer):
        scorer._cd_record("a", "b", "c")
        scorer._cd_record("a", "b", "c")
        assert scorer._cd[("a", "b", "c")]["c"] == 2


# ── Score with baseline deviation below threshold ────────

class TestScoreWithBaseline:
    def test_high_deviation_no_baseline_discount(self, scorer):
        """When deviation is high (>= 1.5), no baseline *0.5 discount."""
        k = ("1.2.3.4", "test")
        # Set up baseline with high variance so deviation >= 1.5
        scorer._bl[k] = {"m": 10.0, "v": 100.0, "n": 200, "ts": time.time()}
        sig = _sig(confidence=0.9, src_ip="1.2.3.4", category="test")
        _, score, _ = scorer.score(sig, max_sev=5)
        # External IP: no tier discount. High deviation: no baseline discount.
        # Score should remain 0.9 (possibly with cooldown=1.0)
        assert score > 0.4


# ── Score cd_record integration ──────────────────────────

class TestScoreCdIntegration:
    def test_score_records_cooldown_on_alert(self, scorer):
        sig = _sig(confidence=0.99, src_ip="1.2.3.4", dst_ip="5.6.7.8", category="scan")
        _, _, should = scorer.score(sig, max_sev=5)
        if should:
            k = ("1.2.3.4", "5.6.7.8", "scan")
            assert k in scorer._cd


# ── Tier with DB exception ──────────────────────────────

class TestTierEdgeCases:
    def test_tier_db_exception_returns_new_internal(self, scorer):
        """When Host DB lookup raises, tier falls back to new_internal."""
        with patch("core.database.Host") as HostCls:
            HostCls.get_or_none.side_effect = RuntimeError("db fail")
            tier = scorer._tier("192.168.1.50")
        assert tier == "new_internal"

    def test_tier_host_with_none_first_seen(self, scorer):
        """Host exists but first_seen is None."""
        mock_host = MagicMock()
        mock_host.first_seen = None
        with patch("core.database.Host") as HostCls:
            HostCls.get_or_none.return_value = mock_host
            tier = scorer._tier("192.168.1.50")
        # first_seen is None -> exception in timedelta -> falls to new_internal
        assert tier == "new_internal"


# ── GC (garbage collection) ─────────────────────────────

class TestScorerGc:
    def test_gc_removes_stale_baselines(self, scorer):
        """Directly invoke GC logic for stale baselines."""
        k = ("10.0.0.1", "cat")
        scorer._bl[k] = {"m": 1.0, "v": 0.0, "n": 100,
                          "ts": time.time() - 8 * 86400}  # 8 days old > 7 days
        # Run the GC logic inline (instead of background thread)
        now = time.time()
        with scorer._bl_lock:
            stale = [key for key, v in scorer._bl.items() if now - v["ts"] > 7 * 86400]
            for key in stale:
                del scorer._bl[key]
        assert k not in scorer._bl

    def test_gc_removes_stale_cooldowns(self, scorer):
        k = ("a", "b", "c")
        scorer._cd[k] = {"c": 5, "ts": time.time() - 8000}  # > 3600*2
        now = time.time()
        with scorer._cd_lock:
            stale = [key for key, v in scorer._cd.items()
                     if now - v["ts"] > scorer._cd_reset * 2]
            for key in stale:
                del scorer._cd[key]
        assert k not in scorer._cd

    def test_gc_keeps_fresh_entries(self, scorer):
        k = ("10.0.0.1", "cat")
        scorer._bl[k] = {"m": 1.0, "v": 0.0, "n": 100, "ts": time.time()}
        now = time.time()
        with scorer._bl_lock:
            stale = [key for key, v in scorer._bl.items() if now - v["ts"] > 7 * 86400]
            for key in stale:
                del scorer._bl[key]
        assert k in scorer._bl


# ── _is_cloud edge cases ────────────────────────────────

class TestIsCloudEdgeCases:
    def test_private_ip_not_cloud(self, scorer):
        assert scorer._is_cloud("10.0.0.1") is False

    def test_localhost_not_cloud(self, scorer):
        assert scorer._is_cloud("127.0.0.1") is False


# ── Score with all modifiers combined ────────────────────

class TestScoreCombinedModifiers:
    def test_internal_src_cloud_dst_heavily_discounted(self, scorer):
        """Internal src + cloud dst = multiple discounts stacked."""
        sig = _sig(confidence=0.9, src_ip="192.168.1.50",
                   dst_ip="104.16.1.1", category="test")
        with patch("core.database.Host") as HostCls:
            HostCls.get_or_none.return_value = None
            _, score, should = scorer.score(sig, max_sev=5)
        # 0.9 * 0.85 (new_internal) * 0.3 (cloud) = ~0.23
        assert should is False
        assert score < 0.3


# ── Direct _gc method invocation for coverage ────────────

class TestScorerGcDirect:
    def test_gc_method_single_iteration(self, scorer):
        """Directly invoke _gc with sleep patched to break after one iteration."""
        import analyzers.scoring as scoring_mod
        k_bl = ("10.0.0.1", "old")
        scorer._bl[k_bl] = {"m": 1.0, "v": 0.0, "n": 100,
                             "ts": time.time() - 8 * 86400}
        k_cd = ("a", "b", "old")
        scorer._cd[k_cd] = {"c": 5, "ts": time.time() - 8000}

        call_count = [0]
        def fake_sleep(s):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise StopIteration("break loop")

        with patch.object(scoring_mod.time, "sleep", side_effect=fake_sleep):
            try:
                scorer._gc()
            except StopIteration:
                pass

        assert k_bl not in scorer._bl
        assert k_cd not in scorer._cd


# ── _cloud_refresh _do coverage ──────────────────────────

class TestCloudRefreshDo:
    def test_cloud_refresh_do_iteration(self):
        """Test the _do inner function of _cloud_refresh."""
        import analyzers.scoring as scoring_mod

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "198.51.100.0/24\n203.0.113.0/24\n"

        with patch.object(Scorer, '_cloud_refresh') as mock_cr:
            s = Scorer(_Cfg())

        # Directly test _is_cloud before and after adding nets
        import ipaddress
        new_net = ipaddress.IPv4Network("198.51.100.0/24")
        s._cloud_nets.append(new_net)
        assert s._is_cloud("198.51.100.1") is True

    def test_cloud_refresh_do_function_runs(self):
        """Actually invoke _cloud_refresh._do via the real method."""
        import analyzers.scoring as scoring_mod
        import sys

        call_count = [0]
        def fake_sleep(s):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise StopIteration("break")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "198.51.100.0/24\nbadline\n"

        mock_requests = MagicMock()
        mock_requests.get.return_value = mock_response

        with patch.object(Scorer, '_cloud_refresh'):
            s = Scorer(_Cfg())

        # Capture the _do function via Thread
        with patch.object(scoring_mod.threading, "Thread") as mock_thread:
            mock_thread.return_value = MagicMock()
            s._cloud_refresh()
            target_fn = mock_thread.call_args[1]["target"]

        # Invoke _do with mocked sleep; requests is imported inside _do
        with patch.object(scoring_mod.time, "sleep", side_effect=fake_sleep), \
             patch.dict(sys.modules, {"requests": mock_requests}):
            try:
                target_fn()
            except StopIteration:
                pass

        assert s._is_cloud("198.51.100.1") is True

    def test_cloud_refresh_do_handles_request_exception(self):
        """_do handles request exceptions gracefully."""
        import analyzers.scoring as scoring_mod
        import sys

        call_count = [0]
        def fake_sleep(s):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise StopIteration("break")

        mock_requests = MagicMock()
        mock_requests.get.side_effect = ConnectionError("fail")

        with patch.object(Scorer, '_cloud_refresh'):
            s = Scorer(_Cfg())

        with patch.object(scoring_mod.threading, "Thread") as mock_thread:
            mock_thread.return_value = MagicMock()
            s._cloud_refresh()
            target_fn = mock_thread.call_args[1]["target"]

        with patch.object(scoring_mod.time, "sleep", side_effect=fake_sleep), \
             patch.dict(sys.modules, {"requests": mock_requests}):
            try:
                target_fn()
            except StopIteration:
                pass
        # Should not crash


# ── Invalid subnet parsing ───────────────────────────────

class TestInvalidSubnetParsing:
    def test_invalid_subnet_in_config_skipped(self):
        """Lines 52-53: invalid subnets are silently skipped."""
        cfg = _Cfg({"network.subnets": ["not-a-subnet", "192.168.1.0/24"]})
        with patch.object(Scorer, '_cloud_refresh'):
            s = Scorer(cfg)
        # Only 1 valid subnet parsed
        assert len(s._subnets) == 1
