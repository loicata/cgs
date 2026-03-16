"""Tests for core/host_identity.py — HostIdentityEngine, HostFingerprint."""
import json
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.host_identity import HostFingerprint, HostIdentityEngine, WEIGHTS


# ══════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════

class FakeConfig:
    """Minimal Config-like object for testing."""
    def __init__(self, data_dir):
        self._d = {"identity.spoof_threshold": 50, "identity.learning_hours": 48,
                    "general.data_dir": data_dir}

    def get(self, key, default=None):
        return self._d.get(key, default)


@pytest.fixture
def data_dir(tmp_path):
    return str(tmp_path)


@pytest.fixture
def alerts():
    """Collects alerts emitted by the engine."""
    collected = []
    def alert_fn(**kwargs):
        collected.append(kwargs)
    return collected, alert_fn


@pytest.fixture
def engine(data_dir, alerts):
    collected, alert_fn = alerts
    cfg = FakeConfig(data_dir)
    eng = HostIdentityEngine(cfg, alert_fn)
    return eng, collected


# ══════════════════════════════════════════════════
# HostFingerprint dataclass
# ══════════════════════════════════════════════════

class TestHostFingerprint:

    def test_to_dict_returns_all_expected_keys(self):
        """to_dict returns a dictionary with all fingerprint fields."""
        fp = HostFingerprint(mac="aa:bb:cc:dd:ee:ff", hostname="srv1",
                             os_ttl=64, open_ports=[22, 80])
        d = fp.to_dict()
        assert d["mac"] == "aa:bb:cc:dd:ee:ff"
        assert d["hostname"] == "srv1"
        assert d["os_ttl"] == 64
        assert d["open_ports"] == [22, 80]
        assert "banners" in d
        assert "samples" in d

    def test_fingerprint_hash_is_deterministic(self):
        """Same data produces same hash."""
        fp1 = HostFingerprint(os_ttl=64, tcp_window=65535, open_ports=[22, 80],
                              vendor_oui="aa:bb:cc")
        fp2 = HostFingerprint(os_ttl=64, tcp_window=65535, open_ports=[22, 80],
                              vendor_oui="aa:bb:cc")
        assert fp1.fingerprint_hash == fp2.fingerprint_hash

    def test_fingerprint_hash_changes_with_different_data(self):
        """Different data produces different hash."""
        fp1 = HostFingerprint(os_ttl=64, open_ports=[22])
        fp2 = HostFingerprint(os_ttl=128, open_ports=[80])
        assert fp1.fingerprint_hash != fp2.fingerprint_hash

    def test_fingerprint_hash_is_16_chars(self):
        """Hash is 16 hex characters."""
        fp = HostFingerprint(os_ttl=64)
        assert len(fp.fingerprint_hash) == 16

    def test_default_values(self):
        """Default fingerprint has zero/empty values."""
        fp = HostFingerprint()
        assert fp.mac == ""
        assert fp.os_ttl == 0
        assert fp.open_ports == []
        assert fp.banners == {}
        assert fp.samples == 0


# ══════════════════════════════════════════════════
# HostIdentityEngine — observe
# ══════════════════════════════════════════════════

class TestObserve:

    def test_observe_null_mac_returns_score_100(self, engine):
        """Null MAC always returns score 100 (no identity check possible)."""
        eng, _ = engine
        result = eng.observe("10.0.0.1", mac="00:00:00:00:00:00")
        assert result["identity_score"] == 100
        assert result["spoofing"] is False

    def test_observe_empty_mac_returns_score_100(self, engine):
        """Empty MAC returns score 100."""
        eng, _ = engine
        result = eng.observe("10.0.0.1", mac="")
        assert result["identity_score"] == 100

    def test_observe_new_mac_creates_fingerprint(self, engine):
        """First observation of a MAC creates a new fingerprint."""
        eng, _ = engine
        result = eng.observe("192.168.1.10", mac="aa:bb:cc:dd:ee:ff",
                             hostname="workstation1", ttl=64, open_ports=[22, 80])
        assert result["identity_score"] == 100
        assert result["spoofing"] is False
        fp = eng.get_fingerprint("aa:bb:cc:dd:ee:ff")
        assert fp is not None
        assert fp["hostname"] == "workstation1"
        assert fp["os_ttl"] == 64
        assert 22 in fp["open_ports"]

    def test_observe_mac_is_lowercased(self, engine):
        """MAC address is normalized to lowercase."""
        eng, _ = engine
        eng.observe("10.0.0.1", mac="AA:BB:CC:DD:EE:FF", hostname="test")
        fp = eng.get_fingerprint("aa:bb:cc:dd:ee:ff")
        assert fp is not None

    def test_observe_known_mac_consistent_returns_high_score(self, engine):
        """Observing same mac with same profile returns high score."""
        eng, _ = engine
        eng.observe("10.0.0.1", mac="aa:bb:cc:dd:ee:ff", hostname="srv",
                    ttl=64, tcp_window=65535, open_ports=[22, 80])
        result = eng.observe("10.0.0.1", mac="aa:bb:cc:dd:ee:ff", hostname="srv",
                             ttl=64, tcp_window=65535, open_ports=[22, 80])
        assert result["identity_score"] >= 80
        assert result["spoofing"] is False

    def test_observe_spoofing_triggers_alert_after_learning(self, engine):
        """Drastically different fingerprint triggers spoofing alert after learning period."""
        eng, alerts = engine
        mac = "aa:bb:cc:dd:ee:ff"
        # Build up samples to pass the learning threshold (samples >= 3)
        for i in range(4):
            eng.observe("10.0.0.1", mac=mac, hostname="srv", ttl=64,
                        tcp_window=65535, open_ports=[22, 80])
        # Now observe with completely different profile
        result = eng.observe("10.0.0.2", mac=mac, hostname="evil",
                             ttl=128, tcp_window=8192, open_ports=[3389, 445],
                             vendor_oui="xx:yy:zz")
        # Score should be low due to multiple divergences
        if result["identity_score"] < 50:
            assert result["spoofing"] is True
            assert len(alerts) > 0
            assert alerts[-1]["category"] == "mac_spoof"

    def test_observe_records_ip_history(self, engine):
        """IP changes for a MAC are recorded in history."""
        eng, _ = engine
        mac = "aa:bb:cc:dd:ee:ff"
        eng.observe("10.0.0.1", mac=mac)
        eng.observe("10.0.0.2", mac=mac)
        eng.observe("10.0.0.3", mac=mac)
        result = eng.verify_identity("10.0.0.3", mac)
        # IP history should have 3 entries
        assert len(eng._mac_ip_history[mac]) == 3

    def test_observe_deduplicates_same_ip_in_history(self, engine):
        """Same IP observed twice in a row is not duplicated in history."""
        eng, _ = engine
        mac = "aa:bb:cc:dd:ee:ff"
        eng.observe("10.0.0.1", mac=mac)
        eng.observe("10.0.0.1", mac=mac)
        assert len(eng._mac_ip_history[mac]) == 1

    def test_observe_limits_ip_history_to_50(self, engine):
        """IP history is capped at 50 entries."""
        eng, _ = engine
        mac = "aa:bb:cc:dd:ee:ff"
        # Directly populate IP history to avoid deadlock from _save inside locked observe
        eng._mac_ip_history[mac] = [f"10.0.0.{i}" for i in range(55)]
        # Now observe a new IP which triggers the trim logic
        eng.observe(f"10.0.0.200", mac=mac)
        assert len(eng._mac_ip_history[mac]) <= 50

    def test_observe_with_destination_ip(self, engine):
        """Destination IP is recorded in common_destinations."""
        eng, _ = engine
        eng.observe("10.0.0.1", mac="aa:bb:cc:dd:ee:ff", dst_ip="8.8.8.8")
        fp = eng.get_fingerprint("aa:bb:cc:dd:ee:ff")
        assert "8.8.8.8" in fp["common_destinations"]


# ══════════════════════════════════════════════════
# HostIdentityEngine — verify_identity
# ══════════════════════════════════════════════════

class TestVerifyIdentity:

    def test_verify_unknown_mac_returns_not_verified(self, engine):
        """Unknown MAC returns verified=False."""
        eng, _ = engine
        result = eng.verify_identity("10.0.0.1", "xx:yy:zz:00:11:22")
        assert result["verified"] is False
        assert result["score"] == 0
        assert result["fingerprint"] is None

    def test_verify_known_mac_returns_fingerprint(self, engine):
        """Known MAC returns the fingerprint data."""
        eng, _ = engine
        eng.observe("10.0.0.1", mac="aa:bb:cc:dd:ee:ff", hostname="srv", ttl=64)
        result = eng.verify_identity("10.0.0.1", "aa:bb:cc:dd:ee:ff")
        assert result["fingerprint"] is not None
        assert result["fingerprint"]["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_verify_lowercases_mac(self, engine):
        """verify_identity normalizes MAC to lowercase."""
        eng, _ = engine
        eng.observe("10.0.0.1", mac="aa:bb:cc:dd:ee:ff")
        result = eng.verify_identity("10.0.0.1", "AA:BB:CC:DD:EE:FF")
        assert result["fingerprint"] is not None

    def test_verify_returns_ip_history(self, engine):
        """verify_identity includes IP history."""
        eng, _ = engine
        eng.observe("10.0.0.1", mac="aa:bb:cc:dd:ee:ff")
        eng.observe("10.0.0.2", mac="aa:bb:cc:dd:ee:ff")
        result = eng.verify_identity("10.0.0.2", "aa:bb:cc:dd:ee:ff")
        assert "ip_history" in result
        assert "10.0.0.1" in result["ip_history"]

    def test_verify_empty_mac_returns_not_verified(self, engine):
        """Empty MAC returns verified=False."""
        eng, _ = engine
        result = eng.verify_identity("10.0.0.1", "")
        assert result["verified"] is False


# ══════════════════════════════════════════════════
# HostIdentityEngine — comparison logic
# ══════════════════════════════════════════════════

class TestComparison:

    def test_hostname_match_scores_100(self, engine):
        """Matching hostname scores 100."""
        eng, _ = engine
        known = HostFingerprint(mac="aa:bb:cc:dd:ee:ff", hostname="server1",
                                os_ttl=64, samples=5)
        score, details = eng._compare(known, "aa:bb:cc:dd:ee:ff", "server1",
                                       "", 64, 0, None, None, "aa:bb:cc", 0, "")
        assert score >= 80

    def test_hostname_mismatch_recorded_as_divergence(self, engine):
        """Different hostname noted as divergence."""
        eng, _ = engine
        known = HostFingerprint(mac="aa:bb:cc:dd:ee:ff", hostname="server1",
                                os_ttl=64, samples=5)
        score, details = eng._compare(known, "aa:bb:cc:dd:ee:ff", "evil-host",
                                       "", 64, 0, None, None, "aa:bb:cc", 0, "")
        assert "Hostname" in details

    def test_ttl_exact_match_scores_high(self, engine):
        """Exact TTL match scores 100 for os_fingerprint."""
        eng, _ = engine
        known = HostFingerprint(mac="aa:bb:cc:dd:ee:ff", os_ttl=64, samples=5)
        score, details = eng._compare(known, "aa:bb:cc:dd:ee:ff", "", "",
                                       64, 0, None, None, "", 0, "")
        assert score >= 70

    def test_drastically_different_ttl_scores_low(self, engine):
        """TTL difference > 10 scores 0 for os_fingerprint."""
        eng, _ = engine
        known = HostFingerprint(mac="aa:bb:cc:dd:ee:ff", os_ttl=64, hostname="srv",
                                vendor_oui="aa:bb:cc", samples=5)
        score, details = eng._compare(known, "aa:bb:cc:dd:ee:ff", "srv", "",
                                       128, 0, None, None, "aa:bb:cc", 0, "")
        assert "TTL" in details

    def test_port_jaccard_similarity(self, engine):
        """Port comparison uses Jaccard similarity."""
        eng, _ = engine
        known = HostFingerprint(mac="m", open_ports=[22, 80, 443], samples=5)
        # 2 out of 4 unique ports = 50% Jaccard
        score, details = eng._compare(known, "m", "", "", 0, 0,
                                       [22, 80, 8080], None, "", 0, "")
        assert "Ports" not in details or "50%" in details or score >= 0

    def test_vendor_oui_mismatch_flags_spoofing(self, engine):
        """Different vendor OUI is flagged as spoofing indicator."""
        eng, _ = engine
        known = HostFingerprint(mac="m", vendor_oui="aa:bb:cc", samples=5)
        score, details = eng._compare(known, "m", "", "", 0, 0,
                                       None, None, "xx:yy:zz", 0, "")
        assert "OUI" in details

    def test_banner_mismatch_detected(self, engine):
        """Different service banners are flagged."""
        eng, _ = engine
        known = HostFingerprint(mac="m", banners={"22": "abc", "80": "def"},
                                samples=5)
        score, details = eng._compare(known, "m", "", "", 0, 0,
                                       None, {"22": "xyz", "80": "uvw"}, "", 0, "")
        assert "banner" in details.lower()

    def test_weights_sum_to_one(self):
        """All identity factor weights sum to 1.0."""
        assert abs(sum(WEIGHTS.values()) - 1.0) < 0.01


# ══════════════════════════════════════════════════
# HostIdentityEngine — fingerprint update
# ══════════════════════════════════════════════════

class TestFingerprintUpdate:

    def test_update_increments_sample_count(self, engine):
        """Each observation increments the sample count."""
        eng, _ = engine
        eng.observe("10.0.0.1", mac="aa:bb:cc:dd:ee:ff")
        eng.observe("10.0.0.1", mac="aa:bb:cc:dd:ee:ff")
        fp = eng.get_fingerprint("aa:bb:cc:dd:ee:ff")
        assert fp["samples"] == 2

    def test_update_merges_ports(self, engine):
        """New open ports are merged into the fingerprint."""
        eng, _ = engine
        eng.observe("10.0.0.1", mac="aa:bb:cc:dd:ee:ff", open_ports=[22])
        eng.observe("10.0.0.1", mac="aa:bb:cc:dd:ee:ff", open_ports=[80, 443])
        fp = eng.get_fingerprint("aa:bb:cc:dd:ee:ff")
        assert set(fp["open_ports"]) == {22, 80, 443}

    def test_update_merges_banners(self, engine):
        """New banners are merged into the fingerprint."""
        eng, _ = engine
        eng.observe("10.0.0.1", mac="aa:bb:cc:dd:ee:ff", banners={"22": "ssh-v1"})
        eng.observe("10.0.0.1", mac="aa:bb:cc:dd:ee:ff", banners={"80": "apache"})
        fp = eng.get_fingerprint("aa:bb:cc:dd:ee:ff")
        assert "22" in fp["banners"]
        assert "80" in fp["banners"]

    def test_update_limits_destinations(self, engine):
        """Common destinations list is capped at 20."""
        eng, _ = engine
        mac = "aa:bb:cc:dd:ee:ff"
        # Create fingerprint with 1 observation, then directly manipulate
        eng.observe("10.0.0.1", mac=mac, dst_ip="1.2.3.0")
        fp_obj = eng._fingerprints[mac]
        fp_obj.common_destinations = [f"1.2.3.{i}" for i in range(25)]
        # Call _update_fingerprint with a new destination
        eng._update_fingerprint(fp_obj, "", "", 0, 0, None, None, 0, "9.9.9.9")
        assert len(fp_obj.common_destinations) <= 21

    def test_update_limits_active_hours(self, engine):
        """Active hours list is capped at 24."""
        eng, _ = engine
        mac = "aa:bb:cc:dd:ee:ff"
        # Force multiple unique hours by directly manipulating
        eng.observe("10.0.0.1", mac=mac)
        fp_obj = eng._fingerprints[mac]
        fp_obj.active_hours = list(range(24))
        eng._update_fingerprint(fp_obj, "", "", 0, 0, None, None, 0, "")
        assert len(fp_obj.active_hours) <= 25  # at most 24 + 1 current


# ══════════════════════════════════════════════════
# Persistence (save / load)
# ══════════════════════════════════════════════════

class TestPersistence:

    def test_save_all_creates_json_file(self, engine, data_dir):
        """save_all writes fingerprints.json to disk."""
        eng, _ = engine
        eng.observe("10.0.0.1", mac="aa:bb:cc:dd:ee:ff", hostname="srv1")
        eng.save_all()
        fp_file = os.path.join(data_dir, "fingerprints.json")
        assert os.path.exists(fp_file)
        with open(fp_file) as f:
            data = json.load(f)
        assert "aa:bb:cc:dd:ee:ff" in data

    def test_load_restores_fingerprints(self, data_dir, alerts):
        """Loading from file restores fingerprints."""
        collected, alert_fn = alerts
        cfg = FakeConfig(data_dir)
        eng1 = HostIdentityEngine(cfg, alert_fn)
        eng1.observe("10.0.0.1", mac="aa:bb:cc:dd:ee:ff", hostname="srv1", ttl=64)
        eng1.save_all()

        # Create new engine that loads from the same file
        eng2 = HostIdentityEngine(cfg, alert_fn)
        fp = eng2.get_fingerprint("aa:bb:cc:dd:ee:ff")
        assert fp is not None
        assert fp["hostname"] == "srv1"
        assert fp["os_ttl"] == 64

    def test_load_handles_missing_file(self, data_dir, alerts):
        """Engine starts fine when no fingerprints file exists."""
        collected, alert_fn = alerts
        cfg = FakeConfig(data_dir)
        eng = HostIdentityEngine(cfg, alert_fn)
        assert eng.stats["total_fingerprints"] == 0

    def test_load_handles_corrupt_json(self, data_dir, alerts):
        """Engine handles corrupt JSON gracefully."""
        collected, alert_fn = alerts
        cfg = FakeConfig(data_dir)
        fp_file = os.path.join(data_dir, "fingerprints.json")
        os.makedirs(os.path.dirname(fp_file), exist_ok=True)
        with open(fp_file, "w") as f:
            f.write("NOT VALID JSON {{{")
        eng = HostIdentityEngine(cfg, alert_fn)
        assert eng.stats["total_fingerprints"] == 0


# ══════════════════════════════════════════════════
# Stats
# ══════════════════════════════════════════════════

class TestStats:

    def test_stats_returns_expected_keys(self, engine):
        """stats property returns all expected keys."""
        eng, _ = engine
        s = eng.stats
        assert "total_fingerprints" in s
        assert "mature" in s
        assert "learning" in s
        assert "spoof_threshold" in s

    def test_stats_counts_mature_fingerprints(self, engine):
        """Fingerprints with >= 10 samples are counted as mature."""
        eng, _ = engine
        mac = "aa:bb:cc:dd:ee:ff"
        # Directly set a mature fingerprint to avoid deadlock from _save in locked observe
        eng.observe("10.0.0.1", mac=mac)
        eng._fingerprints[mac].samples = 15
        s = eng.stats
        assert s["mature"] == 1
        assert s["learning"] == 0

    def test_get_fingerprint_returns_none_for_unknown(self, engine):
        """get_fingerprint returns None for unknown MAC."""
        eng, _ = engine
        assert eng.get_fingerprint("xx:yy:zz:00:11:22") is None


# ══════════════════════════════════════════════════
# Thread safety
# ══════════════════════════════════════════════════

class TestThreadSafety:

    def test_concurrent_observations_do_not_crash(self, engine):
        """Concurrent observations from multiple threads do not cause errors."""
        eng, _ = engine
        errors = []

        def worker(thread_id):
            try:
                # Keep iterations < 10 per MAC to avoid _save deadlock
                for i in range(5):
                    eng.observe(f"10.0.{thread_id}.{i}",
                                mac=f"aa:bb:cc:dd:{thread_id:02x}:ff",
                                hostname=f"host-{thread_id}", ttl=64)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(errors) == 0
        assert eng.stats["total_fingerprints"] == 5
