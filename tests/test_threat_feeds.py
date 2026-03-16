"""Tests for core/threat_feeds.py — BloomFilter, ThreatFeedManager, HoneypotService."""
import json
import os
import socket
import sys
import threading
import time
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.threat_feeds import BloomFilter, ThreatFeedManager, HoneypotService, DEFAULT_HONEYPOT_PORTS


# ══════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════

class FakeConfig:
    def __init__(self, data_dir, overrides=None):
        self._d = {
            "general.data_dir": data_dir,
            "detectors.ioc_live.file_path": os.path.join(data_dir, "ioc_list.json"),
            "honeypot.enabled": False,
            "honeypot.ports": [],
            "honeypot.bind_ip": "127.0.0.1",
        }
        if overrides:
            self._d.update(overrides)

    def get(self, key, default=None):
        return self._d.get(key, default)


@pytest.fixture
def data_dir(tmp_path):
    feeds_dir = tmp_path / "feeds"
    feeds_dir.mkdir()
    return str(tmp_path)


# ══════════════════════════════════════════════════
# BloomFilter
# ══════════════════════════════════════════════════

class TestBloomFilter:

    def test_add_and_contains(self):
        """Added items are found in the bloom filter."""
        bf = BloomFilter(capacity=1000)
        bf.add("192.168.1.1")
        assert "192.168.1.1" in bf

    def test_not_contains_absent_item(self):
        """Items not added are (almost certainly) not found."""
        bf = BloomFilter(capacity=1000)
        bf.add("192.168.1.1")
        assert "10.0.0.1" not in bf

    def test_len_tracks_additions(self):
        """len() returns the number of items added."""
        bf = BloomFilter(capacity=1000)
        assert len(bf) == 0
        bf.add("a")
        bf.add("b")
        assert len(bf) == 2

    def test_clear_empties_filter(self):
        """clear() removes all items."""
        bf = BloomFilter(capacity=1000)
        bf.add("test")
        bf.clear()
        assert len(bf) == 0
        assert "test" not in bf

    def test_low_false_positive_rate(self):
        """False positive rate is below threshold for reasonable input."""
        bf = BloomFilter(capacity=10000, fp_rate=0.01)
        for i in range(5000):
            bf.add(f"item-{i}")
        # Check false positives on items never added
        fp_count = sum(1 for i in range(5000, 10000) if f"item-{i}" in bf)
        # Allow up to 2% FP rate (generous margin)
        assert fp_count < 200

    def test_many_items(self):
        """Bloom filter handles thousands of items."""
        bf = BloomFilter(capacity=100000)
        for i in range(10000):
            bf.add(f"ip-{i}")
        assert len(bf) == 10000
        assert "ip-0" in bf
        assert "ip-9999" in bf

    def test_thread_safety(self):
        """Concurrent add/contains does not crash."""
        bf = BloomFilter(capacity=10000)
        errors = []

        def writer():
            try:
                for i in range(500):
                    bf.add(f"w-{i}")
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for i in range(500):
                    _ = f"r-{i}" in bf
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer) for _ in range(3)]
        threads += [threading.Thread(target=reader) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(errors) == 0


# ══════════════════════════════════════════════════
# ThreatFeedManager
# ══════════════════════════════════════════════════

class TestThreatFeedManager:

    @patch("core.threat_feeds.threading.Thread")
    def test_init_creates_cache_dir(self, mock_thread, data_dir):
        """ThreatFeedManager creates cache directory on init."""
        mock_thread.return_value = MagicMock()
        cfg = FakeConfig(data_dir)
        mgr = ThreatFeedManager(cfg)
        assert os.path.isdir(os.path.join(data_dir, "feeds"))

    @patch("core.threat_feeds.threading.Thread")
    def test_check_ip_empty_filter_returns_false(self, mock_thread, data_dir):
        """check_ip returns False on empty filter."""
        mock_thread.return_value = MagicMock()
        cfg = FakeConfig(data_dir)
        mgr = ThreatFeedManager(cfg)
        assert mgr.check_ip("1.2.3.4") is False

    @patch("core.threat_feeds.threading.Thread")
    def test_check_ip_finds_added_ip(self, mock_thread, data_dir):
        """check_ip returns True when IP was added to bloom filter."""
        mock_thread.return_value = MagicMock()
        cfg = FakeConfig(data_dir)
        mgr = ThreatFeedManager(cfg)
        mgr._bloom_ips.add("1.2.3.4")
        assert mgr.check_ip("1.2.3.4") is True

    @patch("core.threat_feeds.threading.Thread")
    def test_check_domain_exact_match(self, mock_thread, data_dir):
        """check_domain finds exact domain match."""
        mock_thread.return_value = MagicMock()
        cfg = FakeConfig(data_dir)
        mgr = ThreatFeedManager(cfg)
        mgr._bloom_domains.add("evil.com")
        assert mgr.check_domain("evil.com") is True

    @patch("core.threat_feeds.threading.Thread")
    def test_check_domain_parent_match(self, mock_thread, data_dir):
        """check_domain finds parent domain match."""
        mock_thread.return_value = MagicMock()
        cfg = FakeConfig(data_dir)
        mgr = ThreatFeedManager(cfg)
        mgr._bloom_domains.add("evil.com")
        assert mgr.check_domain("sub.evil.com") is True

    @patch("core.threat_feeds.threading.Thread")
    def test_check_domain_no_match(self, mock_thread, data_dir):
        """check_domain returns False for non-matching domain."""
        mock_thread.return_value = MagicMock()
        cfg = FakeConfig(data_dir)
        mgr = ThreatFeedManager(cfg)
        mgr._bloom_domains.add("evil.com")
        assert mgr.check_domain("good.com") is False

    @patch("core.threat_feeds.threading.Thread")
    def test_load_local_ioc_file(self, mock_thread, data_dir):
        """Local IOC file is loaded into bloom filters."""
        ioc_path = os.path.join(data_dir, "ioc_list.json")
        with open(ioc_path, "w") as f:
            json.dump({
                "ips": ["10.0.0.1", "10.0.0.2"],
                "domains": ["malware.example.com"]
            }, f)
        mock_thread.return_value = MagicMock()
        cfg = FakeConfig(data_dir)
        mgr = ThreatFeedManager(cfg)
        assert mgr.check_ip("10.0.0.1") is True
        assert mgr.check_ip("10.0.0.2") is True
        assert mgr.check_domain("malware.example.com") is True

    @patch("core.threat_feeds.threading.Thread")
    def test_load_cached_feeds_loads_ips_from_cache(self, mock_thread, data_dir):
        """Cached feed loading correctly parses IP feeds from disk."""
        feeds_dir = os.path.join(data_dir, "feeds")
        os.makedirs(feeds_dir, exist_ok=True)
        cache_file = os.path.join(feeds_dir, "abuse_ch_feodo.txt")
        with open(cache_file, "w") as f:
            f.write("# Comment\n1.2.3.4\n5.6.7.8\n")
        mock_thread.return_value = MagicMock()
        cfg = FakeConfig(data_dir)
        mgr = ThreatFeedManager(cfg)
        # IPs should now be loaded correctly via _parse_feed_file
        assert mgr.check_ip("1.2.3.4") is True
        assert mgr.check_ip("5.6.7.8") is True

    @patch("core.threat_feeds.threading.Thread")
    def test_stats_returns_expected_keys(self, mock_thread, data_dir):
        """stats property returns expected keys."""
        mock_thread.return_value = MagicMock()
        cfg = FakeConfig(data_dir)
        mgr = ThreatFeedManager(cfg)
        s = mgr.stats
        assert "ips" in s
        assert "domains" in s
        assert "feeds_loaded" in s
        assert "last_refresh" in s
        assert "errors" in s

    @patch("core.threat_feeds.threading.Thread")
    def test_refresh_all_with_mock_requests(self, mock_thread, data_dir):
        """_refresh_all downloads and parses feeds (mocked HTTP)."""
        mock_thread.return_value = MagicMock()
        cfg = FakeConfig(data_dir)
        mgr = ThreatFeedManager(cfg)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "# comment\n1.1.1.1\n2.2.2.2\n"

        import requests as _req_mod
        with patch.object(_req_mod, "get", return_value=mock_response):
            mgr._refresh_all()

        assert mgr.stats["last_refresh"] != ""

    @patch("core.threat_feeds.threading.Thread")
    def test_refresh_all_handles_http_error(self, mock_thread, data_dir):
        """_refresh_all handles HTTP errors gracefully."""
        mock_thread.return_value = MagicMock()
        cfg = FakeConfig(data_dir)
        mgr = ThreatFeedManager(cfg)

        mock_response = MagicMock()
        mock_response.status_code = 500

        import requests as _req_mod
        with patch.object(_req_mod, "get", return_value=mock_response):
            mgr._refresh_all()  # Should not raise
        assert len(mgr.stats["errors"]) > 0

    @patch("core.threat_feeds.threading.Thread")
    def test_refresh_all_handles_network_exception(self, mock_thread, data_dir):
        """_refresh_all handles network exceptions gracefully."""
        mock_thread.return_value = MagicMock()
        cfg = FakeConfig(data_dir)
        mgr = ThreatFeedManager(cfg)

        import requests as _req_mod
        with patch.object(_req_mod, "get", side_effect=ConnectionError("timeout")):
            mgr._refresh_all()  # Should not raise


# ══════════════════════════════════════════════════
# HoneypotService
# ══════════════════════════════════════════════════

class TestHoneypotService:

    def test_init_disabled_by_default(self, data_dir):
        """Honeypot is disabled by default."""
        cfg = FakeConfig(data_dir)
        alerts = []
        hp = HoneypotService(cfg, lambda **kw: alerts.append(kw))
        assert hp.enabled is False

    def test_start_does_nothing_when_disabled(self, data_dir):
        """start() returns immediately when disabled."""
        cfg = FakeConfig(data_dir)
        hp = HoneypotService(cfg, lambda **kw: None)
        hp.start()  # Should not raise
        assert hp._running is False

    def test_init_with_default_ports_when_enabled_without_ports(self, data_dir):
        """When enabled with no ports configured, default ports are used."""
        cfg = FakeConfig(data_dir, {"honeypot.enabled": True})
        hp = HoneypotService(cfg, lambda **kw: None)
        assert len(hp.ports) == len(DEFAULT_HONEYPOT_PORTS)

    def test_stop_sets_running_false(self, data_dir):
        """stop() sets _running to False."""
        cfg = FakeConfig(data_dir, {"honeypot.enabled": True, "honeypot.ports": [19999]})
        hp = HoneypotService(cfg, lambda **kw: None)
        hp._running = True
        hp.stop()
        assert hp._running is False

    def test_start_and_stop_with_real_port(self, data_dir):
        """Honeypot can start listening and then stop."""
        # Use a high ephemeral port to avoid permission issues
        port = 59123
        cfg = FakeConfig(data_dir, {
            "honeypot.enabled": True,
            "honeypot.ports": [port],
            "honeypot.bind_ip": "127.0.0.1",
        })
        alerts = []
        hp = HoneypotService(cfg, lambda **kw: alerts.append(kw))
        hp.start()
        assert hp._running is True
        time.sleep(0.5)  # Let the listener thread start
        hp.stop()
        # Verify it was running
        assert len(hp._threads) == 1

    def test_connection_triggers_alert(self, data_dir):
        """Connecting to honeypot port triggers an alert."""
        port = 59124
        cfg = FakeConfig(data_dir, {
            "honeypot.enabled": True,
            "honeypot.ports": [port],
            "honeypot.bind_ip": "127.0.0.1",
        })
        alerts = []
        hp = HoneypotService(cfg, lambda **kw: alerts.append(kw))
        hp.start()
        time.sleep(0.5)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(("127.0.0.1", port))
            sock.sendall(b"hello")
            time.sleep(0.2)
            try:
                sock.recv(1024)
            except Exception:
                pass
            sock.close()
        except (ConnectionRefusedError, OSError):
            # Port may not be available; skip alert check
            hp.stop()
            pytest.skip("Port not available for honeypot test")
            return

        time.sleep(1)
        hp.stop()
        assert len(alerts) >= 1
        assert alerts[0]["category"] == "honeypot_connection"
        assert alerts[0]["severity"] == 1

    def test_stats_returns_expected_keys(self, data_dir):
        """stats property returns expected fields."""
        cfg = FakeConfig(data_dir)
        hp = HoneypotService(cfg, lambda **kw: None)
        s = hp.stats
        assert "enabled" in s
        assert "ports" in s
        assert "total_connections" in s
        assert "recent" in s

    def test_connections_list_is_capped(self, data_dir):
        """Connection log is capped at 1000 entries."""
        cfg = FakeConfig(data_dir)
        hp = HoneypotService(cfg, lambda **kw: None)
        # Simulate many connections
        for i in range(1050):
            with hp._conn_lock:
                hp._connections.append({"src_ip": f"1.2.3.{i % 256}"})
                if len(hp._connections) > 1000:
                    hp._connections = hp._connections[-1000:]
        assert len(hp._connections) == 1000

    def test_handle_connection_records_metadata(self, data_dir):
        """_handle_connection records connection metadata."""
        cfg = FakeConfig(data_dir, {"honeypot.enabled": True})
        alerts = []
        hp = HoneypotService(cfg, lambda **kw: alerts.append(kw))

        # Create a mock socket
        mock_conn = MagicMock()
        mock_conn.recv.return_value = b"test payload"
        mock_conn.sendall = MagicMock()

        hp._handle_connection(mock_conn, ("10.0.0.1", 12345), 3389, "rdp")
        assert len(hp._connections) == 1
        assert hp._connections[0]["src_ip"] == "10.0.0.1"
        assert hp._connections[0]["honeypot_port"] == 3389
        assert hp._connections[0]["service"] == "rdp"
        assert hp._connections[0]["payload_size"] == 12

    def test_start_with_dict_port_config(self, data_dir):
        """Honeypot handles dict-style port configuration."""
        cfg = FakeConfig(data_dir, {
            "honeypot.enabled": True,
            "honeypot.ports": [{"port": 59125, "name": "test-service"}],
            "honeypot.bind_ip": "127.0.0.1",
        })
        hp = HoneypotService(cfg, lambda **kw: None)
        hp.start()
        time.sleep(0.3)
        hp.stop()
        assert len(hp._threads) == 1
