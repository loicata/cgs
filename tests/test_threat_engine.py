"""Comprehensive tests for analyzers/threat_engine.py — ThreatEngine class."""

import math
import os
import shutil
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.database import (
    Alert, BaselineStat, DnsLog, Flow, Host, db, init_db,
)


# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _fresh_db(tmp_path):
    """Provide a clean DB for every test."""
    try:
        if not db.is_closed():
            db.close()
    except Exception:
        pass
    init_db(str(tmp_path))
    yield
    try:
        db.close()
    except Exception:
        pass


@pytest.fixture()
def cfg(tmp_path):
    """Minimal Config-like object using real Config class."""
    from core.config import Config
    import yaml

    cfg_path = os.path.join(str(tmp_path), "config.yaml")
    with open(cfg_path, "w") as f:
        yaml.dump({
            "general": {"data_dir": str(tmp_path), "log_dir": str(tmp_path)},
            "analysis": {
                "portscan_threshold": 5,
                "bruteforce_threshold": 4,
                "bruteforce_window": 60,
                "beacon_tolerance": 0.15,
                "dns_entropy_threshold": 3.5,
                "exfil_mb": 1,
            },
        }, f)
    return Config(cfg_path)


@pytest.fixture()
def alert_fn():
    return MagicMock()


@pytest.fixture()
def engine(cfg, alert_fn):
    """Create a ThreatEngine without the cleanup daemon thread."""
    with patch("analyzers.threat_engine.threading.Thread"):
        from analyzers.threat_engine import ThreatEngine
        te = ThreatEngine(cfg, alert_fn)
    return te


# ── Helpers ───────────────────────────────────────────────────


def _tcp_syn(src="10.0.0.1", dst="10.0.0.2", dport=80, size=60, ts=None):
    return {
        "type": "tcp", "src": src, "dst": dst,
        "dport": dport, "flags": "SYN", "size": size,
        "ts": ts or time.time(),
    }


def _tcp_synack(src="10.0.0.1", dst="10.0.0.2", dport=80, size=60, ts=None):
    return {
        "type": "tcp", "src": src, "dst": dst,
        "dport": dport, "flags": "SYN ACK", "size": size,
        "ts": ts or time.time(),
    }


# ══════════════════════════════════════════════════════════════
# __init__
# ══════════════════════════════════════════════════════════════


class TestInit:
    def test_default_thresholds_from_config(self, engine, cfg):
        assert engine.ps_th == 5
        assert engine.bf_th == 4
        assert engine.bf_win == 60
        assert engine.bcn_tol == 0.15
        assert engine.dns_th == 3.5
        assert engine.exfil == 1 * 1024 * 1024  # 1 MB

    def test_trackers_initialized_empty(self, engine):
        assert len(engine._scan_tr) == 0
        assert len(engine._bf_tr) == 0
        assert len(engine._bcn_tr) == 0
        assert len(engine._vol_tr) == 0
        assert len(engine._dns_tr) == 0
        assert len(engine._arp_tbl) == 0
        assert len(engine._risk_d) == 0
        assert len(engine._suspicious_port_alerted) == 0


# ══════════════════════════════════════════════════════════════
# on_event dispatch
# ══════════════════════════════════════════════════════════════


class TestOnEvent:
    def test_dispatches_tcp(self, engine):
        with patch.object(engine, "_tcp") as m:
            engine.on_event({"type": "tcp", "src": "1.1.1.1"})
            m.assert_called_once()

    def test_dispatches_udp(self, engine):
        with patch.object(engine, "_udp") as m:
            engine.on_event({"type": "udp", "src": "1.1.1.1"})
            m.assert_called_once()

    def test_dispatches_icmp(self, engine):
        with patch.object(engine, "_icmp") as m:
            engine.on_event({"type": "icmp", "src": "1.1.1.1"})
            m.assert_called_once()

    def test_dispatches_dns_query(self, engine):
        with patch.object(engine, "_dns") as m:
            engine.on_event({"type": "dns_query", "src": "1.1.1.1"})
            m.assert_called_once()

    def test_dispatches_arp_reply(self, engine):
        with patch.object(engine, "_arp") as m:
            engine.on_event({"type": "arp_reply", "src_ip": "1.1.1.1"})
            m.assert_called_once()

    def test_unknown_type_no_crash(self, engine):
        engine.on_event({"type": "unknown_proto"})

    def test_missing_type_no_crash(self, engine):
        engine.on_event({})

    def test_exception_in_handler_is_caught(self, engine):
        with patch.object(engine, "_tcp", side_effect=RuntimeError("boom")):
            engine.on_event({"type": "tcp"})


# ══════════════════════════════════════════════════════════════
# _tcp — SYN scan / portscan
# ══════════════════════════════════════════════════════════════


class TestTcpPortscan:
    def test_portscan_triggers_after_threshold(self, engine, alert_fn):
        for port in range(5):
            engine.on_event(_tcp_syn(dport=1000 + port))
        alert_fn.assert_any_call(
            severity=2, source="analyzer", category="portscan",
            title="Port scan from 10.0.0.1",
            detail=pytest.approx(f"5 ports, 1 hosts", abs=0),
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
        )

    def test_portscan_does_not_fire_below_threshold(self, engine, alert_fn):
        for port in range(4):
            engine.on_event(_tcp_syn(dport=1000 + port))
        for call in alert_fn.call_args_list:
            assert call.kwargs.get("category") != "portscan"

    def test_portscan_only_fires_once(self, engine, alert_fn):
        for port in range(10):
            engine.on_event(_tcp_syn(dport=1000 + port))
        portscan_calls = [c for c in alert_fn.call_args_list
                          if c.kwargs.get("category") == "portscan"]
        assert len(portscan_calls) == 1

    def test_synack_does_not_count_as_scan(self, engine, alert_fn):
        for port in range(10):
            engine.on_event(_tcp_synack(dport=1000 + port))
        portscan_calls = [c for c in alert_fn.call_args_list
                          if c.kwargs.get("category") == "portscan"]
        assert len(portscan_calls) == 0

    def test_risk_increment_on_portscan(self, engine, alert_fn):
        for port in range(5):
            engine.on_event(_tcp_syn(dport=1000 + port))
        assert engine._risk_d["10.0.0.1"] >= 25


# ══════════════════════════════════════════════════════════════
# _tcp — Network sweep / hostscan
# ══════════════════════════════════════════════════════════════


class TestTcpHostscan:
    def test_hostscan_triggers_when_enough_distinct_hosts(self, engine, alert_fn):
        for i in range(5):
            engine.on_event(_tcp_syn(dst=f"10.0.0.{10 + i}", dport=80))
        alert_fn.assert_any_call(
            severity=2, source="analyzer", category="hostscan",
            title="Network sweep from 10.0.0.1",
            detail="5 hosts", src_ip="10.0.0.1",
        )

    def test_hostscan_only_fires_once(self, engine, alert_fn):
        for i in range(10):
            engine.on_event(_tcp_syn(dst=f"10.0.0.{10 + i}", dport=80))
        hostscan_calls = [c for c in alert_fn.call_args_list
                          if c.kwargs.get("category") == "hostscan"]
        assert len(hostscan_calls) == 1


# ══════════════════════════════════════════════════════════════
# _tcp — Brute-force detection
# ══════════════════════════════════════════════════════════════


class TestTcpBruteforce:
    def test_bruteforce_ssh_triggers_after_threshold(self, engine, alert_fn):
        now = time.time()
        with patch("analyzers.threat_engine.time.time", return_value=now):
            for _ in range(4):
                engine.on_event(_tcp_syn(dport=22))
        bf_calls = [c for c in alert_fn.call_args_list
                    if c.kwargs.get("category") == "bruteforce"]
        assert len(bf_calls) == 1

    def test_bruteforce_rdp_triggers(self, engine, alert_fn):
        now = time.time()
        with patch("analyzers.threat_engine.time.time", return_value=now):
            for _ in range(4):
                engine.on_event(_tcp_syn(dport=3389))
        bf_calls = [c for c in alert_fn.call_args_list
                    if c.kwargs.get("category") == "bruteforce"]
        assert len(bf_calls) == 1

    def test_bruteforce_clears_after_alert(self, engine, alert_fn):
        now = time.time()
        with patch("analyzers.threat_engine.time.time", return_value=now):
            for _ in range(4):
                engine.on_event(_tcp_syn(dport=22))
        key = ("10.0.0.1", "10.0.0.2", 22)
        assert len(engine._bf_tr[key]) == 0  # cleared after alert

    def test_bruteforce_old_entries_expire(self, engine, alert_fn):
        """Entries older than bf_win should be pruned."""
        now = time.time()
        # Send 2 attempts at t=0
        with patch("analyzers.threat_engine.time.time", return_value=now):
            engine.on_event(_tcp_syn(dport=22))
            engine.on_event(_tcp_syn(dport=22))
        # Send 2 more at t=now+120, outside the 60s window
        with patch("analyzers.threat_engine.time.time", return_value=now + 120):
            engine.on_event(_tcp_syn(dport=22))
            engine.on_event(_tcp_syn(dport=22))
        # Should NOT fire because old entries expired
        bf_calls = [c for c in alert_fn.call_args_list
                    if c.kwargs.get("category") == "bruteforce"]
        assert len(bf_calls) == 0

    def test_non_bf_port_does_not_trigger(self, engine, alert_fn):
        now = time.time()
        with patch("analyzers.threat_engine.time.time", return_value=now):
            for _ in range(10):
                engine.on_event(_tcp_syn(dport=8080))
        bf_calls = [c for c in alert_fn.call_args_list
                    if c.kwargs.get("category") == "bruteforce"]
        assert len(bf_calls) == 0

    def test_bruteforce_risk_increment(self, engine, alert_fn):
        now = time.time()
        with patch("analyzers.threat_engine.time.time", return_value=now):
            for _ in range(4):
                engine.on_event(_tcp_syn(dport=22))
        assert engine._risk_d["10.0.0.1"] >= 30


# ══════════════════════════════════════════════════════════════
# _tcp — Suspicious port
# ══════════════════════════════════════════════════════════════


class TestTcpSuspiciousPort:
    def test_suspicious_port_4444(self, engine, alert_fn):
        now = time.time()
        with patch("analyzers.threat_engine.time.time", return_value=now):
            engine.on_event(_tcp_syn(dport=4444))
        alert_fn.assert_any_call(
            severity=2, source="analyzer", category="suspicious_port",
            title="Suspicious port 4444",
            detail="10.0.0.1 → 10.0.0.2:4444",
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
        )

    def test_suspicious_port_31337(self, engine, alert_fn):
        now = time.time()
        with patch("analyzers.threat_engine.time.time", return_value=now):
            engine.on_event(_tcp_syn(dport=31337))
        sp_calls = [c for c in alert_fn.call_args_list
                    if c.kwargs.get("category") == "suspicious_port"]
        assert len(sp_calls) >= 1

    def test_suspicious_port_5min_cooldown(self, engine, alert_fn):
        now = time.time()
        with patch("analyzers.threat_engine.time.time", return_value=now):
            engine.on_event(_tcp_syn(dport=4444))
        # Second event within cooldown — should NOT fire again
        with patch("analyzers.threat_engine.time.time", return_value=now + 100):
            engine.on_event(_tcp_syn(dport=4444))
        sp_calls = [c for c in alert_fn.call_args_list
                    if c.kwargs.get("category") == "suspicious_port"]
        assert len(sp_calls) == 1

    def test_suspicious_port_fires_again_after_cooldown(self, engine, alert_fn):
        now = time.time()
        with patch("analyzers.threat_engine.time.time", return_value=now):
            engine.on_event(_tcp_syn(dport=4444))
        with patch("analyzers.threat_engine.time.time", return_value=now + 301):
            engine.on_event(_tcp_syn(dport=4444))
        sp_calls = [c for c in alert_fn.call_args_list
                    if c.kwargs.get("category") == "suspicious_port"]
        assert len(sp_calls) == 2

    def test_normal_port_no_alert(self, engine, alert_fn):
        engine.on_event(_tcp_syn(dport=443))
        sp_calls = [c for c in alert_fn.call_args_list
                    if c.kwargs.get("category") == "suspicious_port"]
        assert len(sp_calls) == 0


# ══════════════════════════════════════════════════════════════
# _tcp — Beaconing
# ══════════════════════════════════════════════════════════════


class TestTcpBeaconing:
    def test_beaconing_not_triggered_with_few_samples(self, engine, alert_fn):
        """Fewer than 20 intervals should not trigger _check_beacon."""
        now = time.time()
        for i in range(10):
            with patch("analyzers.threat_engine.time.time", return_value=now + i * 60):
                engine.on_event(_tcp_syn(dport=443))
        bcn_calls = [c for c in alert_fn.call_args_list
                     if c.kwargs.get("category") == "beaconing"]
        assert len(bcn_calls) == 0

    def test_beaconing_triggers_with_regular_intervals(self, engine, alert_fn):
        """20+ regular intervals with low CV should trigger beaconing alert."""
        now = time.time()
        # Need 21 events (to produce 20 intervals)
        for i in range(22):
            with patch("analyzers.threat_engine.time.time", return_value=now + i * 60):
                engine.on_event(_tcp_syn(dport=443))
        bcn_calls = [c for c in alert_fn.call_args_list
                     if c.kwargs.get("category") == "beaconing"]
        assert len(bcn_calls) >= 1

    def test_beaconing_not_triggered_with_irregular_intervals(self, engine, alert_fn):
        """Highly irregular intervals should not trigger beaconing."""
        import random
        random.seed(42)
        now = time.time()
        t = now
        for i in range(25):
            t += random.uniform(5, 7200)
            with patch("analyzers.threat_engine.time.time", return_value=t):
                engine.on_event(_tcp_syn(dport=443))
        bcn_calls = [c for c in alert_fn.call_args_list
                     if c.kwargs.get("category") == "beaconing"]
        assert len(bcn_calls) == 0


# ══════════════════════════════════════════════════════════════
# _tcp — Volume tracking
# ══════════════════════════════════════════════════════════════


class TestTcpVolume:
    def test_volume_accumulated(self, engine, alert_fn):
        engine.on_event(_tcp_syn(size=1000))
        engine.on_event(_tcp_syn(size=2000))
        assert engine._vol_tr["10.0.0.1"] == 3000


# ══════════════════════════════════════════════════════════════
# _udp
# ══════════════════════════════════════════════════════════════


class TestUdp:
    def test_suspicious_udp_port_alert(self, engine, alert_fn):
        engine.on_event({
            "type": "udp", "src": "10.0.0.1", "dst": "10.0.0.2",
            "dport": 4444, "size": 100,
        })
        alert_fn.assert_any_call(
            severity=3, source="analyzer", category="suspicious_port",
            title="Suspicious UDP port 4444",
            detail="10.0.0.1 → 10.0.0.2:4444",
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
        )

    def test_normal_udp_no_alert(self, engine, alert_fn):
        engine.on_event({
            "type": "udp", "src": "10.0.0.1", "dst": "10.0.0.2",
            "dport": 53, "size": 100,
        })
        assert alert_fn.call_count == 0

    def test_udp_volume_tracking(self, engine, alert_fn):
        engine.on_event({
            "type": "udp", "src": "10.0.0.1", "dst": "10.0.0.2",
            "dport": 53, "size": 500,
        })
        assert engine._vol_tr["10.0.0.1"] == 500


# ══════════════════════════════════════════════════════════════
# _icmp — Ping sweep
# ══════════════════════════════════════════════════════════════


class TestIcmp:
    def test_ping_sweep_triggers_at_threshold(self, engine, alert_fn):
        for i in range(5):
            engine.on_event({
                "type": "icmp", "src": "10.0.0.1",
                "dst": f"10.0.0.{10 + i}", "icmp_type": 8,
            })
        alert_fn.assert_any_call(
            severity=3, source="analyzer", category="ping_sweep",
            title="Ping sweep from 10.0.0.1",
            detail="5 hosts", src_ip="10.0.0.1",
        )

    def test_ping_sweep_does_not_fire_below_threshold(self, engine, alert_fn):
        for i in range(4):
            engine.on_event({
                "type": "icmp", "src": "10.0.0.1",
                "dst": f"10.0.0.{10 + i}", "icmp_type": 8,
            })
        ps_calls = [c for c in alert_fn.call_args_list
                    if c.kwargs.get("category") == "ping_sweep"]
        assert len(ps_calls) == 0

    def test_icmp_type_not_8_ignored(self, engine, alert_fn):
        for i in range(10):
            engine.on_event({
                "type": "icmp", "src": "10.0.0.1",
                "dst": f"10.0.0.{10 + i}", "icmp_type": 0,
            })
        ps_calls = [c for c in alert_fn.call_args_list
                    if c.kwargs.get("category") == "ping_sweep"]
        assert len(ps_calls) == 0

    def test_ping_sweep_only_fires_once(self, engine, alert_fn):
        for i in range(10):
            engine.on_event({
                "type": "icmp", "src": "10.0.0.1",
                "dst": f"10.0.0.{10 + i}", "icmp_type": 8,
            })
        ps_calls = [c for c in alert_fn.call_args_list
                    if c.kwargs.get("category") == "ping_sweep"]
        assert len(ps_calls) == 1


# ══════════════════════════════════════════════════════════════
# _dns
# ══════════════════════════════════════════════════════════════


class TestDns:
    def test_dns_tunnel_high_entropy_long_query(self, engine, alert_fn):
        long_query = "aXZlcnlsb25ncXVlcnl0aGF0aXN1c2VkZm9ydHVubmVsaW5n.evil.com"
        engine.on_event({
            "type": "dns_query", "src": "10.0.0.1",
            "query": long_query, "entropy": 4.2,
        })
        alert_fn.assert_any_call(
            severity=2, source="analyzer", category="dns_tunnel",
            title="Possible DNS tunnel from 10.0.0.1",
            detail=pytest.approx(f"Query: {long_query[:80]} (entropy=4.20)", abs=0),
            src_ip="10.0.0.1", ioc=long_query,
        )

    def test_dns_tunnel_no_alert_low_entropy(self, engine, alert_fn):
        engine.on_event({
            "type": "dns_query", "src": "10.0.0.1",
            "query": "x" * 40, "entropy": 2.0,
        })
        dns_calls = [c for c in alert_fn.call_args_list
                     if c.kwargs.get("category") == "dns_tunnel"]
        assert len(dns_calls) == 0

    def test_dns_tunnel_no_alert_short_query(self, engine, alert_fn):
        engine.on_event({
            "type": "dns_query", "src": "10.0.0.1",
            "query": "short.com", "entropy": 4.5,
        })
        dns_calls = [c for c in alert_fn.call_args_list
                     if c.kwargs.get("category") == "dns_tunnel"]
        assert len(dns_calls) == 0

    def test_tor_domain_onion(self, engine, alert_fn):
        q = "something.onion.example.com"
        engine.on_event({
            "type": "dns_query", "src": "10.0.0.1",
            "query": q, "entropy": 1.0,
        })
        tor_calls = [c for c in alert_fn.call_args_list
                     if c.kwargs.get("category") == "tor_domain"]
        assert len(tor_calls) == 1

    def test_tor_domain_tor2web(self, engine, alert_fn):
        q = "something.tor2web.xyz"
        engine.on_event({
            "type": "dns_query", "src": "10.0.0.1",
            "query": q, "entropy": 1.0,
        })
        tor_calls = [c for c in alert_fn.call_args_list
                     if c.kwargs.get("category") == "tor_domain"]
        assert len(tor_calls) == 1

    def test_tor_domain_i2p(self, engine, alert_fn):
        q = "something.i2p.xyz"
        engine.on_event({
            "type": "dns_query", "src": "10.0.0.1",
            "query": q, "entropy": 1.0,
        })
        tor_calls = [c for c in alert_fn.call_args_list
                     if c.kwargs.get("category") == "tor_domain"]
        assert len(tor_calls) == 1

    def test_tor_domain_risk_increment(self, engine, alert_fn):
        engine.on_event({
            "type": "dns_query", "src": "10.0.0.1",
            "query": "x.onion.z", "entropy": 1.0,
        })
        assert engine._risk_d["10.0.0.1"] >= 20

    def test_entropy_tracked_per_source(self, engine, alert_fn):
        engine.on_event({
            "type": "dns_query", "src": "10.0.0.1",
            "query": "foo.com", "entropy": 2.5,
        })
        assert engine._dns_tr["10.0.0.1"] == [2.5]

    def test_tor_only_fires_once_per_event(self, engine, alert_fn):
        """Even if multiple tor patterns match, only one alert (break)."""
        q = "something.onion.tor2web.i2p.xyz"
        engine.on_event({
            "type": "dns_query", "src": "10.0.0.1",
            "query": q, "entropy": 1.0,
        })
        tor_calls = [c for c in alert_fn.call_args_list
                     if c.kwargs.get("category") == "tor_domain"]
        assert len(tor_calls) == 1


# ══════════════════════════════════════════════════════════════
# _arp — ARP spoofing
# ══════════════════════════════════════════════════════════════


class TestArp:
    def test_arp_spoof_detected_on_mac_change(self, engine, alert_fn):
        engine.on_event({
            "type": "arp_reply", "src_ip": "10.0.0.1",
            "src_mac": "aa:bb:cc:dd:ee:01",
        })
        engine.on_event({
            "type": "arp_reply", "src_ip": "10.0.0.1",
            "src_mac": "aa:bb:cc:dd:ee:02",
        })
        alert_fn.assert_any_call(
            severity=1, source="analyzer", category="arp_spoof",
            title="ARP spoofing on 10.0.0.1",
            detail="Expected=aa:bb:cc:dd:ee:01 Received=aa:bb:cc:dd:ee:02",
            src_ip="10.0.0.1",
        )

    def test_arp_no_alert_same_mac(self, engine, alert_fn):
        for _ in range(5):
            engine.on_event({
                "type": "arp_reply", "src_ip": "10.0.0.1",
                "src_mac": "aa:bb:cc:dd:ee:01",
            })
        assert alert_fn.call_count == 0

    def test_arp_first_seen_no_alert(self, engine, alert_fn):
        engine.on_event({
            "type": "arp_reply", "src_ip": "10.0.0.1",
            "src_mac": "aa:bb:cc:dd:ee:01",
        })
        assert alert_fn.call_count == 0

    def test_arp_spoof_risk_increment(self, engine, alert_fn):
        engine.on_event({
            "type": "arp_reply", "src_ip": "10.0.0.1",
            "src_mac": "aa:bb:cc:dd:ee:01",
        })
        engine.on_event({
            "type": "arp_reply", "src_ip": "10.0.0.1",
            "src_mac": "aa:bb:cc:dd:ee:02",
        })
        assert engine._risk_d["10.0.0.1"] >= 40

    def test_arp_table_updated_after_spoof(self, engine, alert_fn):
        engine.on_event({
            "type": "arp_reply", "src_ip": "10.0.0.1",
            "src_mac": "aa:bb:cc:dd:ee:01",
        })
        engine.on_event({
            "type": "arp_reply", "src_ip": "10.0.0.1",
            "src_mac": "aa:bb:cc:dd:ee:02",
        })
        assert engine._arp_tbl["10.0.0.1"] == "aa:bb:cc:dd:ee:02"


# ══════════════════════════════════════════════════════════════
# _check_beacon
# ══════════════════════════════════════════════════════════════


class TestCheckBeacon:
    def test_too_few_samples_no_alert(self, engine, alert_fn):
        pair = ("10.0.0.1", "10.0.0.2")
        engine._bcn_tr[pair] = [60.0] * 5
        engine._check_beacon(pair, "10.0.0.1", "10.0.0.2")
        assert alert_fn.call_count == 0

    def test_mean_below_2_no_alert(self, engine, alert_fn):
        pair = ("10.0.0.1", "10.0.0.2")
        engine._bcn_tr[pair] = [1.5] * 15
        engine._check_beacon(pair, "10.0.0.1", "10.0.0.2")
        assert alert_fn.call_count == 0

    def test_high_cv_no_alert(self, engine, alert_fn):
        """High coefficient of variation — not beaconing."""
        pair = ("10.0.0.1", "10.0.0.2")
        engine._bcn_tr[pair] = [10, 100, 50, 200, 5, 300, 20, 150, 70, 400, 15, 250]
        engine._check_beacon(pair, "10.0.0.1", "10.0.0.2")
        assert alert_fn.call_count == 0

    def test_low_cv_triggers_beaconing(self, engine, alert_fn):
        """Low CV with mean >= 2 and >= 10 samples → beaconing alert."""
        pair = ("10.0.0.1", "10.0.0.2")
        engine._bcn_tr[pair] = [60.0] * 15
        engine._check_beacon(pair, "10.0.0.1", "10.0.0.2")
        alert_fn.assert_any_call(
            severity=1, source="analyzer", category="beaconing",
            title="C2 beaconing : 10.0.0.1 → 10.0.0.2",
            detail=pytest.approx("Interval=60.0s σ=0.0s CV=0.000 (15 samples)", abs=0),
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
        )

    def test_beacon_clears_tracker_after_alert(self, engine, alert_fn):
        pair = ("10.0.0.1", "10.0.0.2")
        engine._bcn_tr[pair] = [60.0] * 15
        engine._check_beacon(pair, "10.0.0.1", "10.0.0.2")
        assert len(engine._bcn_tr[pair]) == 0

    def test_beacon_risk_increment(self, engine, alert_fn):
        pair = ("10.0.0.1", "10.0.0.2")
        engine._bcn_tr[pair] = [60.0] * 15
        engine._check_beacon(pair, "10.0.0.1", "10.0.0.2")
        assert engine._risk_d["10.0.0.1"] >= 35

    def test_beacon_uses_last_30_samples(self, engine, alert_fn):
        pair = ("10.0.0.1", "10.0.0.2")
        # First 20 are irregular, last 30 are regular — should alert based on last 30
        engine._bcn_tr[pair] = [500, 10, 800, 3, 999] * 4 + [60.0] * 30
        engine._check_beacon(pair, "10.0.0.1", "10.0.0.2")
        bcn_calls = [c for c in alert_fn.call_args_list
                     if c.kwargs.get("category") == "beaconing"]
        assert len(bcn_calls) == 1


# ══════════════════════════════════════════════════════════════
# update_baseline
# ══════════════════════════════════════════════════════════════


class TestUpdateBaseline:
    def test_baseline_creates_stats(self, engine):
        # Insert some flows and DNS
        Flow.create(src_ip="10.0.0.1", dst_ip="10.0.0.2", bytes_total=1000)
        Flow.create(src_ip="10.0.0.1", dst_ip="10.0.0.3", bytes_total=2000)
        DnsLog.create(src_ip="10.0.0.1", query="example.com")

        engine.update_baseline()

        fr = BaselineStat.get_or_none(BaselineStat.key == "flow_rate_h")
        assert fr is not None
        assert fr.value == 2
        assert fr.samples == 1

        bh = BaselineStat.get_or_none(BaselineStat.key == "bytes_h")
        assert bh is not None
        assert bh.value == 3000

        dh = BaselineStat.get_or_none(BaselineStat.key == "dns_h")
        assert dh is not None
        assert dh.value == 1

    def test_baseline_updates_ema(self, engine):
        Flow.create(src_ip="10.0.0.1", dst_ip="10.0.0.2", bytes_total=1000)
        engine.update_baseline()
        # Second call updates with EMA
        Flow.create(src_ip="10.0.0.1", dst_ip="10.0.0.3", bytes_total=2000)
        engine.update_baseline()

        fr = BaselineStat.get(BaselineStat.key == "flow_rate_h")
        assert fr.samples == 2

    def test_baseline_handles_exception(self, engine):
        """Exception in update_baseline should not propagate."""
        with patch("analyzers.threat_engine.Flow.select", side_effect=RuntimeError("db error")):
            engine.update_baseline()  # Should not raise


# ══════════════════════════════════════════════════════════════
# check_anomalies
# ══════════════════════════════════════════════════════════════


class TestCheckAnomalies:
    def test_anomaly_detected_high_z_score(self, engine, alert_fn):
        # Create a baseline with enough samples and known std_dev
        BaselineStat.create(key="flow_rate_h", value=100, std_dev=5, samples=20)
        # Create 500 flows in last hour → z = (500-100)/5 = 80
        for _ in range(500):
            Flow.create(src_ip="10.0.0.1", dst_ip="10.0.0.2", bytes_total=100)

        engine.check_anomalies()

        anomaly_calls = [c for c in alert_fn.call_args_list
                         if c.kwargs.get("category") == "anomaly"]
        assert len(anomaly_calls) >= 1

    def test_no_anomaly_when_within_normal_range(self, engine, alert_fn):
        BaselineStat.create(key="flow_rate_h", value=100, std_dev=50, samples=20)
        for _ in range(100):
            Flow.create(src_ip="10.0.0.1", dst_ip="10.0.0.2", bytes_total=100)
        engine.check_anomalies()
        anomaly_calls = [c for c in alert_fn.call_args_list
                         if c.kwargs.get("category") == "anomaly"]
        assert len(anomaly_calls) == 0

    def test_no_anomaly_when_too_few_samples(self, engine, alert_fn):
        BaselineStat.create(key="flow_rate_h", value=100, std_dev=5, samples=5)
        for _ in range(500):
            Flow.create(src_ip="10.0.0.1", dst_ip="10.0.0.2", bytes_total=100)
        engine.check_anomalies()
        anomaly_calls = [c for c in alert_fn.call_args_list
                         if c.kwargs.get("category") == "anomaly"]
        assert len(anomaly_calls) == 0

    def test_no_anomaly_when_std_dev_zero(self, engine, alert_fn):
        BaselineStat.create(key="flow_rate_h", value=100, std_dev=0, samples=20)
        for _ in range(500):
            Flow.create(src_ip="10.0.0.1", dst_ip="10.0.0.2", bytes_total=100)
        engine.check_anomalies()
        anomaly_calls = [c for c in alert_fn.call_args_list
                         if c.kwargs.get("category") == "anomaly"]
        assert len(anomaly_calls) == 0

    def test_check_anomalies_handles_exception(self, engine, alert_fn):
        with patch("analyzers.threat_engine.Flow.select", side_effect=RuntimeError("boom")):
            engine.check_anomalies()  # Should not raise


# ══════════════════════════════════════════════════════════════
# _check_volumes
# ══════════════════════════════════════════════════════════════


class TestCheckVolumes:
    def test_exfiltration_alert_when_over_threshold(self, engine, alert_fn):
        # exfil is 1 MB = 1048576 bytes
        engine._vol_tr["10.0.0.1"] = 2 * 1024 * 1024  # 2 MB
        engine._check_volumes()
        alert_fn.assert_any_call(
            severity=2, source="analyzer", category="exfiltration",
            title="Abnormal volume from 10.0.0.1",
            detail="2.0 MB transmitted", src_ip="10.0.0.1",
        )

    def test_no_exfiltration_below_threshold(self, engine, alert_fn):
        engine._vol_tr["10.0.0.1"] = 512 * 1024  # 0.5 MB
        engine._check_volumes()
        exfil_calls = [c for c in alert_fn.call_args_list
                       if c.kwargs.get("category") == "exfiltration"]
        assert len(exfil_calls) == 0

    def test_exfiltration_risk_increment(self, engine, alert_fn):
        engine._vol_tr["10.0.0.1"] = 2 * 1024 * 1024
        engine._check_volumes()
        assert engine._risk_d["10.0.0.1"] >= 25

    def test_multiple_ips_checked(self, engine, alert_fn):
        engine._vol_tr["10.0.0.1"] = 2 * 1024 * 1024
        engine._vol_tr["10.0.0.2"] = 3 * 1024 * 1024
        engine._check_volumes()
        exfil_calls = [c for c in alert_fn.call_args_list
                       if c.kwargs.get("category") == "exfiltration"]
        assert len(exfil_calls) == 2


# ══════════════════════════════════════════════════════════════
# _ustat
# ══════════════════════════════════════════════════════════════


class TestUstat:
    def test_ustat_creates_new_entry(self, engine):
        from analyzers.threat_engine import ThreatEngine
        ThreatEngine._ustat("test_key", 42.0)
        st = BaselineStat.get(BaselineStat.key == "test_key")
        assert st.value == 42.0
        assert st.samples == 1
        assert st.std_dev == 0

    def test_ustat_updates_with_ema(self, engine):
        from analyzers.threat_engine import ThreatEngine
        ThreatEngine._ustat("test_key", 100.0)
        ThreatEngine._ustat("test_key", 200.0)
        st = BaselineStat.get(BaselineStat.key == "test_key")
        assert st.samples == 2
        # EMA should be between 100 and 200
        assert 100 < st.value < 200

    def test_ustat_std_dev_grows(self, engine):
        from analyzers.threat_engine import ThreatEngine
        ThreatEngine._ustat("test_key", 100.0)
        ThreatEngine._ustat("test_key", 200.0)
        st = BaselineStat.get(BaselineStat.key == "test_key")
        assert st.std_dev > 0

    def test_ustat_multiple_updates(self, engine):
        from analyzers.threat_engine import ThreatEngine
        for v in [10, 20, 30, 40, 50]:
            ThreatEngine._ustat("test_key", v)
        st = BaselineStat.get(BaselineStat.key == "test_key")
        assert st.samples == 5


# ══════════════════════════════════════════════════════════════
# _update_risk
# ══════════════════════════════════════════════════════════════


class TestUpdateRisk:
    def test_risk_flushed_to_host(self, engine):
        Host.create(ip="10.0.0.1", risk_score=0)
        engine._risk_d["10.0.0.1"] = 25
        engine._update_risk()
        h = Host.get(Host.ip == "10.0.0.1")
        assert h.risk_score == 25

    def test_risk_capped_at_100(self, engine):
        Host.create(ip="10.0.0.1", risk_score=90)
        engine._risk_d["10.0.0.1"] = 50
        engine._update_risk()
        h = Host.get(Host.ip == "10.0.0.1")
        assert h.risk_score == 100

    def test_risk_dict_cleared_after_flush(self, engine):
        Host.create(ip="10.0.0.1", risk_score=0)
        engine._risk_d["10.0.0.1"] = 10
        engine._update_risk()
        assert len(engine._risk_d) == 0

    def test_risk_noop_when_empty(self, engine):
        engine._update_risk()  # Should not raise

    def test_risk_unknown_host_ignored(self, engine):
        """If host not in DB, delta is just skipped (no crash)."""
        engine._risk_d["192.168.99.99"] = 50
        engine._update_risk()
        assert len(engine._risk_d) == 0

    def test_risk_handles_exception(self, engine):
        engine._risk_d["10.0.0.1"] = 10
        with patch("analyzers.threat_engine.db.atomic", side_effect=RuntimeError("db error")):
            engine._update_risk()  # Should not raise

    def test_risk_decay_applied(self, engine):
        """Existing risk_score is decayed by 0.9 before adding delta."""
        Host.create(ip="10.0.0.1", risk_score=50)
        engine._risk_d["10.0.0.1"] = 10
        engine._update_risk()
        h = Host.get(Host.ip == "10.0.0.1")
        # int(50 * 0.9) + 10 = 45 + 10 = 55
        assert h.risk_score == 55


# ══════════════════════════════════════════════════════════════
# _cleanup_loop
# ══════════════════════════════════════════════════════════════


class TestCleanupLoop:
    def test_stale_scan_entries_removed(self, engine):
        now = time.time()
        engine._scan_tr["10.0.0.1"]["last"] = now - 700  # stale (> 600s)
        engine._scan_tr["10.0.0.2"]["last"] = now - 100  # fresh

        # Run one iteration of the cleanup body
        call_count = 0
        original_sleep = time.sleep

        def fake_sleep(secs):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                raise StopIteration("break loop")

        with patch("analyzers.threat_engine.time.time", return_value=now):
            with patch("analyzers.threat_engine.time.sleep", side_effect=fake_sleep):
                try:
                    engine._cleanup_loop()
                except StopIteration:
                    pass

        assert "10.0.0.1" not in engine._scan_tr
        assert "10.0.0.2" in engine._scan_tr

    def test_beacon_tracker_trimmed(self, engine):
        pair = ("10.0.0.1", "10.0.0.2")
        engine._bcn_tr[pair] = list(range(60))  # > 50

        call_count = 0

        def fake_sleep(secs):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                raise StopIteration()

        now = time.time()
        with patch("analyzers.threat_engine.time.time", return_value=now):
            with patch("analyzers.threat_engine.time.sleep", side_effect=fake_sleep):
                try:
                    engine._cleanup_loop()
                except StopIteration:
                    pass

        assert len(engine._bcn_tr[pair]) == 30

    def test_dns_tracker_trimmed(self, engine):
        engine._dns_tr["10.0.0.1"] = list(range(250))  # > 200

        call_count = 0

        def fake_sleep(secs):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                raise StopIteration()

        now = time.time()
        with patch("analyzers.threat_engine.time.time", return_value=now):
            with patch("analyzers.threat_engine.time.sleep", side_effect=fake_sleep):
                try:
                    engine._cleanup_loop()
                except StopIteration:
                    pass

        assert len(engine._dns_tr["10.0.0.1"]) == 100

    def test_volume_decayed_and_small_removed(self, engine):
        engine._vol_tr["10.0.0.1"] = 100_000  # decays to 50000
        engine._vol_tr["10.0.0.2"] = 500       # decays to 250 < 1024 → removed

        call_count = 0

        def fake_sleep(secs):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                raise StopIteration()

        now = time.time()
        with patch("analyzers.threat_engine.time.time", return_value=now):
            with patch("analyzers.threat_engine.time.sleep", side_effect=fake_sleep):
                try:
                    engine._cleanup_loop()
                except StopIteration:
                    pass

        assert engine._vol_tr["10.0.0.1"] == 50_000
        assert "10.0.0.2" not in engine._vol_tr

    def test_suspicious_port_stale_entries_removed(self, engine):
        now = time.time()
        engine._suspicious_port_alerted[("a", "b", 4444)] = now - 700  # stale
        engine._suspicious_port_alerted[("c", "d", 5555)] = now - 100  # fresh

        call_count = 0

        def fake_sleep(secs):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                raise StopIteration()

        with patch("analyzers.threat_engine.time.time", return_value=now):
            with patch("analyzers.threat_engine.time.sleep", side_effect=fake_sleep):
                try:
                    engine._cleanup_loop()
                except StopIteration:
                    pass

        assert ("a", "b", 4444) not in engine._suspicious_port_alerted
        assert ("c", "d", 5555) in engine._suspicious_port_alerted


# ══════════════════════════════════════════════════════════════
# get_threat_summary
# ══════════════════════════════════════════════════════════════


class TestGetThreatSummary:
    def test_summary_structure(self, engine):
        summary = engine.get_threat_summary()
        assert "active_scanners" in summary
        assert "bf_tracked" in summary
        assert "beacon_pairs" in summary
        assert "alerts_today" in summary
        assert "alerts_critical" in summary
        assert "alerts_high" in summary
        assert "top_risk_hosts" in summary

    def test_summary_counts_trackers(self, engine):
        engine._scan_tr["10.0.0.1"]["ports"] = {80, 443}
        engine._scan_tr["10.0.0.2"]["ports"] = {22}
        engine._bf_tr[("a", "b", 22)] = [1, 2, 3]
        engine._bcn_tr[("a", "b")] = [60.0] * 5

        summary = engine.get_threat_summary()
        assert summary["active_scanners"] == 2
        assert summary["bf_tracked"] == 1
        assert summary["beacon_pairs"] == 1

    def test_summary_counts_alerts_today(self, engine):
        Alert.create(severity=1, source="test", title="Critical alert")
        Alert.create(severity=2, source="test", title="High alert")
        Alert.create(severity=3, source="test", title="Medium alert")

        summary = engine.get_threat_summary()
        assert summary["alerts_today"] == 3
        assert summary["alerts_critical"] == 1
        assert summary["alerts_high"] == 1

    def test_summary_top_risk_hosts(self, engine):
        Host.create(ip="10.0.0.1", risk_score=80, os_hint="Linux")
        Host.create(ip="10.0.0.2", risk_score=50, os_hint="Windows")
        Host.create(ip="10.0.0.3", risk_score=0, os_hint="Unknown")

        summary = engine.get_threat_summary()
        assert len(summary["top_risk_hosts"]) == 2  # 10.0.0.3 excluded (score=0)
        assert summary["top_risk_hosts"][0]["ip"] == "10.0.0.1"
        assert summary["top_risk_hosts"][0]["score"] == 80

    def test_summary_empty_state(self, engine):
        summary = engine.get_threat_summary()
        assert summary["active_scanners"] == 0
        assert summary["bf_tracked"] == 0
        assert summary["beacon_pairs"] == 0
        assert summary["alerts_today"] == 0
        assert summary["top_risk_hosts"] == []
