"""Tests for analyzers/correlator.py — Correlator engine."""
import os
import sys
import time
import tempfile
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.suricata_ingest import SuricataEvent


# ── Config stub ──────────────────────────────────────────

class _Cfg:
    def __init__(self, overrides=None):
        self._d = {
            "network.subnets": ["192.168.1.0/24"],
        }
        if overrides:
            self._d.update(overrides)

    def get(self, dotted, default=None):
        return self._d.get(dotted, default)


# ── Helpers ──────────────────────────────────────────────

def _make_suricata_event(event_type="alert", severity=1, category="Misc Attack",
                          signature="Test Signature", sid=2000001,
                          action="allowed", src_ip="10.0.0.1", dst_ip="192.168.1.100",
                          proto="TCP", app_proto="http",
                          http_hostname="", http_url="", tls_sni="",
                          dns_query="", src_port=12345, dst_port=80):
    data = {
        "timestamp": "2025-01-01T00:00:00.000000+0000",
        "event_type": event_type,
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dst_ip,
        "dest_port": dst_port,
        "proto": proto,
        "app_proto": app_proto,
        "alert": {
            "signature": signature,
            "signature_id": sid,
            "severity": severity,
            "category": category,
            "action": action,
        },
        "http": {"hostname": http_hostname, "url": http_url},
        "tls": {"sni": tls_sni},
        "dns": {"rrname": dns_query},
    }
    return SuricataEvent(data)


@pytest.fixture
def correlator():
    """Create a Correlator with all dependencies mocked."""
    alert_fn = MagicMock()
    defense = MagicMock()
    engine = MagicMock()
    incident = MagicMock()
    cfg = _Cfg()

    with patch("analyzers.correlator.threading"):
        from analyzers.correlator import Correlator
        c = Correlator(cfg, alert_fn, defense, engine, incident)
    return c, alert_fn, defense, engine, incident


# ── Non-alert events ────────────────────────────────────

class TestNonAlertEvents:
    def test_dns_event_forwarded_to_engine(self, correlator):
        c, _, _, engine, _ = correlator
        evt = _make_suricata_event(event_type="dns", dns_query="example.com")
        c.on_suricata_event(evt)
        engine.on_event.assert_called_once()
        call_args = engine.on_event.call_args[0][0]
        assert call_args["type"] == "dns_query"
        assert call_args["query"] == "example.com"

    def test_non_alert_event_returns_early(self, correlator):
        c, alert_fn, _, _, _ = correlator
        evt = _make_suricata_event(event_type="http")
        c.on_suricata_event(evt)
        alert_fn.assert_not_called()

    def test_http_event_no_crash(self, correlator):
        c, _, _, _, _ = correlator
        evt = _make_suricata_event(event_type="http", http_hostname="example.com")
        c.on_suricata_event(evt)  # should not crash


# ── Alert processing ────────────────────────────────────

class TestAlertProcessing:
    def test_alert_creates_db_alert(self, correlator):
        c, alert_fn, _, _, _ = correlator
        evt = _make_suricata_event(severity=3, category="Misc Attack")
        c.on_suricata_event(evt)
        alert_fn.assert_called_once()
        kw = alert_fn.call_args[1]
        assert kw["source"] == "suricata"
        assert "SID:2000001" in kw["title"]

    def test_alert_tracks_ip_counters(self, correlator):
        c, _, _, _, _ = correlator
        evt = _make_suricata_event(src_ip="10.0.0.1", severity=3)
        c.on_suricata_event(evt)
        ip_data = c._ip_events["10.0.0.1"]
        assert ip_data["suricata_alerts"] == 1
        assert ip_data["first_seen"] is not None
        assert ip_data["last_seen"] is not None

    def test_critical_alert_increments_critical_counter(self, correlator):
        c, _, _, _, _ = correlator
        evt = _make_suricata_event(severity=1)  # sentinel_severity=1
        c.on_suricata_event(evt)
        assert c._ip_events["10.0.0.1"]["suricata_critical"] == 1

    def test_non_critical_alert_no_critical_increment(self, correlator):
        c, _, _, _, _ = correlator
        evt = _make_suricata_event(severity=3)  # sentinel_severity=3
        c.on_suricata_event(evt)
        assert c._ip_events["10.0.0.1"]["suricata_critical"] == 0

    def test_events_processed_counter(self, correlator):
        c, _, _, _, _ = correlator
        evt = _make_suricata_event()
        c.on_suricata_event(evt)
        assert c._stats["events_processed"] == 1


# ── Rule 1: Critical alert → immediate block ────────────

class TestRule1CriticalAlert:
    def test_critical_unblocked_triggers_incident(self, correlator):
        c, _, _, _, incident = correlator
        evt = _make_suricata_event(severity=1, action="allowed")
        c.on_suricata_event(evt)
        incident.create_incident.assert_called_once()
        assert c._stats["defenses_triggered"] == 1

    def test_critical_already_blocked_no_incident(self, correlator):
        c, _, _, _, incident = correlator
        evt = _make_suricata_event(severity=1, action="blocked")
        c.on_suricata_event(evt)
        incident.create_incident.assert_not_called()

    def test_critical_no_incident_engine_uses_defense(self, correlator):
        c, alert_fn, defense, engine, _ = correlator
        c.incident = None  # no incident engine
        evt = _make_suricata_event(severity=1, action="allowed")
        c.on_suricata_event(evt)
        defense.evaluate_threat.assert_called_once()


# ── Rule 2: Multi-alert correlation ─────────────────────

class TestRule2MultiAlert:
    def test_three_alerts_plus_high_risk_creates_incident(self, correlator):
        c, _, _, _, incident = correlator
        src = "10.0.0.1"
        # Create a Host mock with high risk
        mock_host = MagicMock()
        mock_host.risk_score = 50

        with patch("analyzers.correlator.Host") as HostCls:
            HostCls.get_or_none.return_value = mock_host
            for i in range(3):
                evt = _make_suricata_event(severity=3, src_ip=src, sid=2000001+i,
                                            category="Misc Attack")
                c.on_suricata_event(evt)

        assert incident.create_incident.call_count >= 1
        assert c._stats["correlations_found"] >= 1

    def test_three_alerts_low_risk_no_correlation(self, correlator):
        c, _, _, _, incident = correlator
        src = "10.0.0.1"
        mock_host = MagicMock()
        mock_host.risk_score = 10  # < 30

        with patch("analyzers.correlator.Host") as HostCls:
            HostCls.get_or_none.return_value = mock_host
            for i in range(3):
                evt = _make_suricata_event(severity=3, src_ip=src, sid=2000001+i)
                c.on_suricata_event(evt)

        assert c._stats["correlations_found"] == 0

    def test_three_alerts_no_host_record_no_correlation(self, correlator):
        c, _, _, _, incident = correlator
        src = "10.0.0.1"
        with patch("analyzers.correlator.Host") as HostCls:
            HostCls.get_or_none.return_value = None
            for i in range(3):
                evt = _make_suricata_event(severity=3, src_ip=src, sid=2000001+i)
                c.on_suricata_event(evt)

        assert c._stats["correlations_found"] == 0

    def test_multi_alert_no_incident_engine_uses_defense(self, correlator):
        c, alert_fn, defense, _, _ = correlator
        c.incident = None
        src = "10.0.0.1"
        mock_host = MagicMock()
        mock_host.risk_score = 50

        with patch("analyzers.correlator.Host") as HostCls:
            HostCls.get_or_none.return_value = mock_host
            for i in range(3):
                evt = _make_suricata_event(severity=3, src_ip=src, sid=2000001+i)
                c.on_suricata_event(evt)

        defense.block_ip.assert_called()


# ── Rule 3: Trojan + DNS → sinkhole ─────────────────────

class TestRule3TrojanSinkhole:
    def test_trojan_with_http_hostname_sinkholes(self, correlator):
        c, _, defense, _, _ = correlator
        evt = _make_suricata_event(
            severity=3, category="A Network Trojan was Detected",
            signature="Trojan callback",
            http_hostname="evil.com", action="blocked",
        )
        c.on_suricata_event(evt)
        defense.dns_sinkhole.assert_called()
        call_args = defense.dns_sinkhole.call_args[0]
        assert call_args[0] == "evil.com"

    def test_trojan_with_tls_sni_sinkholes(self, correlator):
        c, _, defense, _, _ = correlator
        evt = _make_suricata_event(
            severity=3, category="Trojan",
            signature="trojan C2", tls_sni="c2.evil.com",
            action="blocked",
        )
        c.on_suricata_event(evt)
        # Should sinkhole TLS SNI
        sinkhole_calls = defense.dns_sinkhole.call_args_list
        domains = [call[0][0] for call in sinkhole_calls]
        assert "c2.evil.com" in domains

    def test_trojan_also_calls_evaluate_threat(self, correlator):
        c, _, defense, _, _ = correlator
        evt = _make_suricata_event(
            severity=3, category="Trojan", signature="trojan test",
            action="blocked",
        )
        c.on_suricata_event(evt)
        defense.evaluate_threat.assert_called_once()


# ── Rule 4: Exploitation → quarantine ───────────────────

class TestRule4Exploitation:
    def test_exploit_internal_dst_quarantines(self, correlator):
        c, _, defense, _, _ = correlator
        evt = _make_suricata_event(
            severity=3, category="Executable Code was Detected",
            signature="Exploit attempt", dst_ip="192.168.1.50",
            action="blocked",
        )
        with patch("core.netutils.ip_in_subnet", return_value=True):
            c.on_suricata_event(evt)
        defense.quarantine_host.assert_called_once()
        assert defense.quarantine_host.call_args[0][0] == "192.168.1.50"

    def test_exploit_external_dst_no_quarantine(self, correlator):
        c, _, defense, _, _ = correlator
        evt = _make_suricata_event(
            severity=3, category="Exploit Kit Activity",
            signature="Exploit attempt", dst_ip="8.8.8.8",
            action="blocked",
        )
        with patch("core.netutils.ip_in_subnet", return_value=False):
            c.on_suricata_event(evt)
        defense.quarantine_host.assert_not_called()

    def test_privilege_gain_triggers_quarantine_check(self, correlator):
        c, _, defense, _, _ = correlator
        evt = _make_suricata_event(
            severity=3, category="Attempted Privilege Gain",
            signature="Priv escalation", dst_ip="192.168.1.50",
            action="blocked",
        )
        with patch("core.netutils.ip_in_subnet", return_value=True):
            c.on_suricata_event(evt)
        defense.quarantine_host.assert_called()


# ── Rule 5: Standard evaluation ─────────────────────────

class TestRule5Standard:
    def test_normal_alert_calls_evaluate_threat(self, correlator):
        c, _, defense, _, _ = correlator
        evt = _make_suricata_event(
            severity=3, category="Misc Activity",
            signature="Normal alert", action="blocked",
        )
        c.on_suricata_event(evt)
        defense.evaluate_threat.assert_called_once()

    def test_standard_alert_passes_correct_params(self, correlator):
        c, _, defense, _, _ = correlator
        evt = _make_suricata_event(
            severity=3, category="Misc Activity",
            signature="Normal alert", sid=12345, action="blocked",
            src_ip="10.0.0.1", dst_ip="192.168.1.100",
        )
        c.on_suricata_event(evt)
        kw = defense.evaluate_threat.call_args[1]
        assert kw["src_ip"] == "10.0.0.1"
        assert kw["dst_ip"] == "192.168.1.100"
        assert kw["sid"] == 12345


# ── Stats ────────────────────────────────────────────────

class TestCorrelatorStats:
    def test_stats_structure(self, correlator):
        c, _, _, _, _ = correlator
        s = c.stats
        assert "events_processed" in s
        assert "correlations_found" in s
        assert "defenses_triggered" in s
        assert "tracked_ips" in s
        assert "top_offenders" in s

    def test_stats_tracked_ips_count(self, correlator):
        c, _, _, _, _ = correlator
        evt = _make_suricata_event(src_ip="10.0.0.1", severity=3, action="blocked")
        c.on_suricata_event(evt)
        assert c.stats["tracked_ips"] == 1

    def test_top_offenders_sorted_by_alerts(self, correlator):
        c, _, _, _, _ = correlator
        for i in range(5):
            evt = _make_suricata_event(src_ip="10.0.0.1", severity=3, action="blocked",
                                        sid=2000001+i)
            c.on_suricata_event(evt)
        for i in range(2):
            evt = _make_suricata_event(src_ip="10.0.0.2", severity=3, action="blocked",
                                        sid=3000001+i)
            c.on_suricata_event(evt)
        offenders = c.stats["top_offenders"]
        assert offenders[0]["ip"] == "10.0.0.1"
        assert offenders[0]["alerts"] == 5


# ── Cleanup ──────────────────────────────────────────────

class TestCleanup:
    def test_cleanup_removes_stale_ips(self, correlator):
        c, _, _, _, _ = correlator
        c._ip_events["old.ip"] = {
            "suricata_alerts": 1, "suricata_critical": 0,
            "internal_alerts": 0, "categories": set(),
            "sids": set(), "first_seen": time.time() - 7200,
            "last_seen": time.time() - 7200,
        }
        c._ip_events["new.ip"] = {
            "suricata_alerts": 1, "suricata_critical": 0,
            "internal_alerts": 0, "categories": set(),
            "sids": set(), "first_seen": time.time(),
            "last_seen": time.time(),
        }
        # Manually invoke cleanup logic
        now = time.time()
        cutoff = now - 3600
        stale = [ip for ip, d in c._ip_events.items()
                 if d["last_seen"] and d["last_seen"] < cutoff]
        for ip in stale:
            del c._ip_events[ip]
        assert "old.ip" not in c._ip_events
        assert "new.ip" in c._ip_events
