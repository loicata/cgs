"""Tests for core/forensic.py — ForensicCollector."""

import json
import os
import sys
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class FakeConfig:
    def __init__(self, log_dir):
        self._log_dir = log_dir

    def get(self, key, default=None):
        if key == "general.log_dir":
            return self._log_dir
        return default


@pytest.fixture
def forensic_collector(tmp_path, test_db):
    """Create a ForensicCollector with temp output dir."""
    cfg = FakeConfig(str(tmp_path))
    from core.forensic import ForensicCollector
    return ForensicCollector(cfg)


@pytest.fixture
def populated_db(test_db):
    """Populate DB with test data."""
    from core.database import Alert, Host, Port, Flow, DnsLog
    now = datetime.now()
    Host.create(
        ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff",
        hostname="target-host", vendor="Dell", os_hint="Linux",
        risk_score=5, status="up",
        first_seen=now, last_seen=now,
    )
    Port.create(host_ip="192.168.1.10", port=22, proto="tcp",
                state="open", service="ssh", banner="OpenSSH")
    Port.create(host_ip="192.168.1.10", port=80, proto="tcp",
                state="open", service="http", banner="nginx")

    Alert.create(
        ts=now, severity=1, source="suricata", category="attack",
        title="SQL Injection", detail="payload detected",
        src_ip="10.0.0.99", dst_ip="192.168.1.10", ioc="sqlmap",
    )
    Flow.create(
        ts=now, src_ip="10.0.0.99", src_port=54321,
        dst_ip="192.168.1.10", dst_port=80,
        proto="TCP", packets=100, bytes_total=50000, flags="SYN",
    )
    DnsLog.create(
        ts=now, src_ip="10.0.0.99", query="evil.com",
        qtype=1, entropy=4.5, suspicious=True,
    )
    DnsLog.create(
        ts=now, src_ip="192.168.1.10", query="google.com",
        qtype=1, entropy=2.0, suspicious=False,
    )
    return now


class TestForensicCollectorInit:
    def test_creates_output_directory(self, tmp_path, test_db):
        cfg = FakeConfig(str(tmp_path))
        from core.forensic import ForensicCollector
        fc = ForensicCollector(cfg)
        assert os.path.isdir(fc.output_dir)
        assert fc.output_dir.endswith("forensics")


class TestCollectAndSave:
    def test_returns_filepath_and_creates_json(self, forensic_collector, populated_db):
        now = populated_db
        path = forensic_collector.collect_and_save(
            incident_id="INC-20260101-001",
            incident_data={"created": now.isoformat(), "target_ip": "192.168.1.10"},
            attacker_ip="10.0.0.99",
            target_ip="192.168.1.10",
            created_at=time.time() - 3600,
        )
        assert os.path.exists(path)
        assert path.endswith(".json")
        with open(path) as f:
            data = json.load(f)
        assert data["_metadata"]["incident_id"] == "INC-20260101-001"
        assert data["_metadata"]["version"] == "2.0"
        assert data["attacker"]["ip"] == "10.0.0.99"
        assert data["target"]["ip"] == "192.168.1.10"

    def test_evidence_contains_alerts_for_attacker(self, forensic_collector, populated_db):
        path = forensic_collector.collect_and_save(
            incident_id="INC-001",
            incident_data={},
            attacker_ip="10.0.0.99",
            target_ip="192.168.1.10",
            created_at=time.time() - 3600,
        )
        with open(path) as f:
            data = json.load(f)
        assert len(data["attacker"]["related_alerts"]) >= 1
        assert data["attacker"]["related_alerts"][0]["title"] == "SQL Injection"

    def test_evidence_contains_host_info(self, forensic_collector, populated_db):
        path = forensic_collector.collect_and_save(
            incident_id="INC-002",
            incident_data={},
            attacker_ip="10.0.0.99",
            target_ip="192.168.1.10",
            created_at=time.time() - 3600,
        )
        with open(path) as f:
            data = json.load(f)
        host_info = data["target"]["host_info"]
        assert host_info["ip"] == "192.168.1.10"
        assert host_info["mac"] == "aa:bb:cc:dd:ee:ff"
        assert len(host_info["ports"]) == 2

    def test_evidence_contains_flows(self, forensic_collector, populated_db):
        path = forensic_collector.collect_and_save(
            incident_id="INC-003",
            incident_data={},
            attacker_ip="10.0.0.99",
            target_ip="192.168.1.10",
            created_at=time.time() - 3600,
        )
        with open(path) as f:
            data = json.load(f)
        assert len(data["attacker"]["related_flows"]) >= 1

    def test_evidence_contains_dns(self, forensic_collector, populated_db):
        path = forensic_collector.collect_and_save(
            incident_id="INC-004",
            incident_data={},
            attacker_ip="10.0.0.99",
            target_ip="192.168.1.10",
            created_at=time.time() - 3600,
        )
        with open(path) as f:
            data = json.load(f)
        assert len(data["attacker"]["dns_queries"]) >= 1
        assert data["attacker"]["dns_queries"][0]["query"] == "evil.com"

    def test_suricata_events_included(self, forensic_collector, populated_db):
        events = [{"sig": "test", "ts": "2026-01-01T00:00:00"}]
        path = forensic_collector.collect_and_save(
            incident_id="INC-005",
            incident_data={},
            attacker_ip="10.0.0.99",
            target_ip="192.168.1.10",
            suricata_raw_events=events,
            created_at=time.time() - 3600,
        )
        with open(path) as f:
            data = json.load(f)
        assert data["suricata_events"] == events

    def test_defense_actions_included(self, forensic_collector, populated_db):
        actions = ["block_ip 10.0.0.99", "sinkhole evil.com"]
        path = forensic_collector.collect_and_save(
            incident_id="INC-006",
            incident_data={"proposed_actions": ["action1"]},
            attacker_ip="10.0.0.99",
            target_ip="192.168.1.10",
            defense_actions=actions,
            created_at=time.time() - 3600,
        )
        with open(path) as f:
            data = json.load(f)
        assert data["defense"]["actions_executed"] == actions
        assert data["defense"]["actions_proposed"] == ["action1"]

    def test_recon_report_included(self, forensic_collector, populated_db):
        recon = {"nmap": {"open_ports": [22, 80]}}
        path = forensic_collector.collect_and_save(
            incident_id="INC-007",
            incident_data={},
            attacker_ip="10.0.0.99",
            target_ip="192.168.1.10",
            recon_report=recon,
            created_at=time.time() - 3600,
        )
        with open(path) as f:
            data = json.load(f)
        assert data["attacker"]["reconnaissance"] == recon

    def test_identity_engine_used_when_provided(self, forensic_collector, populated_db):
        identity = MagicMock()
        identity.verify_identity.return_value = {"score": 0.9}
        mac_res = MagicMock()
        mac_res.ip_to_mac.side_effect = lambda ip: "aa:bb:cc:dd:ee:ff" if ip == "192.168.1.10" else "11:22:33:44:55:66"

        path = forensic_collector.collect_and_save(
            incident_id="INC-008",
            incident_data={},
            attacker_ip="10.0.0.99",
            target_ip="192.168.1.10",
            identity_engine=identity,
            mac_resolver=mac_res,
            created_at=time.time() - 3600,
        )
        with open(path) as f:
            data = json.load(f)
        assert data["target"]["identity_fingerprint"] == {"score": 0.9}
        assert identity.verify_identity.call_count == 2

    def test_collect_without_created_at(self, forensic_collector, populated_db):
        """created_at=0 should still work (uses now - 24h)."""
        path = forensic_collector.collect_and_save(
            incident_id="INC-009",
            incident_data={},
            attacker_ip="10.0.0.99",
            target_ip="192.168.1.10",
            created_at=0,
        )
        assert os.path.exists(path)

    def test_network_context_present(self, forensic_collector, populated_db):
        path = forensic_collector.collect_and_save(
            incident_id="INC-010",
            incident_data={},
            attacker_ip="10.0.0.99",
            target_ip="192.168.1.10",
            created_at=time.time() - 3600,
        )
        with open(path) as f:
            data = json.load(f)
        ctx = data["network_context"]
        assert "all_alerts_24h" in ctx
        assert "suspicious_dns_24h" in ctx
        assert "top_talkers_24h" in ctx
        assert "active_hosts" in ctx

    def test_suspicious_dns_in_context(self, forensic_collector, populated_db):
        path = forensic_collector.collect_and_save(
            incident_id="INC-011",
            incident_data={},
            attacker_ip="10.0.0.99",
            target_ip="192.168.1.10",
            created_at=time.time() - 3600,
        )
        with open(path) as f:
            data = json.load(f)
        suspicious = data["network_context"]["suspicious_dns_24h"]
        assert any(d["query"] == "evil.com" for d in suspicious)

    def test_active_hosts_in_context(self, forensic_collector, populated_db):
        path = forensic_collector.collect_and_save(
            incident_id="INC-012",
            incident_data={},
            attacker_ip="10.0.0.99",
            target_ip="192.168.1.10",
            created_at=time.time() - 3600,
        )
        with open(path) as f:
            data = json.load(f)
        hosts = data["network_context"]["active_hosts"]
        assert any(h["ip"] == "192.168.1.10" for h in hosts)


class TestBuildTimeline:
    def test_timeline_basic(self):
        from core.forensic import ForensicCollector
        data = {"created": "2026-01-01T12:00:00"}
        events = ForensicCollector._build_timeline(data, 0)
        assert len(events) == 1
        assert events[0]["event"] == "Incident detected"

    def test_timeline_with_approval(self):
        from core.forensic import ForensicCollector
        data = {
            "created": "2026-01-01T12:00:00",
            "approved_at": "2026-01-01T12:05:00",
            "approved_by": "admin",
        }
        events = ForensicCollector._build_timeline(data, 0)
        assert any("Approved by admin" in e["event"] for e in events)

    def test_timeline_with_actions_executed(self):
        from core.forensic import ForensicCollector
        data = {
            "created": "2026-01-01T12:00:00",
            "actions_executed": ["block_ip", "sinkhole"],
        }
        events = ForensicCollector._build_timeline(data, 0)
        assert any("block_ip" in e["event"] for e in events)

    def test_timeline_sorted_by_timestamp(self):
        from core.forensic import ForensicCollector
        data = {
            "created": "2026-01-01T12:00:00",
            "approved_at": "2026-01-01T11:00:00",
            "approved_by": "admin",
        }
        events = ForensicCollector._build_timeline(data, 0)
        timestamps = [e["timestamp"] for e in events if e["timestamp"]]
        assert timestamps == sorted(timestamps)

    def test_timeline_shutdown_detected(self):
        from core.forensic import ForensicCollector
        data = {
            "created": "2026-01-01T12:00:00",
            "shutdown_detected_at": "2026-01-01T12:10:00",
            "target_ip": "192.168.1.10",
        }
        events = ForensicCollector._build_timeline(data, 0)
        assert any("shutdown confirmed" in e["event"] for e in events)

    def test_timeline_resolved(self):
        from core.forensic import ForensicCollector
        data = {
            "created": "2026-01-01T12:00:00",
            "resolved": True,
            "resolution": "blocked attacker",
        }
        events = ForensicCollector._build_timeline(data, 0)
        assert any("Resolution" in e["event"] for e in events)

    def test_timeline_report_sent(self):
        from core.forensic import ForensicCollector
        data = {
            "created": "2026-01-01T12:00:00",
            "report_sent": True,
        }
        events = ForensicCollector._build_timeline(data, 0)
        assert any("Report email sent" in e["event"] for e in events)

    def test_timeline_admin_alert_sent(self):
        from core.forensic import ForensicCollector
        data = {
            "created": "2026-01-01T12:00:00",
            "admin_alert_sent": True,
        }
        events = ForensicCollector._build_timeline(data, 0)
        assert any("Email admin sent" in e["event"] for e in events)

    def test_timeline_user_alert_sent(self):
        from core.forensic import ForensicCollector
        data = {
            "created": "2026-01-01T12:00:00",
            "user_alert_sent": True,
            "approved_at": "2026-01-01T12:05:00",
        }
        events = ForensicCollector._build_timeline(data, 0)
        assert any("User email sent" in e["event"] for e in events)


class TestIdentityEdgeCases:
    def test_identity_engine_mac_resolver_returns_empty(self, forensic_collector, populated_db):
        """When mac_resolver returns empty MACs, fingerprints stay empty."""
        identity = MagicMock()
        identity.verify_identity.return_value = {"score": 0.5}
        mac_res = MagicMock()
        mac_res.ip_to_mac.return_value = ""

        path = forensic_collector.collect_and_save(
            incident_id="INC-ID-01",
            incident_data={},
            attacker_ip="10.0.0.99",
            target_ip="192.168.1.10",
            identity_engine=identity,
            mac_resolver=mac_res,
            created_at=time.time() - 3600,
        )
        with open(path) as f:
            data = json.load(f)
        # target_mac resolved from DB Host record (aa:bb:cc:dd:ee:ff)
        # attacker_mac empty -> no verify_identity for attacker
        assert data["attacker"]["identity_fingerprint"] == {}

    def test_identity_engine_exception_handled(self, forensic_collector, populated_db):
        """When identity_engine raises, fingerprints default to empty."""
        identity = MagicMock()
        identity.verify_identity.side_effect = Exception("identity fail")
        mac_res = MagicMock()
        mac_res.ip_to_mac.return_value = "aa:bb:cc:dd:ee:ff"

        path = forensic_collector.collect_and_save(
            incident_id="INC-ID-02",
            incident_data={},
            attacker_ip="10.0.0.99",
            target_ip="192.168.1.10",
            identity_engine=identity,
            mac_resolver=mac_res,
            created_at=time.time() - 3600,
        )
        with open(path) as f:
            data = json.load(f)
        assert data["target"]["identity_fingerprint"] == {}
        assert data["attacker"]["identity_fingerprint"] == {}

    def test_identity_no_mac_resolver_resolves_from_db(self, forensic_collector, populated_db):
        """When mac_resolver is None, target MAC resolved from DB Host record."""
        identity = MagicMock()
        identity.verify_identity.return_value = {"trust": 0.8}

        path = forensic_collector.collect_and_save(
            incident_id="INC-ID-03",
            incident_data={},
            attacker_ip="10.0.0.99",
            target_ip="192.168.1.10",
            identity_engine=identity,
            mac_resolver=None,
            created_at=time.time() - 3600,
        )
        with open(path) as f:
            data = json.load(f)
        # Target has a Host in DB with mac aa:bb:cc:dd:ee:ff
        assert data["target"]["identity_fingerprint"] == {"trust": 0.8}

    def test_identity_no_mac_resolver_no_host_in_db(self, forensic_collector, test_db):
        """When mac_resolver is None and no Host in DB, fingerprint stays empty."""
        identity = MagicMock()
        identity.verify_identity.return_value = {"trust": 0.8}

        path = forensic_collector.collect_and_save(
            incident_id="INC-ID-04",
            incident_data={},
            attacker_ip="10.0.0.99",
            target_ip="99.99.99.99",
            identity_engine=identity,
            mac_resolver=None,
            created_at=time.time() - 3600,
        )
        with open(path) as f:
            data = json.load(f)
        assert data["target"]["identity_fingerprint"] == {}


class TestDBQueryEdgeCases:
    def test_get_alerts_for_ip_no_data(self, test_db):
        from core.forensic import ForensicCollector
        result = ForensicCollector._get_alerts_for_ip("1.2.3.4", 0)
        assert result == []

    def test_get_flows_for_ip_no_data(self, test_db):
        from core.forensic import ForensicCollector
        result = ForensicCollector._get_flows_for_ip("1.2.3.4", 0)
        assert result == []

    def test_get_dns_for_ip_no_data(self, test_db):
        from core.forensic import ForensicCollector
        result = ForensicCollector._get_dns_for_ip("1.2.3.4", 0)
        assert result == []

    def test_get_host_info_not_found(self, test_db):
        from core.forensic import ForensicCollector
        result = ForensicCollector._get_host_info("99.99.99.99")
        assert result == {}

    def test_get_recent_alerts_no_data(self, test_db):
        from core.forensic import ForensicCollector
        result = ForensicCollector._get_recent_alerts(0)
        assert result == []

    def test_get_suspicious_dns_no_data(self, test_db):
        from core.forensic import ForensicCollector
        result = ForensicCollector._get_suspicious_dns(0)
        assert result == []

    def test_get_top_talkers_no_data(self, test_db):
        from core.forensic import ForensicCollector
        result = ForensicCollector._get_top_talkers(0)
        assert result == []

    def test_get_active_hosts_no_data(self, test_db):
        from core.forensic import ForensicCollector
        result = ForensicCollector._get_active_hosts()
        assert result == []


class TestDBQueryExceptionPaths:
    """Test that DB exception handlers return empty lists/dicts."""

    def test_get_alerts_for_ip_db_error(self):
        from core.forensic import ForensicCollector
        with patch("core.forensic.Alert") as MockAlert:
            MockAlert.select.side_effect = Exception("DB error")
            result = ForensicCollector._get_alerts_for_ip("1.2.3.4", 0)
        assert result == []

    def test_get_flows_for_ip_db_error(self):
        from core.forensic import ForensicCollector
        with patch("core.forensic.Flow") as MockFlow:
            MockFlow.select.side_effect = Exception("DB error")
            result = ForensicCollector._get_flows_for_ip("1.2.3.4", 0)
        assert result == []

    def test_get_dns_for_ip_db_error(self):
        from core.forensic import ForensicCollector
        with patch("core.forensic.DnsLog") as MockDns:
            MockDns.select.side_effect = Exception("DB error")
            result = ForensicCollector._get_dns_for_ip("1.2.3.4", 0)
        assert result == []

    def test_get_host_info_db_error(self):
        from core.forensic import ForensicCollector
        with patch("core.forensic.Host") as MockHost:
            MockHost.get_or_none.side_effect = Exception("DB error")
            result = ForensicCollector._get_host_info("1.2.3.4")
        assert result == {}

    def test_get_recent_alerts_db_error(self):
        from core.forensic import ForensicCollector
        with patch("core.forensic.Alert") as MockAlert:
            MockAlert.select.side_effect = Exception("DB error")
            result = ForensicCollector._get_recent_alerts(0)
        assert result == []

    def test_get_suspicious_dns_db_error(self):
        from core.forensic import ForensicCollector
        with patch("core.forensic.DnsLog") as MockDns:
            MockDns.select.side_effect = Exception("DB error")
            result = ForensicCollector._get_suspicious_dns(0)
        assert result == []

    def test_get_top_talkers_db_error(self):
        from core.forensic import ForensicCollector
        with patch("core.forensic.Flow") as MockFlow:
            MockFlow.select.side_effect = Exception("DB error")
            result = ForensicCollector._get_top_talkers(0)
        assert result == []

    def test_get_active_hosts_db_error(self):
        from core.forensic import ForensicCollector
        with patch("core.forensic.Host") as MockHost:
            MockHost.select.side_effect = Exception("DB error")
            result = ForensicCollector._get_active_hosts()
        assert result == []
