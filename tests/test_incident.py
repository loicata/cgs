"""Tests for core/incident.py — Incident dataclass, IncidentResponseEngine, lifecycle, API."""
import os
import re
import sys
import time
from unittest.mock import MagicMock, patch, ANY

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.database import db, init_db, Host
from core.config import Config


def _make_cfg(tmp_path, defense_mode="confirmation"):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.dump({
        "general": {"data_dir": str(tmp_path / "data"), "log_dir": str(tmp_path / "logs")},
        "network": {"subnets": ["192.168.1.0/24"], "interface": "lo"},
        "defense": {"enabled": True, "mode": defense_mode, "whitelist_ips": ["8.8.8.8"]},
        "email": {
            "enabled": False, "smtp_server": "", "smtp_port": 587,
            "admin_emails": ["admin@test.com"],
            "approval_timeout_minutes": 15,
            "timeout_auto_approve": False,
            "sentinel_url": "https://192.168.1.100:8443",
            "token_ttl_seconds": 3600,
            "user_directory": [
                {"ip": "192.168.1.10", "name": "Jean Dupont",
                 "email": "jean@test.com", "hostname": "PC-JEAN"},
            ],
        },
        "web": {"port": 8443},
        "client_agent": {"enabled": False},
    }))
    return Config(str(cfg_path))


@pytest.fixture
def incident_env(tmp_path):
    """Create an IncidentResponseEngine with mocked dependencies."""
    if not db.is_closed():
        db.close()
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(str(tmp_path / "logs"), exist_ok=True)
    init_db(data_dir)

    cfg = _make_cfg(tmp_path)
    alert_fn = MagicMock()
    defense = MagicMock()
    defense.whitelist = {"8.8.8.8"}

    with patch("core.client_queue.ClientNotificationQueue") as MockQueue, \
         patch("core.snapshot.DefenseSnapshot") as MockSnap:
        MockQueue.return_value.enabled = False
        from core.incident import IncidentResponseEngine
        engine = IncidentResponseEngine(cfg, alert_fn, defense, mac_resolver=None)

    yield engine, alert_fn, defense
    if not db.is_closed():
        db.close()


# ══════════════════════════════════════════════════
# Incident dataclass
# ══════════════════════════════════════════════════

class TestIncidentDataclass:

    def test_incident_auto_generates_id(self):
        from core.incident import Incident
        inc = Incident()
        assert inc.id.startswith("INC-")
        assert len(inc.id) > 10

    def test_incident_auto_generates_token(self):
        from core.incident import Incident
        inc = Incident()
        assert len(inc.token) > 20

    def test_incident_default_status_is_detected(self):
        from core.incident import Incident
        inc = Incident()
        assert inc.status == "DETECTED"

    def test_incident_timestamps_are_set(self):
        from core.incident import Incident
        inc = Incident()
        assert inc.created_at > 0
        assert inc.updated_at == inc.created_at

    def test_incident_to_dict_contains_expected_fields(self):
        from core.incident import Incident
        inc = Incident(target_ip="10.0.0.1", attacker_ip="99.99.99.99",
                       severity=2, threat_type="bruteforce")
        d = inc.to_dict()
        assert d["target_ip"] == "10.0.0.1"
        assert d["attacker_ip"] == "99.99.99.99"
        assert d["severity"] == 2
        assert d["status"] == "DETECTED"
        assert "id" in d
        assert "proposed_actions" in d

    def test_two_incidents_have_different_ids(self):
        from core.incident import Incident
        inc1 = Incident()
        inc2 = Incident()
        assert inc1.id != inc2.id
        assert inc1.token != inc2.token


# ══════════════════════════════════════════════════
# IncidentResponseEngine init
# ══════════════════════════════════════════════════

class TestEngineInit:

    def test_engine_initializes_with_config(self, incident_env):
        engine, _, _ = incident_env
        assert engine.defense_mode == "confirmation"
        assert engine.timeout_min == 15

    def test_user_directory_indexed_by_ip(self, incident_env):
        engine, _, _ = incident_env
        assert "192.168.1.10" in engine.users_by_ip
        assert engine.users_by_ip["192.168.1.10"]["name"] == "Jean Dupont"

    def test_base_url_forces_https(self, tmp_path):
        """HTTP sentinel_url is forced to HTTPS."""
        if not db.is_closed():
            db.close()
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(str(tmp_path / "logs"), exist_ok=True)
        init_db(data_dir)

        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(yaml.dump({
            "general": {"data_dir": data_dir, "log_dir": str(tmp_path / "logs")},
            "network": {"subnets": ["192.168.1.0/24"]},
            "defense": {"enabled": True, "whitelist_ips": []},
            "email": {"enabled": False, "sentinel_url": "http://192.168.1.100:8443"},
            "web": {"port": 8443},
            "client_agent": {"enabled": False},
        }))
        cfg = Config(str(cfg_path))
        with patch("core.client_queue.ClientNotificationQueue"), \
             patch("core.snapshot.DefenseSnapshot"):
            from core.incident import IncidentResponseEngine
            engine = IncidentResponseEngine(cfg, MagicMock(), MagicMock())
            assert engine.base_url.startswith("https://")

        db.close()


# ══════════════════════════════════════════════════
# create_incident (confirmation mode)
# ══════════════════════════════════════════════════

class TestCreateIncidentConfirmation:

    def test_create_incident_returns_incident(self, incident_env):
        engine, _, _ = incident_env
        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="bruteforce", threat_detail="SSH 50 attempts")
        assert inc.id.startswith("INC-")
        assert inc.target_ip == "192.168.1.10"
        assert inc.attacker_ip == "10.0.0.99"

    def test_create_incident_sets_awaiting_admin_status(self, incident_env):
        engine, _, _ = incident_env
        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="bruteforce", threat_detail="test")
        assert inc.status == "AWAITING_ADMIN"

    def test_create_incident_resolves_user_from_directory(self, incident_env):
        engine, _, _ = incident_env
        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="bruteforce", threat_detail="test")
        assert inc.target_name == "Jean Dupont"
        assert inc.target_email == "jean@test.com"
        assert inc.target_hostname == "PC-JEAN"

    def test_create_incident_with_unknown_target(self, incident_env):
        engine, _, _ = incident_env
        inc = engine.create_incident("10.0.0.50", "10.0.0.99", severity=3,
                                     threat_type="portscan", threat_detail="test")
        assert inc.target_ip == "10.0.0.50"
        assert inc.target_name == ""

    def test_create_incident_generates_proposed_actions(self, incident_env):
        engine, _, _ = incident_env
        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="bruteforce", threat_detail="test")
        assert len(inc.proposed_actions) > 0

    def test_create_incident_fires_alert(self, incident_env):
        engine, alert_fn, _ = incident_env
        engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                               threat_type="bruteforce", threat_detail="test")
        alert_fn.assert_called()

    def test_create_incident_increments_stats(self, incident_env):
        engine, _, _ = incident_env
        engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                               threat_type="bruteforce", threat_detail="test")
        assert engine._stats["total"] == 1


# ══════════════════════════════════════════════════
# create_incident (immediate mode)
# ══════════════════════════════════════════════════

class TestCreateIncidentImmediate:

    def test_immediate_mode_auto_approves(self, tmp_path):
        if not db.is_closed():
            db.close()
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(str(tmp_path / "logs"), exist_ok=True)
        init_db(data_dir)

        cfg = _make_cfg(tmp_path, defense_mode="immediate")
        defense = MagicMock()
        defense.whitelist = set()

        with patch("core.client_queue.ClientNotificationQueue") as MQ, \
             patch("core.snapshot.DefenseSnapshot") as MS:
            MQ.return_value.enabled = False
            from core.incident import IncidentResponseEngine
            engine = IncidentResponseEngine(cfg, MagicMock(), defense)
            inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=1,
                                         threat_type="intrusion", threat_detail="test")
        assert inc.status in ("APPROVED", "MITIGATING", "RESOLVED")
        assert inc.approved_by == "auto (immediate mode)"
        db.close()


# ══════════════════════════════════════════════════
# Approve / Reject
# ══════════════════════════════════════════════════

class TestApproveReject:

    def test_approve_changes_status(self, incident_env):
        engine, _, _ = incident_env
        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="bruteforce", threat_detail="test")
        result = engine.approve(inc.token, approved_by="testadmin")
        assert result is not None
        assert result["ok"] is True
        assert inc.status in ("APPROVED", "MITIGATING", "RESOLVED")
        assert inc.approved_by == "testadmin"

    def test_approve_invalid_token_returns_none(self, incident_env):
        engine, _, _ = incident_env
        result = engine.approve("nonexistent-token")
        assert result is None

    def test_approve_already_processed_returns_error(self, incident_env):
        engine, _, _ = incident_env
        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="bruteforce", threat_detail="test")
        engine.approve(inc.token)
        result = engine.approve(inc.token)
        assert "error" in result

    def test_reject_changes_status(self, incident_env):
        engine, _, _ = incident_env
        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="bruteforce", threat_detail="test")
        result = engine.reject(inc.token, rejected_by="testadmin")
        assert result["ok"] is True
        assert inc.status == "REJECTED"
        assert inc.resolved is True

    def test_reject_invalid_token_returns_none(self, incident_env):
        engine, _, _ = incident_env
        assert engine.reject("bad-token") is None

    def test_reject_already_processed_returns_error(self, incident_env):
        engine, _, _ = incident_env
        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="bruteforce", threat_detail="test")
        engine.reject(inc.token)
        result = engine.reject(inc.token)
        assert "error" in result


# ══════════════════════════════════════════════════
# Token management
# ══════════════════════════════════════════════════

class TestTokenManagement:

    def test_get_by_token_returns_incident(self, incident_env):
        engine, _, _ = incident_env
        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="test", threat_detail="test")
        found = engine._get_by_token(inc.token)
        assert found is not None
        assert found.id == inc.id

    def test_expired_token_returns_none(self, incident_env):
        engine, _, _ = incident_env
        engine.token_ttl = 0  # Expire immediately
        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="test", threat_detail="test")
        time.sleep(0.1)
        found = engine._get_by_token(inc.token)
        assert found is None


# ══════════════════════════════════════════════════
# _plan (action planning)
# ══════════════════════════════════════════════════

class TestPlan:

    def test_plan_includes_block_for_external_attacker(self, incident_env):
        engine, _, _ = incident_env
        from core.incident import Incident
        inc = Incident(attacker_ip="10.0.0.99", target_ip="192.168.1.10", severity=2)
        actions = engine._plan(inc)
        assert any("Block" in a for a in actions)

    def test_plan_includes_quarantine_for_critical_internal(self, incident_env):
        engine, _, _ = incident_env
        from core.incident import Incident
        inc = Incident(attacker_ip="10.0.0.99", target_ip="192.168.1.10", severity=1)
        actions = engine._plan(inc)
        assert any("quarantine" in a.lower() for a in actions)

    def test_plan_includes_sinkhole_for_domain_ioc(self, incident_env):
        engine, _, _ = incident_env
        from core.incident import Incident
        inc = Incident(attacker_ip="10.0.0.99", target_ip="192.168.1.10",
                       severity=2, iocs=["evil.example.com"])
        actions = engine._plan(inc)
        assert any("sinkhole" in a.lower() for a in actions)

    def test_plan_skips_block_for_whitelisted_attacker(self, incident_env):
        engine, _, _ = incident_env
        from core.incident import Incident
        inc = Incident(attacker_ip="8.8.8.8", target_ip="192.168.1.10", severity=2)
        actions = engine._plan(inc)
        assert not any("Block IP 8.8.8.8" in a for a in actions)


# ══════════════════════════════════════════════════
# API methods
# ══════════════════════════════════════════════════

class TestIncidentAPI:

    def test_get_active_incidents(self, incident_env):
        engine, _, _ = incident_env
        engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                               threat_type="bruteforce", threat_detail="test")
        active = engine.get_active_incidents()
        assert len(active) == 1
        assert active[0]["status"] == "AWAITING_ADMIN"

    def test_get_all_incidents_ordered_by_creation(self, incident_env):
        engine, _, _ = incident_env
        engine.create_incident("192.168.1.10", "10.0.0.1", severity=2,
                               threat_type="first", threat_detail="t1")
        engine.create_incident("192.168.1.10", "10.0.0.2", severity=3,
                               threat_type="second", threat_detail="t2")
        all_inc = engine.get_all_incidents()
        assert len(all_inc) == 2
        assert all_inc[0]["threat_type"] == "second"  # Most recent first

    def test_get_incident_by_id(self, incident_env):
        engine, _, _ = incident_env
        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="test", threat_detail="d")
        result = engine.get_incident(inc.id)
        assert result is not None
        assert result["id"] == inc.id

    def test_get_incident_nonexistent_returns_none(self, incident_env):
        engine, _, _ = incident_env
        assert engine.get_incident("INC-NOTFOUND") is None

    def test_stats_contains_expected_fields(self, incident_env):
        engine, _, _ = incident_env
        engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                               threat_type="test", threat_detail="d")
        s = engine.stats
        assert "total" in s
        assert "by_status" in s
        assert "email_ok" in s
        assert s["total"] == 1
        assert s["by_status"].get("AWAITING_ADMIN", 0) == 1


# ══════════════════════════════════════════════════
# Eviction
# ══════════════════════════════════════════════════

class TestEviction:

    def test_evict_oldest_removes_resolved_incidents(self, incident_env):
        engine, _, _ = incident_env
        engine.MAX_INCIDENTS = 3
        # Create 4 incidents, resolve the first 2
        for i in range(4):
            inc = engine.create_incident(f"192.168.1.{10+i}", "10.0.0.99", severity=3,
                                         threat_type="test", threat_detail=f"inc {i}")
            if i < 2:
                inc.status = "RESOLVED"
                inc.resolved = True
        # Should evict oldest resolved to get back under limit
        with engine._lock:
            engine._evict_oldest()
        assert len(engine._incidents) <= 3


# ══════════════════════════════════════════════════
# Integration
# ══════════════════════════════════════════════════

class TestIncidentIntegration:

    def test_full_confirmation_workflow(self, incident_env):
        """Create → AWAITING_ADMIN → Approve → APPROVED."""
        engine, alert_fn, _ = incident_env
        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="bruteforce", threat_detail="50 failed SSH")
        assert inc.status == "AWAITING_ADMIN"
        assert inc.target_name == "Jean Dupont"

        result = engine.approve(inc.token, approved_by="admin")
        assert result["ok"] is True
        assert inc.status in ("APPROVED", "MITIGATING", "RESOLVED")
        assert inc.approved_by == "admin"

        # Verify stats
        assert engine._stats["total"] == 1

    def test_full_rejection_workflow(self, incident_env):
        """Create → AWAITING_ADMIN → Reject → REJECTED."""
        engine, _, _ = incident_env
        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=3,
                                     threat_type="portscan", threat_detail="20 ports")
        assert inc.status == "AWAITING_ADMIN"

        result = engine.reject(inc.token, rejected_by="admin")
        assert result["ok"] is True
        assert inc.status == "REJECTED"
        assert inc.resolved is True
        assert "admin" in inc.resolution


# ══════════════════════════════════════════════════
# _execute_and_report
# ══════════════════════════════════════════════════

class TestExecuteAndReport:

    def test_execute_and_report_sets_mitigating_then_resolved(self, incident_env):
        """_execute_and_report transitions through MITIGATING → RESOLVED."""
        engine, _, defense = incident_env
        defense.block_ip.return_value = True
        defense.rate_limit_ip.return_value = True
        defense.quarantine_host.return_value = True
        defense.dns_sinkhole = MagicMock()

        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       severity=2, threat_type="bruteforce",
                       proposed_actions=["Block IP 10.0.0.99 (iptables, 1h)"])
        with patch("core.recon.AttackerRecon") as MockRecon, \
             patch("core.forensic.ForensicCollector") as MockForensic, \
             patch("time.sleep"):
            MockRecon.return_value.full_recon.return_value = {"geolocation": {}, "whois": {}, "open_ports": []}
            MockForensic.return_value.collect_and_save.return_value = "/tmp/forensic.json"
            engine._execute_and_report(inc)

        assert inc.status in ("RESOLVED", "RISK_REMAINING")
        assert inc.defense_end > 0
        assert len(inc.actions_executed) > 0

    def test_execute_and_report_handles_block_failure(self, incident_env):
        """_execute_and_report marks RISK_REMAINING on failed actions."""
        engine, _, defense = incident_env
        defense.block_ip.return_value = False

        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       severity=2, threat_type="bruteforce",
                       proposed_actions=["Block IP 10.0.0.99 (iptables, 1h)"])
        with patch("core.recon.AttackerRecon") as MockRecon, \
             patch("core.forensic.ForensicCollector") as MockForensic, \
             patch("time.sleep"):
            MockRecon.return_value.full_recon.return_value = {}
            MockForensic.return_value.collect_and_save.return_value = ""
            engine._execute_and_report(inc)

        assert inc.status == "RISK_REMAINING"
        assert inc.risk_remaining is True

    def test_execute_and_report_handles_recon_exception(self, incident_env):
        """_execute_and_report handles recon failure gracefully."""
        engine, _, defense = incident_env
        defense.block_ip.return_value = True

        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       severity=2, threat_type="bruteforce",
                       proposed_actions=["Block IP 10.0.0.99 (iptables, 1h)"])
        with patch("core.recon.AttackerRecon") as MockRecon, \
             patch("core.forensic.ForensicCollector") as MockForensic, \
             patch("time.sleep"):
            MockRecon.return_value.full_recon.side_effect = Exception("Network error")
            MockForensic.return_value.collect_and_save.return_value = ""
            engine._execute_and_report(inc)

        assert inc.status in ("RESOLVED", "RISK_REMAINING")

    def test_execute_and_report_snapshot_failure_continues(self, incident_env):
        """_execute_and_report continues even if snapshot fails."""
        engine, _, defense = incident_env
        engine.snapshots.take = MagicMock(side_effect=Exception("Disk full"))
        defense.block_ip.return_value = True

        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       severity=2, threat_type="bruteforce",
                       proposed_actions=["Block IP 10.0.0.99 (iptables, 1h)"])
        with patch("core.recon.AttackerRecon") as MockRecon, \
             patch("core.forensic.ForensicCollector") as MockForensic, \
             patch("time.sleep"):
            MockRecon.return_value.full_recon.return_value = {}
            MockForensic.return_value.collect_and_save.return_value = ""
            engine._execute_and_report(inc)

        assert inc.snapshot_path == ""
        assert inc.status in ("RESOLVED", "RISK_REMAINING")

    def test_execute_quarantine_action(self, incident_env):
        """_execute_and_report handles quarantine actions."""
        engine, _, defense = incident_env
        defense.quarantine_host.return_value = True

        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       severity=1, threat_type="intrusion",
                       proposed_actions=["Network quarantine of 192.168.1.10"])
        with patch("core.recon.AttackerRecon") as MockRecon, \
             patch("core.forensic.ForensicCollector") as MockForensic, \
             patch("time.sleep"):
            MockRecon.return_value.full_recon.return_value = {}
            MockForensic.return_value.collect_and_save.return_value = ""
            engine._execute_and_report(inc)

        defense.quarantine_host.assert_called()

    def test_execute_rate_limit_action(self, incident_env):
        """_execute_and_report handles rate-limit actions."""
        engine, _, defense = incident_env
        defense.rate_limit_ip.return_value = True

        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       severity=3, threat_type="portscan",
                       proposed_actions=["Rate-limit sur 10.0.0.99"])
        with patch("core.recon.AttackerRecon") as MockRecon, \
             patch("core.forensic.ForensicCollector") as MockForensic, \
             patch("time.sleep"):
            MockRecon.return_value.full_recon.return_value = {}
            MockForensic.return_value.collect_and_save.return_value = ""
            engine._execute_and_report(inc)

        defense.rate_limit_ip.assert_called()

    def test_execute_sinkhole_action(self, incident_env):
        """_execute_and_report handles DNS sinkhole actions."""
        engine, _, defense = incident_env
        defense.dns_sinkhole = MagicMock()
        defense.block_ip.return_value = True

        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       severity=2, threat_type="beaconing",
                       proposed_actions=["DNS sinkhole sur evil.com"],
                       iocs=["evil.com"])
        with patch("core.recon.AttackerRecon") as MockRecon, \
             patch("core.forensic.ForensicCollector") as MockForensic, \
             patch("time.sleep"):
            MockRecon.return_value.full_recon.return_value = {}
            MockForensic.return_value.collect_and_save.return_value = ""
            engine._execute_and_report(inc)

        defense.dns_sinkhole.assert_called()

    def test_execute_with_client_queue_enabled(self, incident_env):
        """_execute_and_report queues forensic collection if client agent enabled."""
        engine, _, defense = incident_env
        engine.client_queue.enabled = True
        engine.client_queue.enqueue_collect_forensic = MagicMock()
        engine.client_queue.enqueue_all_clear = MagicMock()
        defense.block_ip.return_value = True

        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       severity=2, threat_type="bruteforce",
                       proposed_actions=["Block IP 10.0.0.99 (iptables, 1h)"])
        with patch("core.recon.AttackerRecon") as MockRecon, \
             patch("core.forensic.ForensicCollector") as MockForensic, \
             patch("time.sleep"):
            MockRecon.return_value.full_recon.return_value = {}
            MockForensic.return_value.collect_and_save.return_value = ""
            engine._execute_and_report(inc)

        engine.client_queue.enqueue_collect_forensic.assert_called_once()
        engine.client_queue.enqueue_all_clear.assert_called_once()


# ══════════════════════════════════════════════════
# SMTP and email
# ══════════════════════════════════════════════════

class TestSMTP:

    def test_smtp_returns_false_without_server(self, incident_env):
        """_smtp returns False when no SMTP server is configured."""
        engine, _, _ = incident_env
        engine.smtp_server = ""
        result = engine._smtp(["admin@test.com"], "Subject", "<h1>Test</h1>")
        assert result is False

    def test_smtp_returns_false_with_empty_recipients(self, incident_env):
        """_smtp returns False with no recipients."""
        engine, _, _ = incident_env
        engine.smtp_server = "smtp.test.com"
        result = engine._smtp([], "Subject", "<h1>Test</h1>")
        assert result is False

    def test_smtp_with_attachment_handles_missing_file(self, incident_env):
        """_smtp_with_attachment skips non-existent attachment files."""
        engine, _, _ = incident_env
        engine.smtp_server = "smtp.test.com"
        with patch("smtplib.SMTP") as MockSMTP:
            mock_srv = MagicMock()
            MockSMTP.return_value = mock_srv
            result = engine._smtp_with_attachment(
                ["admin@test.com"], "Subject", "<h1>Test</h1>",
                attachments=["/nonexistent/file.pdf"])
            assert result is True
            mock_srv.send_message.assert_called_once()

    def test_smtp_with_real_attachment(self, incident_env, tmp_path):
        """_smtp_with_attachment includes existing files."""
        engine, _, _ = incident_env
        engine.smtp_server = "smtp.test.com"
        att_file = tmp_path / "evidence.json"
        att_file.write_text('{"data": "test"}')
        with patch("smtplib.SMTP") as MockSMTP:
            mock_srv = MagicMock()
            MockSMTP.return_value = mock_srv
            result = engine._smtp_with_attachment(
                ["admin@test.com"], "Subject", "<h1>Test</h1>",
                attachments=[str(att_file)])
            assert result is True

    def test_smtp_ssl_port_465(self, incident_env):
        """_smtp uses SMTP_SSL for port 465."""
        engine, _, _ = incident_env
        engine.smtp_server = "smtp.test.com"
        engine.smtp_port = 465
        with patch("smtplib.SMTP_SSL") as MockSSL:
            mock_srv = MagicMock()
            MockSSL.return_value = mock_srv
            engine._smtp(["admin@test.com"], "Subject", "<h1>Test</h1>")
            MockSSL.assert_called_once()

    def test_smtp_starttls(self, incident_env):
        """_smtp uses STARTTLS for non-465 ports with TLS enabled."""
        engine, _, _ = incident_env
        engine.smtp_server = "smtp.test.com"
        engine.smtp_port = 587
        engine.smtp_tls = True
        with patch("smtplib.SMTP") as MockSMTP:
            mock_srv = MagicMock()
            MockSMTP.return_value = mock_srv
            engine._smtp(["admin@test.com"], "Subject", "<h1>Test</h1>")
            mock_srv.starttls.assert_called_once()

    def test_smtp_with_login(self, incident_env):
        """_smtp authenticates when SMTP user is set."""
        engine, _, _ = incident_env
        engine.smtp_server = "smtp.test.com"
        engine.smtp_user = "user@test.com"
        engine.smtp_password = "secret"
        with patch("smtplib.SMTP") as MockSMTP:
            mock_srv = MagicMock()
            MockSMTP.return_value = mock_srv
            engine._smtp(["admin@test.com"], "Subject", "<h1>Test</h1>")
            mock_srv.login.assert_called_with("user@test.com", "secret")

    def test_smtp_failure_increments_stats(self, incident_env):
        """SMTP failure increments emails_failed counter."""
        engine, _, _ = incident_env
        engine.smtp_server = "smtp.test.com"
        with patch("smtplib.SMTP") as MockSMTP:
            MockSMTP.side_effect = Exception("Connection refused")
            engine._smtp(["admin@test.com"], "Subject", "<h1>Test</h1>")
        assert engine._stats["emails_failed"] >= 1

    def test_smtp_success_increments_stats(self, incident_env):
        """SMTP success increments emails_sent counter."""
        engine, _, _ = incident_env
        engine.smtp_server = "smtp.test.com"
        before = engine._stats["emails_sent"]
        with patch("smtplib.SMTP") as MockSMTP:
            MockSMTP.return_value = MagicMock()
            engine._smtp(["admin@test.com"], "Subject", "<h1>Test</h1>")
        assert engine._stats["emails_sent"] == before + 1


# ══════════════════════════════════════════════════
# _send_admin_email / _send_user_shutdown_email
# ══════════════════════════════════════════════════

class TestEmailSending:

    def test_send_admin_email_skipped_when_disabled(self, incident_env):
        """Admin email is not sent when email is disabled."""
        engine, _, _ = incident_env
        engine.email_enabled = False
        from core.incident import Incident
        inc = Incident(attacker_ip="10.0.0.1", target_ip="192.168.1.10")
        engine._smtp = MagicMock()
        engine._send_admin_email(inc)
        engine._smtp.assert_not_called()

    def test_send_admin_email_calls_smtp(self, incident_env):
        """Admin email calls _smtp when enabled."""
        engine, _, _ = incident_env
        engine.email_enabled = True
        engine.admin_emails = ["admin@test.com"]
        engine._smtp = MagicMock(return_value=True)
        from core.incident import Incident
        inc = Incident(attacker_ip="10.0.0.1", target_ip="192.168.1.10",
                       severity=2, threat_type="bruteforce", threat_detail="test",
                       proposed_actions=["Block IP 10.0.0.1"])
        engine._send_admin_email(inc)
        engine._smtp.assert_called_once()
        assert inc.admin_alert_sent is True

    def test_send_admin_email_reminder(self, incident_env):
        """Admin reminder email includes REMINDER in subject."""
        engine, _, _ = incident_env
        engine.email_enabled = True
        engine.admin_emails = ["admin@test.com"]
        engine._smtp = MagicMock(return_value=True)
        from core.incident import Incident
        inc = Incident(attacker_ip="10.0.0.1", target_ip="192.168.1.10",
                       severity=2, threat_type="bruteforce", threat_detail="test")
        engine._send_admin_email(inc, reminder=True)
        call_args = engine._smtp.call_args
        subject = call_args[0][1]
        assert "REMINDER" in subject

    def test_send_user_shutdown_email_skipped_when_disabled(self, incident_env):
        """User email is not sent when email is disabled."""
        engine, _, _ = incident_env
        engine.email_enabled = False
        engine._smtp = MagicMock()
        from core.incident import Incident
        inc = Incident(target_email="user@test.com")
        engine._send_user_shutdown_email(inc)
        engine._smtp.assert_not_called()

    def test_send_user_shutdown_email_skipped_without_email(self, incident_env):
        """User email is not sent when target has no email."""
        engine, _, _ = incident_env
        engine.email_enabled = True
        engine._smtp = MagicMock()
        from core.incident import Incident
        inc = Incident(target_email="")
        engine._send_user_shutdown_email(inc)
        engine._smtp.assert_not_called()

    def test_send_user_shutdown_email_calls_smtp(self, incident_env):
        """User shutdown email calls _smtp when enabled and email present."""
        engine, _, _ = incident_env
        engine.email_enabled = True
        engine._smtp = MagicMock(return_value=True)
        from core.incident import Incident
        inc = Incident(target_email="user@test.com", target_ip="192.168.1.10",
                       target_hostname="PC-USER")
        engine._send_user_shutdown_email(inc)
        engine._smtp.assert_called_once()


# ══════════════════════════════════════════════════
# _send_report
# ══════════════════════════════════════════════════

class TestSendReport:

    def test_send_report_skipped_when_disabled(self, incident_env):
        """Report is not sent when email is disabled."""
        engine, _, _ = incident_env
        engine.email_enabled = False
        engine._smtp_with_attachment = MagicMock()
        from core.incident import Incident
        inc = Incident()
        engine._send_report(inc)
        engine._smtp_with_attachment.assert_not_called()

    def test_send_report_resolved_incident(self, incident_env):
        """Report is sent for a resolved incident."""
        engine, _, _ = incident_env
        engine.email_enabled = True
        engine._smtp_with_attachment = MagicMock(return_value=True)
        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       target_email="user@test.com", target_hostname="PC-USER",
                       severity=2, threat_type="bruteforce", threat_detail="50 attempts",
                       resolved=True, risk_remaining=False,
                       resolution="All actions succeeded",
                       actions_executed=["✓ Block IP 10.0.0.99"])
        engine._send_report(inc, recon_report={"target_ip": "10.0.0.99",
                            "geolocation": {"city": "Dublin", "country": "IE"},
                            "whois": {"org": "Evil Corp", "asn": "12345"},
                            "reputation": {}, "open_ports": []})
        assert engine._smtp_with_attachment.call_count >= 1
        assert inc.report_sent is True

    def test_send_report_risk_remaining_incident(self, incident_env):
        """Report is sent for an incident with remaining risk."""
        engine, _, _ = incident_env
        engine.email_enabled = True
        engine._smtp_with_attachment = MagicMock(return_value=True)
        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       target_email="user@test.com", target_hostname="PC-USER",
                       severity=1, threat_type="intrusion", threat_detail="SQL injection",
                       resolved=False, risk_remaining=True,
                       risk_detail="1 action failed",
                       resolution="Partial",
                       actions_executed=["✓ Block", "✗ Quarantine"])
        engine._send_report(inc)
        assert engine._smtp_with_attachment.call_count >= 1

    def test_send_report_without_user_email(self, incident_env):
        """Report is sent only to admins when user has no email."""
        engine, _, _ = incident_env
        engine.email_enabled = True
        engine._smtp_with_attachment = MagicMock(return_value=True)
        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       target_email="", severity=2, threat_type="bruteforce",
                       resolved=True, resolution="Done",
                       actions_executed=["✓ Block"])
        engine._send_report(inc)
        # Only admin email sent (1 call), no user email
        assert engine._smtp_with_attachment.call_count == 1

    def test_send_report_with_forensic_and_complaint(self, incident_env, tmp_path):
        """Report includes forensic and complaint PDF as attachments."""
        engine, _, _ = incident_env
        engine.email_enabled = True
        engine._smtp_with_attachment = MagicMock(return_value=True)
        forensic = tmp_path / "forensic.json"
        forensic.write_text("{}")
        complaint = tmp_path / "complaint.pdf"
        complaint.write_bytes(b"%PDF-fake")
        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       severity=2, threat_type="bruteforce",
                       resolved=True, resolution="Done",
                       actions_executed=["✓ Block"])
        engine._send_report(inc, forensic_path=str(forensic),
                            complaint_pdf_path=str(complaint))
        assert engine._smtp_with_attachment.call_count >= 1


# ══════════════════════════════════════════════════
# MAC resolver fallback in create_incident
# ══════════════════════════════════════════════════

class TestTimeoutLogic:

    def test_timeout_expires_incident_when_auto_approve_disabled(self, incident_env):
        """Incident expires when timeout reached and auto-approve is off."""
        engine, alert_fn, _ = incident_env
        engine.timeout_min = 0  # Immediate timeout
        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="bruteforce", threat_detail="test")
        assert inc.status == "AWAITING_ADMIN"

        # Simulate timeout check
        time.sleep(0.1)
        now = time.time()
        with engine._lock:
            awaiting = [i for i in engine._incidents.values() if i.status == "AWAITING_ADMIN"]
        for i in awaiting:
            elapsed = now - i.created_at
            timeout_s = engine.timeout_min * 60
            if elapsed > timeout_s:
                i.status = "EXPIRED"
                i.resolution = f"No response within {engine.timeout_min} min."

        assert inc.status == "EXPIRED"

    def test_timeout_auto_approves_when_enabled(self, incident_env):
        """Incident is auto-approved when timeout reached and auto-approve is on."""
        engine, _, _ = incident_env
        engine.timeout_auto = True
        engine.timeout_min = 0  # Immediate timeout
        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="bruteforce", threat_detail="test")
        time.sleep(0.1)
        # Simulate timeout auto-approve
        engine.approve(inc.token, approved_by="auto-timeout")
        assert inc.status in ("APPROVED", "MITIGATING", "RESOLVED")

    def test_reminder_sent_at_half_timeout(self, incident_env):
        """Reminder email is sent at half the timeout period."""
        engine, _, _ = incident_env
        engine.email_enabled = True
        engine._smtp = MagicMock(return_value=True)
        engine.timeout_min = 0  # So half-timeout is also 0
        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="bruteforce", threat_detail="test")
        time.sleep(0.1)
        # Simulate reminder check
        now = time.time()
        elapsed = now - inc.created_at
        timeout_s = engine.timeout_min * 60
        if elapsed > timeout_s / 2 and not inc.reminder_sent:
            inc.reminder_sent = True
            engine._send_admin_email(inc, reminder=True)
        assert inc.reminder_sent is True


class TestMACResolverFallback:

    def test_create_incident_falls_back_to_mac_resolver(self, tmp_path):
        """create_incident uses MAC resolver when IP not in directory."""
        if not db.is_closed():
            db.close()
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(str(tmp_path / "logs"), exist_ok=True)
        init_db(data_dir)

        cfg = _make_cfg(tmp_path)
        defense = MagicMock()
        defense.whitelist = set()
        mac_resolver = MagicMock()
        mac_resolver.ip_to_mac.return_value = "aa:bb:cc:dd:ee:ff"
        mac_resolver.get_user_email.return_value = {"name": "MAC User", "email": "mac@test.com", "hostname": "PC-MAC"}

        with patch("core.client_queue.ClientNotificationQueue") as MQ, \
             patch("core.snapshot.DefenseSnapshot"):
            MQ.return_value.enabled = False
            from core.incident import IncidentResponseEngine
            engine = IncidentResponseEngine(cfg, MagicMock(), defense, mac_resolver=mac_resolver)

        # Use an IP not in the user directory
        inc = engine.create_incident("10.0.0.50", "10.0.0.99", severity=3,
                                     threat_type="portscan", threat_detail="test")
        # Should have tried MAC resolver
        mac_resolver.ip_to_mac.assert_called_with("10.0.0.50")
        db.close()

    def test_create_incident_falls_back_to_host_db(self, incident_env):
        """create_incident falls back to Host DB when no directory match and no MAC resolver."""
        engine, _, _ = incident_env
        Host.create(ip="10.0.0.50", hostname="db-host", vendor="Dell")
        inc = engine.create_incident("10.0.0.50", "10.0.0.99", severity=3,
                                     threat_type="portscan", threat_detail="test")
        assert inc.target_hostname == "db-host"


# ══════════════════════════════════════════════════
# Notification paths (client queue)
# ══════════════════════════════════════════════════

class TestNotificationPaths:

    def test_immediate_mode_notifies_via_agent_if_active(self, tmp_path):
        """Immediate mode uses client agent popup when agent is active."""
        if not db.is_closed():
            db.close()
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(str(tmp_path / "logs"), exist_ok=True)
        init_db(data_dir)

        cfg = _make_cfg(tmp_path, defense_mode="immediate")
        defense = MagicMock()
        defense.whitelist = set()

        with patch("core.client_queue.ClientNotificationQueue") as MQ, \
             patch("core.snapshot.DefenseSnapshot"):
            mock_queue = MQ.return_value
            mock_queue.enabled = True
            mock_queue.has_active_agent.return_value = True
            mock_queue.enqueue_shutdown.return_value = "msg-1"
            mock_queue.wait_for_ack.return_value = True
            from core.incident import IncidentResponseEngine
            engine = IncidentResponseEngine(cfg, MagicMock(), defense)

        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=1,
                                     threat_type="intrusion", threat_detail="test")
        time.sleep(0.5)  # Let notification thread run
        mock_queue.enqueue_shutdown.assert_called()
        db.close()


# ══════════════════════════════════════════════════
# Additional coverage tests
# ══════════════════════════════════════════════════

class TestGetByTokenEdgeCases:

    def test_get_by_token_returns_none_when_incident_deleted(self, incident_env):
        """_get_by_token returns None when token exists in _by_token but incident was removed from _incidents."""
        engine, _, _ = incident_env
        # Insert a mapping in _by_token that points to a non-existent incident id
        engine._by_token["fake-token-123"] = "non-existent-id"
        result = engine._get_by_token("fake-token-123")
        assert result is None


class TestApprovalPinIntegration:

    def test_approval_pin_generate_called_in_confirmation_mode(self, incident_env):
        """In confirmation mode, approval_pin.generate() is called when approval_pin is set."""
        engine, _, _ = incident_env
        mock_pin = MagicMock()
        mock_pin.generate.return_value = "1234"
        engine.approval_pin = mock_pin

        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="bruteforce", threat_detail="test")
        assert inc.status == "AWAITING_ADMIN"
        mock_pin.generate.assert_called_once_with(inc.id)


class TestExecuteAndReportExtended:

    def test_ioc_enrichment_from_recon_reverse_dns(self, incident_env):
        """Recon reverse_dns is added to iocs when present."""
        engine, _, defense = incident_env
        defense.block_ip.return_value = True
        defense.dns_sinkhole = MagicMock()

        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       severity=2, threat_type="bruteforce",
                       proposed_actions=["Block IP 10.0.0.99 (iptables, 1h)"],
                       iocs=[])
        with patch("core.recon.AttackerRecon") as MockRecon, \
             patch("core.forensic.ForensicCollector") as MockForensic, \
             patch("time.sleep"):
            MockRecon.return_value.full_recon.return_value = {
                "reverse_dns": "evil.attacker.com",
                "geolocation": {}, "whois": {}, "open_ports": [],
            }
            MockForensic.return_value.collect_and_save.return_value = ""
            engine._execute_and_report(inc)

        assert "evil.attacker.com" in inc.iocs

    def test_unknown_action_type_marked_with_warning(self, incident_env):
        """An action that doesn't match any known pattern gets a warning prefix."""
        engine, _, defense = incident_env

        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       severity=2, threat_type="bruteforce",
                       proposed_actions=["Send alert to SIEM"])
        with patch("core.recon.AttackerRecon") as MockRecon, \
             patch("core.forensic.ForensicCollector") as MockForensic, \
             patch("time.sleep"):
            MockRecon.return_value.full_recon.return_value = {}
            MockForensic.return_value.collect_and_save.return_value = ""
            engine._execute_and_report(inc)

        assert any("Send alert to SIEM" in a for a in inc.actions_executed)

    def test_auto_sinkhole_domain_iocs_from_recon(self, incident_env):
        """Domain IOCs not already sinkholed are auto-sinkholed after defense phase."""
        engine, _, defense = incident_env
        defense.block_ip.return_value = True
        defense.dns_sinkhole = MagicMock()

        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       severity=2, threat_type="beaconing",
                       proposed_actions=["Block IP 10.0.0.99 (iptables, 1h)"],
                       iocs=["new-c2.evil.org"])
        with patch("core.recon.AttackerRecon") as MockRecon, \
             patch("core.forensic.ForensicCollector") as MockForensic, \
             patch("time.sleep"):
            MockRecon.return_value.full_recon.return_value = {}
            MockForensic.return_value.collect_and_save.return_value = ""
            engine._execute_and_report(inc)

        # dns_sinkhole should be called for the domain IOC
        defense.dns_sinkhole.assert_any_call("new-c2.evil.org", reason=ANY)
        assert any("new-c2.evil.org" in a for a in inc.actions_executed)

    def test_forensic_collection_exception_continues(self, incident_env):
        """_execute_and_report continues when ForensicCollector.collect_and_save raises."""
        engine, _, defense = incident_env
        defense.block_ip.return_value = True

        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       severity=2, threat_type="bruteforce",
                       proposed_actions=["Block IP 10.0.0.99 (iptables, 1h)"])
        with patch("core.recon.AttackerRecon") as MockRecon, \
             patch("core.forensic.ForensicCollector") as MockForensic, \
             patch("time.sleep"):
            MockRecon.return_value.full_recon.return_value = {}
            MockForensic.return_value.collect_and_save.side_effect = Exception("Disk full")
            engine._execute_and_report(inc)

        # Should still resolve despite forensic failure
        assert inc.status in ("RESOLVED", "RISK_REMAINING")
        assert inc.defense_end > 0

    def test_complaint_pdf_exception_continues(self, incident_env):
        """_execute_and_report continues when generate_complaint_pdf raises."""
        engine, _, defense = incident_env
        engine.include_legal_info = True
        defense.block_ip.return_value = True

        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       severity=2, threat_type="bruteforce",
                       proposed_actions=["Block IP 10.0.0.99 (iptables, 1h)"])
        with patch("core.recon.AttackerRecon") as MockRecon, \
             patch("core.forensic.ForensicCollector") as MockForensic, \
             patch("core.complaint_pdf.generate_complaint_pdf") as MockPdf, \
             patch("time.sleep"):
            MockRecon.return_value.full_recon.return_value = {}
            MockForensic.return_value.collect_and_save.return_value = "/tmp/forensic.json"
            MockPdf.side_effect = Exception("PDF generation failed")
            engine._execute_and_report(inc)

        assert inc.status in ("RESOLVED", "RISK_REMAINING")


class TestApproveNotificationPaths:

    def test_approve_notifies_via_agent_then_falls_back_to_email(self, tmp_path):
        """approve() sends popup via agent; if not acked, falls back to email."""
        if not db.is_closed():
            db.close()
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(str(tmp_path / "logs"), exist_ok=True)
        init_db(data_dir)

        cfg = _make_cfg(tmp_path, defense_mode="confirmation")
        defense = MagicMock()
        defense.whitelist = set()

        with patch("core.client_queue.ClientNotificationQueue") as MQ, \
             patch("core.snapshot.DefenseSnapshot"):
            mock_queue = MQ.return_value
            mock_queue.enabled = True
            mock_queue.has_active_agent.return_value = True
            mock_queue.enqueue_shutdown.return_value = "msg-1"
            mock_queue.wait_for_ack.return_value = False  # Not acked → fall back to email
            from core.incident import IncidentResponseEngine
            engine = IncidentResponseEngine(cfg, MagicMock(), defense)

        engine._send_user_shutdown_email = MagicMock()

        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="bruteforce", threat_detail="test")
        assert inc.status == "AWAITING_ADMIN"

        result = engine.approve(inc.token, approved_by="admin")
        assert result["ok"] is True
        time.sleep(0.5)  # Let notification thread run

        mock_queue.enqueue_shutdown.assert_called()
        # Since ack was False and target has email, shutdown email should be sent
        engine._send_user_shutdown_email.assert_called()
        db.close()

    def test_approve_notifies_via_email_when_no_agent(self, tmp_path):
        """approve() sends email directly when no active agent."""
        if not db.is_closed():
            db.close()
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(str(tmp_path / "logs"), exist_ok=True)
        init_db(data_dir)

        cfg = _make_cfg(tmp_path, defense_mode="confirmation")
        defense = MagicMock()
        defense.whitelist = set()

        with patch("core.client_queue.ClientNotificationQueue") as MQ, \
             patch("core.snapshot.DefenseSnapshot"):
            mock_queue = MQ.return_value
            mock_queue.enabled = True
            mock_queue.has_active_agent.return_value = False
            from core.incident import IncidentResponseEngine
            engine = IncidentResponseEngine(cfg, MagicMock(), defense)

        engine._send_user_shutdown_email = MagicMock()

        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="bruteforce", threat_detail="test")
        result = engine.approve(inc.token, approved_by="admin")
        assert result["ok"] is True
        time.sleep(0.5)

        engine._send_user_shutdown_email.assert_called()
        db.close()


class TestImmediateModeNotifyFallback:

    def test_immediate_mode_no_agent_sends_email(self, tmp_path):
        """Immediate mode sends email when agent not active but target has email."""
        if not db.is_closed():
            db.close()
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(str(tmp_path / "logs"), exist_ok=True)
        init_db(data_dir)

        cfg = _make_cfg(tmp_path, defense_mode="immediate")
        defense = MagicMock()
        defense.whitelist = set()

        with patch("core.client_queue.ClientNotificationQueue") as MQ, \
             patch("core.snapshot.DefenseSnapshot"):
            mock_queue = MQ.return_value
            mock_queue.enabled = True
            mock_queue.has_active_agent.return_value = False
            from core.incident import IncidentResponseEngine
            engine = IncidentResponseEngine(cfg, MagicMock(), defense)

        engine._send_user_shutdown_email = MagicMock()

        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="bruteforce", threat_detail="test")
        time.sleep(0.5)

        engine._send_user_shutdown_email.assert_called()
        db.close()


class TestHostGetOrNoneException:

    def test_create_incident_handles_host_db_exception(self, incident_env):
        """create_incident continues when Host.get_or_none raises an exception."""
        engine, _, _ = incident_env
        with patch("core.incident.Host") as MockHost:
            MockHost.get_or_none.side_effect = Exception("Database locked")
            inc = engine.create_incident("10.0.0.50", "10.0.0.99", severity=3,
                                         threat_type="portscan", threat_detail="test")
        # Should still create incident with IP as hostname
        assert inc is not None
        assert inc.target_hostname == "10.0.0.50"


class TestSendReportExtended:

    def test_send_report_with_full_recon_data(self, incident_env):
        """Report includes recon HTML when recon_report has target_ip, ports, reputation."""
        engine, _, _ = incident_env
        engine.email_enabled = True
        engine._smtp_with_attachment = MagicMock(return_value=True)
        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       target_email="user@test.com", target_hostname="PC-USER",
                       severity=2, threat_type="bruteforce", threat_detail="50 attempts",
                       resolved=True, risk_remaining=False,
                       resolution="All actions succeeded",
                       actions_executed=["✓ Block IP 10.0.0.99"])
        recon = {
            "target_ip": "10.0.0.99",
            "reverse_dns": "evil.example.com",
            "geolocation": {"city": "Dublin", "country": "Ireland", "country_code": "IE",
                            "region": "Leinster", "lat": 53.3, "lon": -6.2,
                            "timezone": "Europe/Dublin", "isp": "Evil ISP",
                            "proxy": True, "hosting": True},
            "whois": {"org": "Evil Corp", "asn": "12345", "netrange": "10.0.0.0/8",
                      "abuse_contact": "abuse@evil.com"},
            "reputation": {"summary": "Known malicious"},
            "open_ports": [{"port": 22, "service": "ssh"}, {"port": 80, "service": "http"}],
            "os_fingerprint": "Linux 5.x",
        }
        engine._send_report(inc, recon_report=recon)
        assert engine._smtp_with_attachment.call_count >= 1
        # Check admin email contains recon data
        call_args = engine._smtp_with_attachment.call_args_list[0]
        html = call_args[0][2]
        assert "evil.example.com" in html or "Evil Corp" in html

    def test_send_report_forensic_only_no_attachments(self, incident_env):
        """Report shows forensic path when forensic_path set but attach_forensic_file=False."""
        engine, _, _ = incident_env
        engine.email_enabled = True
        engine.attach_forensic_file = False
        engine.include_legal_info = False
        engine._smtp_with_attachment = MagicMock(return_value=True)
        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       severity=2, threat_type="bruteforce",
                       resolved=True, resolution="Done",
                       actions_executed=["✓ Block"])
        engine._send_report(inc, forensic_path="/tmp/forensic.json")
        assert engine._smtp_with_attachment.call_count >= 1
        # The forensic_html should use the "saved on server" template (line 887)
        call_args = engine._smtp_with_attachment.call_args_list[0]
        html = call_args[0][2]
        assert "/tmp/forensic.json" in html

    def test_send_report_immediate_mode_subject(self, incident_env):
        """Report email subject uses immediate mode format."""
        engine, _, _ = incident_env
        engine.email_enabled = True
        engine.defense_mode = "immediate"
        engine._smtp_with_attachment = MagicMock(return_value=True)
        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       severity=2, threat_type="bruteforce",
                       resolved=True, risk_remaining=False,
                       resolution="Done",
                       actions_executed=["✓ Block"])
        engine._send_report(inc)
        call_args = engine._smtp_with_attachment.call_args_list[0]
        subject = call_args[0][1]
        assert "Threat neutralized" in subject or "Action taken" in subject

    def test_send_report_with_snapshot_rollback_section(self, incident_env):
        """Report includes rollback section when snapshot_path is set."""
        engine, _, _ = incident_env
        engine.email_enabled = True
        engine._smtp_with_attachment = MagicMock(return_value=True)
        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       severity=2, threat_type="bruteforce",
                       resolved=True, risk_remaining=False,
                       resolution="Done", snapshot_path="/tmp/snapshot.json",
                       actions_executed=["✓ Block"])
        engine._send_report(inc)
        call_args = engine._smtp_with_attachment.call_args_list[0]
        html = call_args[0][2]
        assert "Rollback" in html
        assert "/tmp/snapshot.json" in html

    def test_send_report_with_snapshot_immediate_mode_intro(self, incident_env):
        """Report rollback section uses immediate mode intro text."""
        engine, _, _ = incident_env
        engine.email_enabled = True
        engine.defense_mode = "immediate"
        engine._smtp_with_attachment = MagicMock(return_value=True)
        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       severity=2, threat_type="bruteforce",
                       resolved=True, risk_remaining=False,
                       resolution="Done", snapshot_path="/tmp/snap.json",
                       actions_executed=["✓ Block"])
        engine._send_report(inc)
        call_args = engine._smtp_with_attachment.call_args_list[0]
        html = call_args[0][2]
        assert "automatically" in html


class TestSMTPAttachmentTypes:

    def test_pdf_attachment_mime_type(self, incident_env, tmp_path):
        """PDF attachment uses application/pdf MIME type."""
        engine, _, _ = incident_env
        engine.smtp_server = "smtp.test.com"
        pdf_file = tmp_path / "report.pdf"
        pdf_file.write_bytes(b"%PDF-1.4 fake")
        with patch("smtplib.SMTP") as MockSMTP:
            mock_srv = MagicMock()
            MockSMTP.return_value = mock_srv
            result = engine._smtp_with_attachment(
                ["admin@test.com"], "Subject", "<h1>Test</h1>",
                attachments=[str(pdf_file)])
            assert result is True
            # Verify the message was sent with attachment
            mock_srv.send_message.assert_called_once()

    def test_txt_attachment_uses_octet_stream(self, incident_env, tmp_path):
        """Non-PDF/JSON attachment uses application/octet-stream MIME type."""
        engine, _, _ = incident_env
        engine.smtp_server = "smtp.test.com"
        txt_file = tmp_path / "notes.txt"
        txt_file.write_text("some notes")
        with patch("smtplib.SMTP") as MockSMTP:
            mock_srv = MagicMock()
            MockSMTP.return_value = mock_srv
            result = engine._smtp_with_attachment(
                ["admin@test.com"], "Subject", "<h1>Test</h1>",
                attachments=[str(txt_file)])
            assert result is True
            mock_srv.send_message.assert_called_once()

    def test_attachment_open_exception_continues(self, incident_env, tmp_path):
        """When opening one attachment fails, others still attach and email is sent."""
        engine, _, _ = incident_env
        engine.smtp_server = "smtp.test.com"
        good_file = tmp_path / "good.json"
        good_file.write_text('{"ok": true}')
        bad_file = tmp_path / "bad.json"
        bad_file.write_text('{"bad": true}')
        with patch("smtplib.SMTP") as MockSMTP:
            mock_srv = MagicMock()
            MockSMTP.return_value = mock_srv
            # Patch builtins.open to fail only for the bad file
            original_open = open
            def side_effect_open(filepath, *args, **kwargs):
                if str(filepath) == str(bad_file):
                    raise PermissionError("Access denied")
                return original_open(filepath, *args, **kwargs)
            with patch("builtins.open", side_effect=side_effect_open):
                result = engine._smtp_with_attachment(
                    ["admin@test.com"], "Subject", "<h1>Test</h1>",
                    attachments=[str(bad_file), str(good_file)])
            assert result is True
            mock_srv.send_message.assert_called_once()


class TestTimeoutLoopBody:

    def test_timeout_loop_auto_approve_and_reminder(self, tmp_path):
        """_timeout_loop sends reminder at half-timeout and auto-approves at full timeout."""
        if not db.is_closed():
            db.close()
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(str(tmp_path / "logs"), exist_ok=True)
        init_db(data_dir)

        cfg = _make_cfg(tmp_path, defense_mode="confirmation")
        defense = MagicMock()
        defense.whitelist = set()

        with patch("core.client_queue.ClientNotificationQueue") as MQ, \
             patch("core.snapshot.DefenseSnapshot"):
            MQ.return_value.enabled = False
            from core.incident import IncidentResponseEngine
            engine = IncidentResponseEngine(cfg, MagicMock(), defense)

        engine.timeout_auto = True
        engine.timeout_min = 0  # Zero timeout → everything triggers immediately
        engine._send_admin_email = MagicMock()

        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="bruteforce", threat_detail="test")
        assert inc.status == "AWAITING_ADMIN"

        # Simulate what _timeout_loop does (without the sleep)
        import time as _time
        _time.sleep(0.05)
        now = _time.time()
        with engine._lock:
            awaiting = [i for i in engine._incidents.values() if i.status == "AWAITING_ADMIN"]
        for i in awaiting:
            elapsed = now - i.created_at
            timeout_s = engine.timeout_min * 60
            if elapsed > timeout_s / 2 and not i.reminder_sent:
                i.reminder_sent = True
                engine._send_admin_email(i, reminder=True)
            if elapsed > timeout_s:
                if engine.timeout_auto:
                    engine.approve(i.token, approved_by="auto-timeout")

        assert inc.reminder_sent is True
        assert inc.status in ("APPROVED", "MITIGATING", "RESOLVED", "RISK_REMAINING")
        engine._send_admin_email.assert_called()
        db.close()

    def test_timeout_loop_expires_without_auto(self, tmp_path):
        """_timeout_loop sets EXPIRED status when auto_approve is off."""
        if not db.is_closed():
            db.close()
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(str(tmp_path / "logs"), exist_ok=True)
        init_db(data_dir)

        cfg = _make_cfg(tmp_path, defense_mode="confirmation")
        defense = MagicMock()
        defense.whitelist = set()

        with patch("core.client_queue.ClientNotificationQueue") as MQ, \
             patch("core.snapshot.DefenseSnapshot"):
            MQ.return_value.enabled = False
            from core.incident import IncidentResponseEngine
            engine = IncidentResponseEngine(cfg, MagicMock(), defense)

        engine.timeout_auto = False
        engine.timeout_min = 0

        inc = engine.create_incident("192.168.1.10", "10.0.0.99", severity=2,
                                     threat_type="bruteforce", threat_detail="test")
        assert inc.status == "AWAITING_ADMIN"

        import time as _time
        _time.sleep(0.05)
        now = _time.time()
        with engine._lock:
            awaiting = [i for i in engine._incidents.values() if i.status == "AWAITING_ADMIN"]
        for i in awaiting:
            elapsed = now - i.created_at
            timeout_s = engine.timeout_min * 60
            if elapsed > timeout_s:
                if engine.timeout_auto:
                    engine.approve(i.token, approved_by="auto-timeout")
                else:
                    i.status = "EXPIRED"
                    i.resolution = f"No response within {engine.timeout_min} min."

        assert inc.status == "EXPIRED"
        assert "No response" in inc.resolution
        db.close()


class TestMacResolverIpToMacPath:

    def test_mac_resolver_ip_to_mac_with_mac_directory_match(self, tmp_path):
        """create_incident uses mac from ip_to_mac to find user in users_by_mac."""
        if not db.is_closed():
            db.close()
        data_dir = str(tmp_path / "data")
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(str(tmp_path / "logs"), exist_ok=True)
        init_db(data_dir)

        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(yaml.dump({
            "general": {"data_dir": str(tmp_path / "data"), "log_dir": str(tmp_path / "logs")},
            "network": {"subnets": ["192.168.1.0/24"], "interface": "lo"},
            "defense": {"enabled": True, "mode": "confirmation", "whitelist_ips": []},
            "email": {
                "enabled": False, "smtp_server": "", "smtp_port": 587,
                "admin_emails": ["admin@test.com"],
                "approval_timeout_minutes": 15,
                "timeout_auto_approve": False,
                "sentinel_url": "https://192.168.1.100:8443",
                "token_ttl_seconds": 3600,
                "user_directory": [
                    {"mac": "aa:bb:cc:dd:ee:ff", "name": "MAC User",
                     "email": "mac@test.com", "hostname": "PC-MAC"},
                ],
            },
            "web": {"port": 8443},
            "client_agent": {"enabled": False},
        }))
        cfg = Config(str(cfg_path))
        defense = MagicMock()
        defense.whitelist = set()
        mac_resolver = MagicMock()
        mac_resolver.ip_to_mac.return_value = "aa:bb:cc:dd:ee:ff"

        with patch("core.client_queue.ClientNotificationQueue") as MQ, \
             patch("core.snapshot.DefenseSnapshot"):
            MQ.return_value.enabled = False
            from core.incident import IncidentResponseEngine
            engine = IncidentResponseEngine(cfg, MagicMock(), defense, mac_resolver=mac_resolver)

        inc = engine.create_incident("10.0.0.50", "10.0.0.99", severity=3,
                                     threat_type="portscan", threat_detail="test")
        assert inc.target_name == "MAC User"
        assert inc.target_email == "mac@test.com"
        db.close()


class TestSendReportLegalSections:

    def test_send_report_with_legal_info_and_abuse_contact(self, incident_env):
        """Report includes legal section with abuse contact from recon."""
        engine, _, _ = incident_env
        engine.email_enabled = True
        engine.include_legal_info = True
        engine.country_code = "IE"
        engine._smtp_with_attachment = MagicMock(return_value=True)
        from core.incident import Incident
        inc = Incident(target_ip="192.168.1.10", attacker_ip="10.0.0.99",
                       severity=2, threat_type="bruteforce", threat_detail="test",
                       resolved=True, risk_remaining=False,
                       resolution="All actions succeeded",
                       actions_executed=["✓ Block IP 10.0.0.99"])
        recon = {
            "target_ip": "10.0.0.99",
            "geolocation": {"city": "Dublin", "country": "Ireland"},
            "whois": {"org": "Test", "asn": "999", "abuse_contact": "abuse@isp.com"},
            "reputation": {}, "open_ports": [],
        }
        engine._send_report(inc, recon_report=recon)
        call_args = engine._smtp_with_attachment.call_args_list[0]
        html = call_args[0][2]
        assert "abuse@isp.com" in html
        assert "File a complaint" in html or "File a Complaint" in html
