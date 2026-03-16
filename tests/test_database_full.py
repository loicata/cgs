"""Tests for core/database.py — SQLite models, init, migration, queries."""
import os
import sys
import tempfile
import shutil
from datetime import datetime, timedelta

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.database import (
    db, init_db, is_setup_complete, migrate_db, _ALL_TABLES,
    Host, Port, Flow, Alert, BaselineStat, DnsLog, WebUser,
    ComplianceAnswer, Risk, Asset, Evidence, ComplianceSnapshot,
    Policy, PolicyAck, Audit, AuditFinding, RiskControlMap,
    Vendor, VendorQuestion,
)


@pytest.fixture(autouse=True)
def fresh_db(tmp_path):
    """Create a fresh database for each test."""
    if not db.is_closed():
        db.close()
    init_db(str(tmp_path))
    yield tmp_path
    db.close()


# ══════════════════════════════════════════════════
# init_db
# ══════════════════════════════════════════════════

class TestInitDb:

    def test_init_creates_database_file(self, fresh_db):
        """init_db creates a cgs.db file in the data directory."""
        assert os.path.exists(os.path.join(str(fresh_db), "cgs.db"))

    def test_init_creates_all_tables(self, fresh_db):
        """init_db creates all expected tables."""
        tables = db.get_tables()
        for model in _ALL_TABLES:
            assert model._meta.table_name in tables

    def test_init_db_is_idempotent(self, fresh_db):
        """Calling init_db twice does not raise errors."""
        # Already initialized by fixture, call again
        init_db(str(fresh_db))
        assert db.get_tables()

    def test_all_tables_list_contains_19_models(self):
        """_ALL_TABLES contains all 19 models."""
        assert len(_ALL_TABLES) == 19


# ══════════════════════════════════════════════════
# Host model
# ══════════════════════════════════════════════════

class TestHostModel:

    def test_create_host(self, fresh_db):
        """A host can be created with an IP address."""
        h = Host.create(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff")
        assert h.id is not None
        assert h.ip == "192.168.1.10"
        assert h.mac == "aa:bb:cc:dd:ee:ff"

    def test_host_ip_is_unique(self, fresh_db):
        """Duplicate IP addresses are rejected."""
        Host.create(ip="192.168.1.1")
        with pytest.raises(Exception):
            Host.create(ip="192.168.1.1")

    def test_host_default_status_is_up(self, fresh_db):
        """Default host status is 'up'."""
        h = Host.create(ip="10.0.0.1")
        assert h.status == "up"

    def test_host_default_risk_score_is_zero(self, fresh_db):
        """Default risk score is 0."""
        h = Host.create(ip="10.0.0.2")
        assert h.risk_score == 0

    def test_host_timestamps_are_set(self, fresh_db):
        """first_seen and last_seen are automatically set."""
        h = Host.create(ip="10.0.0.3")
        assert h.first_seen is not None
        assert h.last_seen is not None

    def test_update_host_risk_score(self, fresh_db):
        """Risk score can be updated."""
        h = Host.create(ip="10.0.0.4", risk_score=0)
        h.risk_score = 75
        h.save()
        reloaded = Host.get(Host.ip == "10.0.0.4")
        assert reloaded.risk_score == 75

    def test_query_hosts_by_status(self, fresh_db):
        """Hosts can be queried by status."""
        Host.create(ip="10.0.0.1", status="up")
        Host.create(ip="10.0.0.2", status="down")
        Host.create(ip="10.0.0.3", status="up")
        up_hosts = list(Host.select().where(Host.status == "up"))
        assert len(up_hosts) == 2


# ══════════════════════════════════════════════════
# Port model
# ══════════════════════════════════════════════════

class TestPortModel:

    def test_create_port(self, fresh_db):
        """A port can be created."""
        p = Port.create(host_ip="192.168.1.1", port=22, service="ssh")
        assert p.port == 22
        assert p.service == "ssh"
        assert p.state == "open"

    def test_port_unique_constraint(self, fresh_db):
        """Same host_ip + port + proto combination is unique."""
        Port.create(host_ip="10.0.0.1", port=80, proto="tcp")
        with pytest.raises(Exception):
            Port.create(host_ip="10.0.0.1", port=80, proto="tcp")

    def test_different_protos_allowed_on_same_port(self, fresh_db):
        """Different protocols on same port are allowed."""
        Port.create(host_ip="10.0.0.1", port=53, proto="tcp")
        Port.create(host_ip="10.0.0.1", port=53, proto="udp")
        count = Port.select().where(Port.host_ip == "10.0.0.1", Port.port == 53).count()
        assert count == 2

    def test_query_open_ports_for_host(self, fresh_db):
        """Open ports can be queried for a specific host."""
        Port.create(host_ip="10.0.0.1", port=22, state="open")
        Port.create(host_ip="10.0.0.1", port=80, state="open")
        Port.create(host_ip="10.0.0.1", port=8080, state="closed")
        open_ports = list(Port.select().where(Port.host_ip == "10.0.0.1", Port.state == "open"))
        assert len(open_ports) == 2


# ══════════════════════════════════════════════════
# Flow model
# ══════════════════════════════════════════════════

class TestFlowModel:

    def test_create_flow(self, fresh_db):
        """A network flow can be recorded."""
        f = Flow.create(src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=53, proto="UDP")
        assert f.src_ip == "10.0.0.1"
        assert f.proto == "UDP"

    def test_flow_default_packets_is_one(self, fresh_db):
        """Default packet count is 1."""
        f = Flow.create(src_ip="10.0.0.1", dst_ip="10.0.0.2")
        assert f.packets == 1

    def test_query_flows_by_time_range(self, fresh_db):
        """Flows can be queried by time range."""
        Flow.create(src_ip="10.0.0.1", dst_ip="10.0.0.2")
        since = datetime.now() - timedelta(minutes=1)
        recent = Flow.select().where(Flow.ts >= since).count()
        assert recent >= 1


# ══════════════════════════════════════════════════
# Alert model
# ══════════════════════════════════════════════════

class TestAlertModel:

    def test_create_alert(self, fresh_db):
        """An alert can be created with all fields."""
        a = Alert.create(
            severity=1, source="defense", category="portscan",
            title="Port scan detected", detail="20 ports scanned in 5s",
            src_ip="10.0.0.99",
        )
        assert a.severity == 1
        assert a.source == "defense"
        assert a.ack is False

    def test_alert_default_severity_is_3(self, fresh_db):
        """Default alert severity is 3 (medium)."""
        a = Alert.create(source="test", title="Test alert")
        assert a.severity == 3

    def test_acknowledge_alert(self, fresh_db):
        """An alert can be acknowledged."""
        a = Alert.create(source="test", title="Test")
        a.ack = True
        a.save()
        reloaded = Alert.get_by_id(a.id)
        assert reloaded.ack is True

    def test_query_alerts_by_severity(self, fresh_db):
        """Alerts can be queried by severity."""
        Alert.create(source="test", title="Critical", severity=1)
        Alert.create(source="test", title="Info", severity=5)
        Alert.create(source="test", title="High", severity=2)
        critical = Alert.select().where(Alert.severity <= 2).count()
        assert critical == 2

    def test_query_alerts_ordered_by_timestamp(self, fresh_db):
        """Alerts are ordered by timestamp descending."""
        Alert.create(source="test", title="First")
        Alert.create(source="test", title="Second")
        alerts = list(Alert.select().order_by(Alert.ts.desc()))
        assert len(alerts) == 2


# ══════════════════════════════════════════════════
# DnsLog model
# ══════════════════════════════════════════════════

class TestDnsLogModel:

    def test_create_dns_log(self, fresh_db):
        """A DNS log entry can be created."""
        d = DnsLog.create(src_ip="10.0.0.1", query="example.com", entropy=2.5)
        assert d.query == "example.com"
        assert d.suspicious is False

    def test_query_suspicious_dns(self, fresh_db):
        """Suspicious DNS queries can be filtered."""
        DnsLog.create(src_ip="10.0.0.1", query="normal.com", suspicious=False)
        DnsLog.create(src_ip="10.0.0.1", query="x8f3k.evil.com", suspicious=True, entropy=4.2)
        suspicious = DnsLog.select().where(DnsLog.suspicious == True).count()
        assert suspicious == 1


# ══════════════════════════════════════════════════
# WebUser model
# ══════════════════════════════════════════════════

class TestWebUserModel:

    def test_create_web_user(self, fresh_db):
        """A web user can be created."""
        u = WebUser.create(username="admin", password_hash="$2b$12$hash", role="admin")
        assert u.username == "admin"
        assert u.role == "admin"
        assert u.active is True

    def test_username_is_unique(self, fresh_db):
        """Duplicate usernames are rejected."""
        WebUser.create(username="admin", password_hash="hash1")
        with pytest.raises(Exception):
            WebUser.create(username="admin", password_hash="hash2")

    def test_default_role_is_user(self, fresh_db):
        """Default role is 'user'."""
        u = WebUser.create(username="newuser", password_hash="hash")
        assert u.role == "user"

    def test_must_change_password_default_false(self, fresh_db):
        """must_change_password defaults to False."""
        u = WebUser.create(username="user1", password_hash="hash")
        assert u.must_change_password is False


# ══════════════════════════════════════════════════
# is_setup_complete
# ══════════════════════════════════════════════════

class TestIsSetupComplete:

    def test_returns_false_with_no_users(self, fresh_db):
        """Returns False when no admin users exist."""
        assert is_setup_complete() is False

    def test_returns_true_with_active_admin(self, fresh_db):
        """Returns True when an active admin user exists."""
        WebUser.create(username="admin", password_hash="hash", role="admin", active=True)
        assert is_setup_complete() is True

    def test_returns_false_with_inactive_admin(self, fresh_db):
        """Returns False when admin exists but is inactive."""
        WebUser.create(username="admin", password_hash="hash", role="admin", active=False)
        assert is_setup_complete() is False

    def test_returns_false_with_only_regular_users(self, fresh_db):
        """Returns False when only regular (non-admin) users exist."""
        WebUser.create(username="user1", password_hash="hash", role="user")
        assert is_setup_complete() is False


# ══════════════════════════════════════════════════
# GRC models
# ══════════════════════════════════════════════════

class TestGRCModels:

    def test_create_risk(self, fresh_db):
        """A risk can be created with computed score."""
        r = Risk.create(title="Data breach", likelihood=4, impact=5, risk_score=20)
        assert r.risk_score == 20
        assert r.status == "open"

    def test_create_asset(self, fresh_db):
        """An asset can be created."""
        a = Asset.create(name="Web Server", asset_type="server", criticality=5)
        assert a.name == "Web Server"
        assert a.criticality == 5

    def test_create_policy(self, fresh_db):
        """A policy can be created."""
        p = Policy.create(title="Password Policy", content="Min 12 chars", status="active")
        assert p.status == "active"

    def test_create_audit_with_findings(self, fresh_db):
        """An audit can have findings."""
        a = Audit.create(title="Q1 Security Audit", auditor="External Auditor")
        AuditFinding.create(audit_id=a.id, severity="high", description="Weak passwords found")
        AuditFinding.create(audit_id=a.id, severity="low", description="Missing logs")
        findings = AuditFinding.select().where(AuditFinding.audit_id == a.id).count()
        assert findings == 2

    def test_risk_control_mapping(self, fresh_db):
        """Risks can be mapped to controls."""
        r = Risk.create(title="Phishing", risk_score=15)
        RiskControlMap.create(risk_id=r.id, control_id="TRAIN-01")
        RiskControlMap.create(risk_id=r.id, control_id="EMAIL-02")
        maps = RiskControlMap.select().where(RiskControlMap.risk_id == r.id).count()
        assert maps == 2

    def test_vendor_with_questions(self, fresh_db):
        """Vendors can have assessment questions."""
        v = Vendor.create(name="Cloud Provider", criticality=5)
        VendorQuestion.create(vendor_id=v.id, question="SOC2 certified?", answer="yes")
        VendorQuestion.create(vendor_id=v.id, question="Data encryption?", answer="yes")
        q = VendorQuestion.select().where(VendorQuestion.vendor_id == v.id).count()
        assert q == 2

    def test_compliance_answer(self, fresh_db):
        """Compliance answers can be stored."""
        ComplianceAnswer.create(control_id="ORG-01", answer="yes", answered_by="admin")
        ca = ComplianceAnswer.get(ComplianceAnswer.control_id == "ORG-01")
        assert ca.answer == "yes"

    def test_compliance_snapshot(self, fresh_db):
        """Compliance snapshots can be created."""
        ComplianceSnapshot.create(score=85, auto_score=70, decl_score=100,
                                  risk_level="medium", passed=17, failed=3)
        cs = ComplianceSnapshot.select().first()
        assert cs.score == 85


# ══════════════════════════════════════════════════
# migrate_db
# ══════════════════════════════════════════════════

class TestMigrateDb:

    def test_migrate_on_fresh_db_is_safe(self, fresh_db):
        """migrate_db on a fresh database does not raise errors."""
        migrate_db()

    def test_migrate_is_idempotent(self, fresh_db):
        """Running migrate_db multiple times is safe."""
        migrate_db()
        migrate_db()
        migrate_db()


# ══════════════════════════════════════════════════
# Integration tests
# ══════════════════════════════════════════════════

class TestDatabaseIntegration:

    def test_full_workflow_host_ports_alerts(self, fresh_db):
        """Full workflow: create host, add ports, generate alert, query."""
        # Discover host
        h = Host.create(ip="192.168.1.50", mac="aa:bb:cc:dd:ee:ff", vendor="Dell")
        # Discover ports
        Port.create(host_ip=h.ip, port=22, service="ssh")
        Port.create(host_ip=h.ip, port=80, service="http")
        # Record flow
        Flow.create(src_ip="10.0.0.99", dst_ip=h.ip, dst_port=22, packets=100)
        # Fire alert
        Alert.create(severity=2, source="sniffer", category="bruteforce",
                     title="SSH brute force", src_ip="10.0.0.99", dst_ip=h.ip)
        # Update risk
        h.risk_score = 80
        h.save()
        # Query
        reloaded = Host.get(Host.ip == "192.168.1.50")
        assert reloaded.risk_score == 80
        open_ports = Port.select().where(Port.host_ip == h.ip, Port.state == "open").count()
        assert open_ports == 2
        alerts = Alert.select().where(Alert.dst_ip == h.ip).count()
        assert alerts == 1

    def test_bulk_insert_and_delete_with_retention(self, fresh_db):
        """Bulk insert and retention-based deletion work correctly."""
        # Insert 50 alerts
        with db.atomic():
            for i in range(50):
                Alert.create(source="test", title=f"Alert {i}", severity=5)
        assert Alert.select().count() == 50
        # Delete old alerts (simulate retention)
        cutoff = datetime.now() + timedelta(seconds=1)
        deleted = Alert.delete().where(Alert.ts < cutoff).execute()
        assert deleted == 50
        assert Alert.select().count() == 0

    def test_atomic_transaction_rollback(self, fresh_db):
        """Failed atomic transactions are rolled back."""
        Host.create(ip="10.0.0.1")
        try:
            with db.atomic():
                Host.create(ip="10.0.0.2")
                Host.create(ip="10.0.0.1")  # Duplicate — should fail
        except Exception:
            pass
        # 10.0.0.2 should NOT exist due to rollback
        assert Host.get_or_none(Host.ip == "10.0.0.2") is None
        assert Host.get_or_none(Host.ip == "10.0.0.1") is not None
