"""Tests for daemon.py — Daemon orchestrator: _safe, _guarded, _cleanup, signal handling."""
import os
import sys
import time
_real_sleep = time.sleep
import threading
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.database import db, init_db, Alert, Flow, DnsLog


@pytest.fixture
def tmp_cfg(tmp_path):
    """Create a minimal config file pointing to temp dirs."""
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.dump({
        "general": {"data_dir": str(tmp_path / "data"), "log_dir": str(tmp_path / "logs"),
                     "log_level": "WARNING", "run_as_user": "nobody"},
        "network": {"subnets": ["192.168.1.0/24"], "interface": "lo"},
        "sniffer": {"enabled": False},
        "defense": {"enabled": False, "whitelist_ips": [], "whitelist_macs": []},
        "web": {"enabled": False, "port": 19443, "secret": "test"},
        "email": {"enabled": False},
        "suricata": {"eve_file": "", "syslog_port": "", "tcp_port": ""},
        "honeypot": {"enabled": False},
        "retention": {"alerts_days": 90, "flows_days": 14, "events_days": 30},
        "reports": {"weekly_enabled": False},
        "detectors": {"confidence_threshold": 0.6},
    }))
    return str(cfg_path)


@pytest.fixture
def fresh_db(tmp_path):
    """Initialize a fresh DB."""
    if not db.is_closed():
        db.close()
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    init_db(data_dir)
    yield
    if not db.is_closed():
        db.close()


_PATCHES = [
    "core.sniffer.PacketSniffer",
    "core.discovery.NetworkDiscovery",
    "core.defense.DefenseEngine",
    "core.health.HealthChecker",
    "analyzers.threat_engine.ThreatEngine",
    "analyzers.correlator.Correlator",
    "core.mac_resolver.MacIpResolver",
    "core.host_identity.HostIdentityEngine",
    "core.incident.IncidentResponseEngine",
    "analyzers.orchestrator.DetectorOrchestrator",
    "core.killchain.KillChainDetector",
    "core.threat_feeds.ThreatFeedManager",
    "core.threat_feeds.HoneypotService",
    "core.resilience.DegradedMode",
    "core.resilience.SelfMonitor",
    "core.resilience.BufferGuard",
    "core.resilience.SafeBackup",
    "core.resilience.enable_wal_mode",
    "core.hardening.TLSAutoGen",
    "core.hardening.LoginGuard",
    "core.hardening.ApprovalPIN",
    "core.hardening.IntegrityCheck",
    "core.hardening.FirewallVerifier",
    "core.hardening.SSHHardener",
    "core.os_hardening.OSHardener",
]


def _make_daemon(tmp_cfg):
    """Instantiate the Daemon with heavy mocking of system-level components."""
    patchers = [patch(p) for p in _PATCHES]
    mocks = [p.start() for p in patchers]
    mock_map = dict(zip(_PATCHES, mocks))

    # Configure mock return values
    mock_map["core.hardening.TLSAutoGen"].ensure_cert.return_value = ("", "")
    mock_map["core.hardening.IntegrityCheck"].verify.return_value = {"ok": True}
    mock_map["core.hardening.SSHHardener"].return_value.verify.return_value = {"secure": True}
    mock_map["core.os_hardening.OSHardener"].return_value.verify.return_value = {"secure": True}
    mock_map["core.resilience.DegradedMode"].return_value.should_run.return_value = True
    mock_map["core.sniffer.PacketSniffer"].return_value._thread = None
    mock_map["core.incident.IncidentResponseEngine"].return_value.client_queue = MagicMock()

    from daemon import Daemon
    d = Daemon(tmp_cfg)
    d._patchers = patchers  # Store for cleanup
    return d


# ══════════════════════════════════════════════════
# Daemon initialization
# ══════════════════════════════════════════════════

class TestDaemonInit:

    def test_daemon_creates_all_subsystems(self, tmp_cfg):
        """Daemon initialization creates all expected subsystems."""
        d = _make_daemon(tmp_cfg)
        assert d.cfg is not None
        assert d.alerter is not None
        assert d.defense is not None
        assert d.sniffer is not None
        assert d.health is not None
        assert d.audit_chain is not None
        assert d.killchain is not None
        assert d._running is False

    def test_daemon_suricata_disabled_by_default(self, tmp_cfg):
        """Suricata is disabled when no channel is configured."""
        d = _make_daemon(tmp_cfg)
        assert d._suricata_enabled is False
        assert d.suricata is None

    def test_daemon_enhanced_fire_wires_audit_and_siem(self, tmp_cfg):
        """Enhanced fire function calls audit chain, SIEM, and kill chain."""
        d = _make_daemon(tmp_cfg)
        d.audit_chain.log = MagicMock()
        d.siem.export = MagicMock()
        d.killchain.on_alert = MagicMock()

        d.alerter.fire(severity=3, source="test", category="test",
                       title="Test alert", src_ip="10.0.0.1")

        d.audit_chain.log.assert_called_once()
        d.siem.export.assert_called_once()
        d.killchain.on_alert.assert_called_once()


# ══════════════════════════════════════════════════
# _safe task execution
# ══════════════════════════════════════════════════

class TestSafeExecution:

    def test_safe_runs_function_in_thread(self, tmp_cfg):
        """_safe executes the function in a daemon thread."""
        d = _make_daemon(tmp_cfg)
        results = []

        def task():
            results.append("done")

        d._safe("test_task", task)
        time.sleep(0.2)
        assert results == ["done"]

    def test_safe_catches_exceptions(self, tmp_cfg):
        """_safe catches exceptions without crashing the daemon."""
        d = _make_daemon(tmp_cfg)

        def failing_task():
            raise ValueError("intentional test error")

        # Should not raise
        d._safe("failing_task", failing_task)
        time.sleep(0.2)

    def test_safe_passes_arguments(self, tmp_cfg):
        """_safe passes extra arguments to the function."""
        d = _make_daemon(tmp_cfg)
        results = []

        def task_with_args(a, b):
            results.append(a + b)

        d._safe("args_task", task_with_args, 3, 7)
        time.sleep(0.2)
        assert results == [10]


# ══════════════════════════════════════════════════
# _guarded task execution
# ══════════════════════════════════════════════════

class TestGuardedExecution:

    def test_guarded_runs_when_not_degraded(self, tmp_cfg):
        """_guarded runs the task when degraded mode allows it."""
        d = _make_daemon(tmp_cfg)
        d.degraded.should_run.return_value = True
        results = []

        d._guarded("test", lambda: results.append("ran"))
        time.sleep(0.2)
        assert results == ["ran"]

    def test_guarded_skips_when_degraded(self, tmp_cfg):
        """_guarded skips the task when in degraded mode."""
        d = _make_daemon(tmp_cfg)
        d.degraded.should_run.return_value = False
        results = []

        d._guarded("test", lambda: results.append("ran"))
        time.sleep(0.2)
        assert results == []


# ══════════════════════════════════════════════════
# _cleanup (data retention)
# ══════════════════════════════════════════════════

class TestCleanup:

    def test_cleanup_deletes_old_alerts(self, tmp_cfg, fresh_db):
        """_cleanup deletes alerts older than retention period."""
        d = _make_daemon(tmp_cfg)
        # Create old and recent alerts
        old_ts = datetime.now() - timedelta(days=100)
        Alert.create(source="test", title="Old alert", ts=old_ts, severity=5)
        Alert.create(source="test", title="Recent alert", severity=5)
        assert Alert.select().count() == 2

        d._cleanup()
        assert Alert.select().count() == 1
        assert Alert.select().first().title == "Recent alert"

    def test_cleanup_deletes_old_flows(self, tmp_cfg, fresh_db):
        """_cleanup deletes flows older than retention period."""
        d = _make_daemon(tmp_cfg)
        old_ts = datetime.now() - timedelta(days=20)
        Flow.create(src_ip="10.0.0.1", dst_ip="10.0.0.2", ts=old_ts)
        Flow.create(src_ip="10.0.0.1", dst_ip="10.0.0.3")
        assert Flow.select().count() == 2

        d._cleanup()
        assert Flow.select().count() == 1

    def test_cleanup_deletes_old_dns_logs(self, tmp_cfg, fresh_db):
        """_cleanup deletes DNS logs older than retention period."""
        d = _make_daemon(tmp_cfg)
        old_ts = datetime.now() - timedelta(days=40)
        DnsLog.create(src_ip="10.0.0.1", query="old.com", ts=old_ts)
        DnsLog.create(src_ip="10.0.0.1", query="recent.com")
        assert DnsLog.select().count() == 2

        d._cleanup()
        assert DnsLog.select().count() == 1

    def test_cleanup_preserves_recent_data(self, tmp_cfg, fresh_db):
        """_cleanup preserves data within retention window."""
        d = _make_daemon(tmp_cfg)
        Alert.create(source="test", title="Recent", severity=5)
        Flow.create(src_ip="10.0.0.1", dst_ip="10.0.0.2")
        DnsLog.create(src_ip="10.0.0.1", query="ok.com")

        d._cleanup()
        assert Alert.select().count() == 1
        assert Flow.select().count() == 1
        assert DnsLog.select().count() == 1


# ══════════════════════════════════════════════════
# Signal handling & stop
# ══════════════════════════════════════════════════

class TestSignalHandling:

    def test_stop_sets_running_to_false(self, tmp_cfg):
        """stop() sets _running to False."""
        d = _make_daemon(tmp_cfg)
        d._running = True
        d.identity.save_all = MagicMock()
        d.sniffer.stop = MagicMock()

        with pytest.raises(SystemExit):
            d.stop()
        assert d._running is False

    def test_stop_calls_sniffer_stop(self, tmp_cfg):
        """stop() stops the packet sniffer."""
        d = _make_daemon(tmp_cfg)
        d.identity.save_all = MagicMock()
        d.sniffer.stop = MagicMock()

        with pytest.raises(SystemExit):
            d.stop()
        d.sniffer.stop.assert_called_once()

    def test_stop_saves_identity_data(self, tmp_cfg):
        """stop() saves identity engine data."""
        d = _make_daemon(tmp_cfg)
        d.identity.save_all = MagicMock()
        d.sniffer.stop = MagicMock()

        with pytest.raises(SystemExit):
            d.stop()
        d.identity.save_all.assert_called_once()

    def test_stop_fires_shutdown_alert(self, tmp_cfg):
        """stop() fires a shutdown alert."""
        d = _make_daemon(tmp_cfg)
        d.identity.save_all = MagicMock()
        d.sniffer.stop = MagicMock()
        fire_calls = []
        original_fire = d.alerter.fire
        def capture_fire(**kwargs):
            fire_calls.append(kwargs)
            original_fire(**kwargs)

        d.alerter.fire = capture_fire
        with pytest.raises(SystemExit):
            d.stop()
        shutdown_alerts = [c for c in fire_calls if c.get("category") == "shutdown"]
        assert len(shutdown_alerts) == 1

    def test_stop_with_suricata_enabled(self, tmp_cfg):
        """stop() stops suricata when it's enabled."""
        d = _make_daemon(tmp_cfg)
        d.identity.save_all = MagicMock()
        d.sniffer.stop = MagicMock()
        d.suricata = MagicMock()

        with pytest.raises(SystemExit):
            d.stop()
        d.suricata.stop.assert_called_once()


# ══════════════════════════════════════════════════
# _send_weekly_report
# ══════════════════════════════════════════════════

class TestWeeklyReport:

    def test_weekly_report_skipped_when_disabled(self, tmp_cfg):
        """Weekly report is skipped when reporting is disabled."""
        d = _make_daemon(tmp_cfg)
        d.weekly_report.enabled = False
        d.weekly_report.generate_html = MagicMock()
        d._send_weekly_report()
        d.weekly_report.generate_html.assert_not_called()

    def test_weekly_report_handles_exceptions(self, tmp_cfg):
        """Weekly report handles exceptions gracefully."""
        d = _make_daemon(tmp_cfg)
        d.weekly_report.enabled = True
        d.weekly_report.generate_html = MagicMock(side_effect=Exception("test error"))
        # Should not raise
        d._send_weekly_report()


# ══════════════════════════════════════════════════
# Integration tests
# ══════════════════════════════════════════════════

class TestDaemonIntegration:

    def test_safe_and_guarded_interplay(self, tmp_cfg):
        """_guarded delegates to _safe when not degraded, both work correctly."""
        d = _make_daemon(tmp_cfg)
        results = []

        # Not degraded: task runs
        d.degraded.should_run.return_value = True
        d._guarded("task1", lambda: results.append("guarded_ran"))
        time.sleep(0.2)

        # Degraded: task skipped
        d.degraded.should_run.return_value = False
        d._guarded("task2", lambda: results.append("should_not_run"))
        time.sleep(0.2)

        # Direct _safe: always runs
        d._safe("task3", lambda: results.append("safe_ran"))
        time.sleep(0.2)

        assert results == ["guarded_ran", "safe_ran"]

    def test_cleanup_respects_retention_config(self, tmp_cfg, fresh_db):
        """Cleanup uses retention settings from config."""
        d = _make_daemon(tmp_cfg)
        # Config: alerts=90d, flows=14d, events=30d
        # Create data just outside each window
        Alert.create(source="t", title="Old", ts=datetime.now() - timedelta(days=91), severity=5)
        Alert.create(source="t", title="Keep", ts=datetime.now() - timedelta(days=89), severity=5)
        Flow.create(src_ip="a", dst_ip="b", ts=datetime.now() - timedelta(days=15))
        Flow.create(src_ip="a", dst_ip="b", ts=datetime.now() - timedelta(days=13))
        DnsLog.create(src_ip="a", query="old", ts=datetime.now() - timedelta(days=31))
        DnsLog.create(src_ip="a", query="keep", ts=datetime.now() - timedelta(days=29))

        d._cleanup()

        assert Alert.select().count() == 1
        assert Alert.select().first().title == "Keep"
        assert Flow.select().count() == 1
        assert DnsLog.select().count() == 1
        assert DnsLog.select().first().query == "keep"


# ══════════════════════════════════════════════════
# Init with failing checks
# ══════════════════════════════════════════════════

class TestDaemonInitEdgeCases:

    def test_daemon_with_integrity_check_failed(self, tmp_cfg):
        """Daemon logs error when integrity check fails."""
        patchers = [patch(p) for p in _PATCHES]
        mocks = [p.start() for p in patchers]
        mock_map = dict(zip(_PATCHES, mocks))
        mock_map["core.hardening.TLSAutoGen"].ensure_cert.return_value = ("", "")
        mock_map["core.hardening.IntegrityCheck"].verify.return_value = {"ok": False}
        mock_map["core.hardening.SSHHardener"].return_value.verify.return_value = {"secure": True}
        mock_map["core.os_hardening.OSHardener"].return_value.verify.return_value = {"secure": True}
        mock_map["core.resilience.DegradedMode"].return_value.should_run.return_value = True
        mock_map["core.sniffer.PacketSniffer"].return_value._thread = None
        mock_map["core.incident.IncidentResponseEngine"].return_value.client_queue = MagicMock()

        from daemon import Daemon
        d = Daemon(tmp_cfg)
        for p in patchers:
            p.stop()
        assert d is not None  # Should not crash

    def test_daemon_with_ssh_insecure(self, tmp_cfg):
        """Daemon logs error when SSH is insecure."""
        patchers = [patch(p) for p in _PATCHES]
        mocks = [p.start() for p in patchers]
        mock_map = dict(zip(_PATCHES, mocks))
        mock_map["core.hardening.TLSAutoGen"].ensure_cert.return_value = ("", "")
        mock_map["core.hardening.IntegrityCheck"].verify.return_value = {"ok": True}
        mock_map["core.hardening.SSHHardener"].return_value.verify.return_value = {
            "secure": False, "issues": ["Password auth enabled"]}
        mock_map["core.os_hardening.OSHardener"].return_value.verify.return_value = {"secure": True}
        mock_map["core.resilience.DegradedMode"].return_value.should_run.return_value = True
        mock_map["core.sniffer.PacketSniffer"].return_value._thread = None
        mock_map["core.incident.IncidentResponseEngine"].return_value.client_queue = MagicMock()

        from daemon import Daemon
        d = Daemon(tmp_cfg)
        for p in patchers:
            p.stop()
        assert d is not None

    def test_daemon_with_os_hardening_drift(self, tmp_cfg):
        """Daemon logs warning when OS hardening has drift."""
        patchers = [patch(p) for p in _PATCHES]
        mocks = [p.start() for p in patchers]
        mock_map = dict(zip(_PATCHES, mocks))
        mock_map["core.hardening.TLSAutoGen"].ensure_cert.return_value = ("", "")
        mock_map["core.hardening.IntegrityCheck"].verify.return_value = {"ok": True}
        mock_map["core.hardening.SSHHardener"].return_value.verify.return_value = {"secure": True}
        mock_map["core.os_hardening.OSHardener"].return_value.verify.return_value = {
            "secure": False, "issues": ["no ASLR", "core dumps enabled"]}
        mock_map["core.resilience.DegradedMode"].return_value.should_run.return_value = True
        mock_map["core.sniffer.PacketSniffer"].return_value._thread = None
        mock_map["core.incident.IncidentResponseEngine"].return_value.client_queue = MagicMock()

        from daemon import Daemon
        d = Daemon(tmp_cfg)
        for p in patchers:
            p.stop()
        assert d is not None

    def test_daemon_with_suricata_enabled(self, tmp_path):
        """Daemon enables suricata module when eve_file is configured."""
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(yaml.dump({
            "general": {"data_dir": str(tmp_path / "data"), "log_dir": str(tmp_path / "logs"),
                         "log_level": "WARNING"},
            "network": {"subnets": ["192.168.1.0/24"], "interface": "lo"},
            "sniffer": {"enabled": False},
            "defense": {"enabled": False, "whitelist_ips": [], "whitelist_macs": []},
            "web": {"enabled": False},
            "email": {"enabled": False},
            "suricata": {"eve_file": "/tmp/eve.json", "syslog_port": "", "tcp_port": ""},
            "honeypot": {"enabled": False},
            "detectors": {"confidence_threshold": 0.6},
        }))

        extra_patches = _PATCHES + ["core.suricata_ingest.SuricataIngester"]
        patchers = [patch(p) for p in extra_patches]
        mocks = [p.start() for p in patchers]
        mock_map = dict(zip(extra_patches, mocks))
        mock_map["core.hardening.TLSAutoGen"].ensure_cert.return_value = ("", "")
        mock_map["core.hardening.IntegrityCheck"].verify.return_value = {"ok": True}
        mock_map["core.hardening.SSHHardener"].return_value.verify.return_value = {"secure": True}
        mock_map["core.os_hardening.OSHardener"].return_value.verify.return_value = {"secure": True}
        mock_map["core.resilience.DegradedMode"].return_value.should_run.return_value = True
        mock_map["core.sniffer.PacketSniffer"].return_value._thread = None
        mock_map["core.incident.IncidentResponseEngine"].return_value.client_queue = MagicMock()

        from daemon import Daemon
        d = Daemon(str(cfg_path))
        for p in patchers:
            p.stop()

        assert d._suricata_enabled is True
        assert d.suricata is not None


# ══════════════════════════════════════════════════
# Signal handling (_sig)
# ══════════════════════════════════════════════════

class TestSignalHandler:

    def test_sig_calls_stop(self, tmp_cfg):
        """_sig method calls stop()."""
        d = _make_daemon(tmp_cfg)
        d.identity.save_all = MagicMock()
        d.sniffer.stop = MagicMock()
        with patch.object(d, 'stop', side_effect=SystemExit(0)) as mock_stop:
            with pytest.raises(SystemExit):
                d._sig(15, None)
            mock_stop.assert_called_once()


# ══════════════════════════════════════════════════
# Helper methods
# ══════════════════════════════════════════════════

class TestDaemonHelpers:

    def test_safe_backup_delegates(self, tmp_cfg):
        """_safe_backup calls safe_backup.run()."""
        d = _make_daemon(tmp_cfg)
        d.safe_backup.run = MagicMock()
        d._safe_backup()
        d.safe_backup.run.assert_called_once()

    def test_verify_firewall_delegates(self, tmp_cfg):
        """_verify_firewall calls firewall_verifier.verify()."""
        d = _make_daemon(tmp_cfg)
        d.firewall_verifier.verify = MagicMock()
        d._verify_firewall()
        d.firewall_verifier.verify.assert_called_once()

    def test_capture_compliance_snapshot(self, tmp_cfg):
        """_capture_compliance_snapshot calls capture_compliance_snapshot."""
        d = _make_daemon(tmp_cfg)
        with patch("core.grc.capture_compliance_snapshot") as mock_snap:
            d._capture_compliance_snapshot()
            mock_snap.assert_called_once()

    def test_start_web_launches_thread(self, tmp_cfg):
        """_start_web starts a thread for the web server."""
        d = _make_daemon(tmp_cfg)
        d.supervisor = MagicMock()  # Set by start(), not __init__
        with patch("web.app.init_app") as mock_init:
            mock_init.return_value = (MagicMock(), MagicMock())
            d._start_web()
            mock_init.assert_called_once()

    def test_log_setup_creates_log_dir(self, tmp_cfg, tmp_path):
        """_log_setup creates log directory and configures logging."""
        d = _make_daemon(tmp_cfg)
        log_dir = d.cfg.get("general.log_dir")
        assert os.path.isdir(log_dir)


# ══════════════════════════════════════════════════
# start() — brief execution
# ══════════════════════════════════════════════════

class TestDaemonStart:

    def test_start_runs_briefly_then_stops(self, tmp_cfg):
        """start() registers signal handlers, starts subsystems, and runs scheduler."""
        import signal as sig_mod
        import schedule as sched_mod
        d = _make_daemon(tmp_cfg)
        d.supervisor = MagicMock()  # Normally created in start()

        # Make _running go False after a short time
        call_count = [0]
        def fake_sleep(seconds):
            call_count[0] += 1
            if call_count[0] >= 2:
                d._running = False
            _real_sleep(0.01)

        with patch("core.security.harden_permissions"), \
             patch("core.security.drop_privileges"), \
             patch("core.safety.Supervisor", return_value=MagicMock()), \
             patch("daemon.time.sleep", side_effect=fake_sleep), \
             patch("daemon.schedule") as mock_sched:
            mock_sched.every.return_value = MagicMock()
            d.sniffer._thread = None
            d.sniffer.start = MagicMock()
            d.honeypot.start = MagicMock()
            d.firewall_verifier.snapshot_expected = MagicMock()
            d.discovery.arp_sweep = MagicMock()
            d.discovery.port_scan = MagicMock()
            d.start()

        # Should have started sniffer and honeypot
        d.sniffer.start.assert_called_once()
        d.honeypot.start.assert_called_once()
        d.firewall_verifier.snapshot_expected.assert_called_once()

    def test_start_with_web_enabled(self, tmp_path):
        """start() launches web server when web.enabled is True."""
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(yaml.dump({
            "general": {"data_dir": str(tmp_path / "data"), "log_dir": str(tmp_path / "logs"),
                         "log_level": "WARNING"},
            "network": {"subnets": ["192.168.1.0/24"], "interface": "lo"},
            "sniffer": {"enabled": False},
            "defense": {"enabled": False, "whitelist_ips": [], "whitelist_macs": []},
            "web": {"enabled": True, "port": 19443, "secret": "test"},
            "email": {"enabled": False},
            "suricata": {"eve_file": "", "syslog_port": "", "tcp_port": ""},
            "honeypot": {"enabled": False},
            "detectors": {"confidence_threshold": 0.6},
        }))

        patchers = [patch(p) for p in _PATCHES]
        mocks = [p.start() for p in patchers]
        mock_map = dict(zip(_PATCHES, mocks))
        mock_map["core.hardening.TLSAutoGen"].ensure_cert.return_value = ("", "")
        mock_map["core.hardening.IntegrityCheck"].verify.return_value = {"ok": True}
        mock_map["core.hardening.SSHHardener"].return_value.verify.return_value = {"secure": True}
        mock_map["core.os_hardening.OSHardener"].return_value.verify.return_value = {"secure": True}
        mock_map["core.resilience.DegradedMode"].return_value.should_run.return_value = True
        mock_map["core.sniffer.PacketSniffer"].return_value._thread = None
        mock_map["core.incident.IncidentResponseEngine"].return_value.client_queue = MagicMock()

        from daemon import Daemon
        d = Daemon(str(cfg_path))
        for p in patchers:
            p.stop()

        call_count = [0]
        def fake_sleep(seconds):
            call_count[0] += 1
            if call_count[0] >= 2:
                d._running = False
            _real_sleep(0.01)

        with patch("core.security.harden_permissions"), \
             patch("core.security.drop_privileges"), \
             patch("core.safety.Supervisor", return_value=MagicMock()), \
             patch("daemon.time.sleep", side_effect=fake_sleep), \
             patch("daemon.schedule") as mock_sched, \
             patch.object(d, '_start_web') as mock_web:
            mock_sched.every.return_value = MagicMock()
            d.sniffer._thread = None
            d.sniffer.start = MagicMock()
            d.honeypot.start = MagicMock()
            d.firewall_verifier.snapshot_expected = MagicMock()
            d.discovery.arp_sweep = MagicMock()
            d.discovery.port_scan = MagicMock()
            d.start()

        mock_web.assert_called_once()

    def test_start_with_suricata_enabled(self, tmp_path):
        """start() calls suricata.start() when suricata is enabled."""
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(yaml.dump({
            "general": {"data_dir": str(tmp_path / "data"), "log_dir": str(tmp_path / "logs"),
                         "log_level": "WARNING"},
            "network": {"subnets": ["192.168.1.0/24"], "interface": "lo"},
            "sniffer": {"enabled": False},
            "defense": {"enabled": False, "whitelist_ips": [], "whitelist_macs": []},
            "web": {"enabled": False},
            "email": {"enabled": False},
            "suricata": {"eve_file": "/tmp/eve.json", "syslog_port": "", "tcp_port": ""},
            "honeypot": {"enabled": False},
            "detectors": {"confidence_threshold": 0.6},
        }))

        extra = _PATCHES + ["core.suricata_ingest.SuricataIngester"]
        patchers = [patch(p) for p in extra]
        mocks = [p.start() for p in patchers]
        mock_map = dict(zip(extra, mocks))
        mock_map["core.hardening.TLSAutoGen"].ensure_cert.return_value = ("", "")
        mock_map["core.hardening.IntegrityCheck"].verify.return_value = {"ok": True}
        mock_map["core.hardening.SSHHardener"].return_value.verify.return_value = {"secure": True}
        mock_map["core.os_hardening.OSHardener"].return_value.verify.return_value = {"secure": True}
        mock_map["core.resilience.DegradedMode"].return_value.should_run.return_value = True
        mock_map["core.sniffer.PacketSniffer"].return_value._thread = None
        mock_map["core.incident.IncidentResponseEngine"].return_value.client_queue = MagicMock()

        from daemon import Daemon
        d = Daemon(str(cfg_path))
        for p in patchers:
            p.stop()

        call_count = [0]
        def fake_sleep(seconds):
            call_count[0] += 1
            if call_count[0] >= 2:
                d._running = False
            _real_sleep(0.01)

        with patch("core.security.harden_permissions"), \
             patch("core.security.drop_privileges"), \
             patch("core.safety.Supervisor", return_value=MagicMock()), \
             patch("daemon.time.sleep", side_effect=fake_sleep), \
             patch("daemon.schedule") as mock_sched:
            mock_sched.every.return_value = MagicMock()
            d.sniffer._thread = None
            d.sniffer.start = MagicMock()
            d.honeypot.start = MagicMock()
            d.firewall_verifier.snapshot_expected = MagicMock()
            d.discovery.arp_sweep = MagicMock()
            d.discovery.port_scan = MagicMock()
            d.suricata.start = MagicMock()
            d.start()

        d.suricata.start.assert_called_once()
