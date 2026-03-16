"""Tests for web/app.py — Flask app routes, setup guard, API endpoints, approve/reject."""
import os
import sys
from unittest.mock import MagicMock, patch

import bcrypt
import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.database import db, init_db, WebUser, Alert, Host, Risk, Asset, Policy, Vendor
from core.config import Config

_app = None
_app_initialized = False


def _get_app(cfg):
    global _app, _app_initialized
    if not _app_initialized:
        from web.app import app, init_app
        init_app(cfg, {})
        app.config["TESTING"] = True
        _app = app
        _app_initialized = True
    else:
        import web.shared as shared
        shared.config = cfg
        shared.ctx.clear()
        shared.ctx["config"] = cfg
        from core.security import CSRFProtection, RateLimiter
        shared.csrf = CSRFProtection(cfg.get("web.secret", "test"))
        shared.rate_limiter = RateLimiter()
        shared.login_guard = None
        _app.secret_key = cfg.get("web.secret", "test")
    return _app


@pytest.fixture(autouse=True)
def fresh_env(tmp_path):
    if not db.is_closed():
        db.close()
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(str(tmp_path / "logs"), exist_ok=True)
    init_db(data_dir)
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.dump({
        "general": {"data_dir": data_dir, "log_dir": str(tmp_path / "logs")},
        "web": {"enabled": True, "port": 9999, "secret": "test-secret-key"},
    }))
    cfg = Config(str(cfg_path))
    app = _get_app(cfg)
    yield app, cfg
    if not db.is_closed():
        db.close()


def _create_admin():
    pw = bcrypt.hashpw(b"TestPassword12345678", bcrypt.gensalt()).decode()
    return WebUser.create(username="admin", password_hash=pw, role="admin", active=True)


def _login(client):
    return client.post("/login", data={"username": "admin", "password": "TestPassword12345678"})


# ══════════════════════════════════════════════════
# Setup guard
# ══════════════════════════════════════════════════

class TestSetupGuard:

    def test_setup_path_bypasses_guard(self, fresh_env):
        app, _ = fresh_env
        with app.test_client() as c:
            r = c.get("/setup")
            assert r.status_code == 200

    def test_api_setup_bypasses_guard(self, fresh_env):
        app, _ = fresh_env
        with app.test_client() as c:
            r = c.get("/api/setup/detect-network")
            assert r.status_code == 200

    def test_client_api_bypasses_guard(self, fresh_env):
        app, _ = fresh_env
        with app.test_client() as c:
            r = c.get("/api/client/check")
            assert r.status_code == 200

    def test_incident_path_bypasses_guard(self, fresh_env):
        app, _ = fresh_env
        with app.test_client() as c:
            r = c.get("/incident/INC-20240101-1/approve?token=x")
            assert r.status_code != 503

    def test_api_blocked_without_admin(self, fresh_env):
        app, _ = fresh_env
        with app.test_client() as c:
            r = c.get("/api/incidents")
            assert r.status_code == 503


# ══════════════════════════════════════════════════
# Audit verify
# ══════════════════════════════════════════════════

class TestAuditVerify:

    def test_audit_verify_with_chain(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.ctx["audit_chain"] = MagicMock(verify=MagicMock(return_value={"ok": True}))
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/audit/verify")
            assert r.get_json()["ok"] is True

    def test_audit_verify_without_chain(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.ctx.pop("audit_chain", None)
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/audit/verify")
            assert r.get_json()["ok"] is False


# ══════════════════════════════════════════════════
# Threat intel
# ══════════════════════════════════════════════════

class TestThreatIntel:

    def test_threat_intel_with_module(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.ctx["threat_intel"] = MagicMock(check_ip=MagicMock(return_value={"known": True}))
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/threat-intel/check/10.0.0.1")
            assert r.get_json()["known"] is True

    def test_threat_intel_without_module(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/threat-intel/check/10.0.0.1")
            assert r.get_json() == {}


# ══════════════════════════════════════════════════
# False positive
# ══════════════════════════════════════════════════

class TestFalsePositive:

    def test_false_positive_list(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.ctx["false_positives"] = MagicMock(get_all=MagicMock(return_value={}))
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/false-positive/list")
            assert r.status_code == 200

    def test_false_positive_not_available(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.csrf = None
        with app.test_client() as c:
            _login(c)
            r = c.post("/api/false-positive", json={"ip": "10.0.0.1", "category": "portscan"})
            assert r.status_code == 503
        from core.security import CSRFProtection
        shared.csrf = CSRFProtection("test")


# ══════════════════════════════════════════════════
# Incidents
# ══════════════════════════════════════════════════

class TestIncidentRoutes:

    def test_get_incidents(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.ctx["incident"] = MagicMock(get_all_incidents=MagicMock(return_value=[]))
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/incidents")
            assert r.status_code == 200

    def test_get_active_incidents(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.ctx["incident"] = MagicMock(get_active_incidents=MagicMock(return_value=[]))
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/incidents/active")
            assert r.status_code == 200

    def test_get_incident_detail_not_found(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.ctx["incident"] = MagicMock(get_incident=MagicMock(return_value=None))
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/incidents/INC-20240101-1")
            assert r.status_code == 404

    def test_get_incident_detail_found(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.ctx["incident"] = MagicMock(get_incident=MagicMock(return_value={"id": "INC-1"}))
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/incidents/INC-1")
            assert r.get_json()["id"] == "INC-1"

    def test_incident_stats(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.ctx["incident"] = MagicMock(stats={"total": 5})
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/incidents/stats")
            assert r.get_json()["total"] == 5

    def test_incident_no_engine(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/incidents/INC-1")
            assert r.status_code == 404


# ══════════════════════════════════════════════════
# Approve / Reject (web)
# ══════════════════════════════════════════════════

class TestWebApproveReject:

    def test_approve_invalid_id(self, fresh_env):
        app, _ = fresh_env
        with app.test_client() as c:
            r = c.get("/incident/INVALID/approve?token=x")
            assert r.status_code == 400

    def test_approve_no_engine(self, fresh_env):
        app, _ = fresh_env
        with app.test_client() as c:
            r = c.get("/incident/INC-20240101-1/approve?token=x")
            assert b"not available" in r.data

    def test_approve_invalid_token(self, fresh_env):
        app, _ = fresh_env
        import web.shared as shared
        shared.ctx["incident"] = MagicMock(approve=MagicMock(return_value=None))
        with app.test_client() as c:
            r = c.get("/incident/INC-20240101-1/approve?token=bad")
            assert b"expired" in r.data.lower() or b"not valid" in r.data.lower()

    def test_approve_already_processed(self, fresh_env):
        app, _ = fresh_env
        import web.shared as shared
        shared.ctx["incident"] = MagicMock(
            approve=MagicMock(return_value={"error": "Already processed"}))
        with app.test_client() as c:
            r = c.get("/incident/INC-20240101-1/approve?token=ok")
            assert b"Already processed" in r.data

    def test_approve_success(self, fresh_env):
        app, _ = fresh_env
        import web.shared as shared
        shared.ctx["incident"] = MagicMock(
            approve=MagicMock(return_value={"ok": True}))
        with app.test_client() as c:
            r = c.get("/incident/INC-20240101-1/approve?token=ok")
            assert b"approved" in r.data.lower()

    def test_reject_invalid_id(self, fresh_env):
        app, _ = fresh_env
        with app.test_client() as c:
            r = c.get("/incident/BAD/reject?token=x")
            assert r.status_code == 400

    def test_reject_success(self, fresh_env):
        app, _ = fresh_env
        import web.shared as shared
        shared.ctx["incident"] = MagicMock(
            reject=MagicMock(return_value={"ok": True}))
        with app.test_client() as c:
            r = c.get("/incident/INC-20240101-1/reject?token=ok")
            assert b"rejected" in r.data.lower()


# ══════════════════════════════════════════════════
# Client API
# ══════════════════════════════════════════════════

class TestClientAPI:

    def test_client_check_no_queue(self, fresh_env):
        app, _ = fresh_env
        with app.test_client() as c:
            r = c.get("/api/client/check")
            assert r.get_json()["messages"] == []

    def test_client_check_auth_failure(self, fresh_env):
        app, _ = fresh_env
        import web.shared as shared
        shared.ctx["client_queue"] = MagicMock(verify_client=MagicMock(return_value=False))
        with app.test_client() as c:
            r = c.get("/api/client/check?hostname=pc&ts=1&sig=bad")
            assert r.status_code == 403

    def test_client_check_success(self, fresh_env):
        app, _ = fresh_env
        import web.shared as shared
        q = MagicMock()
        q.verify_client.return_value = True
        q.get_pending.return_value = ([], 60)
        q.sign_response.return_value = {"messages": [], "poll_interval": 60, "_sig": "ok"}
        shared.ctx["client_queue"] = q
        with app.test_client() as c:
            r = c.get("/api/client/check?hostname=pc&ts=1&sig=ok")
            assert r.status_code == 200

    def test_client_ack_no_queue(self, fresh_env):
        app, _ = fresh_env
        with app.test_client() as c:
            r = c.post("/api/client/ack", json={"message_id": "1"})
            assert r.get_json()["ok"] is False

    def test_client_sensor_no_queue(self, fresh_env):
        app, _ = fresh_env
        with app.test_client() as c:
            r = c.post("/api/client/sensor", json={})
            assert r.get_json()["ok"] is False

    def test_client_sensor_with_anomalies(self, fresh_env):
        app, _ = fresh_env
        import web.shared as shared
        q = MagicMock()
        q.verify_client.return_value = True
        shared.ctx["client_queue"] = q
        alerter = MagicMock()
        shared.ctx["alerter"] = alerter
        with app.test_client() as c:
            r = c.post("/api/client/sensor", json={
                "hostname": "pc", "ts": "1", "sig": "ok",
                "anomalies": [{"category": "suspicious_port", "detail": "port 4444", "severity": 3}],
            })
            assert r.get_json()["ok"] is True
            alerter.fire.assert_called_once()


# ══════════════════════════════════════════════════
# Search
# ══════════════════════════════════════════════════

class TestGlobalSearch:

    def test_search_too_short(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/search?q=a")
            assert r.get_json()["total"] == 0

    def test_search_returns_results(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        Alert.create(source="test", title="SSH brute force", severity=2, src_ip="10.0.0.1")
        Host.create(ip="10.0.0.1", hostname="attacker")
        Risk.create(title="SSH brute risk")
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/search?q=brute")
            data = r.get_json()
            assert data["total"] >= 2


# ══════════════════════════════════════════════════
# Misc routes
# ══════════════════════════════════════════════════

class TestMiscRoutes:

    def test_rules_endpoint(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.ctx["hot_rules"] = MagicMock(stats={"rules_loaded": 5})
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/rules")
            assert r.get_json()["rules_loaded"] == 5

    def test_incident_pin(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.ctx["approval_pin"] = MagicMock(
            get_pin_for_dashboard=MagicMock(return_value="1234"))
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/incidents/INC-1/pin")
            assert r.get_json()["pin"] == "1234"

    def test_incident_pin_no_manager(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/incidents/INC-1/pin")
            assert r.get_json()["pin"] == ""

    def test_docs_endpoint(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            with patch("core.api_docs.generate_api_docs", return_value={"endpoints": []}):
                r = c.get("/api/docs")
                assert r.status_code == 200

    def test_snapshots_list(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.ctx["incident"] = MagicMock(
            snapshots=MagicMock(list_snapshots=MagicMock(return_value=[])))
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/snapshots")
            assert r.status_code == 200

    def test_backup_list(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.ctx["backup"] = MagicMock(list_backups=MagicMock(return_value=[]))
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/backup/list")
            assert r.status_code == 200

    def test_weekly_report(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.ctx["weekly_report"] = MagicMock(generate=MagicMock(return_value={}))
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/report/weekly")
            assert r.status_code == 200

    def test_integrity_check(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            _login(c)
            with patch("core.hardening.IntegrityCheck.verify", return_value={"ok": True}):
                r = c.get("/api/integrity")
                assert r.get_json()["ok"] is True

    def test_ssh_verify(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            _login(c)
            with patch("core.hardening.SSHHardener") as MockSSH:
                MockSSH.return_value.verify.return_value = {"secure": True}
                r = c.get("/api/ssh/verify")
                assert r.get_json()["secure"] is True

    def test_os_verify(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.ctx["os_hardener"] = MagicMock(verify=MagicMock(return_value={"secure": True}))
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/os/verify")
            assert r.get_json()["secure"] is True

    def test_firewall_verify(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.ctx["firewall_verifier"] = MagicMock(verify=MagicMock(return_value={"ok": True}))
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/firewall/verify")
            assert r.get_json()["ok"] is True


# ══════════════════════════════════════════════════
# CSRF-protected admin endpoints
# ══════════════════════════════════════════════════

class TestAdminCSRFEndpoints:

    def test_false_positive_report(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.csrf = None  # Disable CSRF for functional test
        shared.ctx["false_positives"] = MagicMock(
            report_false_positive=MagicMock(return_value={"ip": "10.0.0.1"}))
        with app.test_client() as c:
            _login(c)
            r = c.post("/api/false-positive", json={"ip": "10.0.0.1", "category": "portscan"})
            assert r.get_json()["ok"] is True
        from core.security import CSRFProtection
        shared.csrf = CSRFProtection("test")

    def test_rules_reload(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.csrf = None
        shared.ctx["hot_rules"] = MagicMock(reload=MagicMock(return_value=10))
        with app.test_client() as c:
            _login(c)
            r = c.post("/api/rules/reload", json={})
            assert r.get_json()["rules_loaded"] == 10
        from core.security import CSRFProtection
        shared.csrf = CSRFProtection("test")

    def test_rules_reload_not_available(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.csrf = None
        with app.test_client() as c:
            _login(c)
            r = c.post("/api/rules/reload", json={})
            assert r.status_code == 503
        from core.security import CSRFProtection
        shared.csrf = CSRFProtection("test")

    def test_backup_create(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.csrf = None
        shared.ctx["backup"] = MagicMock(create=MagicMock(return_value="/tmp/backup.tar.gz"))
        with app.test_client() as c:
            _login(c)
            r = c.post("/api/backup", json={})
            assert r.get_json()["path"] == "/tmp/backup.tar.gz"
        from core.security import CSRFProtection
        shared.csrf = CSRFProtection("test")

    def test_backup_not_available(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.csrf = None
        with app.test_client() as c:
            _login(c)
            r = c.post("/api/backup", json={})
            assert r.status_code == 503
        from core.security import CSRFProtection
        shared.csrf = CSRFProtection("test")


# ══════════════════════════════════════════════════
# Rollback
# ══════════════════════════════════════════════════

class TestRollback:

    def test_rollback_no_incident_engine(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.csrf = None
        with app.test_client() as c:
            _login(c)
            r = c.post("/api/snapshots/rollback", json={"filepath": "/x"})
            assert r.get_json()["ok"] is False
        from core.security import CSRFProtection
        shared.csrf = CSRFProtection("test")

    def test_rollback_invalid_path(self, fresh_env):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.csrf = None
        shared.ctx["incident"] = MagicMock(cfg=MagicMock(get=MagicMock(return_value="/var/log/cgs")))
        with app.test_client() as c:
            _login(c)
            r = c.post("/api/snapshots/rollback", json={"filepath": ""})
            assert "not found" in r.get_json().get("error", "")
        from core.security import CSRFProtection
        shared.csrf = CSRFProtection("test")

    def test_rollback_path_traversal_blocked(self, fresh_env, tmp_path):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.csrf = None
        log_dir = str(tmp_path / "logs")
        snap_dir = os.path.join(log_dir, "snapshots")
        os.makedirs(snap_dir, exist_ok=True)
        evil_file = tmp_path / "evil.json"
        evil_file.write_text("{}")
        shared.ctx["incident"] = MagicMock(cfg=MagicMock(get=MagicMock(return_value=log_dir)))
        with app.test_client() as c:
            _login(c)
            r = c.post("/api/snapshots/rollback", json={"filepath": str(evil_file)})
            assert r.status_code == 403
        from core.security import CSRFProtection
        shared.csrf = CSRFProtection("test")

    def test_rollback_success(self, fresh_env, tmp_path):
        app, _ = fresh_env
        _create_admin()
        import web.shared as shared
        shared.csrf = None
        log_dir = str(tmp_path / "logs")
        snap_dir = os.path.join(log_dir, "snapshots")
        os.makedirs(snap_dir, exist_ok=True)
        snap_file = os.path.join(snap_dir, "snap.json")
        with open(snap_file, "w") as f:
            f.write("{}")
        mock_inc = MagicMock()
        mock_inc.cfg.get.return_value = log_dir
        mock_inc.snapshots.restore.return_value = {"ok": True}
        shared.ctx["incident"] = mock_inc
        shared.ctx["audit_chain"] = MagicMock()
        with app.test_client() as c:
            _login(c)
            r = c.post("/api/snapshots/rollback", json={"filepath": snap_file})
            assert r.get_json()["ok"] is True
        from core.security import CSRFProtection
        shared.csrf = CSRFProtection("test")


# ══════════════════════════════════════════════════
# Client ack
# ══════════════════════════════════════════════════

class TestClientAck:

    def test_client_ack_success(self, fresh_env):
        app, _ = fresh_env
        import web.shared as shared
        q = MagicMock()
        q.acknowledge.return_value = True
        shared.ctx["client_queue"] = q
        with app.test_client() as c:
            r = c.post("/api/client/ack", json={"message_id": "msg-1",
                                                  "hostname": "pc", "user": "jean"})
            assert r.get_json()["ok"] is True
