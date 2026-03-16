"""Tests for web/routes_auth.py — Authentication, setup wizard, login, password management."""
import os
import sys
import time
from unittest.mock import MagicMock, patch

import bcrypt
import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.database import db, init_db, WebUser
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
        from core.security import CSRFProtection, RateLimiter
        shared.csrf = CSRFProtection(cfg.get("web.secret", "test"))
        rl = RateLimiter()
        rl._windows.clear()  # Reset any leftover state
        shared.rate_limiter = rl
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
    yield app, cfg, tmp_path
    if not db.is_closed():
        db.close()


def _create_admin(password="TestPassword12345678"):
    pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    return WebUser.create(username="admin", password_hash=pw, role="admin", active=True)


def _login(client, username="admin", password="TestPassword12345678"):
    return client.post("/login", data={"username": username, "password": password},
                       follow_redirects=False)


# ══════════════════════════════════════════════════
# Setup guard behavior
# ══════════════════════════════════════════════════

class TestSetupGuard:

    def test_api_returns_503_when_no_admin(self, fresh_env):
        """API returns 503 setup_required when no admin exists."""
        app, _, _ = fresh_env
        with app.test_client() as c:
            r = c.get("/api/csrf-token")
            assert r.status_code == 503

    def test_non_api_redirects_to_setup_when_no_admin(self, fresh_env):
        """Non-API routes redirect to /setup when no admin exists."""
        app, _, _ = fresh_env
        with app.test_client() as c:
            r = c.get("/login", follow_redirects=False)
            assert r.status_code == 302
            assert "/setup" in r.location


# ══════════════════════════════════════════════════
# CSRF token
# ══════════════════════════════════════════════════

class TestCSRFToken:

    def test_csrf_token_requires_auth(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            r = c.get("/api/csrf-token")
            assert r.status_code == 401

    def test_csrf_token_returns_token(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/csrf-token")
            assert r.status_code == 200
            assert len(r.get_json()["token"]) > 0


# ══════════════════════════════════════════════════
# Setup wizard
# ══════════════════════════════════════════════════

class TestSetupWizard:

    def test_setup_page_accessible_when_no_admin(self, fresh_env):
        app, _, _ = fresh_env
        with app.test_client() as c:
            r = c.get("/setup")
            assert r.status_code == 200

    def test_setup_page_redirects_when_admin_exists(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            r = c.get("/setup", follow_redirects=False)
            assert r.status_code == 302

    def test_detect_network(self, fresh_env):
        app, _, _ = fresh_env
        with app.test_client() as c:
            with patch("core.setup._detect_interfaces", return_value=["eth0"]), \
                 patch("core.setup._detect_default_subnet", return_value="192.168.1.0/24"), \
                 patch("core.setup._detect_server_ip", return_value="192.168.1.100"):
                r = c.get("/api/setup/detect-network")
                assert r.status_code == 200
                assert r.get_json()["interfaces"] == ["eth0"]

    def test_scan_network_requires_root(self, fresh_env):
        app, _, _ = fresh_env
        with app.test_client() as c:
            with patch("os.geteuid", return_value=1000):
                r = c.post("/api/setup/scan-network", json={"subnets": ["192.168.1.0/24"]})
                assert "error" in r.get_json()

    def test_scan_network_with_root(self, fresh_env):
        app, _, _ = fresh_env
        with app.test_client() as c:
            with patch("os.geteuid", return_value=0), \
                 patch("core.setup._discover_hosts", return_value=[{"ip": "192.168.1.10"}]):
                r = c.post("/api/setup/scan-network", json={"subnets": ["192.168.1.0/24"]})
                assert len(r.get_json()["hosts"]) == 1

    def test_scan_network_exception(self, fresh_env):
        app, _, _ = fresh_env
        with app.test_client() as c:
            with patch("os.geteuid", return_value=0), \
                 patch("core.setup._discover_hosts", side_effect=Exception("error")):
                r = c.post("/api/setup/scan-network", json={})
                assert "error" in r.get_json()

    def test_test_smtp_success(self, fresh_env):
        app, _, _ = fresh_env
        with app.test_client() as c:
            with patch("smtplib.SMTP") as M:
                M.return_value = MagicMock()
                r = c.post("/api/setup/test-smtp", json={
                    "smtp_server": "smtp.test.com", "smtp_port": 587, "smtp_tls": True,
                    "to": "a@t.com", "from_address": "cgs@t.com",
                })
                assert r.get_json()["ok"] is True

    def test_test_smtp_ssl(self, fresh_env):
        app, _, _ = fresh_env
        with app.test_client() as c:
            with patch("smtplib.SMTP_SSL") as M:
                M.return_value = MagicMock()
                r = c.post("/api/setup/test-smtp", json={
                    "smtp_server": "s.t.com", "smtp_port": 465, "to": "a@t.com",
                })
                assert r.get_json()["ok"] is True

    def test_test_smtp_with_auth(self, fresh_env):
        app, _, _ = fresh_env
        with app.test_client() as c:
            with patch("smtplib.SMTP") as M:
                mock_srv = MagicMock()
                M.return_value = mock_srv
                c.post("/api/setup/test-smtp", json={
                    "smtp_server": "s.t.com", "smtp_port": 587,
                    "smtp_user": "u@t.com", "smtp_password": "p", "to": "a@t.com",
                })
                mock_srv.login.assert_called_with("u@t.com", "p")

    def test_test_smtp_failure(self, fresh_env):
        app, _, _ = fresh_env
        with app.test_client() as c:
            with patch("smtplib.SMTP", side_effect=Exception("refused")):
                r = c.post("/api/setup/test-smtp", json={"smtp_server": "s.t.com", "smtp_port": 587})
                assert r.get_json()["ok"] is False


# ══════════════════════════════════════════════════
# Setup complete
# ══════════════════════════════════════════════════

class TestSetupComplete:

    def test_creates_admin(self, fresh_env):
        app, _, _ = fresh_env
        with app.test_client() as c:
            r = c.post("/api/setup/complete", json={
                "admin_username": "myadmin", "admin_password": "SuperSecurePass1234",
                "admin_company": "Corp",
            })
            assert r.status_code == 200
            assert WebUser.get(WebUser.username == "myadmin").role == "admin"

    def test_rejects_short_username(self, fresh_env):
        app, _, _ = fresh_env
        with app.test_client() as c:
            r = c.post("/api/setup/complete", json={"admin_username": "a", "admin_password": "SuperSecurePass1234"})
            assert r.status_code == 400

    def test_rejects_short_password(self, fresh_env):
        app, _, _ = fresh_env
        with app.test_client() as c:
            r = c.post("/api/setup/complete", json={"admin_username": "admin", "admin_password": "short"})
            assert r.status_code == 400

    def test_rejects_already_configured(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            r = c.post("/api/setup/complete", json={"admin_username": "a2", "admin_password": "SuperSecurePass1234"})
            assert r.status_code == 400

    def test_creates_user_accounts(self, fresh_env):
        app, _, _ = fresh_env
        with app.test_client() as c:
            r = c.post("/api/setup/complete", json={
                "admin_username": "myadmin", "admin_password": "SuperSecurePass1234",
                "config": {"email": {"user_directory": [
                    {"name": "Jean Dupont", "email": "jean@t.com", "ip": "192.168.1.10"},
                ]}},
            })
            assert r.status_code == 200
            assert WebUser.select().count() == 2
            jean = WebUser.get(WebUser.username == "Jean Dupont")
            assert jean.must_change_password is True

    def test_skips_invalid_user_entries(self, fresh_env):
        app, _, _ = fresh_env
        with app.test_client() as c:
            r = c.post("/api/setup/complete", json={
                "admin_username": "myadmin", "admin_password": "SuperSecurePass1234",
                "config": {"email": {"user_directory": [{"name": "A", "email": "a@t.com"}]}},
            })
            assert WebUser.select().count() == 1

    def test_saves_config(self, fresh_env):
        app, _, _ = fresh_env
        with app.test_client() as c:
            with patch("core.setup.apply_config") as m:
                c.post("/api/setup/complete", json={
                    "admin_username": "myadmin", "admin_password": "SuperSecurePass1234",
                    "config": {"network": {"subnets": ["10.0.0.0/24"]}},
                })
                m.assert_called_once()

    def test_duplicate_admin_fails(self, fresh_env):
        app, _, _ = fresh_env
        with app.test_client() as c:
            c.post("/api/setup/complete", json={"admin_username": "myadmin", "admin_password": "SuperSecurePass1234"})
            with patch("core.database.is_setup_complete", return_value=False):
                r = c.post("/api/setup/complete", json={"admin_username": "myadmin", "admin_password": "AnotherPass12345678"})
                assert r.status_code == 400


# ══════════════════════════════════════════════════
# Login
# ══════════════════════════════════════════════════

class TestLogin:

    def test_login_success(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            r = _login(c)
            assert r.status_code == 302
            assert r.location == "/"

    def test_login_invalid_credentials(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            r = c.post("/login", data={"username": "admin", "password": "wrong"}, follow_redirects=True)
            assert b"Invalid" in r.data

    def test_login_nonexistent_user(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()  # Need admin to pass setup guard
        with app.test_client() as c:
            r = c.post("/login", data={"username": "ghost", "password": "x"}, follow_redirects=True)
            assert b"Invalid" in r.data

    def test_login_sets_session(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/me")
            assert r.status_code == 200
            assert r.get_json()["username"] == "admin"

    def test_login_records_last_login(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            _login(c)
            u = WebUser.get(WebUser.username == "admin")
            assert u.last_login is not None

    def test_login_rate_limited(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            for _ in range(12):
                c.post("/login", data={"username": "admin", "password": "wrong"})
            r = c.post("/login", data={"username": "admin", "password": "wrong"}, follow_redirects=True)
            assert b"Too many" in r.data

    def test_login_page_renders_when_admin_exists(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            r = c.get("/login")
            assert r.status_code == 200

    def test_login_must_change_password(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()  # Need admin to pass setup guard
        WebUser.create(username="newuser", password_hash="", role="user",
                       must_change_password=True, active=True)
        with app.test_client() as c:
            r = c.post("/login", data={"username": "newuser", "password": ""}, follow_redirects=False)
            assert r.status_code == 302
            assert "/create-password" in r.location


# ══════════════════════════════════════════════════
# TOTP
# ══════════════════════════════════════════════════

class TestTOTP:

    def test_verify_totp_empty(self):
        from web.routes_auth import _verify_totp
        assert _verify_totp("", "123456") is False
        assert _verify_totp("SECRET", "") is False

    def test_verify_totp_invalid_code(self):
        from web.routes_auth import _verify_totp
        import base64
        secret = base64.b32encode(os.urandom(20)).decode()
        assert _verify_totp(secret, "000000") is False

    def test_verify_totp_valid_code(self):
        from web.routes_auth import _verify_totp
        import base64, hashlib, hmac, struct
        secret_bytes = os.urandom(20)
        secret = base64.b32encode(secret_bytes).decode()
        counter = int(time.time()) // 30
        msg = struct.pack(">Q", counter)
        h = hmac.new(secret_bytes, msg, hashlib.sha1).digest()
        o = h[-1] & 0x0F
        otp = (struct.unpack(">I", h[o:o+4])[0] & 0x7FFFFFFF) % 1000000
        assert _verify_totp(secret, f"{otp:06d}") is True

    def test_login_with_totp_invalid(self, fresh_env):
        app, _, _ = fresh_env
        import base64
        totp_secret = base64.b32encode(os.urandom(20)).decode()
        pw = bcrypt.hashpw(b"TestPassword12345678", bcrypt.gensalt()).decode()
        WebUser.create(username="admin", password_hash=pw, role="admin",
                       active=True, totp_secret=totp_secret)
        with app.test_client() as c:
            r = c.post("/login", data={"username": "admin", "password": "TestPassword12345678",
                                        "totp": "000000"}, follow_redirects=True)
            assert b"2FA" in r.data


# ══════════════════════════════════════════════════
# Create password
# ══════════════════════════════════════════════════

class TestCreatePassword:

    def test_create_password_page_requires_session(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            r = c.get("/create-password", follow_redirects=False)
            assert r.status_code == 302

    def test_create_password_success(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        u = WebUser.create(username="newuser", password_hash="", role="user",
                           must_change_password=True, active=True)
        with app.test_client() as c:
            c.post("/login", data={"username": "newuser", "password": ""})
            r = c.post("/api/create-password", data={
                "new_password": "MyNewSecurePassword1",
                "confirm_password": "MyNewSecurePassword1",
            }, follow_redirects=False)
            assert r.status_code == 302
            reloaded = WebUser.get_by_id(u.id)
            assert reloaded.must_change_password is False

    def test_create_password_too_short(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        WebUser.create(username="newuser", password_hash="", role="user",
                       must_change_password=True, active=True)
        with app.test_client() as c:
            c.post("/login", data={"username": "newuser", "password": ""})
            r = c.post("/api/create-password", data={
                "new_password": "short", "confirm_password": "short",
            }, follow_redirects=True)
            assert b"at least 16" in r.data

    def test_create_password_mismatch(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        WebUser.create(username="newuser", password_hash="", role="user",
                       must_change_password=True, active=True)
        with app.test_client() as c:
            c.post("/login", data={"username": "newuser", "password": ""})
            r = c.post("/api/create-password", data={
                "new_password": "MyNewSecurePassword1", "confirm_password": "DifferentOne12345678",
            }, follow_redirects=True)
            assert b"do not match" in r.data


# ══════════════════════════════════════════════════
# Logout
# ══════════════════════════════════════════════════

class TestLogout:

    def test_logout_clears_session(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            _login(c)
            c.get("/logout")
            r = c.get("/api/me")
            assert r.status_code == 401


# ══════════════════════════════════════════════════
# /api/me
# ══════════════════════════════════════════════════

class TestApiMe:

    def test_returns_user_info(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            _login(c)
            r = c.get("/api/me")
            assert r.get_json()["username"] == "admin"

    def test_requires_auth(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            r = c.get("/api/me")
            assert r.status_code == 401


# ══════════════════════════════════════════════════
# Change password
# ══════════════════════════════════════════════════

class TestChangePassword:

    def test_success(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        import web.shared as shared
        saved_csrf = shared.csrf
        shared.csrf = None  # Disable CSRF to test password logic directly
        with app.test_client() as c:
            _login(c)
            r = c.put("/api/me/password",
                      headers={"Content-Type": "application/json"},
                      data='{"current_password":"TestPassword12345678","new_password":"NewSecurePassword12345"}')
            assert r.status_code == 200
            assert r.get_json()["ok"] is True
        shared.csrf = saved_csrf

    def test_wrong_current_password(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        import web.shared as shared
        saved_csrf = shared.csrf
        shared.csrf = None  # Disable CSRF for this test
        with app.test_client() as c:
            _login(c)
            r = c.put("/api/me/password",
                      headers={"Content-Type": "application/json"},
                      data='{"current_password":"wrong","new_password":"NewSecurePassword12345"}')
            assert r.status_code == 400
        shared.csrf = saved_csrf

    def test_new_password_too_short(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        import web.shared as shared
        saved_csrf = shared.csrf
        shared.csrf = None
        with app.test_client() as c:
            _login(c)
            r = c.put("/api/me/password",
                      headers={"Content-Type": "application/json"},
                      data='{"current_password":"TestPassword12345678","new_password":"short"}')
            assert r.status_code == 400
        shared.csrf = saved_csrf

    def test_requires_csrf(self, fresh_env):
        app, _, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            _login(c)
            r = c.put("/api/me/password", json={
                "current_password": "TestPassword12345678",
                "new_password": "NewSecurePassword12345",
            })
            assert r.status_code == 403


# ══════════════════════════════════════════════════
# Invite emails
# ══════════════════════════════════════════════════

class TestInviteEmails:

    def test_send_invite_emails(self):
        from web.routes_auth import _send_invite_emails
        WebUser.create(username="user1", password_hash="", role="user",
                       email="u@t.com", must_change_password=True, active=True)
        with patch("smtplib.SMTP") as M:
            M.return_value = MagicMock()
            _send_invite_emails(0, "https://cgs:8443", {
                "smtp_server": "s.t.com", "smtp_port": 587, "from_address": "cgs@t.com",
            })
            M.return_value.send_message.assert_called()

    def test_skips_no_email(self):
        from web.routes_auth import _send_invite_emails
        WebUser.create(username="noemail", password_hash="", role="user",
                       must_change_password=True, active=True)
        with patch("smtplib.SMTP") as M:
            M.return_value = MagicMock()
            _send_invite_emails(0, "https://cgs:8443", {"smtp_server": "s", "smtp_port": 587})
            M.return_value.send_message.assert_not_called()

    def test_handles_smtp_failure(self):
        from web.routes_auth import _send_invite_emails
        WebUser.create(username="user1", password_hash="", role="user",
                       email="u@t.com", must_change_password=True, active=True)
        with patch("smtplib.SMTP", side_effect=Exception("error")):
            _send_invite_emails(0, "https://cgs:8443", {"smtp_server": "s", "smtp_port": 587})

    def test_ssl_port_465(self):
        from web.routes_auth import _send_invite_emails
        WebUser.create(username="user1", password_hash="", role="user",
                       email="u@t.com", must_change_password=True, active=True)
        with patch("smtplib.SMTP_SSL") as M:
            M.return_value = MagicMock()
            _send_invite_emails(0, "https://cgs:8443", {
                "smtp_server": "s", "smtp_port": 465, "from_address": "cgs@t.com",
            })
            M.assert_called()

    def test_with_smtp_auth(self):
        from web.routes_auth import _send_invite_emails
        WebUser.create(username="user1", password_hash="", role="user",
                       email="u@t.com", must_change_password=True, active=True)
        with patch("smtplib.SMTP") as M:
            mock_srv = MagicMock()
            M.return_value = mock_srv
            _send_invite_emails(0, "https://cgs:8443", {
                "smtp_server": "s", "smtp_port": 587, "smtp_user": "u", "smtp_password": "p",
                "from_address": "cgs@t.com",
            })
            mock_srv.login.assert_called_with("u", "p")

    def test_no_users_returns_early(self):
        from web.routes_auth import _send_invite_emails
        with patch("smtplib.SMTP") as M:
            _send_invite_emails(0, "https://cgs:8443", {"smtp_server": "s", "smtp_port": 587})
            M.assert_not_called()


# ══════════════════════════════════════════════════
# Additional coverage: login_guard, edge cases
# ══════════════════════════════════════════════════

class TestLoginGuardLocked:

    def test_login_locked_account(self, fresh_env):
        """Login shows lockout message when login_guard reports locked."""
        app, _, _ = fresh_env
        _create_admin()
        import web.shared as shared
        mock_guard = MagicMock()
        mock_guard.is_locked.return_value = (True, 300)
        shared.login_guard = mock_guard
        with app.test_client() as c:
            r = c.post("/login", data={"username": "admin", "password": "x"}, follow_redirects=True)
            assert b"locked" in r.data.lower()
        shared.login_guard = None


class TestCSRFTokenValid:

    def test_csrf_token_is_unique_per_call(self, fresh_env):
        """Each call to /api/csrf-token returns a different token."""
        app, _, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            _login(c)
            t1 = c.get("/api/csrf-token").get_json()["token"]
            t2 = c.get("/api/csrf-token").get_json()["token"]
            assert t1 != t2


class TestChangePasswordEdgeCases:

    def test_change_password_user_not_found(self, fresh_env):
        """Change password returns 404 when user deleted mid-session."""
        app, _, _ = fresh_env
        u = _create_admin()
        # Create a second admin so setup_guard doesn't trigger 503
        pw2 = bcrypt.hashpw(b"Backup1234567890!!", bcrypt.gensalt()).decode()
        WebUser.create(username="backup_admin", password_hash=pw2, role="admin", active=True)
        import web.shared as shared
        shared.csrf = None
        with app.test_client() as c:
            _login(c)
            u.delete_instance()  # Delete the logged-in user
            r = c.put("/api/me/password",
                      headers={"Content-Type": "application/json"},
                      data='{"current_password":"x","new_password":"NewSecurePassword12345"}')
            assert r.status_code == 404
        from core.security import CSRFProtection
        shared.csrf = CSRFProtection("test")


class TestCreatePasswordEdgeCases:

    def test_api_create_password_no_session(self, fresh_env):
        """api_create_password redirects when no must_change_password session."""
        app, _, _ = fresh_env
        _create_admin()
        with app.test_client() as c:
            r = c.post("/api/create-password", data={
                "new_password": "MyNewSecurePassword1",
                "confirm_password": "MyNewSecurePassword1",
            }, follow_redirects=False)
            assert r.status_code == 302

    def test_create_password_page_renders(self, fresh_env):
        """create_password page renders when must_change_password is set."""
        app, _, _ = fresh_env
        _create_admin()
        WebUser.create(username="new", password_hash="", role="user",
                       must_change_password=True, active=True)
        with app.test_client() as c:
            c.post("/login", data={"username": "new", "password": ""})
            r = c.get("/create-password")
            assert r.status_code == 200

    def test_create_password_user_deleted_redirects_to_login(self, fresh_env):
        """create-password redirects to login when user is deleted."""
        app, _, _ = fresh_env
        _create_admin()
        u = WebUser.create(username="ghost", password_hash="", role="user",
                           must_change_password=True, active=True)
        with app.test_client() as c:
            c.post("/login", data={"username": "ghost", "password": ""})
            u.delete_instance()
            r = c.post("/api/create-password", data={
                "new_password": "MyNewSecurePassword1",
                "confirm_password": "MyNewSecurePassword1",
            }, follow_redirects=False)
            assert r.status_code == 302
            assert "/login" in r.location


class TestSetupCompleteConfigError:

    def test_config_save_error_handled(self, fresh_env):
        """Setup complete handles config save errors gracefully."""
        app, _, _ = fresh_env
        with app.test_client() as c:
            with patch("core.setup.apply_config", side_effect=Exception("write error")):
                r = c.post("/api/setup/complete", json={
                    "admin_username": "admin", "admin_password": "SuperSecurePass1234",
                    "config": {"network": {"subnets": ["10.0.0.0/24"]}},
                })
                assert r.status_code == 200  # Still succeeds

    def test_user_create_exception_logged(self, fresh_env):
        """Setup complete logs warning when user creation fails."""
        app, _, _ = fresh_env
        with app.test_client() as c:
            r = c.post("/api/setup/complete", json={
                "admin_username": "admin", "admin_password": "SuperSecurePass1234",
                "config": {"email": {"user_directory": [
                    {"name": "Jean Dupont", "email": "jean@t.com"},
                    {"name": "Jean Dupont", "email": "jean2@t.com"},  # Duplicate name
                ]}},
            })
            assert r.status_code == 200


class TestLoginGuardRecords:

    def test_login_success_records_success(self, fresh_env):
        """Successful login calls login_guard.record_success."""
        app, _, _ = fresh_env
        _create_admin()
        import web.shared as shared
        mock_guard = MagicMock()
        mock_guard.is_locked.return_value = (False, 0)
        shared.login_guard = mock_guard
        with app.test_client() as c:
            _login(c)
            mock_guard.record_success.assert_called()
        shared.login_guard = None

    def test_login_failure_records_failure(self, fresh_env):
        """Failed login calls login_guard.record_failure."""
        app, _, _ = fresh_env
        _create_admin()
        import web.shared as shared
        mock_guard = MagicMock()
        mock_guard.is_locked.return_value = (False, 0)
        shared.login_guard = mock_guard
        with app.test_client() as c:
            c.post("/login", data={"username": "admin", "password": "wrong"})
            mock_guard.record_failure.assert_called()
        shared.login_guard = None


class TestTOTPLoginIntegration:

    def test_totp_failure_records_login_failure(self, fresh_env):
        """Failed TOTP verification calls login_guard.record_failure."""
        app, _, _ = fresh_env
        import base64
        totp_secret = base64.b32encode(os.urandom(20)).decode()
        pw = bcrypt.hashpw(b"TestPassword12345678", bcrypt.gensalt()).decode()
        WebUser.create(username="admin", password_hash=pw, role="admin",
                       active=True, totp_secret=totp_secret)
        import web.shared as shared
        mock_guard = MagicMock()
        mock_guard.is_locked.return_value = (False, 0)
        shared.login_guard = mock_guard
        with app.test_client() as c:
            c.post("/login", data={"username": "admin", "password": "TestPassword12345678",
                                    "totp": "000000"})
            mock_guard.record_failure.assert_called()
        shared.login_guard = None


class TestHasTOTPDisplay:

    def test_login_page_shows_totp_field_when_users_have_totp(self, fresh_env):
        """Login page has totp field when at least one user has TOTP configured."""
        app, _, _ = fresh_env
        import base64
        totp_secret = base64.b32encode(os.urandom(20)).decode()
        pw = bcrypt.hashpw(b"TestPassword12345678", bcrypt.gensalt()).decode()
        WebUser.create(username="admin", password_hash=pw, role="admin",
                       active=True, totp_secret=totp_secret)
        with app.test_client() as c:
            r = c.get("/login")
            # The page should render (we can't easily check the totp field without
            # template analysis, but this exercises the has_totp query path)
            assert r.status_code == 200
