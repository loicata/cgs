"""Tests for web/shared.py — auth, admin_required, csrf_protect, audit decorators."""
import os
import sys
import time
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ══════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════

@pytest.fixture
def app():
    """Create a standalone Flask app for decorator testing."""
    from flask import Flask, jsonify, session
    app = Flask(__name__)
    app.secret_key = "test-secret-key-for-decorators"
    app.config["TESTING"] = True

    # Import after app creation to avoid blueprint issues
    from web import shared

    # Reset shared module state
    shared.csrf = None
    shared.rate_limiter = None
    shared.login_guard = None
    shared.session_timeout = 1800
    shared.ctx = {}

    # Register test routes using the decorators
    @app.route("/api/protected")
    @shared.auth
    def api_protected():
        return jsonify({"ok": True})

    @app.route("/web/protected")
    @shared.auth
    def web_protected():
        return "ok"

    @app.route("/api/admin-only")
    @shared.admin_required
    def api_admin_only():
        return jsonify({"ok": True})

    @app.route("/web/admin-only")
    @shared.admin_required
    def web_admin_only():
        return "admin page"

    @app.route("/api/csrf-action", methods=["POST"])
    @shared.csrf_protect
    def csrf_action():
        return jsonify({"ok": True})

    @app.route("/api/audit-test", methods=["POST"])
    @shared.auth
    def audit_test():
        shared.audit("test_action", "test detail")
        return jsonify({"ok": True})

    yield app, shared


@pytest.fixture
def client(app):
    """Create test client."""
    flask_app, shared = app
    with flask_app.test_client() as c:
        yield c, shared


# ══════════════════════════════════════════════════
# auth decorator
# ══════════════════════════════════════════════════

class TestAuthDecorator:

    def test_api_returns_401_when_not_authenticated(self, client):
        """API endpoint returns 401 when no user_id in session."""
        c, _ = client
        resp = c.get("/api/protected")
        assert resp.status_code == 401
        assert resp.get_json()["e"] == "auth"

    def test_web_redirects_to_login_when_not_authenticated(self, client):
        """Web endpoint redirects to /login when no user_id in session."""
        c, _ = client
        resp = c.get("/web/protected")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_api_returns_200_when_authenticated(self, client):
        """Authenticated user can access protected API endpoint."""
        c, _ = client
        with c.session_transaction() as sess:
            sess["user_id"] = 1
            sess["last_active"] = time.time()
        resp = c.get("/api/protected")
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True

    def test_must_change_password_api_returns_403(self, client):
        """API returns 403 when user must change password."""
        c, _ = client
        with c.session_transaction() as sess:
            sess["user_id"] = 1
            sess["must_change_password"] = True
            sess["last_active"] = time.time()
        resp = c.get("/api/protected")
        assert resp.status_code == 403
        assert "password" in resp.get_json()["e"]

    def test_must_change_password_web_redirects(self, client):
        """Web redirects to /create-password when must_change_password."""
        c, _ = client
        with c.session_transaction() as sess:
            sess["user_id"] = 1
            sess["must_change_password"] = True
            sess["last_active"] = time.time()
        resp = c.get("/web/protected")
        assert resp.status_code == 302
        assert "/create-password" in resp.headers["Location"]

    def test_session_timeout_api_returns_401(self, client):
        """API returns 401 when session has timed out."""
        c, shared = client
        shared.session_timeout = 10  # 10 seconds
        with c.session_transaction() as sess:
            sess["user_id"] = 1
            sess["last_active"] = time.time() - 20  # 20 seconds ago
        resp = c.get("/api/protected")
        assert resp.status_code == 401
        assert resp.get_json()["e"] == "session expired"

    def test_session_timeout_web_redirects(self, client):
        """Web redirects to /login when session timed out."""
        c, shared = client
        shared.session_timeout = 10
        with c.session_transaction() as sess:
            sess["user_id"] = 1
            sess["last_active"] = time.time() - 20
        resp = c.get("/web/protected")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_session_timeout_updates_last_active(self, client):
        """Successful auth updates last_active timestamp."""
        c, _ = client
        before = time.time()
        with c.session_transaction() as sess:
            sess["user_id"] = 1
            sess["last_active"] = before
        c.get("/api/protected")
        with c.session_transaction() as sess:
            assert sess["last_active"] >= before


# ══════════════════════════════════════════════════
# admin_required decorator
# ══════════════════════════════════════════════════

class TestAdminRequiredDecorator:

    def test_api_returns_401_when_not_authenticated(self, client):
        """API returns 401 when not authenticated for admin route."""
        c, _ = client
        resp = c.get("/api/admin-only")
        assert resp.status_code == 401

    def test_web_redirects_when_not_authenticated(self, client):
        """Web redirects to /login for unauthenticated admin route."""
        c, _ = client
        resp = c.get("/web/admin-only")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_non_admin_returns_403(self, client):
        """Non-admin user gets 403 on admin endpoint."""
        c, _ = client
        with c.session_transaction() as sess:
            sess["user_id"] = 1
            sess["role"] = "user"
            sess["last_active"] = time.time()
        resp = c.get("/api/admin-only")
        assert resp.status_code == 403
        assert resp.get_json()["e"] == "admin required"

    def test_admin_can_access(self, client):
        """Admin user can access admin endpoint."""
        c, _ = client
        with c.session_transaction() as sess:
            sess["user_id"] = 1
            sess["role"] = "admin"
            sess["last_active"] = time.time()
        resp = c.get("/api/admin-only")
        assert resp.status_code == 200

    def test_admin_session_timeout(self, client):
        """Admin session also times out."""
        c, shared = client
        shared.session_timeout = 10
        with c.session_transaction() as sess:
            sess["user_id"] = 1
            sess["role"] = "admin"
            sess["last_active"] = time.time() - 20
        resp = c.get("/api/admin-only")
        assert resp.status_code == 401


# ══════════════════════════════════════════════════
# csrf_protect decorator
# ══════════════════════════════════════════════════

class TestCsrfProtectDecorator:

    def test_no_csrf_module_allows_request(self, client):
        """When csrf is None, requests pass through."""
        c, shared = client
        shared.csrf = None
        resp = c.post("/api/csrf-action")
        assert resp.status_code == 200

    def test_valid_csrf_token_in_header(self, client):
        """Valid CSRF token in X-CSRF-Token header passes."""
        c, shared = client
        mock_csrf = MagicMock()
        mock_csrf.validate.return_value = True
        shared.csrf = mock_csrf
        resp = c.post("/api/csrf-action", headers={"X-CSRF-Token": "valid-token"})
        assert resp.status_code == 200

    def test_invalid_csrf_token_returns_403(self, client):
        """Invalid CSRF token returns 403."""
        c, shared = client
        mock_csrf = MagicMock()
        mock_csrf.validate.return_value = False
        shared.csrf = mock_csrf
        resp = c.post("/api/csrf-action", headers={"X-CSRF-Token": "bad-token"})
        assert resp.status_code == 403
        assert "CSRF" in resp.get_json()["e"]

    def test_csrf_token_from_json_body(self, client):
        """CSRF token can be provided in JSON body as _csrf_token."""
        c, shared = client
        mock_csrf = MagicMock()
        mock_csrf.validate.return_value = True
        shared.csrf = mock_csrf
        resp = c.post("/api/csrf-action",
                       json={"_csrf_token": "body-token"})
        assert resp.status_code == 200

    def test_missing_csrf_token_returns_403(self, client):
        """Missing CSRF token returns 403 when csrf is enabled."""
        c, shared = client
        mock_csrf = MagicMock()
        mock_csrf.validate.return_value = False
        shared.csrf = mock_csrf
        resp = c.post("/api/csrf-action")
        assert resp.status_code == 403


# ══════════════════════════════════════════════════
# audit function
# ══════════════════════════════════════════════════

class TestAuditFunction:

    def test_audit_calls_audit_chain(self, client):
        """audit() calls audit_chain.log when available."""
        c, shared = client
        mock_ac = MagicMock()
        shared.ctx["audit_chain"] = mock_ac
        with c.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "testuser"
            sess["last_active"] = time.time()
        resp = c.post("/api/audit-test")
        assert resp.status_code == 200
        assert mock_ac.log.called

    def test_audit_noop_without_audit_chain(self, client):
        """audit() does nothing when audit_chain is not in ctx."""
        c, shared = client
        shared.ctx.pop("audit_chain", None)
        with c.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "testuser"
            sess["last_active"] = time.time()
        resp = c.post("/api/audit-test")
        assert resp.status_code == 200  # No crash
