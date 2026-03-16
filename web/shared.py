"""Shared state and decorators for all Blueprint modules."""
import functools
import logging
from flask import jsonify, request, session, redirect

logger = logging.getLogger("cgs.web")

# ── Shared state (populated by init_app in app.py) ──
ctx = {}
csrf = None
rate_limiter = None
login_guard = None
session_timeout = 1800
config = None


# ── Decorators ──

def auth(f):
    """Require authenticated user (any role)."""
    @functools.wraps(f)
    def w(*a, **k):
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return jsonify({"e": "auth"}), 401
            return redirect("/login")
        if session.get("must_change_password"):
            if request.path.startswith("/api/"):
                return jsonify({"e": "password change required"}), 403
            return redirect("/create-password")
        import time as _time
        now = _time.time()
        last_active = session.get("last_active", 0)
        if last_active and (now - last_active) > session_timeout:
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"e": "session expired"}), 401
            return redirect("/login")
        session["last_active"] = now
        return f(*a, **k)
    return w


def admin_required(f):
    """Require authenticated admin user."""
    @functools.wraps(f)
    def w(*a, **k):
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return jsonify({"e": "auth"}), 401
            return redirect("/login")
        if session.get("role") != "admin":
            return jsonify({"e": "admin required"}), 403
        import time as _time
        now = _time.time()
        last_active = session.get("last_active", 0)
        if last_active and (now - last_active) > session_timeout:
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"e": "session expired"}), 401
            return redirect("/login")
        session["last_active"] = now
        return f(*a, **k)
    return w


def csrf_protect(f):
    """CSRF protection for state-changing endpoints."""
    @functools.wraps(f)
    def w(*a, **k):
        if not csrf:
            return f(*a, **k)
        token = (request.headers.get("X-CSRF-Token") or
                 (request.get_json(force=True, silent=True) or {}).get("_csrf_token", ""))
        if not csrf.validate(token):
            return jsonify({"e": "CSRF token invalid or missing"}), 403
        return f(*a, **k)
    return w


def audit(action, detail=""):
    ac = ctx.get("audit_chain")
    if ac:
        user = session.get("username", "unknown")
        ac.log(event=f"ADMIN({user}): {action}", detail=f"{detail} | ip={request.remote_addr}",
               source="dashboard", severity=4, ip=request.remote_addr)
