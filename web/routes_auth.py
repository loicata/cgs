"""Auth & setup routes Blueprint."""
import bcrypt, threading
from datetime import datetime
from flask import Blueprint, render_template, jsonify, request, session, redirect
from core.database import WebUser, is_setup_complete
from web.shared import ctx, csrf, rate_limiter, login_guard, config, auth, csrf_protect, logger

auth_bp = Blueprint("auth_bp", __name__)


@auth_bp.route("/api/csrf-token")
@auth
def api_csrf_token():
    if not csrf:
        return jsonify({"token": ""})
    return jsonify({"token": csrf.generate()})


# ══════════════════════════════════════════════════
# Setup wizard
# ══════════════════════════════════════════════════

@auth_bp.route("/setup")
def setup_page():
    if is_setup_complete():
        return redirect("/")
    return render_template("setup.html")

@auth_bp.route("/api/setup/detect-network")
def api_setup_detect():
    """Auto-detect network info for setup wizard."""
    from core.setup import _detect_interfaces, _detect_default_subnet, _detect_server_ip
    return jsonify({
        "interfaces": _detect_interfaces(),
        "subnet": _detect_default_subnet(),
        "server_ip": _detect_server_ip(),
    })

@auth_bp.route("/api/setup/scan-network", methods=["POST"])
def api_setup_scan():
    """Run ARP scan during setup."""
    import os
    if os.geteuid() != 0:
        return jsonify({"hosts": [], "error": "ARP scan requires root privileges. Run with sudo."})
    data = request.get_json(force=True, silent=True) or {}
    subnets = data.get("subnets", ["192.168.1.0/24"])
    iface = data.get("iface", "auto")
    excludes = data.get("excludes", [])
    server_ip = data.get("server_ip", "")
    try:
        from core.setup import _discover_hosts
        hosts = _discover_hosts(subnets, iface, excludes, server_ip)
        return jsonify({"hosts": hosts})
    except Exception as e:
        return jsonify({"hosts": [], "error": str(e)})

@auth_bp.route("/api/setup/test-smtp", methods=["POST"])
def api_setup_test_smtp():
    """Test SMTP connection during setup."""
    data = request.get_json(force=True, silent=True) or {}
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText("CGS test email — SMTP configuration OK.")
        msg["Subject"] = "[CGS] Test email — Configuration OK"
        msg["From"] = data.get("from_address", "sentinel@local")
        msg["To"] = data.get("to", "")
        port = int(data.get("smtp_port", 587))
        if port == 465:
            srv = smtplib.SMTP_SSL(data["smtp_server"], port, timeout=15)
        else:
            srv = smtplib.SMTP(data["smtp_server"], port, timeout=15)
            if data.get("smtp_tls", True):
                srv.starttls()
        user = data.get("smtp_user", "")
        if user:
            srv.login(user, data.get("smtp_password", ""))
        srv.send_message(msg)
        srv.quit()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@auth_bp.route("/api/setup/complete", methods=["POST"])
def api_setup_complete():
    """Finalize setup: create admin account + user accounts + save config."""
    from web.shared import config as _config
    if is_setup_complete():
        return jsonify({"e": "already configured"}), 400

    data = request.get_json(force=True, silent=True) or {}
    admin_user = data.get("admin_username", "").strip()
    admin_pass = data.get("admin_password", "")
    config_data = data.get("config", {})

    if not admin_user or len(admin_user) < 2:
        return jsonify({"e": "Username must be at least 2 characters"}), 400
    if not admin_pass or len(admin_pass) < 16:
        return jsonify({"e": "Password must be at least 16 characters"}), 400

    # Create admin user in DB
    admin_company = data.get("admin_company", "").strip() or None
    pw_hash = bcrypt.hashpw(admin_pass.encode(), bcrypt.gensalt()).decode()
    try:
        WebUser.create(username=admin_user, password_hash=pw_hash, role="admin",
                       company=admin_company)
    except Exception as e:
        return jsonify({"e": f"Cannot create user: {e}"}), 400

    # Create user accounts from directory (no password — must_change_password=True)
    users_data = config_data.get("email", {}).get("user_directory", [])
    for entry in users_data:
        uname = entry.get("name", "").strip()
        uemail = entry.get("email", "").strip()
        if not uname or len(uname) < 2:
            continue
        try:
            WebUser.create(
                username=uname, password_hash="", role="user",
                email=uemail or None, ip=entry.get("ip") or None,
                mac=entry.get("mac") or None, hostname=entry.get("hostname") or None,
                must_change_password=True,
            )
        except Exception as e:
            logger.warning("Cannot create user %s: %s", uname, e)

    # Save config if provided
    if config_data and _config:
        try:
            from core.setup import apply_config
            config_path = _config._path if hasattr(_config, '_path') else "/etc/cgs/config.yaml"
            apply_config(config_data, config_path)
        except Exception as e:
            logger.error("Config save failed: %s", e)

    # Schedule invite emails to users
    email_cfg = config_data.get("email", {})
    if email_cfg.get("enabled"):
        delay = int(email_cfg.get("invite_delay_minutes", 60)) * 60
        base_url = email_cfg.get("sentinel_url", "").rstrip("/")
        t = threading.Thread(target=_send_invite_emails, daemon=True,
                             args=(delay, base_url, email_cfg))
        t.start()

    return jsonify({"ok": True, "message": "Setup complete. Please log in."})


def _send_invite_emails(delay_seconds, base_url, email_cfg):
    """Background: wait then send welcome emails with username + login link."""
    import time
    if delay_seconds > 0:
        logger.info("Invite emails scheduled in %d minutes", delay_seconds // 60)
        time.sleep(delay_seconds)

    users = list(WebUser.select().where(
        WebUser.must_change_password == True,
        WebUser.email.is_null(False),
        WebUser.active == True,
    ))
    if not users:
        return

    login_url = f"{base_url}/login"
    for u in users:
        if not u.email:
            continue
        subject = "[CGS] Your account is ready"
        body = (
            f"Hello {u.username},\n\n"
            f"An account has been created for you on CGS.\n\n"
            f"  Username: {u.username}\n"
            f"  Login: {login_url}\n\n"
            f"You will be asked to create your password on first login.\n\n"
            f"— CGS Server"
        )
        try:
            import smtplib
            from email.mime.text import MIMEText
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = email_cfg.get("from_address", "cgs@localhost")
            msg["To"] = u.email
            port = int(email_cfg.get("smtp_port", 587))
            if port == 465:
                srv = smtplib.SMTP_SSL(email_cfg["smtp_server"], port, timeout=15)
            else:
                srv = smtplib.SMTP(email_cfg["smtp_server"], port, timeout=15)
                if email_cfg.get("smtp_tls", True):
                    srv.starttls()
            smtp_user = email_cfg.get("smtp_user", "")
            if smtp_user:
                srv.login(smtp_user, email_cfg.get("smtp_password", ""))
            srv.send_message(msg)
            srv.quit()
            logger.info("Invite email sent to %s (%s)", u.username, u.email)
        except Exception as e:
            logger.error("Failed to send invite to %s: %s", u.username, e)


# ══════════════════════════════════════════════════
# Auth
# ══════════════════════════════════════════════════

def _verify_totp(totp_secret, code):
    if not totp_secret or not code:
        return False
    try:
        import hmac as _hmac, struct, time as _time, hashlib, base64
        key = base64.b32decode(totp_secret, casefold=True)
        counter = int(_time.time()) // 30
        for offset in (-1, 0, 1):
            msg = struct.pack(">Q", counter + offset)
            h = _hmac.new(key, msg, hashlib.sha1).digest()
            o = h[-1] & 0x0F
            otp = (struct.unpack(">I", h[o:o+4])[0] & 0x7FFFFFFF) % 1000000
            if code == f"{otp:06d}":
                return True
    except Exception as e:
        logger.debug("Failed to verify TOTP code: %s", e)
    return False

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    import time as _time
    from web.shared import login_guard as _login_guard, rate_limiter as _rate_limiter
    error = None
    ip = request.remote_addr

    if _login_guard:
        locked, remaining = _login_guard.is_locked(ip)
        if locked:
            error = f"Account locked. Try again in {remaining}s."
            return render_template("login.html", error=error, totp_enabled=False)

    if _rate_limiter:
        allowed, _ = _rate_limiter.check(f"login:{ip}", limit=10, window=60)
        if not allowed:
            error = "Too many login attempts. Please wait."
            return render_template("login.html", error=error, totp_enabled=False)

    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")

        try:
            user = WebUser.get(WebUser.username == u, WebUser.active == True)
        except WebUser.DoesNotExist:
            user = None

        # First-time user: no password set yet — redirect to create password
        if user and user.must_change_password:
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            session["must_change_password"] = True
            return redirect("/create-password")

        if user and user.password_hash and bcrypt.checkpw(p.encode(), user.password_hash.encode()):
            # TOTP verification if configured for this user
            if user.totp_secret:
                totp_code = request.form.get("totp", "")
                if not _verify_totp(user.totp_secret, totp_code):
                    error = "Invalid 2FA code."
                    if _login_guard:
                        _login_guard.record_failure(ip)
                    return render_template("login.html", error=error, totp_enabled=True)

            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            session["last_active"] = _time.time()
            session["ip"] = ip

            user.last_login = datetime.now()
            user.save()

            if _login_guard:
                _login_guard.record_success(ip)

            return redirect("/")

        error = "Invalid credentials."
        if _login_guard:
            _login_guard.record_failure(ip)

    # Check if any user has TOTP for the form display
    has_totp = False
    try:
        has_totp = WebUser.select().where(WebUser.totp_secret.is_null(False), WebUser.totp_secret != "").exists()
    except Exception as e:
        logger.debug("Failed to check TOTP availability: %s", e)

    return render_template("login.html", error=error, totp_enabled=has_totp)

@auth_bp.route("/create-password")
def create_password_page():
    if not session.get("must_change_password"):
        return redirect("/")
    return render_template("login.html", create_password=True,
                           username=session.get("username", ""), error=None)

@auth_bp.route("/api/create-password", methods=["POST"])
def api_create_password():
    if not session.get("must_change_password"):
        return redirect("/")
    data = request.form
    new_pw = data.get("new_password", "")
    confirm = data.get("confirm_password", "")
    uname = session.get("username", "")
    if not new_pw or len(new_pw) < 16:
        return render_template("login.html", create_password=True,
                               username=uname, error="Password must be at least 16 characters.")
    if new_pw != confirm:
        return render_template("login.html", create_password=True,
                               username=uname, error="Passwords do not match.")
    try:
        u = WebUser.get_by_id(session["user_id"])
    except WebUser.DoesNotExist:
        session.clear()
        return redirect("/login")
    u.password_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
    u.must_change_password = False
    u.save()
    session.pop("must_change_password", None)
    import time as _time
    session["last_active"] = _time.time()
    return redirect("/")

@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@auth_bp.route("/api/me")
@auth
def api_me():
    """Current user info."""
    company = ""
    try:
        u = WebUser.get_by_id(session["user_id"])
        company = u.company or ""
    except Exception as e:
        logger.debug("Failed to get user company info: %s", e)
    return jsonify({
        "id": session.get("user_id"),
        "username": session.get("username"),
        "role": session.get("role"),
        "company": company,
    })

@auth_bp.route("/api/me/password", methods=["PUT"])
@auth
@csrf_protect
def api_change_own_password():
    data = request.get_json(force=True, silent=True) or {}
    current = data.get("current_password", "")
    new_pw = data.get("new_password", "")

    if not new_pw or len(new_pw) < 16:
        return jsonify({"e": "Password must be at least 16 characters"}), 400

    try:
        u = WebUser.get_by_id(session["user_id"])
    except WebUser.DoesNotExist:
        return jsonify({"e": "user not found"}), 404

    if not bcrypt.checkpw(current.encode(), u.password_hash.encode()):
        return jsonify({"e": "Current password incorrect"}), 400

    u.password_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
    u.save()
    return jsonify({"ok": True})
