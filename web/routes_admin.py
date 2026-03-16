"""Admin routes Blueprint."""
import os
import subprocess
import bcrypt
from datetime import datetime
from flask import Blueprint, jsonify, request, session
from core.database import WebUser
from web.shared import ctx, config, auth, admin_required, csrf_protect, audit

admin_bp = Blueprint("admin_bp", __name__)


# ══════════════════════════════════════════════════
# Admin: User management
# ══════════════════════════════════════════════════

@admin_bp.route("/api/admin/users")
@admin_required
def api_admin_users():
    return jsonify([{
        "id": u.id, "username": u.username, "role": u.role,
        "active": u.active, "has_totp": bool(u.totp_secret),
        "company": u.company or "",
        "email": u.email or "" if hasattr(u, 'email') else "",
        "ip": u.ip or "" if hasattr(u, 'ip') else "",
        "mac": u.mac or "" if hasattr(u, 'mac') else "",
        "hostname": u.hostname or "" if hasattr(u, 'hostname') else "",
        "must_change_password": u.must_change_password if hasattr(u, 'must_change_password') else False,
        "created_at": u.created_at.isoformat() if u.created_at else "",
        "last_login": u.last_login.isoformat() if u.last_login else "",
    } for u in WebUser.select().order_by(WebUser.created_at)])

@admin_bp.route("/api/admin/users", methods=["POST"])
@admin_required
@csrf_protect
def api_admin_create_user():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", "user")

    if not username or len(username) < 2:
        return jsonify({"e": "Username must be at least 2 characters"}), 400
    if not password or len(password) < 16:
        return jsonify({"e": "Password must be at least 16 characters"}), 400
    if role not in ("admin", "user"):
        return jsonify({"e": "Role must be 'admin' or 'user'"}), 400

    company = data.get("company", "").strip() or None
    email = data.get("email", "").strip() or None
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        u = WebUser.create(username=username, password_hash=pw_hash, role=role,
                           company=company, email=email)
        audit("CREATE_USER", f"username={username} role={role}")
        return jsonify({"ok": True, "id": u.id})
    except Exception as e:
        return jsonify({"e": f"Cannot create user: {e}"}), 400

@admin_bp.route("/api/admin/users/device", methods=["POST"])
@admin_required
@csrf_protect
def api_admin_create_user_device():
    """Create a user account linked to a device (no password, must_change_password=True)."""
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    if not username or len(username) < 2:
        return jsonify({"e": "Username must be at least 2 characters"}), 400
    try:
        u = WebUser.create(
            username=username, password_hash="", role="user",
            email=email or None, ip=data.get("ip", "").strip() or None,
            mac=data.get("mac", "").strip() or None,
            hostname=data.get("hostname", "").strip() or None,
            must_change_password=True,
        )
        audit("CREATE_USER_DEVICE", f"username={username} ip={data.get('ip','')}")
        return jsonify({"ok": True, "id": u.id})
    except Exception as e:
        return jsonify({"e": f"Cannot create user: {e}"}), 400

@admin_bp.route("/api/admin/users/<int:uid>", methods=["PUT"])
@admin_required
@csrf_protect
def api_admin_update_user(uid):
    data = request.get_json(force=True, silent=True) or {}
    try:
        u = WebUser.get_by_id(uid)
    except WebUser.DoesNotExist:
        return jsonify({"e": "not found"}), 404

    if "role" in data:
        if data["role"] not in ("admin", "user"):
            return jsonify({"e": "Role must be 'admin' or 'user'"}), 400
        # Prevent removing last admin
        if u.role == "admin" and data["role"] != "admin":
            admin_count = WebUser.select().where(WebUser.role == "admin", WebUser.active == True).count()
            if admin_count <= 1:
                return jsonify({"e": "Cannot remove the last admin"}), 400
        u.role = data["role"]

    if "password" in data and data["password"]:
        if len(data["password"]) < 16:
            return jsonify({"e": "Password must be at least 16 characters"}), 400
        u.password_hash = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt()).decode()

    if "active" in data:
        # Prevent deactivating last admin
        if u.role == "admin" and not data["active"]:
            admin_count = WebUser.select().where(WebUser.role == "admin", WebUser.active == True).count()
            if admin_count <= 1:
                return jsonify({"e": "Cannot deactivate the last admin"}), 400
        u.active = data["active"]

    if "totp_secret" in data:
        u.totp_secret = data["totp_secret"] if data["totp_secret"] else None

    if "company" in data:
        u.company = data["company"].strip() if data["company"] else None

    u.save()
    audit("UPDATE_USER", f"uid={uid} username={u.username}")
    return jsonify({"ok": True})

@admin_bp.route("/api/admin/users/<int:uid>", methods=["DELETE"])
@admin_required
@csrf_protect
def api_admin_delete_user(uid):
    try:
        u = WebUser.get_by_id(uid)
    except WebUser.DoesNotExist:
        return jsonify({"e": "not found"}), 404

    if u.id == session.get("user_id"):
        return jsonify({"e": "Cannot delete yourself"}), 400

    if u.role == "admin":
        admin_count = WebUser.select().where(WebUser.role == "admin", WebUser.active == True).count()
        if admin_count <= 1:
            return jsonify({"e": "Cannot delete the last admin"}), 400

    username = u.username
    u.delete_instance()
    audit("DELETE_USER", f"username={username}")
    return jsonify({"ok": True})


# ══════════════════════════════════════════════════
# Admin: Services status
# ══════════════════════════════════════════════════

@admin_bp.route("/api/admin/services")
@admin_required
def api_admin_services():
    cfg = ctx.get("config")
    services = ["cgs"]
    if cfg and (cfg.get("suricata.eve_file") or cfg.get("suricata.syslog_port") or cfg.get("suricata.tcp_port")):
        services.append("suricata")

    result = []
    for svc in services:
        try:
            r = subprocess.run(["systemctl", "is-active", svc],
                              capture_output=True, text=True, timeout=5)
            result.append({"name": svc, "active": r.stdout.strip() == "active"})
        except Exception:
            result.append({"name": svc, "active": None})
    return jsonify(result)

@admin_bp.route("/api/admin/restart", methods=["POST"])
@admin_required
@csrf_protect
def api_admin_restart():
    audit("RESTART_SERVICE")
    try:
        subprocess.Popen(["systemctl", "restart", "cgs"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return jsonify({"ok": True, "message": "Service restart initiated"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@admin_bp.route("/api/admin/resend-invites", methods=["POST"])
@admin_required
@csrf_protect
def api_admin_resend_invites():
    """Resend welcome emails to users who haven't set their password yet."""
    import threading
    cfg = ctx.get("config")
    if not cfg:
        return jsonify({"ok": False, "error": "No config"}), 400
    email_cfg = {
        "smtp_server": cfg.get("email.smtp_server", ""),
        "smtp_port": cfg.get("email.smtp_port", 587),
        "smtp_tls": cfg.get("email.smtp_tls", True),
        "smtp_user": cfg.get("email.smtp_user", ""),
        "smtp_password": cfg.get("email.smtp_password", ""),
        "from_address": cfg.get("email.from_address", "cgs@localhost"),
        "sentinel_url": cfg.get("email.sentinel_url", ""),
    }
    if not email_cfg["smtp_server"]:
        return jsonify({"ok": False, "error": "SMTP not configured"}), 400
    users = list(WebUser.select().where(
        WebUser.must_change_password == True,
        WebUser.email.is_null(False),
        WebUser.active == True,
    ))
    count = len([u for u in users if u.email])
    if count == 0:
        return jsonify({"ok": True, "count": 0})
    from web.routes_auth import _send_invite_emails
    base_url = email_cfg.get("sentinel_url", "").rstrip("/")
    t = threading.Thread(target=_send_invite_emails, daemon=True,
                         args=(0, base_url, email_cfg))
    t.start()
    audit("RESEND_INVITES", f"{count} user(s)")
    return jsonify({"ok": True, "count": count})


# ══════════════════════════════════════════════════
# Admin: Iptables rules
# ══════════════════════════════════════════════════

@admin_bp.route("/api/admin/iptables")
@admin_required
def api_admin_iptables():
    try:
        r = subprocess.run(["iptables", "-L", "CGS", "-n", "-v", "--line-numbers"],
                          capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return jsonify({"ok": True, "rules": r.stdout})
        return jsonify({"ok": True, "rules": ""})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ══════════════════════════════════════════════════
# Admin: Configuration
# ══════════════════════════════════════════════════

def _mask_secrets(d, depth=0):
    """Mask sensitive values in config dict."""
    if depth > 10 or not isinstance(d, dict):
        return
    sensitive = {"password", "secret", "api_key", "api_secret", "smtp_password",
                 "shared_secret", "password_hash", "pfsense_api_key", "opnsense_key",
                 "opnsense_secret", "abuseipdb_key", "virustotal_key", "totp_secret",
                 "misp_key", "opencti_token", "shodan_key", "greynoise_key", "otx_key"}
    for k, v in d.items():
        if isinstance(v, dict):
            _mask_secrets(v, depth + 1)
        elif k in sensitive and v:
            d[k] = "***"

@admin_bp.route("/api/admin/config")
@admin_required
def api_admin_config():
    cfg = ctx.get("config")
    if not cfg:
        return jsonify({"e": "config not available"}), 503
    import yaml
    config_path = cfg._path if hasattr(cfg, '_path') else "/etc/cgs/config.yaml"
    try:
        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}
        # Mask sensitive fields
        _mask_secrets(raw)
        return jsonify({"config": raw, "path": config_path})
    except Exception as e:
        return jsonify({"e": str(e)}), 500

@admin_bp.route("/api/admin/config", methods=["PUT"])
@admin_required
@csrf_protect
def api_admin_config_update():
    cfg = ctx.get("config")
    if not cfg:
        return jsonify({"e": "config not available"}), 503
    data = request.get_json(force=True, silent=True) or {}
    config_data = data.get("config", {})
    if not config_data:
        return jsonify({"e": "No config data provided"}), 400
    try:
        from core.setup import apply_config
        config_path = cfg._path if hasattr(cfg, '_path') else "/etc/cgs/config.yaml"
        apply_config(config_data, config_path)
        audit("CONFIG_UPDATE", "config.yaml updated via web")
        return jsonify({"ok": True, "message": "Config saved. Restart to apply."})
    except Exception as e:
        return jsonify({"e": str(e)}), 500

@admin_bp.route("/api/admin/config/report-options")
@admin_required
def api_admin_report_options():
    cfg = ctx.get("config")
    if not cfg: return jsonify({})
    try:
        from core.legal_data import get_country, get_supported_countries
        country_code = cfg.get("email.country", "IE")
        cdata = get_country(country_code)
        countries = get_supported_countries()
        return jsonify({
            "country": country_code,
            "country_name": cdata.get("name", ""),
            "country_flag": cdata.get("flag", ""),
            "include_legal_info": cfg.get("email.include_legal_info", True),
            "attach_forensic_file": cfg.get("email.attach_forensic_file", True),
            "supported_countries": [{"code": c, "flag": f, "name": n} for c, f, n in countries],
        })
    except Exception as e:
        return jsonify({"e": str(e)}), 500

@admin_bp.route("/api/admin/config/report-options", methods=["PUT"])
@admin_required
@csrf_protect
def api_admin_report_options_update():
    cfg = ctx.get("config")
    if not cfg: return jsonify({"e": "not available"}), 503
    data = request.get_json(force=True, silent=True) or {}
    import yaml
    config_path = cfg._path if hasattr(cfg, '_path') else "/etc/cgs/config.yaml"
    try:
        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}
        email = raw.setdefault("email", {})
        if "country" in data:
            email["country"] = data["country"]
        if "include_legal_info" in data:
            email["include_legal_info"] = bool(data["include_legal_info"])
        if "attach_forensic_file" in data:
            email["attach_forensic_file"] = bool(data["attach_forensic_file"])
        with open(config_path, "w") as f:
            yaml.dump(raw, f, default_flow_style=False, allow_unicode=True)
        audit("REPORT_OPTIONS_UPDATE")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"e": str(e)}), 500


# ══════════════════════════════════════════════════
# Admin: User directory (network device -> person mapping)
# ══════════════════════════════════════════════════

@admin_bp.route("/api/admin/directory")
@admin_required
def api_admin_directory():
    cfg = ctx.get("config")
    if not cfg: return jsonify([])
    import yaml
    config_path = cfg._path if hasattr(cfg, '_path') else "/etc/cgs/config.yaml"
    try:
        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}
        return jsonify(raw.get("email", {}).get("user_directory", []))
    except Exception:
        return jsonify([])

@admin_bp.route("/api/admin/directory", methods=["POST"])
@admin_required
@csrf_protect
def api_admin_directory_add():
    data = request.get_json(force=True, silent=True) or {}
    return _directory_save("add", data)

@admin_bp.route("/api/admin/directory/<int:idx>", methods=["PUT"])
@admin_required
@csrf_protect
def api_admin_directory_update(idx):
    data = request.get_json(force=True, silent=True) or {}
    return _directory_save("update", data, idx)

@admin_bp.route("/api/admin/directory/<int:idx>", methods=["DELETE"])
@admin_required
@csrf_protect
def api_admin_directory_delete(idx):
    return _directory_save("delete", {}, idx)

def _directory_save(action, data, idx=None):
    import yaml
    cfg = ctx.get("config")
    config_path = cfg._path if hasattr(cfg, '_path') else "/etc/cgs/config.yaml"
    try:
        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}
        users = raw.setdefault("email", {}).setdefault("user_directory", [])

        if action == "add":
            entry = {
                "ip": data.get("ip", ""), "mac": data.get("mac", ""),
                "name": data.get("name", ""), "email": data.get("email", ""),
                "hostname": data.get("hostname", ""),
            }
            users.append(entry)
            audit("DIRECTORY_ADD", f"ip={entry['ip']} name={entry['name']}")

        elif action == "update" and idx is not None:
            if 0 <= idx < len(users):
                for k in ("ip", "mac", "name", "email", "hostname"):
                    if k in data:
                        users[idx][k] = data[k]
                audit("DIRECTORY_UPDATE", f"idx={idx}")
            else:
                return jsonify({"e": "invalid index"}), 400

        elif action == "delete" and idx is not None:
            if 0 <= idx < len(users):
                removed = users.pop(idx)
                audit("DIRECTORY_DELETE", f"name={removed.get('name', '')}")
            else:
                return jsonify({"e": "invalid index"}), 400

        with open(config_path, "w") as f:
            yaml.dump(raw, f, default_flow_style=False, allow_unicode=True)
        return jsonify({"ok": True, "directory": users})
    except Exception as e:
        return jsonify({"e": str(e)}), 500

@admin_bp.route("/api/admin/directory/scan", methods=["POST"])
@admin_required
@csrf_protect
def api_admin_directory_scan():
    cfg = ctx.get("config")
    if not cfg: return jsonify({"hosts": []})
    subnets = cfg.get("network.subnets", ["192.168.1.0/24"])
    iface = cfg.get("network.interface", "auto")
    excludes = cfg.get("network.exclude_ips", [])
    try:
        from core.setup import _discover_hosts, _detect_server_ip
        server_ip = _detect_server_ip()
        hosts = _discover_hosts(subnets, iface, excludes, server_ip)
        return jsonify({"hosts": hosts})
    except Exception as e:
        return jsonify({"hosts": [], "error": str(e)})


# ══════════════════════════════════════════════════
# Admin: Email testing
# ══════════════════════════════════════════════════

@admin_bp.route("/api/admin/test-email", methods=["POST"])
@admin_required
@csrf_protect
def api_admin_test_email():
    cfg = ctx.get("config")
    if not cfg: return jsonify({"ok": False, "error": "config not available"})
    if not cfg.get("email.enabled"):
        return jsonify({"ok": False, "error": "Email disabled in config"})

    data = request.get_json(force=True, silent=True) or {}
    to = data.get("to", "")
    if not to:
        admins = cfg.get("email.admin_emails", [])
        to = admins[0] if admins else ""
    if not to:
        return jsonify({"ok": False, "error": "No recipient specified"})

    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText("CGS test email.\n\nSMTP configuration is correct.")
        msg["Subject"] = "[CGS] Test email — Configuration OK"
        msg["From"] = cfg.get("email.from_address", "sentinel@local")
        msg["To"] = to
        server_addr = cfg.get("email.smtp_server")
        port = cfg.get("email.smtp_port", 587)
        if port == 465:
            srv = smtplib.SMTP_SSL(server_addr, port, timeout=15)
        else:
            srv = smtplib.SMTP(server_addr, port, timeout=15)
            if cfg.get("email.smtp_tls", True):
                srv.starttls()
        user = cfg.get("email.smtp_user", "")
        if user:
            srv.login(user, cfg.get("email.smtp_password", ""))
        srv.send_message(msg)
        srv.quit()
        audit("TEST_EMAIL", f"to={to}")
        return jsonify({"ok": True, "to": to})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@admin_bp.route("/api/admin/test-notification", methods=["POST"])
@auth
def api_test_notification():
    alerter = ctx.get("alerter")
    if not alerter or not getattr(alerter, "_notifier", None):
        return jsonify({"ok": False, "error": "No notification channels configured"}), 400
    try:
        alerter._notifier.send(
            severity=5, title="CGS Test Notification",
            detail="This is a test notification from CGS. If you see this, the channel is working.",
            src_ip="0.0.0.0", dst_ip="0.0.0.0")  # nosec B104 — placeholder IP for test notification
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ══════════════════════════════════════════════════
# Admin: Logs
# ══════════════════════════════════════════════════

@admin_bp.route("/api/admin/logs/journal")
@admin_required
def api_admin_logs_journal():
    lines = min(request.args.get("lines", 50, type=int), 200)
    try:
        r = subprocess.run(
            ["journalctl", "-u", "cgs", "--no-pager", "-n", str(lines)],
            capture_output=True, text=True, timeout=10)
        return jsonify({"ok": True, "content": r.stdout})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@admin_bp.route("/api/admin/logs/app")
@admin_required
def api_admin_logs_app():
    cfg = ctx.get("config")
    lines = min(request.args.get("lines", 50, type=int), 200)
    log_dir = cfg.get("general.log_dir", "/var/log/cgs") if cfg else "/var/log/cgs"
    log_file = os.path.join(log_dir, "cgs.log")
    if not os.path.exists(log_file) or not os.path.isfile(log_file):
        return jsonify({"ok": False, "error": "Log file not found"})
    try:
        r = subprocess.run(["tail", f"-{lines}", log_file],
                          capture_output=True, text=True, timeout=5)
        return jsonify({"ok": True, "content": r.stdout})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@admin_bp.route("/api/admin/logs/defense-audit")
@admin_required
def api_admin_logs_defense():
    cfg = ctx.get("config")
    log_dir = cfg.get("general.log_dir", "/var/log/cgs") if cfg else "/var/log/cgs"
    audit_file = os.path.join(log_dir, "defense_audit.jsonl")
    if not os.path.exists(audit_file) or not os.path.isfile(audit_file):
        return jsonify({"ok": True, "content": ""})
    try:
        r = subprocess.run(["tail", "-30", audit_file],
                          capture_output=True, text=True, timeout=5)
        return jsonify({"ok": True, "content": r.stdout})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@admin_bp.route("/api/admin/logs/forensics")
@admin_required
def api_admin_logs_forensics():
    cfg = ctx.get("config")
    log_dir = cfg.get("general.log_dir", "/var/log/cgs") if cfg else "/var/log/cgs"
    forensic_dir = os.path.join(log_dir, "forensics")
    if not os.path.isdir(forensic_dir):
        return jsonify({"files": []})
    try:
        files = []
        for fn in sorted(os.listdir(forensic_dir), reverse=True)[:20]:
            fp = os.path.join(forensic_dir, fn)
            if os.path.isfile(fp):
                files.append({"name": fn, "size_kb": round(os.path.getsize(fp) / 1024, 1)})
        return jsonify({"files": files})
    except Exception as e:
        return jsonify({"files": [], "error": str(e)})
