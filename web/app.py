"""CGS — Unified Web Interface (users + admin)."""
import logging, os, secrets
from flask import Flask, render_template, jsonify, request, session, redirect
from flask_socketio import SocketIO
from markupsafe import escape
from core.database import Alert, Host, is_setup_complete
from core.security import InputValidator
import web.shared as shared

logger = logging.getLogger("cgs.web")
app = Flask(__name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static"))
socketio = SocketIO(app, async_mode="gevent", cors_allowed_origins=[])

# Legacy aliases for external code that imports from web.app directly
_ctx = shared.ctx
_csrf = None
_rate_limiter = None
_login_guard = None
_session_timeout = 1800
_config = None
_auth = shared.auth
_admin_required = shared.admin_required
_csrf_protect = shared.csrf_protect
_audit = shared.audit


def init_app(config, modules):
    global _csrf, _rate_limiter, _login_guard, _session_timeout, _config
    _config = config
    shared.config = config
    secret = config.get("web.secret", "")
    if not secret or secret == "x":
        secret = secrets.token_hex(32)
    app.secret_key = secret
    _session_timeout = config.get("web.session_timeout_minutes", 30) * 60
    shared.session_timeout = _session_timeout
    shared.ctx.update(modules)
    shared.ctx["config"] = config
    if "alerter" in modules:
        modules["alerter"]._ws_cb = lambda d: socketio.emit("alert", d, namespace="/live")
    from core.security import CSRFProtection, RateLimiter
    _csrf = CSRFProtection(secret)
    shared.csrf = _csrf
    _rate_limiter = RateLimiter()
    shared.rate_limiter = _rate_limiter
    _login_guard = modules.get("login_guard")
    shared.login_guard = _login_guard
    allowed = config.get("web.cors_origins", [])
    if allowed:
        socketio.server.eio.cors_allowed_origins = allowed
    from web.routes_auth import auth_bp
    from web.routes_monitoring import monitoring_bp
    from web.routes_compliance import compliance_bp
    from web.routes_grc import grc_bp
    from web.routes_admin import admin_bp
    registered = {bp.name for bp in app.iter_blueprints()}
    for bp in (auth_bp, monitoring_bp, compliance_bp, grc_bp, admin_bp):
        if bp.name not in registered:
            app.register_blueprint(bp)
    return app, socketio


@app.before_request
def _setup_guard():
    """If no admin user exists, force setup wizard."""
    path = request.path
    if (path.startswith("/setup") or
        path.startswith("/api/setup/") or
        path.startswith("/static") or
        path.startswith("/api/client/") or
        path.startswith("/incident/") or
        path.startswith("/create-password") or
        path.startswith("/api/create-password")):
        return None
    if not is_setup_complete():
        if path.startswith("/api/"):
            return jsonify({"e": "setup_required"}), 503
        return redirect("/setup")
    return None


@app.route("/")
@shared.auth
def index():
    return render_template("dashboard.html",
                           role=session.get("role", "user"),
                           username=session.get("username", ""))


@app.route("/api/audit/verify")
@shared.auth
def api_audit_verify():
    ac = shared.ctx.get("audit_chain")
    return jsonify(ac.verify() if ac else {"ok": False})


@app.route("/api/threat-intel/check/<ip>")
@shared.auth
def api_threat_intel(ip):
    ti = shared.ctx.get("threat_intel")
    return jsonify(ti.check_ip(ip) if ti else {})


@app.route("/api/false-positive", methods=["POST"])
@shared.admin_required
@shared.csrf_protect
def api_false_positive():
    fp = shared.ctx.get("false_positives")
    if not fp:
        return jsonify({"error": "not available"}), 503
    data = request.get_json(force=True, silent=True) or {}
    result = fp.report_false_positive(data.get("ip", ""), data.get("category", ""))
    return jsonify({"ok": True, "data": result})


@app.route("/api/false-positive/list")
@shared.auth
def api_false_positive_list():
    fp = shared.ctx.get("false_positives")
    return jsonify(fp.get_all() if fp else {})


@app.route("/api/rules")
@shared.auth
def api_rules():
    hr = shared.ctx.get("hot_rules")
    return jsonify(hr.stats if hr else {})


@app.route("/api/rules/reload", methods=["POST"])
@shared.admin_required
@shared.csrf_protect
def api_rules_reload():
    hr = shared.ctx.get("hot_rules")
    if not hr:
        return jsonify({"error": "not available"}), 503
    count = hr.reload()
    return jsonify({"ok": True, "rules_loaded": count})


@app.route("/api/backup", methods=["POST"])
@shared.admin_required
@shared.csrf_protect
def api_backup():
    bk = shared.ctx.get("backup")
    if not bk:
        return jsonify({"error": "not available"}), 503
    path = bk.create()
    return jsonify({"ok": True, "path": path})


@app.route("/api/backup/list")
@shared.admin_required
def api_backup_list():
    bk = shared.ctx.get("backup")
    return jsonify(bk.list_backups() if bk else [])


@app.route("/api/report/weekly")
@shared.admin_required
def api_weekly_report():
    wr = shared.ctx.get("weekly_report")
    return jsonify(wr.generate() if wr else {})


@app.route("/api/incidents/<incident_id>/pin")
@shared.admin_required
def api_incident_pin(incident_id):
    pin_mgr = shared.ctx.get("approval_pin")
    if not pin_mgr:
        return jsonify({"pin": ""})
    return jsonify({"pin": pin_mgr.get_pin_for_dashboard(incident_id)})


@app.route("/api/integrity")
@shared.admin_required
def api_integrity():
    from core.hardening import IntegrityCheck
    return jsonify(IntegrityCheck.verify())


@app.route("/api/firewall/verify")
@shared.admin_required
def api_firewall_verify():
    fv = shared.ctx.get("firewall_verifier")
    return jsonify(fv.verify() if fv else {})


@app.route("/api/ssh/verify")
@shared.admin_required
def api_ssh_verify():
    from core.hardening import SSHHardener
    return jsonify(SSHHardener().verify())


@app.route("/api/os/verify")
@shared.admin_required
def api_os_verify():
    oh = shared.ctx.get("os_hardener")
    return jsonify(oh.verify() if oh else {})


@app.route("/api/client/sensor", methods=["POST"])
def api_client_sensor():
    q = shared.ctx.get("client_queue")
    if not q:
        return jsonify({"ok": False})
    data = request.get_json(force=True, silent=True) or {}
    hostname = data.get("hostname", "")
    ts = data.get("ts", "")
    sig = data.get("sig", "")
    if not q.verify_client(hostname, ts, sig):
        return jsonify({"error": "authentication failed"}), 403
    anomalies = data.get("anomalies", [])
    alerter = shared.ctx.get("alerter")
    if alerter and anomalies:
        for a in anomalies[:20]:
            category = InputValidator.safe_string(a.get("category", ""), 100)
            detail = InputValidator.safe_string(a.get("detail", ""), 300)
            alerter.fire(severity=a.get("severity", 4), source="client_agent",
                        category=category, title=f"Client sensor: {category}",
                        detail=detail, src_ip=request.remote_addr)
    return jsonify({"ok": True, "processed": len(anomalies)})


@app.route("/api/client/check")
def api_client_check():
    q = shared.ctx.get("client_queue")
    if not q:
        return jsonify({"messages": [], "poll_interval": 60})
    ip = request.remote_addr
    hostname = request.args.get("hostname", "")
    ts = request.args.get("ts", "")
    sig = request.args.get("sig", "")
    if not q.verify_client(hostname, ts, sig):
        return jsonify({"error": "authentication failed"}), 403
    messages, interval = q.get_pending(ip)
    response = {"messages": messages, "poll_interval": interval}
    return jsonify(q.sign_response(response))


@app.route("/api/client/ack", methods=["POST"])
def api_client_ack():
    q = shared.ctx.get("client_queue")
    if not q:
        return jsonify({"ok": False})
    data = request.get_json(force=True, silent=True) or {}
    ok = q.acknowledge(request.remote_addr, data.get("message_id", ""),
                       hostname=data.get("hostname", ""), user=data.get("user", ""))
    return jsonify({"ok": ok})


@app.route("/api/incidents")
@shared.auth
def api_incidents():
    inc = shared.ctx.get("incident")
    return jsonify(inc.get_all_incidents(100) if inc else [])


@app.route("/api/incidents/active")
@shared.auth
def api_incidents_active():
    inc = shared.ctx.get("incident")
    return jsonify(inc.get_active_incidents() if inc else [])


@app.route("/api/incidents/<incident_id>")
@shared.auth
def api_incident_detail(incident_id):
    inc = shared.ctx.get("incident")
    if not inc:
        return jsonify({"e": "not found"}), 404
    detail = inc.get_incident(incident_id)
    return jsonify(detail) if detail else (jsonify({"e": "not found"}), 404)


@app.route("/api/incidents/stats")
@shared.auth
def api_incident_stats():
    inc = shared.ctx.get("incident")
    return jsonify(inc.stats if inc else {})


@app.route("/api/snapshots")
@shared.admin_required
def api_snapshots():
    inc = shared.ctx.get("incident")
    return jsonify(inc.snapshots.list_snapshots() if inc else [])


@app.route("/api/snapshots/rollback", methods=["POST"])
@shared.admin_required
@shared.csrf_protect
def api_rollback():
    inc = shared.ctx.get("incident")
    if not inc:
        return jsonify({"ok": False, "error": "not available"})
    data = request.get_json(force=True, silent=True) or {}
    filepath = data.get("filepath", "")
    if not filepath or not os.path.exists(filepath):
        return jsonify({"ok": False, "error": "snapshot not found"})
    snap_dir = os.path.realpath(inc.cfg.get("general.log_dir", "/var/log/cgs") + "/snapshots")
    real_path = os.path.realpath(filepath)
    if not real_path.startswith(snap_dir + os.sep) and real_path != snap_dir:
        return jsonify({"ok": False, "error": "invalid snapshot path"}), 403
    result = inc.snapshots.restore(filepath)
    shared.audit("ROLLBACK", f"snapshot={filepath}")
    return jsonify(result)


@app.route("/incident/<incident_id>/approve", methods=["POST", "GET"])
def web_approve(incident_id):
    if not InputValidator.incident_id(incident_id):
        return _decision("Error", "Invalid incident ID.", False), 400
    token = request.args.get("token", "") or request.form.get("token", "")
    inc = shared.ctx.get("incident")
    if not inc:
        return _decision("Error", "Incident engine not available.", False)
    result = inc.approve(token, approved_by=request.remote_addr)
    if result is None:
        return _decision("Invalid token", "This link is not valid or has expired.", False)
    if "error" in result:
        return _decision("Already processed", result["error"], False)
    return _decision("Incident approved",
        f"Defense actions for {incident_id} are being executed.", True)


@app.route("/incident/<incident_id>/reject", methods=["POST", "GET"])
def web_reject(incident_id):
    if not InputValidator.incident_id(incident_id):
        return _decision("Error", "Invalid incident ID.", False), 400
    token = request.args.get("token", "") or request.form.get("token", "")
    inc = shared.ctx.get("incident")
    if not inc:
        return _decision("Error", "Incident engine not available.", False)
    result = inc.reject(token, rejected_by=request.remote_addr)
    if result is None:
        return _decision("Invalid token", "This link is not valid or has expired.", False)
    if "error" in result:
        return _decision("Already processed", result["error"], False)
    return _decision("Incident rejected",
        f"No defense actions will be executed for {incident_id}.", True)


def _decision(title, message, success):
    color = "#16A34A" if success else "#DC2626"
    safe_title = escape(title)
    safe_message = escape(message)
    return (f'<!DOCTYPE html>\n<html><head><meta charset="utf-8">'
            f'<title>CGS \u2014 {safe_title}</title>\n'
            f'<style>body{{margin:0;font-family:Arial;background:#0f172a;display:flex;'
            f'align-items:center;justify-content:center;min-height:100vh}}'
            f'.box{{max-width:500px;background:#1e293b;border-radius:12px;padding:40px;'
            f'text-align:center;color:#e2e8f0}}'
            f'h1{{color:{color};font-size:1.3em}}p{{color:#94a3b8}}a{{color:#38bdf8}}</style>\n'
            f'</head><body><div class="box"><h1>{safe_title}</h1>'
            f'<p>{safe_message}</p>\n'
            f'<a href="/">Dashboard</a></div></body></html>')


@app.route("/api/search")
@shared.auth
def api_global_search():
    from core.database import Risk, Asset, Policy, Vendor
    q = request.args.get("q", "").strip()
    if len(q) < 2:
        return jsonify({"query": q, "results": {}, "total": 0})
    results = {}
    total = 0
    al = Alert.select().where(
        Alert.title.contains(q) | Alert.detail.contains(q) |
        Alert.src_ip.contains(q) | Alert.dst_ip.contains(q) |
        Alert.ioc.contains(q)
    ).order_by(Alert.ts.desc()).limit(20)
    results["alerts"] = [{"id": a.id, "title": a.title, "type": "alert",
                          "detail": (a.detail or "")[:120], "ts": a.ts.isoformat()} for a in al]
    total += len(results["alerts"])
    hl = Host.select().where(
        Host.ip.contains(q) | Host.hostname.contains(q) |
        Host.vendor.contains(q) | Host.mac.contains(q)
    ).limit(20)
    results["hosts"] = [{"id": h.ip, "title": h.hostname or h.ip, "type": "host",
                         "detail": f"{h.ip} / {h.vendor or ''}", "ip": h.ip} for h in hl]
    total += len(results["hosts"])
    rl = Risk.select().where(
        Risk.title.contains(q) | Risk.description.contains(q) |
        Risk.owner.contains(q)
    ).limit(20)
    results["risks"] = [{"id": r.id, "title": r.title, "type": "risk",
                         "detail": (r.description or "")[:120]} for r in rl]
    total += len(results["risks"])
    asl = Asset.select().where(
        Asset.name.contains(q) | Asset.owner.contains(q) |
        Asset.description.contains(q) | Asset.location.contains(q)
    ).limit(20)
    results["assets"] = [{"id": a.id, "title": a.name, "type": "asset",
                          "detail": (a.description or "")[:120]} for a in asl]
    total += len(results["assets"])
    pl = Policy.select().where(
        Policy.title.contains(q) | Policy.content.contains(q)
    ).limit(20)
    results["policies"] = [{"id": p.id, "title": p.title, "type": "policy",
                            "detail": (p.content or "")[:120]} for p in pl]
    total += len(results["policies"])
    vl = Vendor.select().where(
        Vendor.name.contains(q) | Vendor.service.contains(q) |
        Vendor.contact.contains(q)
    ).limit(20)
    results["vendors"] = [{"id": v.id, "title": v.name, "type": "vendor",
                           "detail": f"{v.service or ''} / {v.contact or ''}"} for v in vl]
    total += len(results["vendors"])
    return jsonify({"query": q, "results": results, "total": total})


@app.route("/api/docs")
def api_docs():
    """Return auto-generated API documentation as JSON."""
    from core.api_docs import generate_api_docs
    return jsonify(generate_api_docs(app))


@app.route("/docs")
def docs_page():
    """API documentation page."""
    return render_template("docs.html")


@socketio.on("connect", namespace="/live")
def ws_connect():
    pass
