"""CyberGuard Sentinel — API + Dashboard (simplified auth)."""
import functools, logging, os, secrets
from datetime import datetime, timedelta
import bcrypt
from flask import Flask, render_template, jsonify, request, session, redirect
from flask_socketio import SocketIO
from core.database import Alert, Host, Port, Flow, DnsLog, BaselineStat

logger = logging.getLogger("cyberguard.web")
app = Flask(__name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static"))
socketio = SocketIO(app, async_mode="gevent", cors_allowed_origins="*")
_ctx = {}

def init_app(config, modules):
    secret = config.get("web.secret", "")
    if not secret or secret == "x":
        secret = secrets.token_hex(32)
    app.secret_key = secret
    app.config["U"] = config.get("web.username", "admin")
    app.config["PH"] = config.get("web.password_hash", "")
    _ctx.update(modules)
    if "alerter" in modules:
        modules["alerter"]._ws_cb = lambda d: socketio.emit("alert", d, namespace="/live")
    return app, socketio

def _auth(f):
    @functools.wraps(f)
    def w(*a, **k):
        if not session.get("ok"):
            if request.path.startswith("/api/"):
                return jsonify({"e": "auth"}), 401
            return redirect("/login")
        return f(*a, **k)
    return w

def _audit(action, detail=""):
    ac = _ctx.get("audit_chain")
    if ac:
        ac.log(event=f"ADMIN: {action}", detail=f"{detail} | ip={request.remote_addr}",
               source="dashboard", severity=4, ip=request.remote_addr)

# ══════════════════════════════════════════════════
# Auth
# ══════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        ph = app.config["PH"]
        if u == app.config["U"] and ph and bcrypt.checkpw(p.encode(), ph.encode()):
            session["ok"] = True
            return redirect("/")
        error = "Invalid credentials."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ══════════════════════════════════════════════════
# Dashboard
# ══════════════════════════════════════════════════

@app.route("/")
@_auth
def index():
    return render_template("dashboard.html")

@app.route("/api/overview")
@_auth
def api_overview():
    now = datetime.now(); td = now.replace(hour=0, minute=0, second=0); wk = now - timedelta(days=7)
    return jsonify({
        "ts": now.isoformat(),
        "alerts": {
            "today": Alert.select().where(Alert.ts >= td).count(),
            "crit": Alert.select().where(Alert.severity == 1, Alert.ts >= td).count(),
            "high": Alert.select().where(Alert.severity == 2, Alert.ts >= td).count(),
            "med": Alert.select().where(Alert.severity == 3, Alert.ts >= td).count(),
            "unack": Alert.select().where(Alert.ack == False).count(),
        },
        "network": {
            "hosts_up": Host.select().where(Host.status == "up").count(),
            "hosts_total": Host.select().count(),
            "new_week": Host.select().where(Host.first_seen >= wk).count(),
            "open_ports": Port.select().where(Port.state == "open").count(),
        },
        "sniffer": _ctx["sniffer"].stats if "sniffer" in _ctx else {},
        "threats": _ctx["engine"].get_threat_summary() if "engine" in _ctx else {},
    })

# ══════════════════════════════════════════════════
# Alerts
# ══════════════════════════════════════════════════

@app.route("/api/alerts")
@_auth
def api_alerts():
    lim = request.args.get("limit", 200, type=int)
    sv = request.args.get("severity", 5, type=int)
    src = request.args.get("source")
    q = Alert.select().where(Alert.severity <= sv)
    if src: q = q.where(Alert.source == src)
    SL = {1: "CRIT", 2: "HIGH", 3: "MED", 4: "LOW", 5: "INFO"}
    return jsonify([{
        "id": a.id, "ts": a.ts.isoformat(), "severity": a.severity,
        "sev_label": SL.get(a.severity), "source": a.source, "category": a.category,
        "title": a.title, "detail": a.detail, "src_ip": a.src_ip, "dst_ip": a.dst_ip,
        "ioc": a.ioc, "ack": a.ack
    } for a in q.order_by(Alert.ts.desc()).limit(lim)])

@app.route("/api/alerts/<int:aid>/ack", methods=["POST"])
@_auth
def api_ack(aid):
    try:
        a = Alert.get_by_id(aid); a.ack = True; a.save()
        return jsonify({"ok": True})
    except:
        return jsonify({"e": "not found"}), 404

# ══════════════════════════════════════════════════
# Hosts
# ══════════════════════════════════════════════════

@app.route("/api/hosts")
@_auth
def api_hosts():
    out = []
    for h in Host.select().order_by(Host.risk_score.desc(), Host.last_seen.desc()):
        ps = list(Port.select().where(Port.host_ip == h.ip, Port.state == "open"))
        out.append({
            "ip": h.ip, "mac": h.mac, "hostname": h.hostname, "vendor": h.vendor,
            "os": h.os_hint, "status": h.status, "risk": h.risk_score,
            "first": h.first_seen.isoformat(), "last": h.last_seen.isoformat(),
            "ports": [{"port": p.port, "svc": p.service, "banner": (p.banner or "")[:80]} for p in ps],
        })
    return jsonify(out)

# ══════════════════════════════════════════════════
# System
# ══════════════════════════════════════════════════

@app.route("/api/health")
@_auth
def api_health():
    h = _ctx.get("health")
    return jsonify(h.check_all()) if h else jsonify({})

@app.route("/api/dns")
@_auth
def api_dns():
    lim = request.args.get("limit", 100, type=int)
    sus = request.args.get("suspicious")
    q = DnsLog.select().order_by(DnsLog.ts.desc())
    if sus: q = q.where(DnsLog.entropy >= 3.5)
    return jsonify([{
        "ts": d.ts.isoformat(), "src": d.src_ip, "query": d.query,
        "entropy": d.entropy, "suspicious": d.suspicious
    } for d in q.limit(lim)])

@app.route("/api/baseline")
@_auth
def api_baseline():
    return jsonify([{
        "key": b.key, "value": round(b.value, 2), "std": round(b.std_dev, 2),
        "samples": b.samples
    } for b in BaselineStat.select()])

# ══════════════════════════════════════════════════
# Defense
# ══════════════════════════════════════════════════

@app.route("/api/defense")
@_auth
def api_defense():
    d = _ctx.get("defense")
    if not d: return jsonify({})
    result = {"stats": d.get_stats(), "active": d.get_active_actions()}
    if d.netgate:
        result["netgate"] = d.netgate.stats
        result["netgate"]["status"] = d.netgate.get_status()
    return jsonify(result)

@app.route("/api/defense/block", methods=["POST"])
@_auth
def api_block():
    d = _ctx.get("defense")
    if not d: return jsonify({"e": "no defense"}), 503
    ip = request.json.get("ip", "")
    reason = request.json.get("reason", "Manual block")
    ttl = request.json.get("ttl", 3600)
    ok = d.block_ip(ip, reason=reason, ttl=ttl, auto=False)
    _audit("BLOCK_IP", f"ip={ip}")
    return jsonify({"ok": ok, "ip": ip})

@app.route("/api/defense/unblock", methods=["POST"])
@_auth
def api_unblock():
    d = _ctx.get("defense")
    if not d: return jsonify({"e": "no defense"}), 503
    ip = request.json.get("ip", "")
    ok = d.unblock_ip(ip, reason="Manual unblock")
    _audit("UNBLOCK_IP", f"ip={ip}")
    return jsonify({"ok": ok, "ip": ip})

@app.route("/api/defense/quarantine", methods=["POST"])
@_auth
def api_quarantine():
    d = _ctx.get("defense")
    if not d: return jsonify({"e": "no defense"}), 503
    ip = request.json.get("ip", "")
    ok = d.quarantine_host(ip, reason="Manual quarantine", auto=False)
    _audit("QUARANTINE", f"ip={ip}")
    return jsonify({"ok": ok, "ip": ip})

@app.route("/api/defense/audit")
@_auth
def api_audit_log():
    d = _ctx.get("defense")
    return jsonify(d.get_audit_log(200) if d else [])

# ══════════════════════════════════════════════════
# Analysis
# ══════════════════════════════════════════════════

@app.route("/api/correlator")
@_auth
def api_correlator():
    c = _ctx.get("correlator")
    return jsonify(c.stats if c else {})

@app.route("/api/identity")
@_auth
def api_identity():
    i = _ctx.get("identity")
    return jsonify(i.stats if i else {})

@app.route("/api/identity/verify/<ip>")
@_auth
def api_identity_verify(ip):
    i = _ctx.get("identity")
    if not i: return jsonify({"error": "module absent"})
    mr = _ctx.get("mac_resolver")
    mac = mr.ip_to_mac(ip) if mr else ""
    if not mac:
        try:
            h = Host.get_or_none(Host.ip == ip)
            if h: mac = h.mac or ""
        except: pass
    if not mac: return jsonify({"error": "MAC unknown for this IP"})
    return jsonify(i.verify_identity(ip, mac))

@app.route("/api/identity/fingerprint/<mac>")
@_auth
def api_identity_fp(mac):
    i = _ctx.get("identity")
    if not i: return jsonify({})
    fp = i.get_fingerprint(mac)
    return jsonify(fp) if fp else jsonify({"error": "unknown fingerprint"})

@app.route("/api/mac-table")
@_auth
def api_mac_table():
    mr = _ctx.get("mac_resolver")
    return jsonify(mr.stats if mr else {})

@app.route("/api/killchain")
@_auth
def api_killchain():
    kc = _ctx.get("killchain")
    return jsonify(kc.stats if kc else {})

# ══════════════════════════════════════════════════
# Resilience
# ══════════════════════════════════════════════════

@app.route("/api/resilience")
@_auth
def api_resilience():
    sm = _ctx.get("self_monitor")
    dg = _ctx.get("degraded")
    result = {}
    if sm: result["server_health"] = sm.check()
    if dg: result["degraded_mode"] = dg.stats
    return jsonify(result)

@app.route("/api/resilience/degraded", methods=["POST"])
@_auth
def api_degraded_toggle():
    dg = _ctx.get("degraded")
    if not dg: return jsonify({"error": "not available"}), 503
    data = request.get_json(force=True, silent=True) or {}
    action = data.get("action", "")
    if action == "enter":
        dg.enter(reason="Manual activation by admin")
        return jsonify({"ok": True, "active": True})
    elif action == "exit":
        dg.exit()
        return jsonify({"ok": True, "active": False})
    return jsonify({"error": "action must be 'enter' or 'exit'"}), 400

# ══════════════════════════════════════════════════
# Extended features
# ══════════════════════════════════════════════════

@app.route("/api/audit/verify")
@_auth
def api_audit_verify():
    ac = _ctx.get("audit_chain")
    return jsonify(ac.verify() if ac else {"ok": False})

@app.route("/api/threat-intel/check/<ip>")
@_auth
def api_threat_intel(ip):
    ti = _ctx.get("threat_intel")
    return jsonify(ti.check_ip(ip) if ti else {})

@app.route("/api/false-positive", methods=["POST"])
@_auth
def api_false_positive():
    fp = _ctx.get("false_positives")
    if not fp: return jsonify({"error": "not available"}), 503
    data = request.get_json(force=True, silent=True) or {}
    result = fp.report_false_positive(data.get("ip", ""), data.get("category", ""))
    return jsonify({"ok": True, "data": result})

@app.route("/api/false-positive/list")
@_auth
def api_false_positive_list():
    fp = _ctx.get("false_positives")
    return jsonify(fp.get_all() if fp else {})

@app.route("/api/rules")
@_auth
def api_rules():
    hr = _ctx.get("hot_rules")
    return jsonify(hr.stats if hr else {})

@app.route("/api/rules/reload", methods=["POST"])
@_auth
def api_rules_reload():
    hr = _ctx.get("hot_rules")
    if not hr: return jsonify({"error": "not available"}), 503
    count = hr.reload()
    return jsonify({"ok": True, "rules_loaded": count})

@app.route("/api/backup", methods=["POST"])
@_auth
def api_backup():
    bk = _ctx.get("backup")
    if not bk: return jsonify({"error": "not available"}), 503
    path = bk.create()
    return jsonify({"ok": True, "path": path})

@app.route("/api/backup/list")
@_auth
def api_backup_list():
    bk = _ctx.get("backup")
    return jsonify(bk.list_backups() if bk else [])

@app.route("/api/report/weekly")
@_auth
def api_weekly_report():
    wr = _ctx.get("weekly_report")
    return jsonify(wr.generate() if wr else {})

@app.route("/api/incidents/<incident_id>/pin")
@_auth
def api_incident_pin(incident_id):
    pin_mgr = _ctx.get("approval_pin")
    if not pin_mgr: return jsonify({"pin": ""})
    return jsonify({"pin": pin_mgr.get_pin_for_dashboard(incident_id)})

@app.route("/api/integrity")
@_auth
def api_integrity():
    from core.hardening import IntegrityCheck
    return jsonify(IntegrityCheck.verify())

@app.route("/api/firewall/verify")
@_auth
def api_firewall_verify():
    fv = _ctx.get("firewall_verifier")
    return jsonify(fv.verify() if fv else {})

@app.route("/api/ssh/verify")
@_auth
def api_ssh_verify():
    from core.hardening import SSHHardener
    return jsonify(SSHHardener().verify())

@app.route("/api/os/verify")
@_auth
def api_os_verify():
    oh = _ctx.get("os_hardener")
    return jsonify(oh.verify() if oh else {})

# ══════════════════════════════════════════════════
# Client agent API (HMAC authenticated)
# ══════════════════════════════════════════════════

@app.route("/api/client/sensor", methods=["POST"])
def api_client_sensor():
    q = _ctx.get("client_queue")
    if not q: return jsonify({"ok": False})
    data = request.get_json(force=True, silent=True) or {}
    anomalies = data.get("anomalies", [])
    alerter = _ctx.get("alerter")
    if alerter and anomalies:
        for a in anomalies[:20]:
            alerter.fire(severity=a.get("severity", 4), source="client_agent",
                        category=a.get("category", ""), title=f"Client sensor: {a.get('category', '')}",
                        detail=a.get("detail", "")[:300], src_ip=request.remote_addr)
    return jsonify({"ok": True, "processed": len(anomalies)})

@app.route("/api/client/check")
def api_client_check():
    q = _ctx.get("client_queue")
    if not q: return jsonify({"messages": [], "poll_interval": 60})
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
    q = _ctx.get("client_queue")
    if not q: return jsonify({"ok": False})
    data = request.get_json(force=True, silent=True) or {}
    ok = q.acknowledge(request.remote_addr, data.get("message_id", ""),
                       hostname=data.get("hostname", ""), user=data.get("user", ""))
    return jsonify({"ok": ok})

# ══════════════════════════════════════════════════
# Suricata
# ══════════════════════════════════════════════════

@app.route("/api/suricata")
@_auth
def api_suricata():
    s = _ctx.get("suricata")
    return jsonify(s.stats if s else {})

# ══════════════════════════════════════════════════
# Incidents
# ══════════════════════════════════════════════════

@app.route("/api/incidents")
@_auth
def api_incidents():
    inc = _ctx.get("incident")
    return jsonify(inc.get_all_incidents(100) if inc else [])

@app.route("/api/incidents/active")
@_auth
def api_incidents_active():
    inc = _ctx.get("incident")
    return jsonify(inc.get_active_incidents() if inc else [])

@app.route("/api/incidents/<incident_id>")
@_auth
def api_incident_detail(incident_id):
    inc = _ctx.get("incident")
    if not inc: return jsonify({"e": "not found"}), 404
    detail = inc.get_incident(incident_id)
    return jsonify(detail) if detail else (jsonify({"e": "not found"}), 404)

@app.route("/api/incidents/stats")
@_auth
def api_incident_stats():
    inc = _ctx.get("incident")
    return jsonify(inc.stats if inc else {})

@app.route("/api/snapshots")
@_auth
def api_snapshots():
    inc = _ctx.get("incident")
    return jsonify(inc.snapshots.list_snapshots() if inc else [])

@app.route("/api/snapshots/rollback", methods=["POST"])
@_auth
def api_rollback():
    inc = _ctx.get("incident")
    if not inc: return jsonify({"ok": False, "error": "not available"})
    data = request.get_json(force=True, silent=True) or {}
    filepath = data.get("filepath", "")
    if not filepath or not os.path.exists(filepath):
        return jsonify({"ok": False, "error": "snapshot not found"})
    result = inc.snapshots.restore(filepath)
    _audit("ROLLBACK", f"snapshot={filepath}")
    return jsonify(result)

# ══════════════════════════════════════════════════
# Approval / Rejection (email links)
# ══════════════════════════════════════════════════

@app.route("/incident/<incident_id>/approve")
def web_approve(incident_id):
    token = request.args.get("token", "")
    inc = _ctx.get("incident")
    if not inc:
        return _decision("Error", "Incident engine not available.", False)
    result = inc.approve(token, approved_by=request.remote_addr)
    if result is None:
        return _decision("Invalid token", "This link is not valid or has expired.", False)
    if "error" in result:
        return _decision("Already processed", result["error"], False)
    return _decision("Incident approved",
        f"Defense actions for {incident_id} are being executed.", True)

@app.route("/incident/<incident_id>/reject")
def web_reject(incident_id):
    token = request.args.get("token", "")
    inc = _ctx.get("incident")
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
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>CyberGuard — {title}</title>
<style>body{{margin:0;font-family:Arial;background:#0f172a;display:flex;align-items:center;
justify-content:center;min-height:100vh}}.box{{max-width:500px;background:#1e293b;
border-radius:12px;padding:40px;text-align:center;color:#e2e8f0}}
h1{{color:{color};font-size:1.3em}}p{{color:#94a3b8}}a{{color:#38bdf8}}</style>
</head><body><div class="box"><h1>{title}</h1><p>{message}</p>
<a href="/">Dashboard</a></div></body></html>"""

@socketio.on("connect", namespace="/live")
def ws_connect():
    pass
